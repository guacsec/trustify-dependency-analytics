/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.redhat.exhort.integration.backend;

import static com.redhat.exhort.integration.Constants.PROVIDERS_PARAM;
import static com.redhat.exhort.integration.Constants.RECOMMEND_PARAM;
import static com.redhat.exhort.integration.Constants.REQUEST_CONTENT_PROPERTY;
import static com.redhat.exhort.integration.Constants.VERBOSE_MODE_HEADER;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.apache.camel.component.micrometer.MicrometerConstants;
import org.apache.camel.component.micrometer.routepolicy.MicrometerRoutePolicyFactory;
import org.apache.camel.model.rest.RestParamType;
import org.apache.camel.processor.aggregate.GroupedBodyAggregationStrategy;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.analytics.AnalyticsService;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.AnalysisReport;
import com.redhat.exhort.config.exception.DetailedException;
import com.redhat.exhort.config.exception.SbomValidationException;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.ProviderAggregationStrategy;
import com.redhat.exhort.integration.providers.ProvidersBodyPlusResponseCodeAggregationStrategy;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;
import com.redhat.exhort.integration.sbom.SbomParser;
import com.redhat.exhort.integration.sbom.SbomParserFactory;
import com.redhat.exhort.integration.trustedcontent.TcResponseAggregation;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;
import com.redhat.exhort.monitoring.MonitoringProcessor;

import io.micrometer.core.instrument.MeterRegistry;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.ParseException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@ApplicationScoped
public class ExhortIntegration extends EndpointRouteBuilder {

  private static final Logger LOGGER = Logger.getLogger(ExhortIntegration.class);
  private static final String GZIP_ENCODING = "gzip";

  private final MeterRegistry registry;

  @Inject VulnerabilityProvider vulnerabilityProvider;

  @Inject AnalyticsService analytics;

  @Inject MonitoringProcessor monitoringProcessor;

  @Inject TcResponseAggregation tcResponseAggregation;

  @Inject ObjectMapper mapper;

  ExhortIntegration(MeterRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void configure() {

    // fmt:off
    getContext().getRegistry().bind(MicrometerConstants.METRICS_REGISTRY_NAME, registry);
    getContext().addRoutePolicyFactory(new MicrometerRoutePolicyFactory());
    
    restConfiguration().contextPath("/api/v4")
      .clientRequestValidation(true);

    errorHandler(deadLetterChannel("direct:processInternalError"));

    onException(IllegalArgumentException.class)
      .routeId("onExhortIllegalArgumentException")
      .useOriginalMessage()
      .process(monitoringProcessor::processClientException)
      .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(422))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .handled(true)
      .setBody().simple("${exception.message}");

    onException(ClientErrorException.class)
      .routeId("onExhortClientErrorException")
      .useOriginalMessage()
      .process(monitoringProcessor::processClientException)
      .setHeader(Exchange.HTTP_RESPONSE_CODE, simple("${exception.getResponse().getStatus()}"))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .handled(true)
      .setBody().simple("${exception.message}")
      .choice()
        .when(exchangeProperty(Constants.GZIP_RESPONSE_PROPERTY).isNotNull()).marshal().gzipDeflater()
        .setHeader(Exchange.CONTENT_ENCODING, constant("gzip"))
      .end();

    onException(DetailedException.class)
      .routeId("onExhortDetailedException")
      .useOriginalMessage()
      .process(monitoringProcessor::processClientException)
      .setHeader(Exchange.HTTP_RESPONSE_CODE, simple("${exception.getStatus()}"))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .handled(true)
      .setBody().simple("${exception.message}: ${exception.getDetails}")
      .choice()
      .when(exchangeProperty(Constants.GZIP_RESPONSE_PROPERTY).isNotNull()).marshal().gzipDeflater()
      .setHeader(Exchange.CONTENT_ENCODING, constant("gzip"))
      .end();

    rest()
      .post("/analysis")
        .routeId("restAnalysis")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:analysis")
      .post("/batch-analysis")
        .routeId("restBatchAnalysis")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:batchAnalysis")
      .get("/token")
        .routeId("restTokenValidation")
        .to("direct:validateToken")
      .get("/model-cards/{modelCardId}")
        .routeId("restModelCard")
        .to("direct:getModelCard")
      .post("/model-cards")
        .routeId("restListModelCards")
        .to("direct:listModelCards");

    from(direct("analysis"))
      .routeId("dependencyAnalysis")
      .to(direct("preProcessAnalysisRequest"))
      .process(this::processAnalysisRequest)
      .to(direct("analyticsIdentify"))
      .to(direct("analyzeSbom"))
      .to(direct("report"))
      .to(direct("postProcessAnalysisRequest"));

    from(direct("batchAnalysis"))
      .routeId("batchDependencyAnalysis")
      .to(direct("preProcessAnalysisRequest"))
      .process(this::processBatchAnalysisRequest)
      .to(direct("analyticsIdentify"))
      .to(direct("analyzeSboms"))
      .to(direct("batchReport"))
      .to(direct("postProcessAnalysisRequest"));

    from(direct("analyzeSbom"))
      .routeId("analyzeSbom")
      .enrich(direct("getTrustedContent"), tcResponseAggregation)
      .to(direct("findVulnerabilities"))
      .transform().method(ProviderAggregationStrategy.class, "toReport");

    from(direct("analyzeSboms"))
      .routeId("analyzeSboms")
      .split(body(), new GroupedBodyAggregationStrategy())
        .parallelProcessing()
          .process(this::processSbomEntry)
          .bean(this, "addSbomIdToDependencyTree")
          .setProperty(Constants.DEPENDENCY_TREE_PROPERTY, bodyAs(DependencyTree.class))
          .to(direct("analyzeSbom"))
          .bean(this, "transformBatchAnalysisReport")
      .end()
      .bean(this, "transformBatchAnalysisReportList");

    from(direct("preProcessAnalysisRequest"))
      .routeId("preProcessAnalysisRequest")
      .setProperty(Constants.EXHORT_REQUEST_ID_HEADER, method(BackendUtils.class,"generateRequestId"))
      .choice()
        .when(header(Exchange.CONTENT_ENCODING).isEqualToIgnoreCase(GZIP_ENCODING)).unmarshal().gzipDeflater()
        .setProperty(Constants.GZIP_RESPONSE_PROPERTY, constant(Boolean.TRUE))
      .end()
      .setProperty(PROVIDERS_PARAM, method(vulnerabilityProvider, "getProvidersFromQueryParam"))
      .setProperty(RECOMMEND_PARAM, header(RECOMMEND_PARAM))
      .setProperty(REQUEST_CONTENT_PROPERTY, method(BackendUtils.class, "getResponseMediaType"))
      .setProperty(VERBOSE_MODE_HEADER, header(VERBOSE_MODE_HEADER));

    from(direct("postProcessAnalysisRequest"))
      .routeId("postProcessAnalysisRequest")
      .to(seda("analyticsTrackAnalysis"))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .choice()
        .when(exchangeProperty(Constants.GZIP_RESPONSE_PROPERTY).isNotNull()).marshal().gzipDeflater()
        .setHeader(Exchange.CONTENT_ENCODING, constant("gzip"))
      .end()
      .process(this::cleanUpHeaders);

    from(direct("findVulnerabilities"))
      .routeId("findVulnerabilities")
      .recipientList(method(vulnerabilityProvider, "getProviderEndpoints"))
      .aggregationStrategy(AggregationStrategies.beanAllowNull(ProviderAggregationStrategy.class, "aggregate"))
        .parallelProcessing();

    from(direct("validateToken"))
      .routeId("validateToken")
      .setProperty(Constants.EXHORT_REQUEST_ID_HEADER, method(BackendUtils.class,"generateRequestId"))
      .to(direct("analyticsIdentify"))
      .choice()
        .when(header(Constants.SNYK_TOKEN_HEADER).isNotNull())
          .setProperty(PROVIDERS_PARAM, constant(Arrays.asList(Constants.SNYK_PROVIDER)))
          .to(direct("snykValidateToken"))
        .when(header(Constants.OSS_INDEX_TOKEN_HEADER).isNotNull())
          .setProperty(PROVIDERS_PARAM, constant(Arrays.asList(Constants.OSS_INDEX_PROVIDER)))
          .to(direct("ossValidateCredentials"))
        .when(header(Constants.TPA_TOKEN_HEADER).isNotNull())
          .setProperty(PROVIDERS_PARAM, constant(Arrays.asList(Constants.TPA_PROVIDER)))
          .to(direct("tpaValidateCredentials"))
        .otherwise()
          .setProperty(PROVIDERS_PARAM, constant(Arrays.asList(Constants.UNKNOWN_PROVIDER)))
          .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(Response.Status.BAD_REQUEST.getStatusCode()))
          .setBody(constant("Missing provider authentication headers"))
      .end()
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .to(seda("analyticsTrackToken"))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .process(this::cleanUpHeaders);

    from(direct("analyticsIdentify"))
      .routeId("analyticsIdentify")
      .process(monitoringProcessor::processOriginalRequest)
      .to(seda("analyticsAsyncIdentify"));

    from(seda("analyticsAsyncIdentify"))
      .routeId("analyticsAsyncIdentify")
      .process(analytics::identify);

    from(seda("analyticsTrackToken"))
      .routeId("analyticsTrackToken")
      .process(analytics::trackToken);

    from(seda("analyticsTrackAnalysis"))
      .routeId("analyticsTrackAnalysis")
      .process(analytics::trackAnalysis);

    from(seda("processFailedRequests"))
      .routeId("processFailedRequests")
      .process(monitoringProcessor::processServerError);

    from(direct("processInternalError"))
      .routeId("processInternalError")
      .log(LoggingLevel.ERROR, "${exception.stacktrace}")
      .to(seda("processFailedRequests"))
      .setBody().simple("${exception.message}")
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(Status.INTERNAL_SERVER_ERROR.getStatusCode()))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN));

    from(direct("exhortHealthCheck"))
      .routeId("exhortHealthCheck")
      .recipientList(header(Constants.HEALTH_CHECKS_LIST_HEADER_NAME))
      .aggregationStrategy(new ProvidersBodyPlusResponseCodeAggregationStrategy());

    from(direct("healthCheckProviderDisabled"))
      .routeId("healthCheckProviderDisabled")
      .setProperty(Constants.EXCLUDE_FROM_READINESS_CHECK, constant(true))
      .setBody(constant(String.format("Provider %s is disabled",exchangeProperty(Constants.PROVIDER_NAME))))

      .process(exchange -> {
        String providerName = exchange.getProperty(Constants.PROVIDER_NAME, String.class);
        exchange.getMessage().setHeader(Exchange.HTTP_RESPONSE_TEXT,String.format("Provider %s is disabled", providerName)); })
      .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(Response.Status.SERVICE_UNAVAILABLE));

    //fmt:on

  }

  private void processAnalysisRequest(Exchange exchange) {
    removeRequestHeader(exchange);
    var parser = getSbomParser(exchange);
    var tree = parser.parse(exchange.getIn().getBody(InputStream.class));
    exchange.setProperty(Constants.DEPENDENCY_TREE_PROPERTY, tree);
    exchange.getIn().setBody(tree);
  }

  private void processBatchAnalysisRequest(Exchange exchange) {
    removeRequestHeader(exchange);
    var parser = getSbomParser(exchange);
    try {
      Map<?, ?> sboms = mapper.readValue(exchange.getIn().getBody(InputStream.class), Map.class);
      Map<String, DependencyTree> trees =
          sboms.entrySet().stream()
              .collect(
                  Collectors.toMap(
                      e -> e.getKey().toString(),
                      e -> {
                        try {
                          return parser.parse(
                              new ByteArrayInputStream(mapper.writeValueAsBytes(e.getValue())));
                        } catch (Exception parseEx) {
                          throw new SbomValidationException(
                              "Failed to parse SBOM " + parseEx.getMessage(), parseEx);
                        }
                      }));
      exchange.getIn().setBody(trees);
    } catch (DetailedException e) {
      throw e;
    } catch (IOException | RuntimeException ex) {
      throw new ClientErrorException(
          "Unable to parse received request: " + ex.getMessage(), Response.Status.BAD_REQUEST);
    }
  }

  private void removeRequestHeader(Exchange exchange) {
    exchange.getIn().removeHeader(Constants.ACCEPT_HEADER);
    exchange.getIn().removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    exchange.getIn().removeHeader(Exchange.CONTENT_ENCODING);
  }

  private SbomParser getSbomParser(Exchange exchange) {
    ContentType ct;
    try {
      ct = new ContentType(exchange.getIn().getHeader(Exchange.CONTENT_TYPE, String.class));
    } catch (ParseException e) {
      throw new ClientErrorException(Response.Status.UNSUPPORTED_MEDIA_TYPE, e);
    }
    var parser = SbomParserFactory.newInstance(ct.getBaseType());
    exchange.setProperty(Constants.SBOM_TYPE_PARAM, ct.getBaseType());
    return parser;
  }

  private void cleanUpHeaders(Exchange exchange) {
    var msg = exchange.getIn();
    msg.removeHeader(VERBOSE_MODE_HEADER);
    msg.removeHeaders("ex-.*-user");
    msg.removeHeaders("ex-.*-token");
    msg.removeHeader(Constants.AUTHORIZATION_HEADER);
    msg.removeHeaders("rhda-.*");

    // Clean up monitoring context to prevent contamination between requests
    monitoringProcessor.cleanupContext(exchange);
  }

  private void processSbomEntry(Exchange exchange) {
    Map.Entry<?, ?> entry = exchange.getIn().getBody(Map.Entry.class);
    exchange.setProperty(Constants.SBOM_ID_PROPERTY, entry.getKey());
    exchange.getIn().setBody(entry.getValue());
  }

  public DependencyTree addSbomIdToDependencyTree(
      @Body DependencyTree tree, @ExchangeProperty(Constants.SBOM_ID_PROPERTY) String sbomId) {
    Map<PackageRef, DirectDependency> dependencies = new HashMap<>();
    if (tree.dependencies() != null) {
      dependencies.putAll(tree.dependencies());
    }
    PackageRef sbomRef = new PackageRef(sbomId);
    if (!dependencies.containsKey(sbomRef)) {
      dependencies.put(sbomRef, new DirectDependency(sbomRef, Collections.emptySet()));
    }
    return DependencyTree.builder().dependencies(dependencies).build();
  }

  public Map.Entry<String, AnalysisReport> transformBatchAnalysisReport(
      @Body AnalysisReport report, @ExchangeProperty(Constants.SBOM_ID_PROPERTY) String sbomId) {
    return new AbstractMap.SimpleEntry<>(sbomId, report);
  }

  public Map<String, AnalysisReport> transformBatchAnalysisReportList(
      @Body List<Map.Entry<String, AnalysisReport>> reports) {
    return reports.stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }
}
