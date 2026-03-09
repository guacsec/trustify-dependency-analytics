/*
 * Copyright 2023-2025 Trustify Dependency Analytics Authors
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

package io.github.guacsec.trustifyda.integration.backend;

import static io.github.guacsec.trustifyda.integration.Constants.PROVIDERS_PARAM;
import static io.github.guacsec.trustifyda.integration.Constants.RECOMMEND_PARAM;
import static io.github.guacsec.trustifyda.integration.Constants.REQUEST_CONTENT_PROPERTY;
import static io.github.guacsec.trustifyda.integration.Constants.VERBOSE_MODE_HEADER;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangeProperty;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.apache.camel.component.micrometer.MicrometerConstants;
import org.apache.camel.component.micrometer.routepolicy.MicrometerRoutePolicyFactory;
import org.apache.camel.model.rest.RestParamType;
import org.apache.camel.processor.aggregate.GroupedBodyAggregationStrategy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.config.exception.DetailedException;
import io.github.guacsec.trustifyda.config.exception.SbomValidationException;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.licenses.LicenseAggregationStrategy;
import io.github.guacsec.trustifyda.integration.providers.ProviderAggregationStrategy;
import io.github.guacsec.trustifyda.integration.providers.VulnerabilityProvider;
import io.github.guacsec.trustifyda.integration.sbom.SbomParser;
import io.github.guacsec.trustifyda.integration.sbom.SbomParserFactory;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;
import io.github.guacsec.trustifyda.monitoring.MonitoringProcessor;
import io.micrometer.core.instrument.MeterRegistry;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.ParseException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@ApplicationScoped
public class ExhortIntegration extends EndpointRouteBuilder {

  private static final String GZIP_ENCODING = "gzip";

  private final MeterRegistry registry;

  @Inject VulnerabilityProvider vulnerabilityProvider;

  @Inject MonitoringProcessor monitoringProcessor;

  @Inject ObjectMapper mapper;

  ExhortIntegration(MeterRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void configure() {

    // fmt:off
    getContext().getRegistry().bind(MicrometerConstants.METRICS_REGISTRY_NAME, registry);
    getContext().addRoutePolicyFactory(new MicrometerRoutePolicyFactory());
    
    restConfiguration().contextPath("/api")
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
      .post("/v4/analysis")
        .routeId("restAnalysisV4")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:analysisV4")
      .post("/v4/batch-analysis")
        .routeId("restBatchAnalysisV4")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:batchAnalysisV4")
      .get("/v4/token")
        .routeId("restTokenValidationV4")
        .to("direct:validateTokenV4")
      .get("/v4/model-cards/{modelCardId}")
        .routeId("restModelCard")
        .to("direct:getModelCard")
      .post("/v4/model-cards")
        .routeId("restListModelCards")
        .to("direct:listModelCards")

      .post("/v5/analysis")
        .routeId("restAnalysisV5")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:analysisV5")
      .post("/v5/batch-analysis")
        .routeId("restBatchAnalysisV5")
        .param()
          .name(RECOMMEND_PARAM)
          .type(RestParamType.query)
          .dataType("boolean")
          .defaultValue(Boolean.TRUE.toString())
          .endParam()
        .to("direct:batchAnalysisV5")
      .post("/v5/licenses")
        .routeId("restLicensesV5")
        .to("direct:getLicensesFromEndpoint")
      .get("/v5/licenses/{licenseId}")
        .routeId("restLicenseV5")
        .to("direct:getLicense")
      .post("/v5/licenses/identify")
        .routeId("restLicenseIdentifyV5")
        .to("direct:identifyLicense")
      .get("/v5/token")
        .routeId("restTokenValidationV5")
        .to("direct:validateTokenV5");

    from(direct("analysisV4"))
      .to(direct("analysis"));
    from(direct("analysisV5"))
      .to(direct("analysis"));
    from(direct("batchAnalysisV4"))
      .to(direct("batchAnalysis"));
    from(direct("batchAnalysisV5"))
      .to(direct("batchAnalysis"));
    from(direct("validateTokenV4"))
      .to(direct("validateToken"));
    from(direct("validateTokenV5"))
      .to(direct("validateToken"));

    from(direct("analysis"))
      .routeId("dependencyAnalysis")
      .to(direct("preProcessAnalysisRequest"))
      .process(this::processAnalysisRequest)
      .process(monitoringProcessor::processOriginalRequest)
      .to(direct("analyzeSbom"))
      .to(direct("report"))
      .to(direct("postProcessAnalysisRequest"));

    from(direct("batchAnalysis"))
      .routeId("batchDependencyAnalysis")
      .to(direct("preProcessAnalysisRequest"))
      .process(this::processBatchAnalysisRequest)
      .process(monitoringProcessor::processOriginalRequest)
      .to(direct("analyzeSboms"))
      .to(direct("batchReport"))
      .to(direct("postProcessAnalysisRequest"));

    from(direct("analyzeSbom"))
      .routeId("analyzeSbom")
      .multicast(new LicenseAggregationStrategy())
        .parallelProcessing()
          .to(direct("findVulnerabilities"), direct("getLicensesFromSbom"))
      .end();

    from(direct("analyzeSboms"))
      .routeId("analyzeSboms")
      .process(this::validateSbomsInput)
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
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .choice()
        .when(exchangeProperty(Constants.GZIP_RESPONSE_PROPERTY).isNotNull()).marshal().gzipDeflater()
        .setHeader(Exchange.CONTENT_ENCODING, constant("gzip"))
      .end()
      .process(this::cleanUpHeaders);

    from(direct("findVulnerabilities"))
      .routeId("findVulnerabilities")
      .process(this::setProviderConfiguration)
      .toD("direct:trustifyScan")
      .process(this::wrapSingleProviderResult)
      .transform().method(ProviderAggregationStrategy.class, "toReport");

    from(direct("validateToken"))
      .routeId("validateToken")
      .setProperty(Constants.EXHORT_REQUEST_ID_HEADER, method(BackendUtils.class,"generateRequestId"))
      .process(monitoringProcessor::processOriginalRequest)
      .to(direct("trustifyValidateCredentials"))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .process(this::cleanUpHeaders);

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
                        } catch (JsonProcessingException parseEx) {
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

  private void handleInvocationTargetException(Exchange exchange) {
    Exception ex = exchange.getException(InvocationTargetException.class);
    if (ex == null) {
      return;
    }
    Throwable cause = ex.getCause();
    if (cause instanceof NotFoundException notFound) {
      monitoringProcessor.processClientException(exchange);
      exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, Status.NOT_FOUND.getStatusCode());
      exchange.getIn().setHeader(Exchange.CONTENT_TYPE, MediaType.TEXT_PLAIN);
      exchange.getIn().setBody(notFound.getMessage());
      exchange
          .getIn()
          .setHeader(
              Constants.EXHORT_REQUEST_ID_HEADER,
              exchange.getProperty(Constants.EXHORT_REQUEST_ID_HEADER));
      exchange.setProperty(Exchange.EXCEPTION_HANDLED, true);
    }
  }

  private void cleanUpHeaders(Exchange exchange) {
    var msg = exchange.getIn();
    msg.removeHeader(VERBOSE_MODE_HEADER);
    msg.removeHeaders("ex-.*-token");
    msg.removeHeader(Constants.AUTHORIZATION_HEADER);
    msg.removeHeaders("trust-da-.*");
    msg.removeHeader(Constants.RECOMMEND_PARAM);

    monitoringProcessor.cleanupContext(exchange);
  }

  private void processSbomEntry(Exchange exchange) {
    Map.Entry<?, ?> entry = exchange.getIn().getBody(Map.Entry.class);
    exchange.setProperty(Constants.SBOM_ID_PROPERTY, entry.getKey());
    exchange.getIn().setBody(entry.getValue());
  }

  private void validateSbomsInput(Exchange exchange) {
    @SuppressWarnings("unchecked")
    Map<String, DependencyTree> map = exchange.getIn().getBody(Map.class);
    if (map == null || map.isEmpty()) {
      throw new SbomValidationException(
          "SBOM Batch cannot be empty",
          new IllegalArgumentException("Empty or null SBOM map provided"));
    }
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

  private void setProviderConfiguration(Exchange exchange) {
    @SuppressWarnings("unchecked")
    List<String> providers = exchange.getProperty(Constants.PROVIDERS_PARAM, List.class);

    String provider = (providers != null && !providers.isEmpty()) ? providers.get(0) : "trustify";

    var config = vulnerabilityProvider.getProviderConfig(provider);
    exchange.setProperty(Constants.PROVIDER_NAME_PROPERTY, provider);
    exchange.setProperty(Constants.PROVIDER_CONFIG_PROPERTY, config);
  }

  private void wrapSingleProviderResult(Exchange exchange) {
    var providerReport =
        exchange.getIn().getBody(io.github.guacsec.trustifyda.api.v5.ProviderReport.class);
    if (providerReport != null) {
      Map<String, io.github.guacsec.trustifyda.api.v5.ProviderReport> result = new HashMap<>();
      result.put(providerReport.getStatus().getName(), providerReport);
      exchange.getIn().setBody(result);
    }
  }
}
