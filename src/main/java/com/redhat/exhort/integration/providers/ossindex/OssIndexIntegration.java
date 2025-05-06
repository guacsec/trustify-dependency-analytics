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

package com.redhat.exhort.integration.providers.ossindex;

import java.util.Base64;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.monitoring.MonitoringProcessor;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class OssIndexIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.ossindex.timeout", defaultValue = "10s")
  String timeout;

  @Inject VulnerabilityProvider vulnerabilityProvider;

  @Inject OssIndexResponseHandler responseHandler;

  @Inject MonitoringProcessor monitoringProcessor;

  @Override
  public void configure() {

    // fmt:off
    from(direct("ossIndexScan"))
      .routeId("ossIndexScan")
      .transform(method(OssIndexRequestBuilder.class, "split"))
      .choice()
        .when(method(OssIndexRequestBuilder.class, "missingAuthHeaders"))
          .setBody(method(OssIndexResponseHandler.class, "unauthenticatedResponse"))
        .when(method(OssIndexRequestBuilder.class, "isEmpty"))
          .setBody(method(OssIndexResponseHandler.class, "emptyResponse"))
          .transform().method(OssIndexResponseHandler.class, "buildReport")
        .endChoice()
        .otherwise()
          .to(direct("ossSplitReq"))
          .transform().method(OssIndexResponseHandler.class, "buildReport");

    from(direct("ossSplitReq"))
      .routeId("ossSplitReq")
      .split(body(), AggregationStrategies.beanAllowNull(OssIndexResponseHandler.class, "aggregateSplit"))
        .parallelProcessing()
          .transform().method(OssIndexRequestBuilder.class, "buildRequest")
          .process(this::processComponentRequest)
        .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
          .end()
          .to(vertxHttp("{{api.ossindex.host}}"))
          .transform(method(OssIndexResponseHandler.class, "responseToIssues"))
        .onFallback()
          .process(responseHandler::processResponseError);

    from(direct("ossIndexHealthCheck"))
      .routeId("ossIndexHealthCheck")
      .setProperty(Constants.PROVIDER_NAME, constant(Constants.OSS_INDEX_PROVIDER))
      .choice()
        .when(method(vulnerabilityProvider, "getEnabled").contains(Constants.OSS_INDEX_PROVIDER))
          .to(direct("ossCheckVersionEndpoint"))
        .otherwise()
          .to(direct("healthCheckProviderDisabled"));

    from(direct("ossCheckVersionEndpoint"))
      .routeId("ossCheckVersionEndpoint")
      .circuitBreaker()
        .faultToleranceConfiguration()
           .timeoutEnabled(true)
           .timeoutDuration(timeout)
        .end()
        .process(this::processVersionRequest)
        .to(vertxHttp("{{api.ossindex.host}}"))
        .setBody(constant("Service is up and running"))
        .setHeader(Exchange.HTTP_RESPONSE_TEXT,constant("Service is up and running"))
        .onFallback()
           .setBody(constant(Constants.OSS_INDEX_PROVIDER + "Service is down"))
           .setHeader(Exchange.HTTP_RESPONSE_CODE,constant(Response.Status.SERVICE_UNAVAILABLE))
      .end();

    from(direct("ossValidateCredentials"))
      .routeId("ossValidateCredentials")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .setBody(constant(List.of(DependencyTree.getDefaultRoot(Constants.MAVEN_PURL_TYPE))))
        .transform().method(OssIndexRequestBuilder.class, "buildRequest")
        .process(this::processComponentRequest)
        .to(vertxHttp("{{api.ossindex.host}}"))
        .setBody(constant("Token validated successfully"))
      .onFallback()
        .process(responseHandler::processTokenFallBack);
    // fmt:on
  }

  private void processComponentRequest(Exchange exchange) {
    var message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);

    var username = message.getHeader(Constants.OSS_INDEX_USER_HEADER, String.class);
    var token = message.getHeader(Constants.OSS_INDEX_TOKEN_HEADER, String.class);
    message.setHeader(Exchange.HTTP_PATH, Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH);
    String auth = username + ":" + token;
    message.setHeader(
        Constants.AUTHORIZATION_HEADER,
        "Basic " + Base64.getEncoder().encodeToString(auth.getBytes()));
    message.removeHeader(Constants.OSS_INDEX_USER_HEADER);
    message.removeHeader(Constants.OSS_INDEX_TOKEN_HEADER);
    exchange.setProperty(
        Constants.AUTH_PROVIDER_REQ_PROPERTY_PREFIX + Constants.OSS_INDEX_PROVIDER, Boolean.TRUE);
  }

  private void processVersionRequest(Exchange exchange) {
    var message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
    message.setHeader(Exchange.HTTP_PATH, Constants.OSS_INDEX_VERSION_PATH);
  }
}
