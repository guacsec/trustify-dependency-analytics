/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers.trustify;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class TrustifyIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.trustify.timeout", defaultValue = "60s")
  String timeout;

  @Inject VulnerabilityProvider vulnerabilityProvider;
  @Inject TrustifyResponseHandler responseHandler;
  @Inject TrustifyRequestBuilder requestBuilder;

  @Override
  public void configure() throws Exception {
    // fmt:off
    from(direct("trustifyScan"))
      .routeId("trustifyScan")
      .choice()
      .when(method(TrustifyRequestBuilder.class, "isEmpty"))
        .setBody(method(responseHandler, "emptyResponse"))
        .transform().method(responseHandler, "buildReport")
      .endChoice()
      .otherwise()
        .to(direct("trustifySplitRequest"))
        .transform().method(responseHandler, "buildReport");

    from(direct("trustifySplitRequest"))
      .routeId("trustifySplitRequest")
      .transform(method(TrustifyRequestBuilder.class, "split"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateSplit"))
        .parallelProcessing()
          .transform().method(requestBuilder, "buildRequest")
          .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
          .end()
          .process(this::processRequest)
          .process(requestBuilder::addAuthentication)
          .to(http("{{api.trustify.host}}"))
          .transform(method(responseHandler, "responseToIssues"))
        .onFallback()
          .process(responseHandler::processResponseError);
  

    from(direct("trustifyHealthCheck"))
      .routeId("trustifyHealthCheck")
      .setProperty(Constants.PROVIDER_NAME, constant(Constants.TRUSTIFY_PROVIDER))
      .choice()
         .when(method(vulnerabilityProvider, "getEnabled").contains(Constants.TRUSTIFY_PROVIDER))
            .to(direct("trustifyHealthCheckEndpoint"))
         .otherwise()
            .to(direct("healthCheckProviderDisabled"));

    from(direct("trustifyHealthCheckEndpoint"))
      .routeId("trustifyHealthCheckEndpoint")
      .process(this::processHealthRequest)
      .circuitBreaker()
         .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
         .end()
         .process(requestBuilder::addAuthentication)
         .to(http("{{api.trustify.management.host}}"))
         .setHeader(Exchange.HTTP_RESPONSE_TEXT,constant("Service is up and running"))
         .setBody(constant("Service is up and running"))
      .onFallback()
         .setBody(constant(Constants.TRUSTIFY_PROVIDER + "Service is down"))
         .setHeader(Exchange.HTTP_RESPONSE_CODE,constant(Response.Status.SERVICE_UNAVAILABLE))
      .end();

    from(direct("trustifyValidateCredentials"))
      .routeId("trustifyValidateCredentials")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::processTokenRequest)
        .process(requestBuilder::addAuthentication)
        .to(http("{{api.trustify.host}}"))
        .setBody(constant("Token validated successfully"))
      .onFallback()
        .process(responseHandler::processTokenFallBack);
    // fmt:on
  }

  private void processRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);

    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_ANALYZE_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
  }

  private void processHealthRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_HOST);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_HEALTH_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
  }

  private void processTokenRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_HOST);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_TOKEN_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
    message.setHeader(Exchange.HTTP_QUERY, "limit=0");
  }
}
