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

package com.redhat.exhort.integration.providers.snyk;

import static com.redhat.exhort.integration.Constants.PROVIDERS_PARAM;
import static com.redhat.exhort.integration.Constants.RECOMMEND_PARAM;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.config.exception.DetailedException;
import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;
import com.redhat.exhort.monitoring.MonitoringProcessor;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;

@ApplicationScoped
public class SnykIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.snyk.timeout", defaultValue = "20s")
  String timeout;

  @ConfigProperty(name = "api.snyk.token")
  String defaultToken;

  @Inject VulnerabilityProvider vulnerabilityProvider;

  @Inject SnykResponseHandler responseHandler;

  @Inject MonitoringProcessor monitoringProcessor;

  @ConfigProperty(name = "project.shortname")
  String projectName;

  @ConfigProperty(name = "project.version")
  String projectVersion;

  @Override
  public void configure() {

    // fmt:off
    onException(IllegalArgumentException.class, DetailedException.class)
      .routeId("snykIllegalArgumentException")
      .useOriginalMessage()
      .handled(true)
      .process(responseHandler::processResponseError);

    from(direct("snykScan"))
      .routeId("snykScan")
      .process(this::setAuthToken)
      .transform(method(SnykRequestBuilder.class, "splitByPkgManager"))
      .choice()
        .when(method(SnykRequestBuilder.class, "isEmpty"))
          .setBody(method(SnykResponseHandler.class, "emptyResponse"))
          .setBody(method(SnykResponseHandler.class, "buildReport"))
        .otherwise()
          .to(direct("snykRequest"))
          .transform().method(SnykResponseHandler.class, "buildReport");

    from(direct("snykRequest"))
      .routeId("snykRequest")
      .split(body(), AggregationStrategies.beanAllowNull(SnykResponseHandler.class, "aggregateSplit"))
        .parallelProcessing()
          .circuitBreaker()
            .faultToleranceConfiguration()
              .timeoutEnabled(true)
              .timeoutDuration(timeout)
            .end()
            .process(SnykRequestBuilder::validate)
            .choice()
              .when(exchangeProperty(Constants.UNSCANNED_REFS_PROPERTY).isNotNull())
                .setBody(method(SnykResponseHandler.class, "unscannedResponse"))
              .otherwise()
                .transform().method(SnykRequestBuilder.class, "buildRequest")
                .process(this::processDepGraphRequest)
                .to(vertxHttp("{{api.snyk.host}}"))
                .transform(method(SnykResponseHandler.class, "responseToIssues"))
            .endChoice()
          .endCircuitBreaker()
          .onFallback()
            .process(responseHandler::processResponseError);

    from(direct("snykValidateToken"))
      .routeId("snykValidateToken")
      .process(this::processTokenValidation)
      .to(direct("snykTokenRequest"));

    from(direct("snykHealthCheck"))
      .routeId("snykHealthCheck")
      .setProperty(Constants.PROVIDER_NAME, constant(Constants.SNYK_PROVIDER))
      .choice()
        .when(method(vulnerabilityProvider, "getEnabled").contains(Constants.SNYK_PROVIDER))
          .process(this::setAuthToken)
          .to(direct("snykTokenRequest"))
          .setHeader(Exchange.HTTP_RESPONSE_TEXT,constant("Service is up and running"))
          .setBody(constant("Service is up and running"))
        .otherwise()
          .to(direct("healthCheckProviderDisabled"));

    from(direct("snykTokenRequest"))
      .routeId("snykTokenRequest")
      .process(this::processTokenRequest)
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .to(vertxHttp("{{api.snyk.host}}"))
        .setBody(constant("Token validated successfully"))
      .onFallback()
        .process(responseHandler::processTokenFallBack);
    // fmt:on
  }

  private void setAuthToken(Exchange exchange) {
    var message = exchange.getMessage();
    var token = message.getHeader(Constants.SNYK_TOKEN_HEADER, String.class);
    if (token == null) {
      token = defaultToken;
      vulnerabilityProvider.addProviderPrivateData(exchange, Constants.SNYK_PROVIDER);
    }
    exchange.setProperty(
        Constants.AUTH_PROVIDER_REQ_PROPERTY_PREFIX + Constants.SNYK_PROVIDER, token != null);
    message.setHeader(Constants.AUTHORIZATION_HEADER, "token " + token);
  }

  private void processDepGraphRequest(Exchange exchange) {
    var message = exchange.getMessage();
    processRequestHeaders(message);
    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_PATH, Constants.SNYK_DEP_GRAPH_API_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
  }

  private void processTokenValidation(Exchange exchange) {
    var message = exchange.getMessage();
    message.setHeader(
        Constants.AUTHORIZATION_HEADER, "token " + message.getHeader(Constants.SNYK_TOKEN_HEADER));
  }

  private void processTokenRequest(Exchange exchange) {
    var message = exchange.getMessage();
    processRequestHeaders(message);
    message.setHeader(Exchange.HTTP_PATH, Constants.SNYK_TOKEN_API_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
  }

  private void processRequestHeaders(Message message) {
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.SNYK_TOKEN_HEADER);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(PROVIDERS_PARAM);
    message.removeHeader(RECOMMEND_PARAM);
    message.setHeader(
        Constants.USER_AGENT_HEADER,
        String.format(Constants.SNYK_USER_AGENT_HEADER_FORMAT, projectName, projectVersion));
  }
}
