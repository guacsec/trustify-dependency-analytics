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
import org.apache.camel.http.base.HttpOperationFailedException;
import org.jboss.logging.Logger;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;
import com.redhat.exhort.model.ProviderHealthCheckResult;
import com.redhat.exhort.model.trustify.ProviderConfig;
import com.redhat.exhort.model.trustify.ProvidersConfig;
import com.redhat.exhort.service.DynamicOidcClientService;

import io.micrometer.core.instrument.MeterRegistry;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class TrustifyIntegration extends EndpointRouteBuilder {

  private static final String TIMEOUT_DURATION = "60s";
  private static final String TIMEOUT_DURATION_HEALTH = "1s";

  private static final String TRUSTIFY_URL_PROPERTY = "trustifyUrl";

  private static final Logger LOGGER = Logger.getLogger(TrustifyIntegration.class);

  @Inject ProvidersConfig providersConfig;

  @Inject DynamicOidcClientService dynamicOidcClientService;

  @Inject VulnerabilityProvider vulnerabilityProvider;
  @Inject TrustifyResponseHandler responseHandler;
  @Inject TrustifyRequestBuilder requestBuilder;
  @Inject MeterRegistry registry;

  @Override
  public void configure() throws Exception {
    // fmt:off
    // Generic trustify scan route that accepts provider configuration
    from(direct("trustifyScan"))
      .routeId("trustifyScan")
      .choice()
        .when(method(requestBuilder, "isEmpty"))
          .setBody(method(responseHandler, "emptyResponse"))
          .transform()
          .method(responseHandler, "buildReport")
        .endChoice()
        .otherwise()
          .to(direct("trustifySplitRequest"))
          .transform()
          .method(responseHandler, "buildReport");

    // Generic split request route
    from(direct("trustifySplitRequest"))
      .routeId("trustifySplitRequest")
      .transform(method(TrustifyRequestBuilder.class, "split"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateSplit"))
      .parallelProcessing()
        .transform()
        .method(requestBuilder, "buildRequest")
        .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(TIMEOUT_DURATION)
          .end()
          .to(direct("trustifyRequest"))
        .onFallback()
          .process(responseHandler::processResponseError);
    
    from(direct("trustifyRequest"))
      .routeId("trustifyRequest")
      .routePolicy(new ProviderRoutePolicy(registry))
      .process(this::processRequest)
      .process(this::addAuthentication)
      .toD("${exchangeProperty.trustifyUrl}")
      .transform(method(responseHandler, "responseToIssues"));

    // Generic health check route
    from(direct("trustifyHealthCheck"))
      .routeId("trustifyHealthCheck")
      .routePolicy(new ProviderRoutePolicy(registry))
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(TIMEOUT_DURATION_HEALTH)
        .end()
        .process(this::processHealthRequest)
        .toD("${exchangeProperty.trustifyUrl}")
        .process(this::buildSuccessHealthResult)
      .onFallback()
        .process(this::buildFailureHealthResult)
      .end();

    // Generic credential validation route
    from(direct("trustifyValidateCredentials"))
      .routeId("trustifyValidateCredentials")
      .routePolicy(new ProviderRoutePolicy(registry))
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(TIMEOUT_DURATION)
        .end()
        .process(this::validateToken)
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
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_ANALYZE_PATH);
    var config = exchange.getProperty(Constants.PROVIDER_CONFIG_PROPERTY, ProviderConfig.class);
    exchange.setProperty(TRUSTIFY_URL_PROPERTY, config.host());
  }

  private void processHealthRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_HOST);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
    var config = exchange.getIn().getBody(ProviderConfig.class);
    exchange.setProperty(TRUSTIFY_URL_PROPERTY, config.host());
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_HEALTH_PATH);
  }

  private void buildSuccessHealthResult(Exchange exchange) {
    String providerName = exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
    ProviderHealthCheckResult result = ProviderHealthCheckResult.success(providerName);

    exchange.getMessage().setBody(result);
  }

  private void buildFailureHealthResult(Exchange exchange) {
    String providerName = exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
    Integer statusCode = 503;
    String message = providerName + " Service is down";

    // Check if there's an HTTP operation failure with specific status code
    Exception exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
    if (exception instanceof HttpOperationFailedException httpException) {
      statusCode = httpException.getStatusCode();
      message = "HTTP " + statusCode + ": " + httpException.getStatusText();
    } else if (exception != null) {
      message = "Error: " + exception.getMessage();
    }

    ProviderHealthCheckResult result =
        ProviderHealthCheckResult.error(providerName, statusCode, message);

    exchange.getMessage().setBody(result);
  }

  private void addAuthentication(Exchange exchange) {
    // Get the provider configuration from exchange property
    var config = exchange.getProperty(Constants.PROVIDER_CONFIG_PROPERTY, ProviderConfig.class);

    if (config != null && config.auth().isPresent()) {
      // Get provider key from exchange property
      String providerKey = exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
      String providerTokenHeader = String.format("ex-%s-token", providerKey);
      String token = exchange.getIn().getHeader(providerTokenHeader, String.class);
      if (token == null) {
        token = dynamicOidcClientService.getToken(providerKey);
      }

      if (token != null) {
        exchange.getMessage().setHeader(Constants.AUTHORIZATION_HEADER, "Bearer " + token);
        LOGGER.debug("Using OIDC token for provider: " + providerKey);
      }
    }
  }

  private void validateToken(Exchange exchange) {
    var headerName = getTokenHeader(exchange);
    if (headerName == null || headerName.isEmpty()) {
      throw new ClientErrorException(
          "Provider token header is missing", Response.Status.UNAUTHORIZED);
    }
    var providerKey = headerName.substring(3, headerName.length() - 6); // Remove "ex-" and "-token"
    var token = exchange.getIn().getHeader(headerName, String.class);
    if (providerKey == null) {
      throw new ClientErrorException(
          "Provider token header is missing", Response.Status.BAD_REQUEST);
    }
    if (vulnerabilityProvider.getProviderConfig(providerKey) == null
        || !vulnerabilityProvider.isProviderEnabled(providerKey)) {
      throw new ClientErrorException(
          "Provider " + providerKey + " is not available", Response.Status.BAD_REQUEST);
    }

    // Get provider configuration from exchange property (set by ExhortIntegration)
    var config = providersConfig.providers().get(providerKey);
    if (config != null && config.auth().isPresent()) {
      // Use OIDC client for token validation if auth configuration is available
      // Validate the provided token using OIDC introspection
      if (dynamicOidcClientService.hasClient(providerKey)) {
        try {
          boolean isValid = dynamicOidcClientService.validateToken(providerKey, token);
          if (isValid) {
            // Use the validated token for authentication
            LOGGER.debug("Token validated successfully for provider: " + providerKey);
            exchange.getIn().setBody("Token validated successfully for provider: " + providerKey);
          } else {
            LOGGER.debug("Token validation failed for provider: " + providerKey);
            throw new ClientErrorException(
                "Invalid token for provider " + providerKey, Response.Status.UNAUTHORIZED);
          }
        } catch (ServerErrorException e) {
          LOGGER.error("Token validation failed for provider: " + providerKey, e);
          throw new ServerErrorException(
              "Token validation failed for provider: " + providerKey,
              Response.Status.INTERNAL_SERVER_ERROR);
        }
      }
    } else {
      LOGGER.debug("No auth configuration found for provider: " + providerKey);
      throw new ClientErrorException(
          "No auth configuration found for provider: " + providerKey, Response.Status.BAD_REQUEST);
    }
  }

  private String getTokenHeader(Exchange exchange) {
    var headers = exchange.getIn().getHeaders();

    for (String headerName : headers.keySet()) {
      if (headerName != null && headerName.startsWith("ex-") && headerName.endsWith("-token")) {
        return headerName;
      }
    }
    return null;
  }
}
