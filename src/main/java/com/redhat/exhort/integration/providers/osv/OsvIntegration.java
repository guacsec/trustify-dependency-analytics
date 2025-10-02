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

package com.redhat.exhort.integration.providers.osv;

import org.apache.camel.Exchange;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.integration.Constants;
import com.redhat.exhort.integration.providers.VulnerabilityProvider;
import com.redhat.exhort.model.ProviderHealthCheckResult;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;

@ApplicationScoped
public class OsvIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.onguard.timeout", defaultValue = "60s")
  String timeout;

  @Inject VulnerabilityProvider vulnerabilityProvider;
  @Inject OsvResponseHandler responseHandler;

  @Override
  public void configure() throws Exception {
    // fmt:off
    from(direct("osvScan"))
      .routeId("osvScan")
      .choice()
      .when(method(OsvRequestBuilder.class, "isEmpty"))
        .setBody(method(responseHandler, "emptyResponse"))
        .transform().method(responseHandler, "buildReport")
      .endChoice()
      .otherwise()
        .to(direct("osvSplitRequest"))
        .transform().method(responseHandler, "buildReport");

    from(direct("osvSplitRequest"))
      .routeId("osvSplitRequest")
      .transform(method(OsvRequestBuilder.class, "split"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateSplit"))
        .parallelProcessing()
          .transform().method(OsvRequestBuilder.class, "buildRequest")
          .process(this::processRequest)
        .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
          .end()
          .to(vertxHttp("{{api.onguard.host}}"))
          .transform(method(responseHandler, "responseToIssues"))
        .onFallback()
          .process(responseHandler::processResponseError);

    from(direct("osvRequest"))
      .routeId("osvRequest")
      .process(this::processRequest)
      .to(vertxHttp("{{api.onguard.host}}"))
      .transform().method(responseHandler, "responseToIssues");

    from(direct("osvHealthCheck"))
      .routeId("osvHealthCheck")
      .setProperty(Constants.PROVIDER_NAME_PROPERTY, constant(Constants.OSV_PROVIDER))
      .choice()
         .when(method(vulnerabilityProvider, "getEnabled").contains(Constants.OSV_PROVIDER))
            .to(direct("osvHealthCheckEndpoint"))
         .otherwise()
          .setBody(constant(ProviderHealthCheckResult.disabled(Constants.OSV_PROVIDER)))
         ;

    from(direct("osvHealthCheckEndpoint"))
      .routeId("osvHealthCheckEndpoint")
      .process(this::processHealthRequest)
      .circuitBreaker()
         .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
         .end()
         .to(vertxHttp("{{api.onguard.management.host}}"))
         .setBody(constant(ProviderHealthCheckResult.success(Constants.OSV_PROVIDER)))
      .onFallback()
        .process(this::buildErrorHealthResult)
      .end();
    // fmt:on
  }

  private void processRequest(Exchange exchange) {
    var message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_PATH, Constants.OSV_NVD_PURLS_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
  }

  private void processHealthRequest(Exchange exchange) {
    var message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
    message.removeHeader(Exchange.CONTENT_TYPE);
    message.setHeader(Exchange.HTTP_PATH, Constants.OSV_NVD_HEALTH_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.GET);
  }

  private void buildErrorHealthResult(Exchange exchange) {
    Exception exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
    switch (exception) {
      case HttpOperationFailedException httpException -> {
        ProviderHealthCheckResult result =
            ProviderHealthCheckResult.error(
                Constants.OSV_PROVIDER,
                httpException.getStatusCode(),
                httpException.getStatusText());
        exchange.getMessage().setBody(result);
      }
      default -> {
        ProviderHealthCheckResult result =
            ProviderHealthCheckResult.error(Constants.OSV_PROVIDER, 500, exception.getMessage());
        exchange.getMessage().setBody(result);
      }
    }
  }
}
