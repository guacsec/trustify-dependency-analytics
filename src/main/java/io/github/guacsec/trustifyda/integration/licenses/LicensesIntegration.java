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

package io.github.guacsec.trustifyda.integration.licenses;

import java.util.Collections;
import java.util.concurrent.TimeoutException;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.github.guacsec.trustifyda.api.v5.LicensesRequest;
import io.github.guacsec.trustifyda.integration.Constants;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;

@ApplicationScoped
public class LicensesIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.licenses.depsdev.host", defaultValue = "https://api.deps.dev")
  String depsDevHost;

  @ConfigProperty(name = "api.licenses.depsdev.timeout", defaultValue = "60s")
  String timeout;

  @Inject DepsDevRequestBuilder requestBuilder;
  @Inject DepsDevResponseHandler responseHandler;

  @Override
  public void configure() {

    // fmt:off
    onException(TimeoutException.class)
      .handled(true)
      .process(responseHandler::processResponseError);

    from(direct("getLicensesFromEndpoint"))
      .routeId("getLicensesFromEndpoint")
      .unmarshal().json(LicensesRequest.class)
      .transform(method(requestBuilder, "fromEndpoint"))
      .to(direct("getLicenses"))
      .marshal().json();
    
    from(direct("getLicensesFromSbom"))
      .routeId("getLicensesFromSbom")
      .transform(method(requestBuilder, "fromSbom"))
      .to(direct("getLicenses"));

    from(direct("getLicenses"))
        .routeId("getLicenses")
        .choice()
          .when(method(requestBuilder, "isEmpty"))
            .setBody(constant(Collections.emptyMap()))
        .endChoice()
        .otherwise()
            .to(direct("depsDevSplitRequest"))
        .end()
        .transform(method(responseHandler, "buildResponse"));

    from(direct("depsDevSplitRequest"))
      .routeId("depsDevSplitRequest")
      .setProperty("depsDevLicensesUrl")
        .constant(depsDevHost + Constants.DEPS_DEV_LICENSES_PATH)
      .transform(method(requestBuilder, "splitIntoBatches"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateLicenses"))
      .parallelProcessing()
        .to(direct("depsDevRequest"))
      .end();

    from(direct("depsDevRequest"))
      .routeId("depsDevRequest")
      .circuitBreaker()
      .faultToleranceConfiguration()
        .timeoutEnabled(true)
        .timeoutDuration(timeout)
      .end()
        .transform(method(requestBuilder, "toRequest"))
        .process(this::processRequest)
        .toD("${exchangeProperty.depsDevLicensesUrl}")
        .process(responseHandler::handleResponse)
      .onFallback()
        // Mark fallback so null exception (FT timeout) is mapped to 504; other failures keep their status
        .setProperty(Constants.CIRCUIT_BREAKER_FALLBACK_WITH_TIMEOUT, constant(true))
        .process(responseHandler::processResponseError)
      .end();
          
    // fmt:on
  }

  /** Clears HTTP headers from the REST consumer so the HTTP producer uses only the full URL. */
  private void processRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);

    message.setHeader(Exchange.CONTENT_TYPE, constant(MediaType.APPLICATION_JSON));
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
  }
}
