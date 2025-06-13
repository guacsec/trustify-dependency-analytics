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

package com.redhat.exhort.integration.trustedcontent;

import org.apache.camel.Exchange;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.integration.Constants;

import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;

@ApplicationScoped
@RegisterForReflection
public class TrustedContentIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "api.trustedcontent.timeout", defaultValue = "60s")
  String timeout;

  @Inject TcResponseHandler responseHandler;

  @Inject TrustedContentRequestBuilder requestBuilder;

  @Inject TcResponseAggregation aggregation;

  @Override
  public void configure() {
    // fmt:off
    from(direct("getTrustedContent"))
        .routeId("getTrustedContent")
        .setBody(method(requestBuilder, "filterCachedRecommendations"))
        .to(direct("getRemoteTrustedContent"))
        .setBody(method(aggregation, "aggregateCachedResponse"));

    from(direct("getRemoteTrustedContent"))
      .routeId("getRemoteTrustedContent")
      .transform(method(requestBuilder, "split"))
      .split(body(), AggregationStrategies.bean(TcResponseHandler.class, "mergeSplitRecommendations"))
        .parallelProcessing()
          .transform().method(requestBuilder, "buildRequest")
          .process(this::handleHeaders)
        .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
          .end()
          .to(vertxHttp("{{api.trustedcontent.host}}"))
          .transform(method(TcResponseHandler.class, "processRecommendations"))  
        .onFallback()
          .process(responseHandler::processResponseError);
    // fmt:on
  }

  private void handleHeaders(Exchange exchange) {
    var message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);

    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTED_CONTENT_PATH);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
  }
}
