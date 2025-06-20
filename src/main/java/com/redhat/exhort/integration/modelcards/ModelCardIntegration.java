/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.modelcards;

import java.util.UUID;
import java.util.concurrent.TimeoutException;

import org.apache.camel.Exchange;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.redhat.exhort.api.v4.ModelCardQueryRequest;
import com.redhat.exhort.api.v4.ModelCardResponse;
import com.redhat.exhort.modelcards.ModelCardService;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class ModelCardIntegration extends EndpointRouteBuilder {

  @ConfigProperty(name = "exhort.model-card.timeout", defaultValue = "20s")
  String timeout;

  @Inject ModelCardService service;

  @Override
  public void configure() {
    // fmt:off
    from(direct("getModelCard"))
      .routeId("getModelCard")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::getModelCard)
        .marshal().json()
      .endCircuitBreaker()
      .onFallback()
        .process(this::processResponseError);
    from(direct("listModelCards"))
      .routeId("listModelCards")
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .unmarshal().json(ModelCardQueryRequest.class)
        .process(this::listModelCards)
        .marshal().json()
      .endCircuitBreaker()
      .onFallback()
        .process(this::processResponseError);
    // fmt:on
  }

  @Transactional
  public void getModelCard(Exchange exchange) {
    var id = exchange.getIn().getHeader("modelCardId", String.class);
    if (id == null) {
      throw new NotFoundException("Model card ID is required");
    }
    try {
      UUID uuid = UUID.fromString(id);
      ModelCardResponse report = service.get(uuid);
      if (report == null) {
        throw new NotFoundException("Model card not found with ID: " + id);
      }

      exchange.getIn().setBody(report);
    } catch (IllegalArgumentException e) {
      throw new BadRequestException("Invalid model card ID: " + id);
    }
  }

  @Transactional
  public void listModelCards(Exchange exchange) {
    var req = exchange.getIn().getBody(ModelCardQueryRequest.class);
    if (req == null) {
      throw new BadRequestException("Model card request is required");
    }
    var summaries = service.find(req.getQueries());
    exchange.getIn().setBody(summaries);
  }

  private void processResponseError(Exchange exchange) {
    Exception cause = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
    if (cause == null) {
      exchange
          .getIn()
          .setHeader(
              Exchange.HTTP_RESPONSE_CODE, Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
      exchange.getIn().setBody("Unknown error occurred while processing model card");
      return;
    }

    Throwable unwrappedCause = cause;
    while (unwrappedCause instanceof org.apache.camel.RuntimeCamelException
        && unwrappedCause.getCause() != null) {
      unwrappedCause = unwrappedCause.getCause();
    }

    if (unwrappedCause instanceof TimeoutException) {
      exchange
          .getIn()
          .setHeader(Exchange.HTTP_RESPONSE_CODE, Response.Status.GATEWAY_TIMEOUT.getStatusCode());
      exchange
          .getIn()
          .setBody("Request timed out while fetching model card: " + unwrappedCause.getMessage());
    } else if (unwrappedCause instanceof NotFoundException) {
      exchange
          .getIn()
          .setHeader(Exchange.HTTP_RESPONSE_CODE, Response.Status.NOT_FOUND.getStatusCode());
      exchange.getIn().setBody("Model card not found: " + unwrappedCause.getMessage());
    } else if (unwrappedCause instanceof BadRequestException) {
      exchange
          .getIn()
          .setHeader(Exchange.HTTP_RESPONSE_CODE, Response.Status.BAD_REQUEST.getStatusCode());
      exchange.getIn().setBody("Bad request: " + unwrappedCause.getMessage());
    } else {
      exchange
          .getIn()
          .setHeader(
              Exchange.HTTP_RESPONSE_CODE, Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
      exchange.getIn().setBody("Error processing model card: " + cause.getMessage());
    }
  }
}
