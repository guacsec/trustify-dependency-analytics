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

package com.redhat.exhort.monitoring;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.camel.Exchange;

import com.redhat.exhort.integration.Constants;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class MonitoringProcessor {

  private static final String MONITORING_CONTEXT = "monitoringContext";
  private static final String ERROR_TYPE_TAG = "error_type";
  private static final String SERVER_ERROR_TYPE = "server";
  private static final String CLIENT_ERROR_TYPE = "client";
  private static final String PROVIDER_ERROR_TYPE = "provider";
  private static final String PROVIDER_TAG = "provider";

  private static final String[] LOGGED_REQUEST_HEADERS = {
    Exchange.CONTENT_TYPE,
    Constants.ACCEPT_HEADER,
    Constants.USER_AGENT_HEADER,
    Constants.TRUST_DA_SOURCE_HEADER,
    Constants.TRUST_DA_OPERATION_TYPE_HEADER,
    Constants.TRUST_DA_PKG_MANAGER_HEADER
  };

  private static final String[] LOGGED_PROPERTIES = {
    Exchange.FAILURE_ENDPOINT, Exchange.FAILURE_ROUTE_ID, Constants.EXHORT_REQUEST_ID_HEADER
  };

  @Inject MonitoringClient client;

  public void processOriginalRequest(Exchange exchange) {
    var metadata =
        Stream.of(LOGGED_REQUEST_HEADERS)
            .filter(e -> exchange.getIn().getHeaders().containsKey(e))
            .collect(Collectors.toMap(h -> h, h -> exchange.getIn().getHeader(h, String.class)));

    var requestId = exchange.getProperty(Constants.EXHORT_REQUEST_ID_HEADER, String.class);
    metadata.put(Constants.EXHORT_REQUEST_ID_HEADER, requestId);

    var context =
        new MonitoringContext(
            null, // Start with empty breadcrumbs
            exchange.getIn().getHeader(Constants.TRUST_DA_TOKEN_HEADER, String.class),
            metadata,
            null);

    String requestBody = exchange.getIn().getBody(String.class);
    context.breadcrumbs().add("Request received - " + requestId);
    context
        .breadcrumbs()
        .add("Content-Type: " + exchange.getIn().getHeader(Exchange.CONTENT_TYPE, String.class));

    context.metadata().put("request_body", requestBody);
    context.metadata().put("request_id", requestId);

    exchange.setProperty(MONITORING_CONTEXT, context);
  }

  public void processProviderError(Exchange exchange, Exception exception, String providerName) {
    var context = exchange.getProperty(MONITORING_CONTEXT, MonitoringContext.class);
    if (context == null) {
      return;
    }
    var errorContext = MonitoringContext.copyOf(context);

    // Add meaningful breadcrumbs for provider errors
    var requestId = exchange.getProperty(Constants.EXHORT_REQUEST_ID_HEADER, String.class);
    errorContext.breadcrumbs().add("Provider error in " + providerName + " - " + requestId);
    errorContext.breadcrumbs().add("Error type: " + exception.getClass().getSimpleName());

    errorContext.tags().put(PROVIDER_TAG, providerName);
    errorContext.tags().put(ERROR_TYPE_TAG, PROVIDER_ERROR_TYPE);
    Stream.of(LOGGED_PROPERTIES)
        .forEach(p -> errorContext.metadata().put(p, exchange.getProperty(p, String.class)));
    if (exception.getCause() != null) {
      client.reportException(exception.getCause(), errorContext);
    } else {
      client.reportException(exception, errorContext);
    }
  }

  public void processClientException(Exchange exchange) {
    processOriginalRequest(exchange);
    processError(exchange, CLIENT_ERROR_TYPE);
  }

  public void processServerError(Exchange exchange) {
    processError(exchange, SERVER_ERROR_TYPE);
  }

  private void processError(Exchange exchange, String errorType) {
    MonitoringContext context = exchange.getProperty(MONITORING_CONTEXT, MonitoringContext.class);
    if (context == null) {
      return;
    }

    // Add meaningful breadcrumbs for errors
    var requestId = exchange.getProperty(Constants.EXHORT_REQUEST_ID_HEADER, String.class);
    var exception = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);

    context.breadcrumbs().add(errorType + " error occurred - " + requestId);
    context.breadcrumbs().add("Exception: " + exception.getClass().getSimpleName());
    if (exception.getMessage() != null && !exception.getMessage().isEmpty()) {
      context.breadcrumbs().add("Error message: " + exception.getMessage());
    }

    context.tags().put(ERROR_TYPE_TAG, errorType);
    Stream.of(LOGGED_PROPERTIES)
        .forEach(p -> context.metadata().put(p, exchange.getProperty(p, String.class)));

    // Create a sanitized exception without Exchange IDs for better GlitchTip grouping
    Exception sanitizedException = sanitizeException(exception);
    client.reportException(sanitizedException, context);
  }

  /**
   * Clean up monitoring context after request completion to prevent contamination between requests.
   * This should be called at the end of each request.
   */
  public void cleanupContext(Exchange exchange) {
    exchange.removeProperty(MONITORING_CONTEXT);
  }

  private Exception sanitizeException(Exception originalException) {
    if (originalException == null) {
      return originalException;
    }

    // Use the root cause exception for more informative error messages
    Throwable rootCause = getRootCause(originalException);
    if (rootCause != originalException && rootCause.getMessage() != null) {
      return new RuntimeException(rootCause.getMessage(), originalException.getCause());
    }

    return originalException;
  }

  private Throwable getRootCause(Throwable throwable) {
    Throwable rootCause = throwable;
    while (rootCause.getCause() != null && rootCause.getCause() != rootCause) {
      rootCause = rootCause.getCause();
    }
    return rootCause;
  }
}
