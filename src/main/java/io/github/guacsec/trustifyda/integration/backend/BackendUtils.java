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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Objects;

import org.apache.camel.Exchange;
import org.apache.camel.Header;
import org.apache.camel.RuntimeCamelException;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.common.util.MediaTypeHelper;

import io.github.guacsec.trustifyda.config.exception.PackageValidationException;
import io.github.guacsec.trustifyda.config.exception.UnexpectedProviderException;
import io.github.guacsec.trustifyda.integration.Constants;
import io.quarkus.runtime.annotations.RegisterForReflection;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@RegisterForReflection
public class BackendUtils {

  private static final Logger LOGGER = Logger.getLogger(BackendUtils.class);

  public BackendUtils() {
    this.clock = Clock.systemDefaultZone();
  }

  public BackendUtils(Clock clock) {
    this.clock = clock;
  }

  private final Clock clock;

  public String getResponseMediaType(@Header(Constants.ACCEPT_HEADER) String acceptHeader) {
    if (acceptHeader == null || acceptHeader.isBlank()) {
      return Constants.DEFAULT_ACCEPT_MEDIA_TYPE;
    }
    var requested = MediaTypeHelper.parseHeader(acceptHeader);
    var match = MediaTypeHelper.getBestMatch(Constants.VALID_RESPONSE_MEDIA_TYPES, requested);
    if (match == null) {
      throw new ClientErrorException(
          "Unexpected Accept header "
              + acceptHeader
              + ". Supported content types are: "
              + Constants.VALID_RESPONSE_MEDIA_TYPES,
          Status.UNSUPPORTED_MEDIA_TYPE);
    }
    return match.toString();
  }

  public String generateRequestId(@Header(Constants.TRUST_DA_TOKEN_HEADER) String rhdaToken) {
    byte[] requestId;
    try {
      MessageDigest digestMaker = MessageDigest.getInstance("SHA-256");
      String tsOfNow;
      tsOfNow = LocalDateTime.now(this.clock).toString();
      var token = rhdaToken;
      if (Objects.isNull(rhdaToken) || rhdaToken.trim().equals("")) {
        token = Double.toString(Math.random());
      }
      byte[] inputForSha256 = (token + tsOfNow).getBytes(StandardCharsets.UTF_8);
      requestId = digestMaker.digest(inputForSha256);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    return bytesToHex(requestId);
  }

  private static String bytesToHex(byte[] hash) {
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }

  public static Exception getExceptionFromExchange(Exchange exchange) {
    var exception =
        firstNonNull(
            exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class),
            exchange.getException(),
            exchange.getProperty("CamelCircuitBreakerException", Exception.class),
            exchange
                .getMessage()
                .getHeader("CamelFaultToleranceExecutionException", Exception.class));

    if (exception == null) {
      LOGGER.warn("Fallback triggered but no exception found in exchange");
      return null;
    }

    LOGGER.debugf(
        "Handling exception: %s - message: %s",
        exception.getClass().getName(), exception.getMessage());

    String detailedMessage = extractDetailedMessage(exception);
    Exception unwrapped = unwrapException(exception);

    if (!detailedMessage.isEmpty()) {
      exchange.setProperty("detailedErrorMessage", detailedMessage);
    }

    return unwrapped;
  }

  private static String extractDetailedMessage(Throwable exception) {
    Throwable current = exception;
    while (current != null) {
      String msg = current.getMessage();
      String className = current.getClass().getSimpleName();
      LOGGER.debugf("Exception in chain: %s, message: %s", className, msg);
      current = current.getCause();
    }

    String bestMessage = ExceptionUtils.getLongestMessage(exception);
    LOGGER.debugf("Extracted detailed message: %s", bestMessage);
    return bestMessage;
  }

  /**
   * Resolves both the exception (for monitoring) and the error mapping (for HTTP status) from the
   * exchange. Call this once in error handlers; pass the exception to monitoring and use the
   * mapping for the response status.
   */
  public static ErrorMappingResult getErrorMappingFromExchange(Exchange exchange) {
    Exception exception = getExceptionFromExchange(exchange);
    ErrorMapping mapping = computeMappingFromExchange(exchange, exception);
    return new ErrorMappingResult(exception, mapping);
  }

  /**
   * Result of resolving an error from an exchange: exception for monitoring, mapping for status.
   */
  public record ErrorMappingResult(Exception exception, ErrorMapping mapping) {}

  /**
   * Determines the error mapping from the exchange and optional exception. Handles timeout when
   * MicroProfile FT does not set the exception on the exchange (e.g. split/parallel).
   */
  private static ErrorMapping computeMappingFromExchange(Exchange exchange, Exception exception) {
    if (isTimeoutFromExchange(exchange, exception)) {
      return ErrorMapping.timeout();
    }
    return mapException(exception);
  }

  private static boolean isTimeoutFromExchange(Exchange exchange, Exception unwrappedException) {
    if (Boolean.TRUE.equals(exchange.getProperty("CamelResponseTimedOut", Boolean.class))) {
      return true;
    }
    var raw = getRawExceptionFromExchange(exchange);
    if (raw != null && isTimeoutException(raw)) {
      return true;
    }
    if (Boolean.TRUE.equals(exchange.getProperty("CamelResponseFromFallback", Boolean.class))) {
      for (Object value : exchange.getProperties().values()) {
        if (value instanceof Throwable t && isTimeoutException(t)) {
          return true;
        }
      }
      Object headerEx = exchange.getMessage().getHeader("CamelFaultToleranceExecutionException");
      if (headerEx instanceof Throwable t && isTimeoutException(t)) {
        return true;
      }
    }
    return unwrappedException == null
        && Boolean.TRUE.equals(
            exchange.getProperty(Constants.CIRCUIT_BREAKER_FALLBACK_WITH_TIMEOUT, Boolean.class));
  }

  /** Returns the exception as stored on the exchange, without unwrapping. */
  private static Exception getRawExceptionFromExchange(Exchange exchange) {
    return firstNonNull(
        exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class),
        exchange.getException(),
        exchange.getProperty("CamelCircuitBreakerException", Exception.class),
        exchange.getMessage().getHeader("CamelFaultToleranceExecutionException", Exception.class));
  }

  public static ErrorMapping mapException(Exception exception) {
    if (exception == null) {
      return ErrorMapping.internalError("Unknown error");
    }

    if (isTimeoutException(exception)) {
      return ErrorMapping.timeout();
    }

    if (exception instanceof HttpOperationFailedException http) {
      return new ErrorMapping(prettifyHttpError(http), http.getStatusCode());
    }

    if (isUnknownHostException(exception)) {
      String hostname = getDetailedErrorMessage(exception);
      return ErrorMapping.internalError("Failed to resolve hostname: " + hostname);
    }

    if (exception instanceof IllegalArgumentException
        || exception instanceof UnexpectedProviderException
        || exception instanceof PackageValidationException) {
      return ErrorMapping.unprocessableEntity(exception.getMessage());
    }

    return ErrorMapping.internalError(getDetailedErrorMessage(exception));
  }

  private static String getDetailedErrorMessage(Exception exception) {
    return ExceptionUtils.getLongestMessage(exception);
  }

  public static boolean isTimeoutException(Throwable cause) {
    if (cause == null) {
      return false;
    }
    return ExceptionUtils.findInChain(
            cause,
            e -> {
              var className = e.getClass().getName();
              var message = e.getMessage();
              var msgLower = message != null ? message.toLowerCase() : "";
              return className.contains("TimeoutException")
                  || className.contains("CircuitBreakerOpenException")
                  || className.contains("SocketTimeoutException")
                  || msgLower.contains("timeout")
                  || msgLower.contains("timed out");
            })
        .isPresent();
  }

  private static boolean isUnknownHostException(Throwable cause) {
    if (cause == null) {
      return false;
    }
    return ExceptionUtils.findInChain(cause, java.net.UnknownHostException.class).isPresent();
  }

  public record ErrorMapping(String message, int statusCode) {

    static ErrorMapping timeout() {
      return new ErrorMapping("Request timed out", Response.Status.GATEWAY_TIMEOUT.getStatusCode());
    }

    static ErrorMapping unprocessableEntity(String message) {
      return new ErrorMapping(message, Response.Status.BAD_REQUEST.getStatusCode());
    }

    static ErrorMapping internalError(String message) {
      return new ErrorMapping(message, Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
    }
  }

  private static String prettifyHttpError(HttpOperationFailedException httpException) {
    String text = httpException.getStatusText();
    String defaultReason =
        httpException.getResponseBody() != null && !httpException.getResponseBody().isBlank()
            ? httpException.getResponseBody()
            : httpException.getMessage();
    return text
        + switch (httpException.getStatusCode()) {
          case 401 -> ": Verify the provided credentials are valid.";
          case 403 -> ": The provided credentials don't have the required permissions.";
          case 429 -> ": The rate limit has been exceeded.";
          default -> ": " + defaultReason;
        };
  }

  @SafeVarargs
  private static <T> T firstNonNull(T... values) {
    for (T value : values) {
      if (value != null) {
        return value;
      }
    }
    return null;
  }

  public static Exception unwrapException(Exception exception) {
    Throwable cause = exception;
    while (cause instanceof RuntimeCamelException && cause.getCause() != null) {
      cause = cause.getCause();
    }
    if (cause instanceof Exception ex) {
      return ex;
    }
    return exception;
  }
}
