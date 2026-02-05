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

package io.github.guacsec.trustifyda.integration.providers.trustify;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.cache.CacheService;
import io.github.guacsec.trustifyda.integration.providers.VulnerabilityProvider;
import io.github.guacsec.trustifyda.integration.providers.trustify.ubi.UBIRecommendation;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderHealthCheckResult;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustify.ProviderConfig;
import io.github.guacsec.trustifyda.model.trustify.ProvidersConfig;
import io.github.guacsec.trustifyda.model.trustify.Recommendation;
import io.github.guacsec.trustifyda.model.trustify.RecommendationsResponse;
import io.github.guacsec.trustifyda.model.trustify.Vulnerability;
import io.github.guacsec.trustifyda.service.DynamicOidcClientService;
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

  private static final String TIMEOUT_DURATION_HEALTH = "1s";

  @ConfigProperty(name = "api.trustify.timeout", defaultValue = "60s")
  String timeout;

  private static final String TRUSTIFY_URL_PROPERTY = "trustifyUrl";

  private static final Logger LOGGER = Logger.getLogger(TrustifyIntegration.class);

  @Inject ProvidersConfig providersConfig;

  @Inject DynamicOidcClientService dynamicOidcClientService;

  @Inject VulnerabilityProvider vulnerabilityProvider;
  @Inject TrustifyResponseHandler responseHandler;
  @Inject TrustifyRequestBuilder requestBuilder;
  @Inject ObjectMapper mapper;
  @Inject UBIRecommendation ubiRecommendation;
  @Inject MeterRegistry registry;
  @Inject CacheService cacheService;

  // Other values are Affected and UnderInvestigation
  // see https://www.cisa.gov/sites/default/files/2023-01/VEX_Status_Justification_Jun22.pdf
  private static final List<String> FIXED_STATUSES = List.of("NotAffected", "Fixed");
  private static final String OCI_PURL_TYPE = "oci";

  @Override
  public void configure() throws Exception {
    // fmt:off
    onException(TimeoutException.class)
      .handled(true)
      .process(responseHandler::processResponseError);

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

    from(direct("trustifySplitRequest"))
      .routeId("trustifySplitRequest")
      .process(this::lookupCachedItems)
      .transform(method(requestBuilder, "splitMisses"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateSplit"))
      .parallelProcessing()
        .transform()
        .method(requestBuilder, "buildRequest")
        .to(direct("trustifyRequest"))
        .bean(cacheService, "cacheItems")
      .end()
      .process(this::aggregateCacheHits);

    from(direct("recommendations"))
      .routeId("recommendations")
      .routePolicy(new ProviderRoutePolicy(registry))
      .choice()
        .when(exchangeProperty(Constants.RECOMMEND_PARAM).isEqualTo(Boolean.TRUE))
        .circuitBreaker()
          .faultToleranceConfiguration()
            .timeoutEnabled(true)
            .timeoutDuration(timeout)
          .end()
          .process(this::processRecommendationsRequest)
          .toD("${exchangeProperty.trustifyUrl}")
          .process(this::processRecommendations)
      .onFallback()
        // Mark fallback so null exception (FT timeout) is mapped to 504; other failures keep their status
        .setProperty(Constants.CIRCUIT_BREAKER_FALLBACK_WITH_TIMEOUT, constant(true))
        .process(responseHandler::processResponseError)
      .endChoice()
      
      .end();

    from(direct("vulnerabilities"))
      .routeId("vulnerabilities")
      .routePolicy(new ProviderRoutePolicy(registry))
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::processVulnerabilitiesRequest)
      .toD("${exchangeProperty.trustifyUrl}")
      .transform(method(responseHandler, "responseToIssues"))
      .onFallback()
        // Mark fallback so null exception (FT timeout) is mapped to 504; other failures keep their status
        .setProperty(Constants.CIRCUIT_BREAKER_FALLBACK_WITH_TIMEOUT, constant(true))
        .process(responseHandler::processResponseError)
      .end();
    
    from(direct("trustifyRequest"))
      .routeId("trustifyRequest")
      .process(this::setProviderConfig)
      .process(this::addAuthentication)
      .multicast(new RecommendationAggregation())
        .parallelProcessing()
          .to(direct("vulnerabilities"))
          .to(direct("recommendations"))
      .end();

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

    from(direct("trustifyValidateCredentials"))
      .routeId("trustifyValidateCredentials")
      .routePolicy(new ProviderRoutePolicy(registry))
      .circuitBreaker()
        .faultToleranceConfiguration()
          .timeoutEnabled(true)
          .timeoutDuration(timeout)
        .end()
        .process(this::validateToken)
      .onFallback()
        .process(responseHandler::processTokenFallBack);
    // fmt:on
  }

  private void setProviderConfig(Exchange exchange) {
    var config = exchange.getProperty(Constants.PROVIDER_CONFIG_PROPERTY, ProviderConfig.class);
    exchange.setProperty(TRUSTIFY_URL_PROPERTY, config.host());
  }

  private void processVulnerabilitiesRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);

    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_ANALYZE_PATH);
  }

  private void processRecommendationsRequest(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);

    message.setHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    message.setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
    message.setHeader(Exchange.HTTP_PATH, Constants.TRUSTIFY_RECOMMEND_PATH);
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
    var config = exchange.getProperty(Constants.PROVIDER_CONFIG_PROPERTY, ProviderConfig.class);

    if (config != null && config.auth().isPresent()) {
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

    var config = providersConfig.providers().get(providerKey);
    if (config != null && config.auth().isPresent()) {
      if (dynamicOidcClientService.hasClient(providerKey)) {
        try {
          boolean isValid = dynamicOidcClientService.validateToken(providerKey, token);
          if (isValid) {
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

  /**
   * Processes recommendations response from Trusted Content API. Converts the JSON response to a
   * map of PackageRef to IndexedRecommendation.
   */
  public void processRecommendations(Exchange exchange) throws IOException {
    byte[] tcResponse = exchange.getIn().getBody(byte[].class);
    String sbomId = exchange.getProperty(Constants.SBOM_ID_PROPERTY, String.class);

    var response = mapper.readValue(tcResponse, RecommendationsResponse.class);
    var mergedRecommendations = indexRecommendations(response);
    mergedRecommendations.putAll(getUBIRecommendation(sbomId));

    exchange.getMessage().setBody(mergedRecommendations);
  }

  private Map<PackageRef, IndexedRecommendation> indexRecommendations(
      RecommendationsResponse response) {
    Map<PackageRef, IndexedRecommendation> result = new HashMap<>();
    if (response == null) {
      return result;
    }
    response.getMatchings().entrySet().stream()
        .filter(e -> !e.getValue().isEmpty())
        .forEach(
            e -> {
              List<Recommendation> recommendations = e.getValue();
              PackageRef pkgRef = recommendations.get(0).packageName();
              Map<String, Vulnerability> vulnerabilities =
                  recommendations.stream()
                      .map(Recommendation::vulnerabilities)
                      .flatMap(List::stream)
                      .collect(
                          Collectors.toMap(
                              v -> v.getId().toUpperCase(), v -> v, this::filterFixed));
              var sourcePkgRef = new PackageRef(e.getKey()).toGav();
              var recommendationPkgRef = pkgRef.toGav();
              if (!sourcePkgRef.equals(recommendationPkgRef)) {
                result.put(
                    new PackageRef(e.getKey()), new IndexedRecommendation(pkgRef, vulnerabilities));
              }
            });
    return result;
  }

  private Map<PackageRef, IndexedRecommendation> getUBIRecommendation(String sbomId) {
    if (sbomId == null) {
      return Collections.emptyMap();
    }

    var pkgRef = new PackageRef(sbomId);
    if (!OCI_PURL_TYPE.equals(pkgRef.purl().getType())) {
      return Collections.emptyMap();
    }

    var recommendedUBIPurl = ubiRecommendation.mapping().get(pkgRef.name());
    if (recommendedUBIPurl != null) {
      var recommendation = new IndexedRecommendation(new PackageRef(recommendedUBIPurl), null);
      return Collections.singletonMap(pkgRef, recommendation);
    }
    return Collections.emptyMap();
  }

  private Vulnerability filterFixed(Vulnerability a, Vulnerability b) {
    if (a.getStatus() != null && !FIXED_STATUSES.contains(a.getStatus().toString())) {
      return a;
    }
    return b;
  }

  private void lookupCachedItems(Exchange exchange) {
    DependencyTree tree =
        exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class);
    if (tree == null || tree.dependencies().isEmpty()) {
      exchange.setProperty(Constants.CACHE_MISSES_PROPERTY, Collections.emptySet());
      exchange.setProperty(Constants.CACHE_HITS_PROPERTY, Collections.emptyMap());
      return;
    }

    Set<PackageRef> allPurls = tree.getAll();
    Map<PackageRef, PackageItem> cachedItems = cacheService.getCachedItems(allPurls);

    exchange.setProperty(Constants.CACHE_HITS_PROPERTY, cachedItems);

    Set<PackageRef> misses = new HashSet<>(allPurls);
    misses.removeAll(cachedItems.keySet());
    exchange.setProperty(Constants.CACHE_MISSES_PROPERTY, misses);

    LOGGER.debugf(
        "Cache lookup: %d hits, %d misses out of %d total",
        cachedItems.size(), misses.size(), allPurls.size());
  }

  @SuppressWarnings("unchecked")
  private void aggregateCacheHits(Exchange exchange) {
    Map<PackageRef, PackageItem> cacheHits =
        exchange.getProperty(Constants.CACHE_HITS_PROPERTY, Map.class);

    if (cacheHits == null || cacheHits.isEmpty()) {
      return;
    }

    ProviderResponse response = exchange.getIn().getBody(ProviderResponse.class);
    if (response == null) {
      String providerName = exchange.getProperty(Constants.PROVIDER_NAME_PROPERTY, String.class);
      Map<String, PackageItem> pkgItems = new HashMap<>();
      cacheHits.forEach((ref, item) -> pkgItems.put(ref.ref(), item));
      exchange
          .getIn()
          .setBody(new ProviderResponse(pkgItems, responseHandler.defaultOkStatus(providerName)));
      return;
    }

    Map<String, PackageItem> mergedItems = new HashMap<>();
    if (response.pkgItems() != null) {
      mergedItems.putAll(response.pkgItems());
    }
    cacheHits.forEach((ref, item) -> mergedItems.put(ref.ref(), item));

    exchange.getIn().setBody(new ProviderResponse(mergedItems, response.status()));
  }
}
