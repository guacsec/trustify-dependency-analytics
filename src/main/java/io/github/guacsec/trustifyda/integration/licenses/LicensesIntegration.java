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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.endpoint.EndpointRouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.LicensesRequest;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.cache.CacheService;
import io.github.guacsec.trustifyda.model.licenses.LicenseSplitResult;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class LicensesIntegration extends EndpointRouteBuilder {

  private static final String DEPS_DEV_SOURCE = "deps.dev";
  private static final Logger LOGGER = Logger.getLogger(LicensesIntegration.class);

  @ConfigProperty(name = "api.licenses.depsdev.host", defaultValue = "https://api.deps.dev")
  String depsDevHost;

  @ConfigProperty(name = "api.licenses.depsdev.timeout", defaultValue = "60s")
  String timeout;

  @Inject DepsDevRequestBuilder requestBuilder;
  @Inject DepsDevResponseHandler responseHandler;
  @Inject SpdxLicenseService spdxLicenseService;
  @Inject CacheService cacheService;

  @Override
  public void configure() {

    // fmt:off
    onException(TimeoutException.class)
      .handled(true)
      .process(responseHandler::processResponseError);

    onException(NotFoundException.class)
      .routeId("onLicensesNotFoundException")
      .useOriginalMessage()
      .setHeader(Exchange.HTTP_RESPONSE_CODE, constant(Response.Status.NOT_FOUND.getStatusCode()))
      .setHeader(Exchange.CONTENT_TYPE, constant(MediaType.TEXT_PLAIN))
      .setHeader(Constants.EXHORT_REQUEST_ID_HEADER, exchangeProperty(Constants.EXHORT_REQUEST_ID_HEADER))
      .handled(true)
      .setBody().simple("${exception.message}");

    from(direct("getLicense"))
      .routeId("getLicense")
      .process(this::removeHeaders)
      .setBody(header("licenseId"))
      .transform(method(spdxLicenseService, "fromLicenseId"))
      .marshal().json();

    from(direct("identifyLicense"))
      .routeId("identifyLicense")
      .process(this::removeHeaders)
      .transform(method(spdxLicenseService, "identifyLicense"))
      .marshal().json();

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
        .process(this::lookupCachedLicenses)
        .choice()
          .when(method(requestBuilder, "isEmpty"))
            .process(this::buildResponseFromLicenseCacheHitsOnly)
        .endChoice()
        .otherwise()
            .to(direct("depsDevSplitRequest"))
            .process(this::aggregateLicenseCacheHits)
        .end()
        .transform(method(responseHandler, "toResult"))    
        .transform(method(spdxLicenseService, "aggregateSbomLicenses"));

    from(direct("depsDevSplitRequest"))
      .routeId("depsDevSplitRequest")
      .setProperty("depsDevLicensesUrl")
        .constant(depsDevHost + Constants.DEPS_DEV_LICENSES_PATH)
      .transform(method(requestBuilder, "splitIntoBatches"))
      .split(body(), AggregationStrategies.beanAllowNull(responseHandler, "aggregateLicenses"))
      .parallelProcessing()
        .to(direct("depsDevRequest"))
        .bean(cacheService, "cacheLicenses")
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

  private void lookupCachedLicenses(Exchange exchange) {
    @SuppressWarnings("unchecked")
    List<PackageRef> purls = exchange.getIn().getBody(List.class);
    if (purls == null || purls.isEmpty()) {
      exchange.setProperty(Constants.CACHE_LICENSES_HITS_PROPERTY, Collections.emptyMap());
      exchange.setProperty(Constants.CACHE_LICENSES_PROPERTY, Collections.emptySet());
      exchange.getIn().setBody(Collections.emptyList());
      return;
    }
    Set<PackageRef> allPurls = purls.stream().collect(Collectors.toSet());
    Map<PackageRef, PackageLicenseResult> cachedLicenses = cacheService.getCachedLicenses(allPurls);
    exchange.setProperty(Constants.CACHE_LICENSES_HITS_PROPERTY, cachedLicenses);

    // Compare using coordinates since cache uses coordinates as keys
    Set<String> cachedCoordinates =
        cachedLicenses.keySet().stream()
            .map(p -> p.purl().getCoordinates())
            .collect(Collectors.toSet());
    Set<PackageRef> misses =
        allPurls.stream()
            .filter(p -> !cachedCoordinates.contains(p.purl().getCoordinates()))
            .collect(Collectors.toSet());

    exchange.setProperty(Constants.CACHE_LICENSES_PROPERTY, misses);
    exchange.getIn().setBody(new ArrayList<>(misses));
    LOGGER.debugf(
        "License cache lookup: %d hits, %d misses out of %d total",
        cachedLicenses.size(), misses.size(), allPurls.size());
  }

  private void buildResponseFromLicenseCacheHitsOnly(Exchange exchange) {
    @SuppressWarnings("unchecked")
    Map<PackageRef, PackageLicenseResult> cacheHits =
        exchange.getProperty(Constants.CACHE_LICENSES_HITS_PROPERTY, Map.class);
    if (cacheHits == null) {
      cacheHits = Collections.emptyMap();
    }
    Map<String, PackageLicenseResult> packages = new HashMap<>();
    cacheHits.forEach((ref, result) -> packages.put(ref.ref(), result));
    var status = new ProviderStatus().ok(true).name(DEPS_DEV_SOURCE);
    exchange.getIn().setBody(new LicenseSplitResult(status, packages));
  }

  @SuppressWarnings("unchecked")
  private void aggregateLicenseCacheHits(Exchange exchange) {
    Map<PackageRef, PackageLicenseResult> cacheHits =
        exchange.getProperty(Constants.CACHE_LICENSES_HITS_PROPERTY, Map.class);
    if (cacheHits == null || cacheHits.isEmpty()) {
      return;
    }
    LicenseSplitResult result = exchange.getIn().getBody(LicenseSplitResult.class);
    if (result == null) {
      Map<String, PackageLicenseResult> packages = new HashMap<>();
      cacheHits.forEach((ref, r) -> packages.put(ref.ref(), r));
      exchange
          .getIn()
          .setBody(
              new LicenseSplitResult(
                  new ProviderStatus().ok(true).name(DEPS_DEV_SOURCE), packages));
      return;
    }
    Map<String, PackageLicenseResult> merged = new HashMap<>(result.packages());
    cacheHits.forEach((ref, r) -> merged.put(ref.ref(), r));
    exchange.getIn().setBody(new LicenseSplitResult(result.status(), merged));
  }

  private void removeHeaders(Exchange exchange) {
    Message message = exchange.getMessage();
    message.removeHeader(Exchange.HTTP_RAW_QUERY);
    message.removeHeader(Exchange.HTTP_QUERY);
    message.removeHeader(Exchange.HTTP_URI);
    message.removeHeader(Exchange.HTTP_PATH);
    message.removeHeader(Constants.ACCEPT_ENCODING_HEADER);
  }

  /** Clears HTTP headers from the REST consumer so the HTTP producer uses only the full URL. */
  private void processRequest(Exchange exchange) {
    removeHeaders(exchange);
    exchange.getMessage().setHeader(Exchange.CONTENT_TYPE, constant(MediaType.APPLICATION_JSON));
    exchange.getMessage().setHeader(Exchange.HTTP_METHOD, HttpMethod.POST);
  }
}
