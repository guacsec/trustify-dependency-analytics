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

package io.github.guacsec.trustifyda.integration.providers.trustify.hardened;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.camel.Exchange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.extensions.InjectWireMock;
import io.github.guacsec.trustifyda.extensions.OidcWiremockExtension;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.inject.Inject;
import jakarta.ws.rs.core.MediaType;

/**
 * WireMock-based integration tests for the hardened image recommendation pipeline. Verifies that
 * hardened image recommendations from the HardenedImageProvider are wired into the Camel multicast
 * and appear in analysis responses.
 */
@QuarkusTest
@QuarkusTestResource(OidcWiremockExtension.class)
public class HardenedImageIntegrationTest {

  @Inject ObjectMapper mapper;
  private static final String OK_TOKEN = "test-token";
  private static final String TRUSTIFY_PROVIDER = "trustify";

  private static final String NGINX_BASE_REF = "docker.io/library/nginx:1.25";
  private static final String HARDENED_NGINX_PURL =
      "pkg:oci/hardened-nginx@sha256:abc123?repository_url=registry.example.com%2Fhardened-nginx&tag=1.25";

  /**
   * OCI PURL used as the batch SBOM key (sbomId). The repository_url and tag qualifiers allow
   * reconstruction of the Docker reference for index lookup.
   */
  private static final String OCI_SBOM_ID =
      "pkg:oci/nginx@sha256:def456?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25";

  /** An OCI PURL whose base image is NOT in the hardened index. */
  private static final String OCI_SBOM_ID_NO_MATCH =
      "pkg:oci/alpine@sha256:ghi789?repository_url=docker.io%2Flibrary%2Falpine&tag=3.19";

  private static final String HARDENED_SOURCE = "hardened";

  private static final String MAVEN_COMPONENT_PURL =
      "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar";

  @InjectWireMock WireMockServer server;

  @Inject HardenedImageProvider hardenedImageProvider;

  @Inject MeterRegistry meterRegistry;

  @Inject RedisDataSource redisDataSource;

  @BeforeEach
  void setup() {
    if (redisDataSource != null) {
      redisDataSource.flushall();
    }
    if (server != null) {
      OidcWiremockExtension.restubOidcEndpoints(server);
    }
    populateHardenedIndex();
    stubTrustifyEndpoints();
  }

  @AfterEach
  void teardown() {
    if (server != null) {
      server.resetAll();
    }
  }

  /** Pre-populates the hardened image index with test data. */
  private void populateHardenedIndex() {
    PackageRef hardenedPkg = new PackageRef(HARDENED_NGINX_PURL);
    IndexedRecommendation recommendation =
        IndexedRecommendation.builder()
            .packageName(hardenedPkg)
            .vulnerabilities(Collections.emptyMap())
            .sourceName(HARDENED_SOURCE)
            .build();
    hardenedImageProvider.getIndex().replaceAll(Map.of(NGINX_BASE_REF, recommendation));
  }

  /** Stubs the Trustify vulnerability and recommendation endpoints in WireMock. */
  private void stubTrustifyEndpoints() {
    // Stub vulnerability analysis endpoint
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + OK_TOKEN))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/empty_report.json")));

    // Stub recommendation endpoint
    server.stubFor(
        post(Constants.TRUSTIFY_RECOMMEND_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + OK_TOKEN))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustedcontent/empty_report.json")));

    // Stub deps.dev licenses endpoint
    server.stubFor(
        post(Constants.DEPS_DEV_LICENSES_PATH)
            .willReturn(aResponse().withStatus(200).withBodyFile("depsdev/maven_response.json")));
  }

  /**
   * Verifies that a batch analysis request with an OCI image that has a hardened recommendation
   * returns the recommendation in the response with recommendationSource = "hardened".
   */
  @Test
  void testHardenedRecommendationIncludedInResponse() throws Exception {
    // Given an OCI SBOM that matches a hardened recommendation in the index

    // When sending a batch analysis with the matching OCI SBOM
    String batchBody = createOciBatchRequest(OCI_SBOM_ID);
    Map<String, AnalysisReport> response = sendBatchAnalysis(batchBody);

    // Then the response contains the hardened recommendation
    assertNotNull(response, "Response should not be null");

    var report = response.values().iterator().next();
    var trustifyResult = report.getProviders().get(TRUSTIFY_PROVIDER);
    assertNotNull(trustifyResult, "Trustify provider result should not be null");

    var recommendations = trustifyResult.getRecommendations();
    assertNotNull(recommendations, "Recommendations map should not be null");
    assertTrue(
        recommendations.containsKey(HARDENED_SOURCE),
        "Recommendations should contain 'hardened' source");

    var hardenedRec = recommendations.get(HARDENED_SOURCE);
    assertNotNull(hardenedRec, "Hardened recommendation source should not be null");
    assertNotNull(
        hardenedRec.getDependencies(), "Hardened recommendation dependencies should not be null");
    assertTrue(
        hardenedRec.getDependencies().size() > 0,
        "Hardened recommendation should have at least one dependency");
  }

  /**
   * Verifies that hardened image recommendations are skipped when the recommend=false query
   * parameter is set.
   */
  @Test
  void testHardenedRecommendationSkippedWhenRecommendFalse() throws Exception {
    // Given an OCI SBOM with a hardened recommendation available

    // When sending a batch analysis with recommend=false
    String batchBody = createOciBatchRequest(OCI_SBOM_ID);
    String body =
        given()
            .header("Content-Type", Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)
            .queryParam(Constants.RECOMMEND_PARAM, false)
            .body(batchBody)
            .when()
            .post("/api/v5/batch-analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .extract()
            .body()
            .asString();

    Map<String, AnalysisReport> response =
        mapper.readValue(body, new TypeReference<Map<String, AnalysisReport>>() {});

    // Then no hardened recommendations appear in the response
    assertNotNull(response);
    for (var report : response.values()) {
      var providers = report.getProviders();
      if (providers == null) continue;
      var trustifyResult = providers.get(TRUSTIFY_PROVIDER);
      if (trustifyResult == null) continue;
      var recommendations = trustifyResult.getRecommendations();
      assertTrue(
          recommendations == null || !recommendations.containsKey(HARDENED_SOURCE),
          "No hardened recommendations should appear when recommend=false");
    }
  }

  /**
   * Verifies that an analysis request for an OCI image without a hardened recommendation returns no
   * hardened recommendation in the response.
   */
  @Test
  void testNoHardenedRecommendationForUnmatchedImage() throws Exception {
    // Given an OCI SBOM whose image is NOT in the hardened index

    // When sending a batch analysis with the unmatched OCI image
    String batchBody = createOciBatchRequest(OCI_SBOM_ID_NO_MATCH);
    Map<String, AnalysisReport> response = sendBatchAnalysis(batchBody);

    // Then no hardened recommendations appear
    assertNotNull(response);
    for (var report : response.values()) {
      var providers = report.getProviders();
      if (providers == null) continue;
      var trustifyResult = providers.get(TRUSTIFY_PROVIDER);
      if (trustifyResult == null) continue;
      var recommendations = trustifyResult.getRecommendations();
      assertTrue(
          recommendations == null
              || recommendations.isEmpty()
              || !recommendations.containsKey(HARDENED_SOURCE),
          "No hardened recommendation should appear for unmatched image");
    }
  }

  /**
   * Verifies that the Prometheus timer metric is recorded for the hardened recommendation route
   * after an analysis request.
   */
  @Test
  void testPrometheusMetricsRecordedForHardenedRoute() throws Exception {
    // Given an OCI SBOM

    // When sending a batch analysis request
    String batchBody = createOciBatchRequest(OCI_SBOM_ID);
    sendBatchAnalysis(batchBody);

    // Then Prometheus metrics are recorded for the hardened recommendation route
    var timer =
        meterRegistry
            .find("camel.route.provider.requests")
            .tag("routeId", "trustify-hardened-recommend")
            .timer();
    assertNotNull(timer, "Prometheus timer should exist for the trustify-hardened-recommend route");
  }

  /** Sends a batch analysis request and returns the parsed response map. */
  private Map<String, AnalysisReport> sendBatchAnalysis(String batchBody) throws Exception {
    String body =
        given()
            .header("Content-Type", Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)
            .body(batchBody)
            .when()
            .post("/api/v5/batch-analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .extract()
            .body()
            .asString();
    return mapper.readValue(body, new TypeReference<Map<String, AnalysisReport>>() {});
  }

  /**
   * Creates a minimal batch request body with a single OCI CycloneDX SBOM entry. The SBOM contains
   * no real dependencies — the purpose is to exercise the hardened recommendation lookup via the
   * sbomId (the batch map key).
   */
  private String createOciBatchRequest(String ociPurl) throws Exception {
    var component =
        Map.of(
            "name",
            "quarkus-core",
            "purl",
            MAVEN_COMPONENT_PURL,
            "type",
            "library",
            "bom-ref",
            MAVEN_COMPONENT_PURL);
    var rootDep = Map.of("ref", ociPurl, "dependsOn", List.of(MAVEN_COMPONENT_PURL));
    var leafDep = Map.of("ref", MAVEN_COMPONENT_PURL, "dependsOn", List.of());
    var sbom =
        Map.of(
            "bomFormat",
            "CycloneDX",
            "specVersion",
            "1.4",
            "version",
            1,
            "metadata",
            Map.of(
                "component",
                Map.of(
                    "name",
                    "test-image",
                    "purl",
                    ociPurl,
                    "type",
                    "container",
                    "bom-ref",
                    ociPurl)),
            "components",
            List.of(component),
            "dependencies",
            List.of(rootDep, leafDep));
    return mapper.writeValueAsString(Map.of(ociPurl, sbom));
  }
}
