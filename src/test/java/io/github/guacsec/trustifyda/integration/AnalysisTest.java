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

package io.github.guacsec.trustifyda.integration;

import static io.github.guacsec.trustifyda.extensions.WiremockExtension.TRUSTIFY_TOKEN;
import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

import org.apache.camel.Exchange;
import org.hamcrest.text.MatchesPattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.Scanned;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.extensions.OidcWiremockExtension;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@QuarkusTest
@QuarkusTestResource(OidcWiremockExtension.class)
public class AnalysisTest extends AbstractAnalysisTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final String CYCLONEDX = "cyclonedx";
  private static final String SPDX = "spdx";
  private static final String DEFAULT_TRUST_DA_TOKEN = "example-trust-da-token";
  private static final String OSV_SOURCE = "osv";
  private static final String CSAF_SOURCE = "csaf";

  @Override
  @AfterEach
  void resetMock() {
    if (server != null) {
      server.resetAll();
      // Re-stub OIDC endpoints after reset using the extension
      OidcWiremockExtension.restubOidcEndpoints(server);
    }
  }

  @BeforeEach
  void setupOidcStubs() {
    if (server != null) {
      // Ensure OIDC endpoints are stubbed at the beginning of each test
      OidcWiremockExtension.restubOidcEndpoints(server);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testWithWrongProvider(String sbom) {
    List<PackageRef> req = Collections.emptyList();
    given()
        .header(CONTENT_TYPE, getContentType(sbom))
        .queryParam(Constants.PROVIDERS_PARAM, "unknown")
        .body(req)
        .when()
        .post("/api/v5/analysis")
        .then()
        .assertThat()
        .statusCode(422)
        .contentType(MediaType.TEXT_PLAIN)
        .header(
            Constants.EXHORT_REQUEST_ID_HEADER,
            MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
        .body(equalTo("Unsupported providers: [unknown]"));

    verifyNoInteractions();
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testWithInvalidSbom(String sbom) {
    var response =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .body(loadFileAsString(String.format("%s/invalid-sbom.json", sbom)))
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(400)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.TEXT_PLAIN)
            .extract()
            .body()
            .asString();

    switch (sbom) {
      case CYCLONEDX -> assertTrue(response.startsWith("CycloneDX Validation"));
      case SPDX -> assertTrue(response.startsWith("SPDX-2.3 Validation"));
    }

    verifyNoInteractions();
  }

  @ParameterizedTest
  @MethodSource("emptySbomArguments")
  public void testEmptySbom(Map<String, Integer> providers, Map<String, String> authHeaders) {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .headers(authHeaders)
            .queryParam(Constants.PROVIDERS_PARAM, providers.keySet())
            .body(loadFileAsString(String.format("%s/empty-sbom.json", CYCLONEDX)))
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(Status.OK.getStatusCode())
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .as(AnalysisReport.class);

    providers
        .entrySet()
        .forEach(
            p -> {
              var provider =
                  report.getProviders().values().stream()
                      .filter(s -> s.getStatus().getName().equals(p.getKey()))
                      .findFirst();
              assertEquals(p.getValue(), provider.get().getStatus().getCode());
              assertEquals(
                  p.getValue().equals(Status.OK.getStatusCode()),
                  provider.get().getStatus().getOk());
              assertTrue(provider.get().getSources().isEmpty());
            });

    verifyNoInteractionsWithTrustify();
    verifyNoInteractionsWithRecommend();
  }

  private static Stream<Arguments> emptySbomArguments() {
    return Stream.of(
        Arguments.of(Map.of(TRUSTIFY_PROVIDER, 200), Collections.emptyMap()),
        Arguments.of(
            Map.of(TRUSTIFY_PROVIDER, 200), Map.of(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)));
  }

  @Test
  public void testDefaultTokens() {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asPrettyString();
    assertJson("reports/report.json", body);
    verifyTrustifyRequest(TRUSTIFY_TOKEN);
    verifyOsvRequest();
    verifyRecommendRequest();
  }

  @Test
  public void testDefaultTokensOptOutRecommendations() {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .queryParam(Constants.RECOMMEND_PARAM, Boolean.FALSE)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asPrettyString();
    assertRecommendations(body, TRUSTIFY_PROVIDER, CSAF_SOURCE, 0);
    assertRecommendations(body, TRUSTIFY_PROVIDER, OSV_SOURCE, 0);
    verifyTrustifyRequest(TRUSTIFY_TOKEN);
    verifyOsvRequest();
    verifyNoInteractionsWithRecommend();
  }

  @Test
  public void testAllWithToken() {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asPrettyString();
    assertJson("reports/report.json", body);
    verifyTrustifyRequest(OK_TOKEN);
    verifyOsvRequest();
  }

  @Test
  public void testUnauthorizedRequest() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadFileAsString(String.format("%s/maven-sbom.json", CYCLONEDX)))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, INVALID_TOKEN)
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .as(AnalysisReport.class);

    assertEquals(2, report.getProviders().size());
    assertEquals(
        Response.Status.UNAUTHORIZED.getStatusCode(),
        report.getProviders().get(TRUSTIFY_PROVIDER).getStatus().getCode());

    verifyTrustifyRequest(INVALID_TOKEN);
  }

  @Test
  public void testForbiddenRequest() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadFileAsString(String.format("%s/maven-sbom.json", CYCLONEDX)))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, INVALID_TOKEN)
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .as(AnalysisReport.class);

    assertEquals(2, report.getProviders().size());
    assertEquals(401, report.getProviders().get(TRUSTIFY_PROVIDER).getStatus().getCode());
    assertTrue(report.getProviders().get(TRUSTIFY_PROVIDER).getSources().isEmpty());

    verifyTrustifyRequest(INVALID_TOKEN);
  }

  @Test
  public void testNonVerboseJson() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.APPLICATION_JSON)
            .queryParam(Constants.VERBOSE_MODE_HEADER, Boolean.FALSE)
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .as(AnalysisReport.class);

    assertScanned(report.getScanned());
    var osvSource = report.getProviders().get(TRUSTIFY_PROVIDER).getSources().get(OSV_SOURCE);
    var csafSource = report.getProviders().get(TRUSTIFY_PROVIDER).getSources().get(CSAF_SOURCE);
    assertOsvSummary(osvSource);
    assertCsafSummary(csafSource);

    assertNull(osvSource.getDependencies());
    assertNull(csafSource.getDependencies());

    verifyTrustifyRequest(TRUSTIFY_TOKEN);
  }

  @ParameterizedTest
  @ValueSource(strings = {"HTTP_1_1", "HTTP_2"})
  public void testMultipart_HttpVersions(String version) throws IOException, InterruptedException {
    stubAllProviders();

    var client = HttpClient.newHttpClient();
    var request =
        HttpRequest.newBuilder(URI.create("http://localhost:8081/api/v5/analysis"))
            .setHeader(Constants.TRUST_DA_TOKEN_HEADER, DEFAULT_TRUST_DA_TOKEN)
            .setHeader(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .setHeader("Accept", Constants.MULTIPART_MIXED)
            .version(Version.valueOf(version))
            .POST(HttpRequest.BodyPublishers.ofFile(loadSBOMFile(CYCLONEDX).toPath()))
            .build();

    var response = client.send(request, HttpResponse.BodyHandlers.ofString());

    assertEquals(Status.OK.getStatusCode(), response.statusCode());

    // Validate content type
    var contentType = response.headers().firstValue("Content-Type").orElse("");
    assertTrue(
        contentType.startsWith("multipart/mixed"),
        "Expected multipart/mixed content type, but got: " + contentType);
    assertTrue(
        contentType.contains("boundary="),
        "Expected boundary parameter in content type: " + contentType);

    // Validate multipart response structure
    String body = response.body();
    assertNotNull(body, "Response body should not be null");
    assertFalse(body.isEmpty(), "Response body should not be empty");

    // Validate multipart boundaries
    assertTrue(body.contains("--"), "Response should contain multipart boundaries");
    // Multipart responses end with --boundary-- (not just --)
    assertTrue(body.contains("--"), "Response should contain multipart boundary markers");

    // Validate JSON part
    assertTrue(
        body.contains("Content-Type: application/json"),
        "Response should contain JSON part with correct content type");
    assertTrue(
        body.contains("Content-Transfer-Encoding: binary"),
        "JSON part should have binary transfer encoding");

    // Validate HTML part
    assertTrue(
        body.contains("Content-Type: text/html"),
        "Response should contain HTML part with correct content type");
    assertTrue(
        body.contains("Content-Disposition: attachment; filename=report.html"),
        "HTML part should have correct content disposition");
    assertTrue(
        body.contains("Content-Transfer-Encoding: 8bit"),
        "HTML part should have 8bit transfer encoding");

    // Validate that both parts contain actual content (not just headers)
    // Count the number of boundary markers (each part starts with --)
    long boundaryCount = body.chars().filter(ch -> ch == '-').count();
    assertTrue(
        boundaryCount >= 6, // At least 6 dashes for proper multipart structure
        "Should have proper multipart boundary structure");

    // Verify API calls were made
    verifyTrustifyRequest(TRUSTIFY_TOKEN);
  }

  @Test
  public void testUnknownMediaType() {
    given()
        .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
        .body(loadSBOMFile(CYCLONEDX))
        .header("Accept", MediaType.APPLICATION_XML)
        .when()
        .post("/api/v5/analysis")
        .then()
        .assertThat()
        .header(
            Constants.EXHORT_REQUEST_ID_HEADER,
            MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
        .statusCode(415)
        .contentType(MediaType.TEXT_PLAIN);

    verifyNoInteractions();
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testGzipDeflatedContentEncoding(String sbom) throws IOException {
    stubAllProviders();

    var fileContent = loadFileAsString(String.format("%s/empty-sbom.json", sbom));
    var byteArray = new ByteArrayOutputStream(fileContent.length());
    var output = new GZIPOutputStream(byteArray);
    output.write(fileContent.getBytes());
    output.close();
    byteArray.close();
    var report =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .header(Exchange.CONTENT_ENCODING, "gzip")
            .body(byteArray.toByteArray())
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(Exchange.CONTENT_ENCODING, "gzip")
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .as(AnalysisReport.class);

    report.getProviders().values().stream().allMatch(p -> p.getStatus().getOk());
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testInvalidGzipDeflatedContentEncoding(String sbom) throws IOException {
    stubAllProviders();

    var fileContent = loadFileAsString(String.format("%s/invalid-sbom.json", sbom));
    var byteArray = new ByteArrayOutputStream(fileContent.length());
    var output = new GZIPOutputStream(byteArray);
    output.write(fileContent.getBytes());
    output.close();
    byteArray.close();
    var response =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .header(Exchange.CONTENT_ENCODING, "gzip")
            .body(byteArray.toByteArray())
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(400)
            .header(Exchange.CONTENT_ENCODING, "gzip")
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .asString();

    switch (sbom) {
      case CYCLONEDX -> assertTrue(response.startsWith("CycloneDX Validation"));
      case SPDX -> assertTrue(response.startsWith("SPDX-2.3 Validation"));
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testBatchSBOMAllWithToken(String sbom) {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.TRUSTIFY_TOKEN_HEADER, OK_TOKEN)
            .body(loadBatchSBOMFile(sbom))
            .when()
            .post("/api/v5/batch-analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asPrettyString();
    assertJson("reports/batch_report.json", body);
    verifyTrustifyRequest(OK_TOKEN, 3);
    verifyOsvRequest(3);
  }

  private void assertScanned(Scanned scanned) {
    assertEquals(3, scanned.getDirect());
    assertEquals(7, scanned.getTransitive());
    assertEquals(10, scanned.getTotal());
  }

  private void assertOsvSummary(Source source) {
    assertNotNull(source);
    var summary = source.getSummary();
    assertEquals(7, summary.getTotal());

    assertEquals(0, summary.getDirect());
    assertEquals(7, summary.getTransitive());
    assertEquals(1, summary.getCritical());
    assertEquals(4, summary.getHigh());
    assertEquals(2, summary.getMedium());
    assertEquals(0, summary.getLow());
  }

  private void assertCsafSummary(Source source) {
    assertNotNull(source);
    var summary = source.getSummary();
    assertEquals(2, summary.getTotal());
    assertEquals(0, summary.getDirect());
    assertEquals(2, summary.getTransitive());
    assertEquals(1, summary.getCritical());
    assertEquals(1, summary.getHigh());
    assertEquals(0, summary.getMedium());
    assertEquals(0, summary.getLow());
  }

  private void assertRecommendations(
      String body, String provider, String source, int recommendations) {
    try {
      var report = MAPPER.readValue(body, AnalysisReport.class);
      assertTrue(report.getProviders().containsKey(provider));
      assertTrue(report.getProviders().get(provider).getSources().containsKey(source));
      assertEquals(
          recommendations,
          report
              .getProviders()
              .get(provider)
              .getSources()
              .get(source)
              .getSummary()
              .getRecommendations());
    } catch (IOException e) {
      fail("Failed to read report: " + e.getMessage());
    }
  }
}
