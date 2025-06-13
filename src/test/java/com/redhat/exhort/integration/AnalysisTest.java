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

package com.redhat.exhort.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.redhat.exhort.extensions.WiremockExtension.SNYK_TOKEN;
import static com.redhat.exhort.extensions.WiremockExtension.TPA_TOKEN;
import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.AnalysisReport;
import com.redhat.exhort.api.v4.DependencyReport;
import com.redhat.exhort.api.v4.Scanned;
import com.redhat.exhort.api.v4.SourceSummary;

import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@QuarkusTest
public class AnalysisTest extends AbstractAnalysisTest {

  private static final String CYCLONEDX = "cyclonedx";
  private static final String SPDX = "spdx";
  private static final String DEFAULT_RHDA_TOKEN = "example-rhda-token";

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testWithWrongProvider(String sbom) {
    List<PackageRef> req = Collections.emptyList();
    given()
        .header(CONTENT_TYPE, getContentType(sbom))
        .queryParam(Constants.PROVIDERS_PARAM, "unknown")
        .body(req)
        .when()
        .post("/api/v4/analysis")
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
            .post("/api/v4/analysis")
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
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testWithInvalidPkgManagers(String sbom) {
    var report =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .body(loadFileAsString(String.format("%s/unsupported-invalid-sbom.json", sbom)))
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .as(AnalysisReport.class);

    assertEquals(4, report.getProviders().size());
    assertEquals(
        401, report.getProviders().get(Constants.OSS_INDEX_PROVIDER).getStatus().getCode());
    var snykProvider = report.getProviders().get(Constants.SNYK_PROVIDER);
    var status = snykProvider.getStatus();
    assertEquals(200, status.getCode());
    assertEquals(Constants.SNYK_PROVIDER, status.getName());
    assertTrue(status.getOk());
    assertEquals(1, snykProvider.getSources().size());
    var unscanned = snykProvider.getSources().get(Constants.SNYK_PROVIDER).getUnscanned();
    assertEquals(1, unscanned.size());

    verifyNoInteractionsWithOSS();
    verifyNoInteractionsWithSnyk();
    verifyTrustedContentRequest();
  }

  @ParameterizedTest
  @ValueSource(strings = {CYCLONEDX, SPDX})
  public void testWithMixedPkgManagers(String sbom) {
    stubAllProviders();
    var report =
        given()
            .header(CONTENT_TYPE, getContentType(sbom))
            .body(loadFileAsString(String.format("%s/mixed-sbom.json", sbom)))
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(Status.OK.getStatusCode())
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .as(AnalysisReport.class);

    assertEquals(4, report.getProviders().size());
    assertEquals(
        Status.UNAUTHORIZED.getStatusCode(),
        report.getProviders().get(Constants.OSS_INDEX_PROVIDER).getStatus().getCode());
    var status = report.getProviders().get(Constants.SNYK_PROVIDER).getStatus();
    assertEquals(Status.OK.getStatusCode(), status.getCode());
    assertEquals(Constants.SNYK_PROVIDER, status.getName());
    assertEquals(
        Status.OK.getStatusCode(),
        report.getProviders().get(Constants.TRUSTED_CONTENT_PROVIDER).getStatus().getCode());

    server.verify(2, postRequestedFor(urlPathEqualTo(Constants.SNYK_DEP_GRAPH_API_PATH)));
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
            .post("/api/v4/analysis")
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

    verifyNoInteractionsWithSnyk();
    verifyNoInteractionsWithOSS();
    verifyNoInteractionsWithTpa();
    verifyNoInteractionsWithTrustedContent();
  }

  private static Stream<Arguments> emptySbomArguments() {
    return Stream.of(
        Arguments.of(Map.of(Constants.SNYK_PROVIDER, 200), Collections.emptyMap()),
        Arguments.of(Map.of(Constants.OSS_INDEX_PROVIDER, 401), Collections.emptyMap()),
        Arguments.of(Map.of(Constants.TPA_PROVIDER, 200), Collections.emptyMap()),
        Arguments.of(
            Map.of(Constants.SNYK_PROVIDER, 200, Constants.OSS_INDEX_PROVIDER, 401),
            Collections.emptyMap()),
        Arguments.of(
            Map.of(
                Constants.SNYK_PROVIDER,
                200,
                Constants.OSS_INDEX_PROVIDER,
                401,
                Constants.TPA_PROVIDER,
                200),
            Map.of(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)),
        Arguments.of(
            Map.of(
                Constants.SNYK_PROVIDER,
                200,
                Constants.OSS_INDEX_PROVIDER,
                200,
                Constants.TPA_PROVIDER,
                200),
            Map.of(
                Constants.OSS_INDEX_USER_HEADER,
                OK_USER,
                Constants.OSS_INDEX_TOKEN_HEADER,
                OK_TOKEN)),
        Arguments.of(
            Map.of(
                Constants.SNYK_PROVIDER,
                200,
                Constants.OSS_INDEX_PROVIDER,
                200,
                Constants.TPA_PROVIDER,
                200),
            Map.of(
                Constants.SNYK_TOKEN_HEADER,
                OK_TOKEN,
                Constants.OSS_INDEX_USER_HEADER,
                OK_USER,
                Constants.OSS_INDEX_TOKEN_HEADER,
                OK_TOKEN,
                Constants.TPA_TOKEN_HEADER,
                OK_TOKEN)),
        Arguments.of(
            Map.of(
                Constants.SNYK_PROVIDER,
                200,
                Constants.OSS_INDEX_PROVIDER,
                200,
                Constants.TPA_PROVIDER,
                200),
            Map.of(
                Constants.SNYK_TOKEN_HEADER,
                OK_TOKEN,
                Constants.OSS_INDEX_USER_HEADER,
                OK_USER,
                Constants.OSS_INDEX_TOKEN_HEADER,
                OK_TOKEN,
                Constants.TPA_TOKEN_HEADER,
                OK_TOKEN)));
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
            .post("/api/v4/analysis")
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
    assertJson("reports/report_default_token.json", body);
    verifySnykRequest(SNYK_TOKEN);
    verifyTpaRequest(TPA_TOKEN);
  }

  @Test
  public void testAllWithToken() {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.OSS_INDEX_USER_HEADER, OK_USER)
            .header(Constants.OSS_INDEX_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.TPA_TOKEN_HEADER, OK_TOKEN)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v4/analysis")
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
    assertJson("reports/report_all_token.json", body);
    verifySnykRequest(OK_TOKEN);
    verifyOssRequest(OK_USER, OK_TOKEN);
    verifyTpaRequest(OK_TOKEN);
  }

  @Test
  public void testSnykWithNoToken() {
    stubAllProviders();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .queryParam(Constants.PROVIDERS_PARAM, Constants.SNYK_PROVIDER)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v4/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .header(
                Constants.EXHORT_REQUEST_ID_HEADER,
                MatchesPattern.matchesPattern(REGEX_MATCHER_REQUEST_ID))
            .extract()
            .body()
            .asPrettyString();

    assertJson("reports/report_all_no_snyk_token.json", body);
    verifySnykRequest(null);
  }

  @Test
  public void testUnauthorizedRequest() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadFileAsString(String.format("%s/maven-sbom.json", CYCLONEDX)))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.SNYK_TOKEN_HEADER, INVALID_TOKEN)
            .header(Constants.TPA_TOKEN_HEADER, INVALID_TOKEN)
            .when()
            .post("/api/v4/analysis")
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

    assertEquals(4, report.getProviders().size());
    assertEquals(
        Response.Status.UNAUTHORIZED.getStatusCode(),
        report.getProviders().get(Constants.OSS_INDEX_PROVIDER).getStatus().getCode());
    assertEquals(
        Response.Status.UNAUTHORIZED.getStatusCode(),
        report.getProviders().get(Constants.TPA_PROVIDER).getStatus().getCode());
    assertTrue(report.getProviders().get(Constants.SNYK_PROVIDER).getSources().isEmpty());
    var status = report.getProviders().get(Constants.SNYK_PROVIDER).getStatus();
    assertFalse(status.getOk());
    assertEquals(Constants.SNYK_PROVIDER, status.getName());
    assertEquals(Status.UNAUTHORIZED.getStatusCode(), status.getCode());

    verifyTpaRequest(INVALID_TOKEN);
  }

  @Test
  public void testForbiddenRequest() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadFileAsString(String.format("%s/maven-sbom.json", CYCLONEDX)))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.SNYK_TOKEN_HEADER, UNAUTH_TOKEN)
            .when()
            .post("/api/v4/analysis")
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

    assertEquals(4, report.getProviders().size());
    assertEquals(
        401, report.getProviders().get(Constants.OSS_INDEX_PROVIDER).getStatus().getCode());
    assertTrue(report.getProviders().get(Constants.SNYK_PROVIDER).getSources().isEmpty());
    var status = report.getProviders().get(Constants.SNYK_PROVIDER).getStatus();
    assertFalse(status.getOk());
    assertEquals(Constants.SNYK_PROVIDER, status.getName());
    assertEquals(Status.FORBIDDEN.getStatusCode(), status.getCode());

    verifySnykRequest(UNAUTH_TOKEN);
  }

  @Test
  public void testSBOMJsonWithToken() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .body(loadSBOMFile(CYCLONEDX))
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .when()
            .post("/api/v4/analysis")
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
    var snykSource =
        report
            .getProviders()
            .get(Constants.SNYK_PROVIDER)
            .getSources()
            .get(Constants.SNYK_PROVIDER);
    assertSummary(snykSource.getSummary());
    assertDependenciesReport(snykSource.getDependencies());

    verifySnykRequest(OK_TOKEN);
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
            .post("/api/v4/analysis")
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
    var snykSource =
        report
            .getProviders()
            .get(Constants.SNYK_PROVIDER)
            .getSources()
            .get(Constants.SNYK_PROVIDER);
    assertSummary(snykSource.getSummary());
    assertNull(snykSource.getDependencies());

    verifySnykRequest(null);
  }

  @Test
  public void testNonVerboseWithToken() {
    stubAllProviders();

    var report =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .queryParam(Constants.VERBOSE_MODE_HEADER, Boolean.FALSE)
            .body(loadSBOMFile(CYCLONEDX))
            .when()
            .post("/api/v4/analysis")
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
    var snykSource =
        report
            .getProviders()
            .get(Constants.SNYK_PROVIDER)
            .getSources()
            .get(Constants.SNYK_PROVIDER);
    assertSummary(snykSource.getSummary());
    assertNull(snykSource.getDependencies());

    verifySnykRequest(OK_TOKEN);
  }

  @ParameterizedTest
  @ValueSource(strings = {"HTTP_1_1", "HTTP_2"})
  public void testMultipart_HttpVersions(String version) throws IOException, InterruptedException {
    stubAllProviders();

    var client = HttpClient.newHttpClient();
    var request =
        HttpRequest.newBuilder(URI.create("http://localhost:8081/api/v4/analysis"))
            .setHeader(Constants.RHDA_TOKEN_HEADER, DEFAULT_RHDA_TOKEN)
            .setHeader(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .setHeader("Accept", Constants.MULTIPART_MIXED)
            .setHeader(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .setHeader(Constants.OSS_INDEX_USER_HEADER, OK_USER)
            .setHeader(Constants.OSS_INDEX_TOKEN_HEADER, OK_TOKEN)
            .version(Version.valueOf(version))
            .POST(HttpRequest.BodyPublishers.ofFile(loadSBOMFile(CYCLONEDX).toPath()))
            .build();

    var response = client.send(request, HttpResponse.BodyHandlers.ofString());

    assertEquals(Status.OK.getStatusCode(), response.statusCode());

    verifySnykRequest(OK_TOKEN);
    verifyOssRequest(OK_USER, OK_TOKEN);
  }

  @Test
  public void testUnknownMediaType() {
    given()
        .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
        .body(loadSBOMFile(CYCLONEDX))
        .header("Accept", MediaType.APPLICATION_XML)
        .when()
        .post("/api/v4/analysis")
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
            .post("/api/v4/analysis")
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
            .post("/api/v4/analysis")
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
      case CYCLONEDX:
        assertTrue(response.startsWith("CycloneDX Validation"));
        break;
      case SPDX:
        assertTrue(response.startsWith("SPDX-2.3 Validation"));
        break;
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
            .header(Constants.SNYK_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.OSS_INDEX_USER_HEADER, OK_USER)
            .header(Constants.OSS_INDEX_TOKEN_HEADER, OK_TOKEN)
            .header(Constants.TPA_TOKEN_HEADER, OK_TOKEN)
            .body(loadBatchSBOMFile(sbom))
            .when()
            .post("/api/v4/batch-analysis")
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

    assertJson("reports/batch_report_all_token.json", body);
    verifySnykRequest(OK_TOKEN, 3);
    verifyOssRequest(OK_USER, OK_TOKEN, 3);
    verifyTpaRequest(OK_TOKEN, 3);
  }

  private void assertScanned(Scanned scanned) {
    assertEquals(2, scanned.getDirect());
    assertEquals(7, scanned.getTransitive());
    assertEquals(9, scanned.getTotal());
  }

  private void assertSummary(SourceSummary summary) {
    assertEquals(4, summary.getTotal());

    assertEquals(0, summary.getDirect());
    assertEquals(4, summary.getTransitive());
    assertEquals(0, summary.getCritical());
    assertEquals(1, summary.getHigh());
    assertEquals(3, summary.getMedium());
    assertEquals(0, summary.getLow());
  }

  private void assertDependenciesReport(List<DependencyReport> dependencies) {
    assertEquals(2, dependencies.size());

    var hibernate =
        new PackageRef("pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar");
    var report = getReport(hibernate.name(), dependencies);
    assertNotNull(report);
    assertEquals(hibernate, report.getRef());
    assertTrue(report.getIssues().isEmpty());

    assertEquals(1, report.getTransitive().size());
    var tReport = report.getTransitive().get(0);
    var jackson =
        new PackageRef("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar");
    assertEquals(jackson, tReport.getRef());
    assertEquals(3, tReport.getIssues().size());
    assertEquals(tReport.getHighestVulnerability(), tReport.getIssues().get(0));
    assertEquals(report.getHighestVulnerability(), tReport.getHighestVulnerability());
  }

  private DependencyReport getReport(String pkgName, List<DependencyReport> dependencies) {
    var dep =
        dependencies.stream()
            .filter(d -> d.getRef().name().equals(pkgName))
            .findFirst()
            .orElse(null);
    assertNotNull(dep);
    return dep;
  }
}
