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

import static io.github.guacsec.trustifyda.integration.licenses.LicensesIntegration.LICENSES_POST_INVALID_BODY_MESSAGE;
import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;
import io.github.guacsec.trustifyda.extensions.OidcWiremockExtension;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@QuarkusTest
@QuarkusTestResource(OidcWiremockExtension.class)
public class LicensesEndpointTest extends AbstractAnalysisTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final String PURL_QUARKUS_H2 = "pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final";
  private static final String PURL_CDI_API =
      "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2";

  @Test
  public void postLicenses_multiplePurls_returnsLicensesAndCallsDepsDev() throws Exception {
    stubLicensesRequests();

    String requestJson =
        MAPPER.writeValueAsString(Map.of("purls", List.of(PURL_QUARKUS_H2, PURL_CDI_API)));

    String json =
        given()
            .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .body(requestJson)
            .when()
            .post("/api/v5/licenses")
            .then()
            .statusCode(Response.Status.OK.getStatusCode())
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asString();

    verifyLicensesRequest(1);

    List<LicenseProviderResult> results =
        MAPPER.readValue(json, new TypeReference<List<LicenseProviderResult>>() {});
    assertEquals(1, results.size());
    LicenseProviderResult depsDev = results.get(0);
    assertNotNull(depsDev.getStatus());
    assertTrue(depsDev.getStatus().getOk());
    assertEquals("deps.dev", depsDev.getStatus().getName());
    var packages = depsDev.getPackages();
    assertTrue(
        packages.containsKey(PURL_QUARKUS_H2), "Response should include first requested purl");
    assertTrue(packages.containsKey(PURL_CDI_API), "Response should include second requested purl");
    assertNotNull(packages.get(PURL_QUARKUS_H2).getConcluded());
    assertNotNull(packages.get(PURL_CDI_API).getConcluded());
    assertFalse(packages.get(PURL_QUARKUS_H2).getEvidence().isEmpty());
  }

  @Test
  public void postLicenses_emptyPurls_returnsOkWithoutDepsDevCall() throws Exception {
    String json =
        given()
            .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .body("{\"purls\":[]}")
            .when()
            .post("/api/v5/licenses")
            .then()
            .statusCode(Response.Status.OK.getStatusCode())
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asString();

    verifyLicensesRequest(0);

    List<LicenseProviderResult> results =
        MAPPER.readValue(json, new TypeReference<List<LicenseProviderResult>>() {});
    assertEquals(1, results.size());
    LicenseProviderResult depsDev = results.get(0);
    assertNotNull(depsDev.getStatus());
    assertTrue(depsDev.getStatus().getOk());
    assertEquals("deps.dev", depsDev.getStatus().getName());
    assertTrue(depsDev.getPackages().isEmpty());
  }

  /** Missing {@code purls} is treated like an empty request (same as {@code null}). */
  @Test
  public void postLicenses_missingPurls_returnsOkWithoutDepsDevCall() throws Exception {
    String json =
        given()
            .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .body("{}")
            .when()
            .post("/api/v5/licenses")
            .then()
            .statusCode(Response.Status.OK.getStatusCode())
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asString();

    verifyLicensesRequest(0);

    List<LicenseProviderResult> results =
        MAPPER.readValue(json, new TypeReference<List<LicenseProviderResult>>() {});
    assertEquals(1, results.size());
    assertTrue(results.get(0).getPackages().isEmpty());
  }

  /** Malformed JSON is rejected by quarkus-rest-jackson before reaching the Camel route. */
  @Test
  public void postLicenses_malformedJson_returnsBadRequest() {
    given()
        .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
        .body("{\"purls\":[}")
        .when()
        .post("/api/v5/licenses")
        .then()
        .statusCode(Response.Status.BAD_REQUEST.getStatusCode());

    verifyLicensesRequest(0);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "{\"purls\":\"not-array\"}",
        "{\"purls\":[123]}",
        "{\"purls\":[true]}",
      })
  public void postLicenses_invalidJsonShape_returnsBadRequestAndPlainHint(String requestJson) {
    String body =
        given()
            .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .body(requestJson)
            .when()
            .post("/api/v5/licenses")
            .then()
            .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
            .contentType(MediaType.TEXT_PLAIN)
            .extract()
            .body()
            .asString();

    assertEquals(LICENSES_POST_INVALID_BODY_MESSAGE, body);
    verifyLicensesRequest(0);
  }

  /**
   * Empty purl string fails PackageRef deserialization, triggering the JsonMappingException
   * handler.
   */
  @Test
  public void postLicenses_invalidPurl_returnsBadRequestAndPlainHint() {
    String body =
        given()
            .header(CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .body("{\"purls\":[\"\"]}")
            .when()
            .post("/api/v5/licenses")
            .then()
            .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
            .contentType(MediaType.TEXT_PLAIN)
            .extract()
            .body()
            .asString();

    assertEquals(LICENSES_POST_INVALID_BODY_MESSAGE, body);
    verifyLicensesRequest(0);
  }
}
