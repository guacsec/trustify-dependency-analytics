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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.github.guacsec.trustifyda.extensions.WiremockExtension.TRUSTIFY_TOKEN;
import static io.restassured.RestAssured.given;
import static org.apache.camel.Exchange.CONTENT_TYPE;

import java.io.File;

import org.apache.camel.Exchange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.extensions.OidcWiremockExtension;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

import jakarta.ws.rs.core.MediaType;

@QuarkusTest
@QuarkusTestResource(OidcWiremockExtension.class)
public class Pep691AnalysisTest extends AbstractAnalysisTest {

  @Override
  @AfterEach
  void resetMock() {
    if (server != null) {
      server.resetAll();
      OidcWiremockExtension.restubOidcEndpoints(server);
    }
  }

  @BeforeEach
  void setupOidcStubs() {
    if (server != null) {
      OidcWiremockExtension.restubOidcEndpoints(server);
    }
  }

  @Test
  public void testPypiRecommendations() throws Exception {
    stubAllProviders();
    stubDepsDevTimeoutRequest();
    stubPypiTrustifyRequests();
    stubPep691RegistryRequests();

    var body =
        given()
            .header(CONTENT_TYPE, Constants.CYCLONEDX_MEDIATYPE_JSON)
            .header("Accept", MediaType.APPLICATION_JSON)
            .body(loadPypiSBOMFile())
            .when()
            .post("/api/v5/analysis")
            .then()
            .assertThat()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .extract()
            .body()
            .asPrettyString();

    body = replaceMockedDepsDevSourceUrl(body);
    body = replaceMockedRegistryUrl(body);
    assertJson("reports/pypi_report.json", body);
  }

  private File loadPypiSBOMFile() {
    return new File(
        getClass().getClassLoader().getResource("cyclonedx/pypi-sbom-with-hashes.json").getPath());
  }

  private void stubPypiTrustifyRequests() {
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TRUSTIFY_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/trustify/pypi_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/pypi_report.json")));
    OidcWiremockExtension.restubOidcEndpoints(server);
  }

  private void stubPep691RegistryRequests() {
    server.stubFor(
        get(urlPathEqualTo("/requests/"))
            .withHeader("Accept", equalTo("application/vnd.pypi.simple.v1+json"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
                    .withBodyFile("pypi-registry/requests_response.json")));
  }
}
