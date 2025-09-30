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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.redhat.exhort.extensions.WiremockExtension.TRUSTIFY_TOKEN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;

import org.apache.camel.Exchange;
import org.junit.jupiter.api.AfterEach;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.redhat.exhort.extensions.InjectWireMock;
import com.redhat.exhort.extensions.OidcWiremockExtension;
import com.redhat.exhort.extensions.WiremockExtension;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.DecoderConfig;
import io.restassured.config.EncoderConfig;

import jakarta.ws.rs.core.MediaType;

@QuarkusTest
@QuarkusTestResource(WiremockExtension.class)
public abstract class AbstractAnalysisTest {

  static final String OK_TOKEN = "test-token";
  static final String ERROR_TOKEN = "fail";
  static final String INVALID_TOKEN = "invalid-token";
  static final String UNAUTH_TOKEN = "test-not-authorized";

  static final String WIREMOCK_URL_TEMPLATE = "__WIREMOCK_URL__";

  static final String REGEX_MATCHER_REQUEST_ID = "[a-f0-9]{64}";

  @InjectWireMock WireMockServer server;

  static {
    RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    RestAssured.config()
        .encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8"));
    RestAssured.config()
        .decoderConfig(DecoderConfig.decoderConfig().defaultContentCharset("UTF-8"));
  }

  @AfterEach
  void resetMock() {
    if (server != null) {
      server.resetAll();
    }
  }

  protected void assertJson(String expectedFile, String currentBody) {
    try {
      var expectedContent =
          new String(
              getClass()
                  .getClassLoader()
                  .getResourceAsStream("__files/" + expectedFile)
                  .readAllBytes());
      assertTrue(
          equalToJson(expectedContent, true, false).match(currentBody).isExactMatch(),
          String.format("Expecting: %s \nGot: %s", expectedContent, currentBody));
    } catch (IOException e) {
      fail("Unexpected processing exception");
    }
  }

  protected void assertHtml(String expectedFile, String currentBody) throws URISyntaxException {
    String expected;
    try {
      expected =
          Files.readString(
              Path.of(getClass().getClassLoader().getResource("__files/" + expectedFile).toURI()),
              Charset.defaultCharset());
      expected = expected.replaceAll(WIREMOCK_URL_TEMPLATE, server.baseUrl());
      assertEquals(expected, currentBody);
    } catch (IOException e) {
      fail("Unable to read HTML file", e);
    }
  }

  protected void assertReportContains(String expectedText, String currentBody) {
    assertTrue(currentBody.contains(expectedText));
  }

  protected void assertReportDoesNotContains(String expectedText, String currentBody) {
    assertFalse(currentBody.contains(expectedText));
  }

  protected String getContentType(String sbomType) {
    return switch (sbomType) {
      case "cyclonedx" -> Constants.CYCLONEDX_MEDIATYPE_JSON;
      case "spdx" -> Constants.SPDX_MEDIATYPE_JSON;
      default -> fail("Sbom Type not implemented: " + sbomType);
    };
  }

  protected File loadSBOMFile(String sbomType) {
    return new File(
        getClass()
            .getClassLoader()
            .getResource(String.format("%s/maven-sbom.json", sbomType))
            .getPath());
  }

  protected File loadBatchSBOMFile(String sbomType) {
    return new File(
        getClass()
            .getClassLoader()
            .getResource(String.format("%s/batch-sbom.json", sbomType))
            .getPath());
  }

  protected String loadFileAsString(String file) {
    try {
      return Files.readString(
          Path.of(getClass().getClassLoader().getResource(file).toURI()), StandardCharsets.UTF_8);
    } catch (IOException | URISyntaxException e) {
      fail("Unable to read expected file: " + file, e);
      return null;
    }
  }

  protected void verifyTokenRequest(String provider, Map<String, String> headers) {

    verifyTrustifyTokenRequest(headers.get(Constants.TRUSTIFY_TOKEN_HEADER));
  }

  protected void verifyTrustifyTokenRequest(String token) {
    if (token == null) {
      server.verify(
          1,
          getRequestedFor(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
              .withQueryParam("limit", equalTo("0")));
    } else {
      server.verify(
          1,
          getRequestedFor(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
              .withQueryParam("limit", equalTo("0"))
              .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + token)));
    }
  }

  protected void verifyTrustifyRequest(String token) {
    verifyTrustifyRequest(token, 1);
  }

  protected void verifyTrustifyRequest(String token, int count) {
    server.verify(
        count,
        postRequestedFor(urlEqualTo(Constants.TRUSTIFY_ANALYZE_PATH))
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + token)));
  }

  protected void stubAllProviders() {
    stubOsvRequests();
    stubTrustifyRequests();
    stubTrustedContentRequests();
  }

  protected void verifyProviders(Collection<String> providers, Map<String, String> credentials) {
    providers.stream()
        .forEach(
            p -> {
              switch (p) {
                case Constants.TRUSTIFY_PROVIDER -> verifyTrustifyRequest(
                    credentials.get(Constants.TRUSTIFY_TOKEN_HEADER));
              }
            });
    verifyTrustedContentRequest();
  }

  protected void stubTrustedContentRequests() {
    server.stubFor(
        post(Constants.TRUSTED_CONTENT_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustedcontent/empty_report.json")));
    server.stubFor(
        post(Constants.TRUSTED_CONTENT_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(
                    loadFileAsString("__files/trustedcontent/maven_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustedcontent/maven_report.json")));
    server.stubFor(
        post(Constants.TRUSTED_CONTENT_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(
                    loadFileAsString("__files/trustedcontent/batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustedcontent/maven_report.json")));
  }

  protected void stubOsvRequests() {
    server.stubFor(
        post(Constants.OSV_NVD_PURLS_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("onguard/empty_report.json")));

    server.stubFor(
        post(Constants.OSV_NVD_PURLS_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/onguard/maven_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("onguard/maven_report.json")));
    server.stubFor(
        post(Constants.OSV_NVD_PURLS_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/onguard/batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("onguard/maven_report.json")));
  }

  protected void stubTrustifyRequests() {
    // Missing token
    server.stubFor(post(Constants.TRUSTIFY_ANALYZE_PATH).willReturn(aResponse().withStatus(401)));

    // Invalid token
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + INVALID_TOKEN))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"error\": \"Unauthorized\", \"message\": \"Verify the provided"
                            + " credentials are valid.\"}}")));
    // Internal Error
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + ERROR_TOKEN))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(aResponse().withStatus(500).withBody("Unexpected error")));
    // Forbidden
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + UNAUTH_TOKEN))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(403)
                    .withBody(
                        "{\"error\": \"Forbidden\", \"message\": \"The provided credentials don't"
                            + " have the required permissions.\"}}")));
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TRUSTIFY_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/empty_report.json")));

    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TRUSTIFY_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/trustify/maven_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/maven_report.json")));
    server.stubFor(
        post(Constants.TRUSTIFY_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TRUSTIFY_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/trustify/batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/maven_report.json")));

    // Re-stub OIDC endpoints to ensure they're available for token exchange
    OidcWiremockExtension.restubOidcEndpoints(server);
  }

  protected void stubTrustifyTokenRequests() {
    // Missing token
    server.stubFor(
        get(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(aResponse().withStatus(401)));

    // Accepted tokens
    server.stubFor(
        get(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TRUSTIFY_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("trustify/empty_report.json")));

    // Internal Error
    server.stubFor(
        get(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + ERROR_TOKEN))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(aResponse().withStatus(500).withBody("This is an example error")));

    // Invalid token
    server.stubFor(
        get(urlPathEqualTo(Constants.TRUSTIFY_TOKEN_PATH))
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + INVALID_TOKEN))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"error\": \"Unauthorized\", \"message\": \"Authentication failed\"}")));
  }

  protected void verifyTrustedContentRequest() {
    server.verify(1, postRequestedFor(urlEqualTo(Constants.TRUSTED_CONTENT_PATH)));
  }

  protected void verifyOsvRequest() {
    verifyOsvRequest(1);
  }

  protected void verifyOsvRequest(int count) {
    server.verify(count, postRequestedFor(urlEqualTo(Constants.OSV_NVD_PURLS_PATH)));
  }

  protected void verifyNoInteractions() {
    verifyNoInteractionsWithOsv();
    verifyNoInteractionsWithTrustify();
  }

  protected void verifyNoInteractionsWithTrustedContent() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.TRUSTED_CONTENT_PATH)));
  }

  protected void verifyNoInteractionsWithOsv() {
    server.verify(0, postRequestedFor(urlPathEqualTo(Constants.OSV_NVD_PURLS_PATH)));
  }

  protected void verifyNoInteractionsWithTrustify() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.TRUSTIFY_ANALYZE_PATH)));
  }
}
