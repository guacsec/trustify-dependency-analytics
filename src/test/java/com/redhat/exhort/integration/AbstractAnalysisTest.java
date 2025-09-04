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
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.redhat.exhort.extensions.WiremockExtension.SNYK_TOKEN;
import static com.redhat.exhort.extensions.WiremockExtension.TPA_TOKEN;
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
import com.github.tomakehurst.wiremock.client.BasicCredentials;
import com.redhat.exhort.extensions.InjectWireMock;
import com.redhat.exhort.extensions.WiremockExtension;
import com.redhat.exhort.integration.providers.snyk.SnykRequestBuilder;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.DecoderConfig;
import io.restassured.config.EncoderConfig;

import jakarta.ws.rs.core.MediaType;

@QuarkusTest
@QuarkusTestResource(WiremockExtension.class)
public abstract class AbstractAnalysisTest {

  private static final String SNYK_UA_PATTERN = "redhat-snyk-exhort-.*";
  static final String OK_USER = "test-user";
  static final String OK_TOKEN = "test-token";
  static final String ERROR_TOKEN = "fail";
  static final String INVALID_TOKEN = "invalid-token";
  static final String UNAUTH_TOKEN = "test-not-authorized";
  static final String RATE_LIMIT_TOKEN = "too-many-requests-token";

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

  protected void verifyRequest(String provider, Map<String, String> headers) {
    switch (provider) {
      case Constants.SNYK_PROVIDER -> verifySnykRequest(headers.get(Constants.SNYK_TOKEN_HEADER));
      case Constants.OSS_INDEX_PROVIDER -> verifyOssRequest(
          headers.get(Constants.OSS_INDEX_USER_HEADER),
          headers.get(Constants.OSS_INDEX_TOKEN_HEADER));
    }
  }

  protected void verifySnykRequest(String token) {
    verifySnykRequest(token, 1);
  }

  protected void verifySnykRequest(String token, int count) {
    if (token == null) {
      server.verify(count, postRequestedFor(urlEqualTo(Constants.SNYK_DEP_GRAPH_API_PATH)));
    } else {
      server.verify(
          count,
          postRequestedFor(urlEqualTo(Constants.SNYK_DEP_GRAPH_API_PATH))
              .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + token))
              .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN)));
    }
  }

  protected void verifyTokenRequest(String provider, Map<String, String> headers) {
    switch (provider) {
      case Constants.SNYK_PROVIDER -> verifySnykTokenRequest(
          headers.get(Constants.SNYK_TOKEN_HEADER));
      case Constants.OSS_INDEX_PROVIDER -> verifyOssRequest(
          headers.get(Constants.OSS_INDEX_USER_HEADER),
          headers.get(Constants.OSS_INDEX_TOKEN_HEADER));
      case Constants.TPA_PROVIDER -> verifyTpaTokenRequest(headers.get(Constants.TPA_TOKEN_HEADER));
    }
  }

  protected void verifySnykTokenRequest(String token) {
    if (token == null) {
      server.verify(1, getRequestedFor(urlEqualTo(Constants.SNYK_TOKEN_API_PATH)));
    } else {
      server.verify(
          1,
          getRequestedFor(urlEqualTo(Constants.SNYK_TOKEN_API_PATH))
              .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + token))
              .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN)));
    }
  }

  protected void verifyTpaTokenRequest(String token) {
    if (token == null) {
      server.verify(
          1,
          getRequestedFor(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
              .withQueryParam("limit", equalTo("0")));
    } else {
      server.verify(
          1,
          getRequestedFor(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
              .withQueryParam("limit", equalTo("0"))
              .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + token)));
    }
  }

  protected void verifyTpaRequest(String token) {
    verifyTpaRequest(token, 1);
  }

  protected void verifyTpaRequest(String token, int count) {
    if (token == null) {
      server.verify(count, postRequestedFor(urlEqualTo(Constants.TPA_ANALYZE_PATH)));
    } else {
      server.verify(
          count,
          postRequestedFor(urlEqualTo(Constants.TPA_ANALYZE_PATH))
              .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + token)));
    }
  }

  protected void stubAllProviders() {
    stubSnykRequests();
    stubOssToken();
    stubOsvRequests();
    stubTpaRequests();
    stubTrustedContentRequests();
  }

  protected void verifyProviders(Collection<String> providers, Map<String, String> credentials) {
    providers.stream()
        .forEach(
            p -> {
              switch (p) {
                case Constants.SNYK_PROVIDER -> verifySnykRequest(
                    credentials.get(Constants.SNYK_TOKEN_HEADER));
                case Constants.OSS_INDEX_PROVIDER -> verifyOssRequest(
                    credentials.get(Constants.OSS_INDEX_USER_HEADER),
                    credentials.get(Constants.OSS_INDEX_TOKEN_HEADER));
                case Constants.TPA_PROVIDER -> verifyTpaRequest(
                    credentials.get(Constants.TPA_TOKEN_HEADER));
              }
            });
    verifyTrustedContentRequest();
  }

  protected void stubSnykTokenRequests() {
    // Missing token
    server.stubFor(
        get(Constants.SNYK_TOKEN_API_PATH)
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"code\": 401, \"error\": \"Not authorised\""
                            + ", \"message\": \"Not authorised\"}")));
    // Default request
    server.stubFor(
        get(Constants.SNYK_TOKEN_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + OK_TOKEN))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/user_validation.json")));
    // Internal Error
    server.stubFor(
        get(Constants.SNYK_TOKEN_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + ERROR_TOKEN))
            .willReturn(aResponse().withStatus(500).withBody("This is an example error")));
    // Invalid token
    server.stubFor(
        get(Constants.SNYK_TOKEN_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + INVALID_TOKEN))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"code\": 401, \"error\": \"Invalid auth token"
                            + " provided\", \"message\": \"Invalid auth"
                            + " token provided\"}")));
    // Too many requests
    server.stubFor(
        get(Constants.SNYK_TOKEN_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + RATE_LIMIT_TOKEN))
            .willReturn(
                aResponse()
                    .withStatus(429)
                    .withBody(
                        "{\"message\": \"The org acme (82be6926-dff6-4c22-a54a-8fb25ed4ee43)"
                            + " has exceeded the rate limit.\""
                            + ", \"error\": \"true\"}")));
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

  protected void stubTpaRequests() {
    // Missing token
    server.stubFor(post(Constants.TPA_ANALYZE_PATH).willReturn(aResponse().withStatus(401)));

    // Invalid token
    server.stubFor(
        post(Constants.TPA_ANALYZE_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + INVALID_TOKEN))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"error\": \"Unauthorized\", \"message\": \"Authentication failed\"}")));

    server.stubFor(
        post(Constants.TPA_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TPA_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("tpa/empty_report.json")));

    server.stubFor(
        post(Constants.TPA_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TPA_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/tpa/maven_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("tpa/maven_report.json")));
    server.stubFor(
        post(Constants.TPA_ANALYZE_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TPA_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, containing(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/tpa/batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("tpa/maven_report.json")));
  }

  protected void stubTpaTokenRequests() {
    // Missing token
    server.stubFor(
        get(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(aResponse().withStatus(401)));

    // Accepted tokens
    server.stubFor(
        get(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("Bearer " + TPA_TOKEN).or(equalTo("Bearer " + OK_TOKEN)))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("tpa/empty_report.json")));

    // Internal Error
    server.stubFor(
        get(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("Bearer " + ERROR_TOKEN))
            .withQueryParam("limit", equalTo("0"))
            .willReturn(aResponse().withStatus(500).withBody("This is an example error")));

    // Invalid token
    server.stubFor(
        get(urlPathEqualTo(Constants.TPA_TOKEN_PATH))
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

  protected void stubSnykRequests() {
    // Missing token
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"code\": 401, \"error\": \"Not authorised\""
                            + ", \"message\": \"Not authorised\"}")));
    // Other requests
    SnykRequestBuilder.SUPPORTED_PURL_TYPES.forEach(this::stubSnykEmptyRequest);
    // Dependency request
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/snyk/maven_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/maven_report.json")));
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/snyk/maven_batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/maven_report.json")));
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/snyk/pypi_small_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/empty_report.json")));
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/snyk/npm_small_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/empty_report.json")));
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/snyk/npm_batch_request.json"), true, false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBodyFile("snyk/empty_report.json")));
    // Internal Error
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + ERROR_TOKEN))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .willReturn(aResponse().withStatus(500).withBody("This is an example error")));
    // Invalid token
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + INVALID_TOKEN))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"code\": 401, \"error\": \"Invalid auth token"
                            + " provided\", \"message\": \"Invalid auth"
                            + " token provided\"}")));
    // Forbidden (i.e. token does not have access to the API)
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + UNAUTH_TOKEN))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .willReturn(
                aResponse()
                    .withStatus(403)
                    .withBody(
                        "{\"message\": \"The org acme (82be6926-dff6-4c22-a54a-8fb25ed4ee43) is not"
                            + " entitled for api access. Please upgrade your plan to access this"
                            + " capability\", \"error\": \"true\"}")));
    // Too many requests
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(Constants.AUTHORIZATION_HEADER, equalTo("token " + RATE_LIMIT_TOKEN))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .willReturn(
                aResponse()
                    .withStatus(429)
                    .withBody(
                        "{\"message\": \"The org acme (82be6926-dff6-4c22-a54a-8fb25ed4ee43)"
                            + " has exceeded the rate limit.\""
                            + ", \"error\": \"true\"}")));
  }

  private void stubSnykEmptyRequest(String provider) {
    // Empty request
    server.stubFor(
        post(Constants.SNYK_DEP_GRAPH_API_PATH)
            .withHeader(
                Constants.AUTHORIZATION_HEADER,
                equalTo("token " + OK_TOKEN).or(equalTo("token " + SNYK_TOKEN)))
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withHeader(Constants.USER_AGENT_HEADER, matching(SNYK_UA_PATTERN))
            .withRequestBody(
                equalToJson(
                    loadFileAsString("__files/snyk/empty_request.json")
                        .replaceAll("__PKG_MANAGER__", provider),
                    true,
                    false))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader(Exchange.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .withBody(
                        loadFileAsString("__files/snyk/empty_report.json")
                            .replaceAll("__PKG_MANAGER__", provider))));
  }

  protected void stubOssToken() {

    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withBody(
                        "{\"code\": 401, \"error\": \"Not authorised\""
                            + ", \"message\": \"Not authorised\"}")));
    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withBasicAuth(OK_USER, OK_TOKEN)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/ossindex/empty_request.json"), true, false))
            .willReturn(aResponse().withStatus(200).withBodyFile("ossindex/empty_report.json")));
    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withBasicAuth(OK_USER, OK_TOKEN)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/ossindex/maven_request.json"), true, false))
            .willReturn(aResponse().withStatus(200).withBodyFile("ossindex/maven_report.json")));
    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withBasicAuth(OK_USER, OK_TOKEN)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .withRequestBody(
                equalToJson(loadFileAsString("__files/ossindex/batch_request.json"), true, false))
            .willReturn(aResponse().withStatus(200).withBodyFile("ossindex/maven_report.json")));
    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withBasicAuth(OK_USER, RATE_LIMIT_TOKEN)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .willReturn(
                aResponse()
                    .withStatus(429)
                    .withBody(
                        "{\"message\": \"The org acme (82be6926-dff6-4c22-a54a-8fb25ed4ee43)"
                            + " has exceeded the rate limit.\""
                            + ", \"error\": \"true\"}")));
    server.stubFor(
        post(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)
            .withBasicAuth(OK_USER, ERROR_TOKEN)
            .withHeader(Exchange.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON))
            .willReturn(aResponse().withStatus(500).withBody("This is an example error")));
  }

  protected void verifyOssRequest(String user, String pass) {
    verifyOssRequest(user, pass, 1);
  }

  protected void verifyOssRequest(String user, String pass, int count) {
    if (user == null || pass == null) {
      server.verify(
          count, postRequestedFor(urlEqualTo(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)));
    } else {
      server.verify(
          count,
          postRequestedFor(urlEqualTo(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH))
              .withBasicAuth(new BasicCredentials(user, pass)));
    }
  }

  protected void verifyOsvRequest() {
    verifyOsvRequest(1);
  }

  protected void verifyOsvRequest(int count) {
    server.verify(count, postRequestedFor(urlEqualTo(Constants.OSV_NVD_PURLS_PATH)));
  }

  protected void verifyNoInteractions() {
    verifyNoInteractionsWithSnyk();
    verifyNoInteractionsWithOSS();
    verifyNoInteractionsWithOsv();
    verifyNoInteractionsWithTpa();
  }

  protected void verifyNoInteractionsWithSnyk() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.SNYK_DEP_GRAPH_API_PATH)));
    server.verify(0, getRequestedFor(urlEqualTo(Constants.SNYK_TOKEN_API_PATH)));
  }

  protected void verifyNoInteractionsWithOSS() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.OSS_INDEX_AUTH_COMPONENT_API_PATH)));
  }

  protected void verifyNoInteractionsWithTrustedContent() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.TRUSTED_CONTENT_PATH)));
  }

  protected void verifyNoInteractionsWithOsv() {
    server.verify(0, postRequestedFor(urlPathEqualTo(Constants.OSV_NVD_PURLS_PATH)));
  }

  protected void verifyNoInteractionsWithTpa() {
    server.verify(0, postRequestedFor(urlEqualTo(Constants.TPA_ANALYZE_PATH)));
  }
}
