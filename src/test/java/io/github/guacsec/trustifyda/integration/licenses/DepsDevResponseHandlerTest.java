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

import static io.github.guacsec.trustifyda.api.v5.LicenseInfo.CategoryEnum;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.model.licenses.LicenseSplitResult;
import io.github.guacsec.trustifyda.monitoring.MonitoringProcessor;

class DepsDevResponseHandlerTest {

  private DepsDevResponseHandler handler;
  private MonitoringProcessor monitoringProcessor;

  @BeforeEach
  void setUp() throws IOException {
    handler = new DepsDevResponseHandler();
    handler.mapper = new ObjectMapper();
    handler.licensesFile = "licenses.yaml";
    handler.depsDevHost = "https://api.deps.dev/";
    handler.init();

    monitoringProcessor = mock(MonitoringProcessor.class);
    handler.monitoringProcessor = monitoringProcessor;
  }

  @Test
  void testHandleResponse_withValidData() throws IOException {
    byte[] jsonResponseBytes;
    try (var in =
        getClass().getClassLoader().getResourceAsStream("__files/depsdev/maven_response.json")) {
      jsonResponseBytes = in.readAllBytes();
    }

    Exchange exchange = buildExchange(new String(jsonResponseBytes));
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    assertNotNull(result);
    assertTrue(result.status().getOk());
    assertEquals("deps.dev", result.status().getName());

    // 10 responses in current maven_response.json
    assertEquals(10, result.packages().size());

    // Verify quarkus-jdbc-h2: Apache-2.0 (single license, permissive)
    var quarkusJdbcResult =
        result.packages().get("pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final");
    assertNotNull(quarkusJdbcResult);
    assertEquals(1, quarkusJdbcResult.getEvidence().size());
    assertEquals("Apache-2.0", quarkusJdbcResult.getEvidence().get(0).getExpression());
    assertEquals(CategoryEnum.PERMISSIVE, quarkusJdbcResult.getEvidence().get(0).getCategory());
    assertEquals(1, quarkusJdbcResult.getEvidence().get(0).getIdentifiers().size());

    // Verify jakarta.interceptor-api: non-standard + GPL-2.0-with-classpath-exception (weak
    // copyleft)
    var interceptorResult =
        result.packages().get("pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5");
    assertNotNull(interceptorResult);
    assertEquals(2, interceptorResult.getEvidence().size());
    assertTrue(
        interceptorResult.getEvidence().stream()
            .anyMatch(e -> CategoryEnum.WEAK_COPYLEFT.equals(e.getCategory())));

    // Verify postgresql: BSD-2-Clause (permissive)
    var postgresResult = result.packages().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(postgresResult);
    assertEquals(1, postgresResult.getEvidence().size());
    assertEquals("BSD-2-Clause", postgresResult.getEvidence().get(0).getExpression());
    assertEquals(CategoryEnum.PERMISSIVE, postgresResult.getEvidence().get(0).getCategory());
  }

  @Test
  void testHandleResponse_withEmptyBody() {
    Exchange exchange = buildExchange("");

    RuntimeException exception =
        assertThrows(RuntimeException.class, () -> handler.handleResponse(exchange));
    assertTrue(exception.getMessage().contains("Empty response"));
  }

  @Test
  void testHandleResponse_withNullBody() {
    Exchange exchange = buildExchange(null);

    RuntimeException exception =
        assertThrows(RuntimeException.class, () -> handler.handleResponse(exchange));
    assertTrue(exception.getMessage().contains("Empty response"));
  }

  @Test
  void testAggregateLicenses_withBothResults() {
    var status1 = new ProviderStatus().ok(true).name("deps.dev");
    var status2 = new ProviderStatus().ok(true).name("deps.dev");

    var package1 = new PackageLicenseResult();
    var package2 = new PackageLicenseResult();

    var packages1 = new java.util.HashMap<String, PackageLicenseResult>();
    packages1.put("pkg:npm/a@1.0", package1);
    var packages2 = new java.util.HashMap<String, PackageLicenseResult>();
    packages2.put("pkg:npm/b@1.0", package2);

    var result1 = new LicenseSplitResult(status1, packages1);
    var result2 = new LicenseSplitResult(status2, packages2);

    LicenseSplitResult aggregated = handler.aggregateLicenses(result1, result2);

    assertNotNull(aggregated);
    assertEquals(2, aggregated.packages().size());
    assertTrue(aggregated.status().getOk());
  }

  @Test
  void testAggregateLicenses_withNullOldResult() {
    var status = new ProviderStatus().ok(true).name("deps.dev");
    var result = new LicenseSplitResult(status, Collections.emptyMap());

    LicenseSplitResult aggregated = handler.aggregateLicenses(null, result);

    assertEquals(result, aggregated);
  }

  @Test
  void testAggregateLicenses_withNullNewResult() {
    var status = new ProviderStatus().ok(true).name("deps.dev");
    var result = new LicenseSplitResult(status, Collections.emptyMap());

    LicenseSplitResult aggregated = handler.aggregateLicenses(result, null);

    assertEquals(status, aggregated.status());
  }

  @Test
  void testAggregateLicenses_withFailedStatus() {
    var okStatus = new ProviderStatus().ok(true).name("deps.dev");
    var failedStatus = new ProviderStatus().ok(false).name("deps.dev").message("Error");

    var result1 = new LicenseSplitResult(failedStatus, Collections.emptyMap());
    var result2 = new LicenseSplitResult(okStatus, Collections.emptyMap());

    LicenseSplitResult aggregated = handler.aggregateLicenses(result1, result2);

    // We expect the worst status to be received
    assertFalse(aggregated.status().getOk());
  }

  @Test
  void testBuildResult() {
    var status = new ProviderStatus().ok(true).name("deps.dev");
    var licenseInfo =
        new io.github.guacsec.trustifyda.api.v5.LicenseInfo()
            .identifiers(List.of("MIT"))
            .category(CategoryEnum.PERMISSIVE);
    var packageResult = new PackageLicenseResult().evidence(List.of(licenseInfo));
    var packages = Collections.singletonMap("pkg:npm/test@1.0", packageResult);
    var splitResult = new LicenseSplitResult(status, packages);

    List<LicenseProviderResult> response = handler.toResultList(splitResult);

    assertNotNull(response);
    assertEquals(1, response.size());
    assertEquals(packages, response.get(0).getPackages());
    assertEquals(status, response.get(0).getStatus());
    assertNotNull(response.get(0).getSummary());
  }

  @Test
  void testBuildSummary() throws IOException {
    byte[] jsonResponseBytes;
    try (var in =
        getClass().getClassLoader().getResourceAsStream("__files/depsdev/maven_response.json")) {
      jsonResponseBytes = in.readAllBytes();
    }

    Exchange exchange = buildExchange(new String(jsonResponseBytes));
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    List<LicenseProviderResult> providerResult = handler.toResultList(result);

    var summary = providerResult.get(0).getSummary();
    assertNotNull(summary);
    // maven_response.json: 10 packages, 12 license identifiers (8 Apache-2.0, 1 BSD-2-Clause, 2
    // weak copyleft, 2 unknown)
    assertEquals(10, summary.getConcluded());
    assertEquals(12, summary.getTotal());
    assertEquals(8, summary.getPermissive());
    assertEquals(2, summary.getWeakCopyleft());
    assertEquals(2, summary.getUnknown());
  }

  @Test
  void testProcessResponseError_withException() {
    Exchange exchange = mock(Exchange.class);
    Message message = mock(Message.class);

    when(exchange.getIn()).thenReturn(message);
    when(exchange.getMessage()).thenReturn(message);
    when(exchange.getException()).thenReturn(new RuntimeException("Test error"));

    handler.processResponseError(exchange);

    verify(message).setBody(any(LicenseSplitResult.class));
    verify(monitoringProcessor).processProviderError(eq(exchange), any(), eq("deps.dev"));
  }

  @Test
  void testProcessResponseError_setsFailedStatus() {
    Exchange exchange = mock(Exchange.class);
    Message message = mock(Message.class);

    when(exchange.getIn()).thenReturn(message);
    when(exchange.getMessage()).thenReturn(message);
    when(exchange.getException()).thenReturn(new RuntimeException("Connection timeout"));

    handler.processResponseError(exchange);

    verify(message)
        .setBody(
            argThat(
                result -> {
                  LicenseSplitResult splitResult = (LicenseSplitResult) result;
                  return !splitResult.status().getOk()
                      && splitResult.status().getName().equals("deps.dev")
                      && splitResult.packages().isEmpty();
                }));
  }

  @Test
  void testLicenseCategory_permissive() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "MIT", "spdx": "MIT"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    assertEquals(CategoryEnum.PERMISSIVE, packageResult.getEvidence().get(0).getCategory());
  }

  @Test
  void testLicenseCategory_strongCopyleft() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "GPL-3.0", "spdx": "GPL-3.0"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    assertEquals(CategoryEnum.STRONG_COPYLEFT, packageResult.getEvidence().get(0).getCategory());
  }

  @Test
  void testLicenseCategory_weakCopyleft() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "LGPL-2.1", "spdx": "LGPL-2.1"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    assertEquals(CategoryEnum.WEAK_COPYLEFT, packageResult.getEvidence().get(0).getCategory());
  }

  @Test
  void testLicenseCategory_andExpression() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "MIT AND GPL-3.0", "spdx": "MIT AND GPL-3.0"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    // AND expression should return least permissive (strong copyleft)
    assertEquals(CategoryEnum.STRONG_COPYLEFT, packageResult.getConcluded().getCategory());
  }

  @Test
  void testLicenseCategory_andExpression_multipleLicenses() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {
                "purl": "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5"
              },
              "result": {
                "version": {
                  "licenseDetails": [
                    {
                      "license": "EPL 2.0",
                      "spdx": "non-standard"
                    },
                    {
                      "license": "GPL2 w/ CPE",
                      "spdx": "GPL-2.0-with-classpath-exception"
                    }
                  ]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult =
        result.packages().get("pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5");

    assertEquals(CategoryEnum.WEAK_COPYLEFT, packageResult.getConcluded().getCategory());
  }

  @Test
  void testLicenseCategory_orExpression() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "MIT OR GPL-3.0", "spdx": "MIT OR GPL-3.0"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    // OR expression should return most permissive
    assertEquals(CategoryEnum.PERMISSIVE, packageResult.getEvidence().get(0).getCategory());
  }

  @Test
  void testLicenseCategory_unknown() throws IOException {
    String jsonResponse =
        """
        {
          "responses": [
            {
              "request": {"purl": "pkg:npm/test@1.0"},
              "result": {
                "version": {
                  "licenseDetails": [{"license": "Custom-License", "spdx": "Custom-License"}]
                }
              }
            }
          ]
        }
        """;

    Exchange exchange = buildExchange(jsonResponse);
    handler.handleResponse(exchange);

    LicenseSplitResult result = exchange.getMessage().getBody(LicenseSplitResult.class);
    var packageResult = result.packages().get("pkg:npm/test@1.0");

    assertEquals(CategoryEnum.UNKNOWN, packageResult.getEvidence().get(0).getCategory());
  }

  private Exchange buildExchange(String body) {
    Exchange exchange = mock(Exchange.class);
    Message inMessage = mock(Message.class);
    Message outMessage = mock(Message.class);

    when(exchange.getIn()).thenReturn(inMessage);
    when(exchange.getMessage()).thenReturn(outMessage);
    when(inMessage.getBody(String.class)).thenReturn(body);

    // Capture the body being set and return it when getBody is called
    doAnswer(
            invocation -> {
              Object bodyArg = invocation.getArgument(0);
              when(outMessage.getBody(LicenseSplitResult.class))
                  .thenReturn((LicenseSplitResult) bodyArg);
              return null;
            })
        .when(outMessage)
        .setBody(any(LicenseSplitResult.class));

    return exchange;
  }
}
