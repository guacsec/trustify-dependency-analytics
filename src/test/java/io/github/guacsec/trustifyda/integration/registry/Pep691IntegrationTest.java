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

package io.github.guacsec.trustifyda.integration.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.registry.Pep691Response;

public class Pep691IntegrationTest {

  private Pep691Integration integration;

  @BeforeEach
  void setUp() {
    integration = new Pep691Integration();
  }

  @Test
  void disabledWhenRegistryHostEmpty() {
    integration.registryHost = Optional.of("");
    assertFalse(integration.isEnabled());
  }

  @Test
  void disabledWhenRegistryHostAbsent() {
    integration.registryHost = Optional.empty();
    assertFalse(integration.isEnabled());
  }

  @Test
  void enabledWhenRegistryHostConfigured() {
    integration.registryHost = Optional.of("https://registry.example.com");
    assertTrue(integration.isEnabled());
  }

  @Test
  void enrichWithNoComponentHashes() {
    integration.registryHost = Optional.of("https://registry.example.com");
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var tree =
        DependencyTree.builder()
            .dependencies(Collections.emptyMap())
            .componentHashes(Collections.emptyMap())
            .build();

    integration.enrich(report, tree);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  private AnalysisReport buildReportWithPypiDep(String purl) {
    var dep = new DependencyReport();
    dep.ref(PackageRef.builder().purl(purl).build());

    var source = new Source();
    source.dependencies(new ArrayList<>(List.of(dep)));

    var providerReport = new ProviderReport();
    providerReport.sources(Map.of("source1", source));

    var report = new AnalysisReport();
    report.providers(Map.of("provider1", providerReport));
    return report;
  }

  /** Verifies that registry URLs with special characters are URL-encoded in the PURL qualifier. */
  @Test
  void queryRegistryAndCompareEncodesRepositoryUrl() throws Exception {
    // Given a registry URL with special characters
    String registryUrl = "https://registry.example.com/path?token=abc&flag=true";
    integration.registryHost = Optional.of(registryUrl);
    integration.producerTemplate = mock(ProducerTemplate.class);
    integration.objectMapper = mock(ObjectMapper.class);

    Exchange responseExchange = mock(Exchange.class);
    Message responseMessage = mock(Message.class);
    when(responseExchange.getMessage()).thenReturn(responseMessage);
    when(responseMessage.getHeader(Exchange.HTTP_RESPONSE_CODE, Integer.class)).thenReturn(200);
    when(responseMessage.getBody(String.class)).thenReturn("{}");
    when(integration.producerTemplate.send(anyString(), any(Processor.class)))
        .thenReturn(responseExchange);

    Pep691Response.FileInfo fileInfo =
        new Pep691Response.FileInfo(
            "requests-2.31.0.tar.gz",
            "https://files.example.com/requests-2.31.0.tar.gz",
            Map.of("sha256", "registrysha256"));
    Pep691Response pep691Response = new Pep691Response("requests", List.of(fileInfo));
    when(integration.objectMapper.readValue(anyString(), eq(Pep691Response.class)))
        .thenReturn(pep691Response);

    // When querying the registry with a non-matching hash
    Optional<PackageRef> result =
        integration.queryRegistryAndCompare("pkg:pypi/requests@2.31.0", "sbomsha256");

    // Then the PURL should contain the URL-encoded registry URL
    assertTrue(result.isPresent());
    String expectedEncodedUrl = URLEncoder.encode(registryUrl, StandardCharsets.UTF_8);
    String expectedPurl = "pkg:pypi/requests@2.31.0?repository_url=" + expectedEncodedUrl;
    assertEquals(expectedPurl, result.get().purl().toString());
  }

  private DependencyReport getFirstDep(AnalysisReport report) {
    return report
        .getProviders()
        .values()
        .iterator()
        .next()
        .getSources()
        .values()
        .iterator()
        .next()
        .getDependencies()
        .get(0);
  }
}
