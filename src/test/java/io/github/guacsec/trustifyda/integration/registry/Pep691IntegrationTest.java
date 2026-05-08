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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;

public class Pep691IntegrationTest {

  private Pep691Integration integration;
  private Exchange exchange;
  private Message message;

  @BeforeEach
  void setUp() {
    integration = new Pep691Integration();
    exchange = mock(Exchange.class);
    message = mock(Message.class);
    when(exchange.getIn()).thenReturn(message);
  }

  @Test
  void skipWhenRegistryHostEmpty() {
    integration.registryHost = "";
    var report = new AnalysisReport();
    when(message.getBody()).thenReturn(report);

    integration.enrichRecommendations(exchange);
  }

  @Test
  void skipWhenRegistryHostNull() {
    integration.registryHost = null;
    var report = new AnalysisReport();
    when(message.getBody()).thenReturn(report);

    integration.enrichRecommendations(exchange);
  }

  @Test
  void skipWhenBodyNotAnalysisReport() {
    integration.registryHost = "https://registry.example.com";
    when(message.getBody()).thenReturn("not a report");

    integration.enrichRecommendations(exchange);
  }

  @Test
  void proceedWhenNoComponentHashes() {
    integration.registryHost = "https://registry.example.com";
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    when(message.getBody()).thenReturn(report);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(
            DependencyTree.builder()
                .dependencies(Collections.emptyMap())
                .componentHashes(Collections.emptyMap())
                .build());

    integration.enrichRecommendations(exchange);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  @Test
  void skipNonPypiDependencies() {
    integration.registryHost = "https://registry.example.com";
    var report = buildReportWithDep("pkg:npm/lodash@4.17.21");
    when(message.getBody()).thenReturn(report);

    PackageRef npmRef = PackageRef.builder().purl("pkg:npm/lodash@4.17.21").build();
    Map<PackageRef, DirectDependency> deps = new HashMap<>();
    deps.put(npmRef, DirectDependency.builder().ref(npmRef).build());

    Map<String, Map<String, String>> hashes = new HashMap<>();
    hashes.put("pkg:npm/lodash@4.17.21", Map.of("SHA-256", "abc123"));
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(DependencyTree.builder().dependencies(deps).componentHashes(hashes).build());

    integration.enrichRecommendations(exchange);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  @Test
  void proceedWhenNoSha256Hash() {
    integration.registryHost = "https://registry.example.com";
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    when(message.getBody()).thenReturn(report);

    Map<String, Map<String, String>> hashes = new HashMap<>();
    hashes.put("pkg:pypi/requests@2.31.0", Map.of("MD5", "abc123"));
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(
            DependencyTree.builder()
                .dependencies(Collections.emptyMap())
                .componentHashes(hashes)
                .build());

    integration.enrichRecommendations(exchange);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  @Test
  void skipWhenRecommendationAlreadySet() {
    integration.registryHost = "https://registry.example.com";
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var existingRec = PackageRef.builder().purl("pkg:pypi/requests@2.32.0").build();
    getFirstDep(report).recommendation(existingRec);
    when(message.getBody()).thenReturn(report);

    Map<String, Map<String, String>> hashes = new HashMap<>();
    hashes.put("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(
            DependencyTree.builder()
                .dependencies(Collections.emptyMap())
                .componentHashes(hashes)
                .build());

    integration.enrichRecommendations(exchange);

    assertEquals(existingRec, getFirstDep(report).getRecommendation());
  }

  private AnalysisReport buildReportWithPypiDep(String purl) {
    return buildReportWithDep(purl);
  }

  private AnalysisReport buildReportWithDep(String purl) {
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
