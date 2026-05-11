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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.api.v5.SourceSummary;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;

public class RegistryEnrichmentServiceTest {

  private static final String PKG_PYPI_PREFIX = "pkg:pypi/";

  private RegistryEnrichmentService service;
  private BiFunction<String, String, Optional<PackageRef>> alwaysRecommend;
  private BiFunction<String, String, Optional<PackageRef>> neverRecommend;

  @BeforeEach
  void setUp() {
    service = new RegistryEnrichmentService();

    alwaysRecommend =
        (purl, sha) ->
            Optional.of(
                PackageRef.builder()
                    .purl(purl + "?repository_url=https://registry.example.com")
                    .build());

    neverRecommend = (purl, sha) -> Optional.empty();
  }

  @Test
  void enrichExistingDepsWithMatchingPrefix() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    var dep = getFirstDep(report);
    assertNotNull(dep.getRecommendation());
    assertEquals(
        "pkg:pypi/requests@2.31.0?repository_url=https%3A%2F%2Fregistry.example.com",
        dep.getRecommendation().ref());
  }

  @Test
  void skipDepsWithNonMatchingPrefix() {
    var report = buildReportWithDep("pkg:npm/lodash@4.17.21");
    var tree = buildTree("pkg:npm/lodash@4.17.21", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    var dep = getFirstDep(report);
    assertNull(dep.getRecommendation());
  }

  @Test
  void skipDepsWithExistingRecommendation() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var existingRec = PackageRef.builder().purl("pkg:pypi/requests@2.32.0").build();
    getFirstDep(report).recommendation(existingRec);

    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertEquals(existingRec, getFirstDep(report).getRecommendation());
  }

  @Test
  void enrichUnreportedTreeDeps() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");

    PackageRef requestsRef = PackageRef.builder().purl("pkg:pypi/requests@2.31.0").build();
    PackageRef flaskRef = PackageRef.builder().purl("pkg:pypi/flask@3.0.0").build();
    Map<PackageRef, DirectDependency> deps = new HashMap<>();
    deps.put(requestsRef, DirectDependency.builder().ref(requestsRef).build());
    deps.put(flaskRef, DirectDependency.builder().ref(flaskRef).build());

    var tree =
        DependencyTree.builder().dependencies(deps).componentHashes(Collections.emptyMap()).build();

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    var allDeps =
        report
            .getProviders()
            .values()
            .iterator()
            .next()
            .getSources()
            .values()
            .iterator()
            .next()
            .getDependencies();
    assertEquals(2, allDeps.size());

    var flaskDep = allDeps.stream().filter(d -> d.getRef().ref().contains("flask")).findFirst();
    assertNotNull(flaskDep.orElse(null));
    assertNotNull(flaskDep.get().getRecommendation());
  }

  @Test
  void recountRecommendations() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var source =
        report.getProviders().values().iterator().next().getSources().values().iterator().next();
    source.summary(new SourceSummary().recommendations(0));

    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertEquals(1, source.getSummary().getRecommendations());
  }

  @Test
  void setIssueRemediationAlongsideRecommendation() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var dep = getFirstDep(report);
    dep.issues(new ArrayList<>(List.of(new Issue().id("CVE-2024-35195"))));

    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertNotNull(dep.getRecommendation());
    var issue = dep.getIssues().get(0);
    assertNotNull(issue.getRemediation());
    assertNotNull(issue.getRemediation().getTrustedContent());
    assertEquals(dep.getRecommendation(), issue.getRemediation().getTrustedContent().getRef());
  }

  @Test
  void noEnrichmentWhenRegistryReturnsEmpty() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");
    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, neverRecommend);

    assertNull(getFirstDep(report).getRecommendation());
  }

  @Test
  void handleEmptyProviders() {
    var report = new AnalysisReport();
    var tree = buildTree("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertNotNull(report.getProviders());
    assertEquals(0, report.getProviders().size());
  }

  @Test
  void passHashToRegistryQuery() {
    var report = buildReportWithPypiDep("pkg:pypi/requests@2.31.0");

    Map<String, Map<String, String>> hashes = new HashMap<>();
    hashes.put("pkg:pypi/requests@2.31.0", Map.of("SHA-256", "expected-hash"));

    PackageRef requestsRef = PackageRef.builder().purl("pkg:pypi/requests@2.31.0").build();
    Map<PackageRef, DirectDependency> deps = new HashMap<>();
    deps.put(requestsRef, DirectDependency.builder().ref(requestsRef).build());
    var tree = DependencyTree.builder().dependencies(deps).componentHashes(hashes).build();

    String[] capturedHash = new String[1];
    BiFunction<String, String, Optional<PackageRef>> capturingQuery =
        (purl, sha) -> {
          capturedHash[0] = sha;
          return Optional.empty();
        };

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, capturingQuery);

    assertEquals("expected-hash", capturedHash[0]);
  }

  @Test
  void enrichCreatesSourceWhenProvidersHaveEmptySources() {
    var providerReport = new ProviderReport();
    providerReport.sources(new HashMap<>());
    var report = new AnalysisReport();
    report.providers(new HashMap<>(Map.of("provider1", providerReport)));

    var tree = buildTree("pkg:pypi/amqp@5.3.1", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertFalse(providerReport.getSources().isEmpty());
    var deps = providerReport.getSources().values().iterator().next().getDependencies();
    assertEquals(1, deps.size());
    assertNotNull(deps.get(0).getRecommendation());
  }

  @Test
  void enrichCreatesSourceWhenSourcesIsNull() {
    var providerReport = new ProviderReport();
    var report = new AnalysisReport();
    report.providers(new HashMap<>(Map.of("provider1", providerReport)));

    var tree = buildTree("pkg:pypi/amqp@5.3.1", Map.of("SHA-256", "abc123"));

    service.enrichReport(report, tree, PKG_PYPI_PREFIX, alwaysRecommend);

    assertNotNull(providerReport.getSources());
    assertFalse(providerReport.getSources().isEmpty());

    var deps = providerReport.getSources().values().iterator().next().getDependencies();
    assertEquals(1, deps.size());
    assertNotNull(deps.get(0).getRecommendation());
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

  private DependencyTree buildTree(String purl, Map<String, String> hashMap) {
    PackageRef ref = PackageRef.builder().purl(purl).build();
    Map<PackageRef, DirectDependency> deps = new HashMap<>();
    deps.put(ref, DirectDependency.builder().ref(ref).build());

    Map<String, Map<String, String>> hashes = new HashMap<>();
    hashes.put(purl, new HashMap<>(hashMap));

    return DependencyTree.builder().dependencies(deps).componentHashes(hashes).build();
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
