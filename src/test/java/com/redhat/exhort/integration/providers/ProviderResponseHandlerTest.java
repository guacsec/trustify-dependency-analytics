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

package com.redhat.exhort.integration.providers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.DependencyReport;
import com.redhat.exhort.api.v4.Issue;
import com.redhat.exhort.api.v4.ProviderReport;
import com.redhat.exhort.api.v4.SeverityUtils;
import com.redhat.exhort.api.v4.Source;
import com.redhat.exhort.api.v4.SourceSummary;
import com.redhat.exhort.api.v4.TransitiveDependencyReport;
import com.redhat.exhort.api.v4.UnscannedDependency;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;
import com.redhat.exhort.model.ProviderResponse;
import com.redhat.exhort.model.trustedcontent.IndexedRecommendation;
import com.redhat.exhort.model.trustedcontent.TrustedContentResponse;
import com.redhat.exhort.model.trustedcontent.Vulnerability;

import jakarta.ws.rs.core.Response;

public class ProviderResponseHandlerTest {

  private static final String NPM_PURL_TYPE = "npm";
  private static final String TEST_PROVIDER = "example";
  private static final String TEST_SOURCE = "test-source";
  private static final TrustedContentResponse EMPTY_TRUSTED_CONTENT_RESPONSE =
      new TrustedContentResponse(null, null);

  @ParameterizedTest
  @MethodSource("getSummaryValues")
  public void testSummary(
      Map<String, List<Issue>> issuesData,
      List<UnscannedDependency> unscanned,
      DependencyTree tree,
      SourceSummary expected)
      throws IOException {

    ProviderResponseHandler handler = new TestResponseHandler();
    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issuesData, null, unscanned),
            tree,
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);
    assertOkStatus(response);
    SourceSummary summary = getValidSource(response).getSummary();

    assertEquals(expected.getDirect(), summary.getDirect());
    assertEquals(expected.getTotal(), summary.getTotal());
    assertEquals(expected.getTransitive(), summary.getTransitive());
    assertEquals(expected.getCritical(), summary.getCritical());
    assertEquals(expected.getHigh(), summary.getHigh());
    assertEquals(expected.getMedium(), summary.getMedium());
    assertEquals(expected.getLow(), summary.getLow());
    assertEquals(expected.getRecommendations(), summary.getRecommendations());
    assertEquals(expected.getRemediations(), summary.getRemediations());
    assertEquals(expected.getDependencies(), summary.getDependencies());
    assertEquals(expected.getUnscanned(), summary.getUnscanned());
  }

  private static Stream<Arguments> getSummaryValues() {
    return Stream.of(
        Arguments.of(
            Map.of("pkg:npm/aa@1", List.of(buildIssue(1, 5f))),
            List.of(
                new UnscannedDependency().ref(new PackageRef("pkg:npm/aaa@1")).reason("aaa"),
                new UnscannedDependency().ref(new PackageRef("pkg:npm/aaaaa@1")).reason("aaaaa")),
            buildTree(),
            new SourceSummary().direct(1).total(1).medium(1).dependencies(1).unscanned(2)),
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1", List.of(buildIssue(1, 3f)),
                "pkg:npm/aaa@1", List.of(buildIssue(2, 4f)),
                "pkg:npm/aba@1", List.of(buildIssue(3, 8f))),
            List.of(
                new UnscannedDependency().ref(new PackageRef("pkg:npm/aab@1")).reason("aab"),
                new UnscannedDependency().ref(new PackageRef("pkg:npm/aabbb@1")).reason("aabbb"),
                new UnscannedDependency().ref(new PackageRef("pkg:npm/aabbc@1")).reason("aabbc")),
            buildTree(),
            new SourceSummary()
                .total(3)
                .direct(1)
                .transitive(2)
                .high(1)
                .medium(1)
                .low(1)
                .dependencies(3)
                .unscanned(3)),
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1", List.of(buildIssue(1, 5f)),
                "pkg:npm/aaa@1", List.of(buildIssue(2, 5f))),
            null,
            buildTreeWithDuplicates(),
            new SourceSummary()
                .total(2)
                .direct(1)
                .transitive(1)
                .medium(2)
                .dependencies(2)
                .unscanned(0)));
  }

  @Test
  public void testFilterDepsWithoutIssues() throws IOException {
    Map<String, List<Issue>> issues = Map.of("pkg:npm/aa@1", List.of(buildIssue(1, 5f)));
    ProviderResponseHandler handler = new TestResponseHandler();
    DependencyTree tree = buildTree();
    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, null), tree, null, EMPTY_TRUSTED_CONTENT_RESPONSE);
    assertOkStatus(response);
    assertEquals(1, response.getSources().size());
    Source report = response.getSources().get(TEST_SOURCE);
    assertEquals(1, report.getDependencies().size());
    assertEquals(1, report.getDependencies().get(0).getIssues().size());
    assertEquals("aa", report.getDependencies().get(0).getRef().name());
  }

  @Test
  public void testFilterTransitiveWithoutIssues() throws IOException {

    Map<String, List<Issue>> issues =
        Map.of(
            "pkg:npm/aa@1", List.of(buildIssue(1, 3f)),
            "pkg:npm/aaa@1", List.of(buildIssue(2, 4f)),
            "pkg:npm/aba@1", List.of(buildIssue(3, 8f)));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);

    assertOkStatus(response);

    // Validate aa has 1 direct and 1 transitive being the transitive the
    // highestVulnerability
    assertEquals(1, response.getSources().size());
    Source source = response.getSources().get(TEST_SOURCE);
    assertEquals(2, source.getDependencies().size());
    DependencyReport report =
        source.getDependencies().stream()
            .filter(r -> "aa".equals(r.getRef().name()))
            .findFirst()
            .get();
    assertEquals(1, report.getIssues().size());
    assertEquals("aa", report.getRef().name());
    assertEquals(4f, report.getHighestVulnerability().getCvssScore());
    assertEquals("ISSUE-002", report.getHighestVulnerability().getId());

    assertEquals(1, report.getTransitive().size());
    TransitiveDependencyReport transitive = report.getTransitive().get(0);
    assertEquals("aaa", transitive.getRef().name());

    // Validate that ab has no issues and one transitive.
    report =
        source.getDependencies().stream()
            .filter(r -> "ab".equals(r.getRef().name()))
            .findFirst()
            .get();
    assertTrue(report.getIssues().isEmpty());
    assertEquals("ab", report.getRef().name());
    assertEquals(8f, report.getHighestVulnerability().getCvssScore());
    assertEquals("ISSUE-003", report.getHighestVulnerability().getId());

    assertEquals(1, report.getTransitive().size());
    transitive = report.getTransitive().get(0);
    assertEquals("aba", transitive.getRef().name());
  }

  @Test
  public void testSorted() throws IOException {
    Map<String, List<Issue>> issues =
        Map.of(
            "pkg:npm/aa@1", List.of(buildIssue(1, 4f)),
            "pkg:npm/aaa@1", List.of(buildIssue(2, 3f)),
            "pkg:npm/aab@1", List.of(buildIssue(3, 1f)),
            "pkg:npm/ab@1", List.of(buildIssue(4, 2f)),
            "pkg:npm/aba@1", List.of(buildIssue(5, 3f)),
            "pkg:npm/abb@1", List.of(buildIssue(6, 9f)),
            "pkg:npm/abc@1", List.of(buildIssue(7, 6f)));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);

    assertOkStatus(response);
    DependencyReport reportHighest = getValidSource(response).getDependencies().get(0);
    assertEquals("ab", reportHighest.getRef().name());

    assertEquals("abb", reportHighest.getTransitive().get(0).getRef().name());
    assertEquals("abc", reportHighest.getTransitive().get(1).getRef().name());
    assertEquals("aba", reportHighest.getTransitive().get(2).getRef().name());

    DependencyReport reportLowest = getValidSource(response).getDependencies().get(1);
    assertEquals("aa", reportLowest.getRef().name());
    assertEquals("aaa", reportLowest.getTransitive().get(0).getRef().name());
    assertEquals("aab", reportLowest.getTransitive().get(1).getRef().name());

    assertEquals("ISSUE-006", reportHighest.getHighestVulnerability().getId());
    assertEquals("ISSUE-001", reportLowest.getHighestVulnerability().getId());
  }

  @Test
  public void testHighestVulnerabilityInDirectDependency() throws IOException {
    Map<String, List<Issue>> issues =
        Map.of("pkg:npm/aa@1", List.of(buildIssue(1, 4f), buildIssue(2, 9f), buildIssue(3, 1f)));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);

    assertOkStatus(response);
    DependencyReport highest = getValidSource(response).getDependencies().get(0);
    assertEquals("ISSUE-002", highest.getHighestVulnerability().getId());
    assertEquals(9f, highest.getHighestVulnerability().getCvssScore());
  }

  @Test
  public void testHighestVulnerabilityInTransitiveDependency() throws IOException {
    Map<String, List<Issue>> issues =
        Map.of(
            "pkg:npm/aa@1", Collections.emptyList(),
            "pkg:npm/aaa@1", List.of(buildIssue(1, 4f), buildIssue(2, 9f), buildIssue(3, 1f)));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);

    assertOkStatus(response);
    DependencyReport highest = getValidSource(response).getDependencies().get(0);
    assertEquals("ISSUE-002", highest.getHighestVulnerability().getId());
    assertEquals(9f, highest.getHighestVulnerability().getCvssScore());
  }

  @Test
  public void testRecommendations() throws IOException {
    PackageRef abRecommendation = new PackageRef("pkg:npm/ab@1-redhat-00001");
    PackageRef acRecommendation = new PackageRef("pkg:npm/ac@1-redhat-00006");
    Map<PackageRef, IndexedRecommendation> recommendations =
        Map.of(
            new PackageRef("pkg:npm/ab@1"),
            new IndexedRecommendation(abRecommendation, Collections.emptyMap()),
            acRecommendation, // recommend the same should be ignored
            new IndexedRecommendation(acRecommendation, Collections.emptyMap()));

    Map<String, List<Issue>> issues = Map.of("pkg:npm/aa@1", List.of(buildIssue(1, 4f)));

    ProviderResponseHandler handler = new TestResponseHandler();

    var report =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            new TrustedContentResponse(recommendations, null));
    Source source = getValidSource(report);

    assertEquals(1, source.getSummary().getRecommendations());
    assertEquals(2, source.getDependencies().size());
    assertTrue(
        source.getDependencies().stream()
            .anyMatch(d -> d.getRef().name().equals("aa") && d.getRecommendation() == null));
    assertTrue(
        source.getDependencies().stream()
            .anyMatch(
                d ->
                    d.getRef().name().equals("ab")
                        && d.getRecommendation().equals(abRecommendation)));
    assertTrue(source.getDependencies().stream().noneMatch(d -> d.getRef().name().equals("ac")));
  }

  @Test
  public void testRecommendationsWithoutIssues() throws IOException {
    PackageRef abRecommendation = new PackageRef("pkg:npm/ab@1-redhat-00001");
    PackageRef acRecommendation = new PackageRef("pkg:npm/ac@1-redhat-00006");
    Map<PackageRef, IndexedRecommendation> recommendations =
        Map.of(
            new PackageRef("pkg:npm/ab@1"),
            new IndexedRecommendation(abRecommendation, Collections.emptyMap()),
            acRecommendation, // recommend the same should be ignored
            new IndexedRecommendation(acRecommendation, Collections.emptyMap()));

    Map<String, List<Issue>> issues = Collections.emptyMap();

    ProviderResponseHandler handler = new TestResponseHandler();

    var report =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            new TrustedContentResponse(recommendations, null));

    assertNotNull(report);
    assertNotNull(report.getSources());
    Source source = report.getSources().get(TEST_PROVIDER);
    assertNotNull(source);

    assertEquals(1, source.getSummary().getRecommendations());
    assertEquals(1, source.getDependencies().size());

    assertTrue(
        source.getDependencies().stream()
            .anyMatch(
                d ->
                    d.getRef().name().equals("ab")
                        && d.getRecommendation().equals(abRecommendation)));
    assertTrue(source.getDependencies().stream().noneMatch(d -> d.getRef().name().equals("aa")));
    assertTrue(source.getDependencies().stream().noneMatch(d -> d.getRef().name().equals("ac")));
  }

  @Test
  public void testRemediations() throws IOException {
    PackageRef abRemediation = new PackageRef("pkg:npm/ab@1-redhat-00008");
    PackageRef aabRemediation = new PackageRef("pkg:npm/aab@1-redhat-00001");
    PackageRef acRemediation = new PackageRef("pkg:npm/ac@1-redhat-00006");

    Map<PackageRef, IndexedRecommendation> recommendations =
        Map.of(
            new PackageRef("pkg:npm/aab@1"),
            new IndexedRecommendation(
                aabRemediation, Map.of("CVE-003", new Vulnerability("cve-003", "Fixed", "test"))),
            new PackageRef("pkg:npm/ab@1"),
            new IndexedRecommendation(
                abRemediation, Map.of("CVE-005", new Vulnerability("cve-005", "Affected", "test"))),
            new PackageRef("pkg:npm/ac@1-redhat-00006"),
            new IndexedRecommendation(
                acRemediation,
                Map.of(
                    "CVE-007",
                    new Vulnerability("cve-007", "Not Affected", "test"),
                    "CVE-008",
                    new Vulnerability("cve-008", null, "test"))));
    Map<String, List<Issue>> issues =
        Map.of(
            "pkg:npm/aa@1", List.of(buildIssue(1, 4f)),
            "pkg:npm/aaa@1", List.of(buildIssue(2, 3f)),
            "pkg:npm/aab@1", List.of(buildIssue(3, 1f), buildIssue(4, 3f)),
            "pkg:npm/ab@1", List.of(buildIssue(5, 2f)),
            "pkg:npm/abb@1", List.of(buildIssue(6, 9f)),
            "pkg:npm/ac@1-redhat-00006", List.of(buildIssue(7, 6f), buildIssue(8, 5f)));
    ProviderResponseHandler handler = new TestResponseHandler();

    var report =
        handler.buildReport(
            new ProviderResponse(issues, null, null),
            buildTree(),
            null,
            new TrustedContentResponse(recommendations, null));
    Source source = getValidSource(report);
    assertEquals(1, source.getSummary().getRecommendations());
    assertEquals(1, source.getSummary().getRemediations());
    assertEquals(3, source.getDependencies().size());

    // ab has an affected vuln so it should not contain the remediation
    var dep =
        source.getDependencies().stream().filter(d -> d.getRef().name().equals("ab")).findFirst();
    assertTrue(dep.isPresent());
    assertEquals(1, dep.get().getIssues().size());
    assertNull(dep.get().getIssues().get(0).getRemediation());

    // aab has a remediation for cve-003 but not for cve-004
    var tdep =
        source.getDependencies().stream()
            .filter(d -> d.getRef().name().equals("aa"))
            .map(DependencyReport::getTransitive)
            .flatMap(List::stream)
            .filter(t -> t.getRef().name().equals("aab"))
            .findFirst();
    assertTrue(tdep.isPresent());
    assertEquals(2, tdep.get().getIssues().size());
    assertNull(tdep.get().getIssues().get(0).getRemediation());
    assertEquals("CVE-004", tdep.get().getIssues().get(0).getCves().get(0));
    assertEquals(
        aabRemediation,
        tdep.get().getIssues().get(1).getRemediation().getTrustedContent().getRef());
    assertEquals("CVE-003", tdep.get().getIssues().get(1).getCves().get(0));

    // ac the provider reports a vulnerability but TC says it's Not Affected
    dep = source.getDependencies().stream().filter(d -> d.getRef().name().equals("ac")).findFirst();
    assertTrue(dep.isPresent());
    assertEquals(2, dep.get().getIssues().size());
    assertEquals("CVE-007", dep.get().getIssues().get(0).getCves().get(0));
    assertEquals("CVE-008", dep.get().getIssues().get(1).getCves().get(0));
    assertNull(dep.get().getIssues().get(0).getRemediation());
  }

  @Test
  void testUnscanned() throws IOException {
    Map<String, List<Issue>> issues = Map.of("pkg:npm/aa@1", List.of(buildIssue(1, 5f)));
    ProviderResponseHandler handler = new TestResponseHandler();
    List<UnscannedDependency> unscanned =
        List.of(
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aab@1")).reason("aab"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aabbb@1")).reason("aabbb"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aabbc@1")).reason("aabbc"));
    DependencyTree tree = buildTree();
    ProviderReport response =
        handler.buildReport(
            new ProviderResponse(issues, null, unscanned),
            tree,
            null,
            EMPTY_TRUSTED_CONTENT_RESPONSE);
    assertOkStatus(response);
    assertEquals(1, response.getSources().size());
    Source report = response.getSources().get(TEST_SOURCE);
    assertEquals(unscanned, report.getUnscanned());
  }

  @Test
  void testUnscannedResponse() {
    var unscanned =
        List.of(
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aa@1")).reason("aa"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aaa@1")).reason("aaa"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/aab@1")).reason("aab"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/ab@1")).reason("ab"),
            new UnscannedDependency().ref(new PackageRef("pkg:npm/abb@1")).reason("abb"));
    var handler = new TestResponseHandler();
    var response = handler.unscannedResponse(unscanned);
    assertNotNull(response);
    assertTrue(response.issues().isEmpty());
    assertNull(response.status());
    assertEquals(unscanned, response.unscanned());
  }

  private void assertOkStatus(ProviderReport response) {
    assertNotNull(response);
    assertNotNull(response.getStatus());

    assertEquals(Response.Status.OK.getStatusCode(), response.getStatus().getCode());
    assertEquals(Response.Status.OK.getReasonPhrase(), response.getStatus().getMessage());
    assertTrue(response.getStatus().getOk());
    assertEquals(TEST_PROVIDER, response.getStatus().getName());
  }

  private Source getValidSource(ProviderReport report) {
    assertNotNull(report);
    assertNotNull(report.getSources());
    Source source = report.getSources().get(TEST_SOURCE);
    assertNotNull(source);
    return source;
  }

  private static DependencyTree buildTree() {
    Map<PackageRef, DirectDependency> direct =
        Map.of(
            PackageRef.builder().name("aa").version("1").pkgManager(NPM_PURL_TYPE).build(),
            DirectDependency.builder()
                .ref(PackageRef.builder().name("aa").version("1").pkgManager(NPM_PURL_TYPE).build())
                .transitive(
                    Set.of(
                        PackageRef.builder()
                            .name("aaa")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build(),
                        PackageRef.builder()
                            .name("aab")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build()))
                .build(),
            PackageRef.builder().name("ab").version("1").pkgManager(NPM_PURL_TYPE).build(),
            DirectDependency.builder()
                .ref(PackageRef.builder().name("ab").version("1").pkgManager(NPM_PURL_TYPE).build())
                .transitive(
                    Set.of(
                        PackageRef.builder()
                            .name("aba")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build(),
                        PackageRef.builder()
                            .name("abb")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build(),
                        PackageRef.builder()
                            .name("abc")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build()))
                .build(),
            PackageRef.builder()
                .name("ac")
                .version("1-redhat-00006")
                .pkgManager(NPM_PURL_TYPE)
                .build(),
            DirectDependency.builder()
                .ref(PackageRef.builder().name("ac").version("1").pkgManager(NPM_PURL_TYPE).build())
                .build());
    return DependencyTree.builder().dependencies(direct).build();
  }

  private static DependencyTree buildTreeWithDuplicates() {
    Map<PackageRef, DirectDependency> direct =
        Map.of(
            PackageRef.builder().name("aa").version("1").pkgManager(NPM_PURL_TYPE).build(),
            DirectDependency.builder()
                .ref(PackageRef.builder().name("aa").version("1").pkgManager(NPM_PURL_TYPE).build())
                .transitive(
                    Set.of(
                        PackageRef.builder()
                            .name("aaa")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build(),
                        PackageRef.builder()
                            .name("aab")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build()))
                .build(),
            PackageRef.builder().name("ab").version("1").pkgManager(NPM_PURL_TYPE).build(),
            DirectDependency.builder()
                .ref(PackageRef.builder().name("ab").version("1").pkgManager(NPM_PURL_TYPE).build())
                .transitive(
                    Set.of(
                        PackageRef.builder()
                            .name("aaa")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build(),
                        PackageRef.builder()
                            .name("abb")
                            .version("1")
                            .pkgManager(NPM_PURL_TYPE)
                            .build()))
                .build());
    return DependencyTree.builder().dependencies(direct).build();
  }

  private static Issue buildIssue(int id, Float score) {
    return new Issue()
        .id(String.format("ISSUE-00%d", id))
        .title(String.format("ISSUE Example 00%d", id))
        .source(TEST_SOURCE)
        .severity(SeverityUtils.fromScore(score))
        .cves(List.of(String.format("CVE-00%d", id)))
        .cvssScore(score);
  }

  private static class TestResponseHandler extends ProviderResponseHandler {

    @Override
    protected String getProviderName() {
      return TEST_PROVIDER;
    }

    @Override
    public ProviderResponse responseToIssues(
        byte[] response, String privateProviders, DependencyTree tree) throws IOException {
      throw new IllegalArgumentException("not implemented");
    }
  }
}
