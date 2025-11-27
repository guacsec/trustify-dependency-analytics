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

package io.github.guacsec.trustifyda.integration.providers;

import static io.github.guacsec.trustifyda.model.trustify.Vulnerability.JustificationEnum.NotProvided;
import static io.github.guacsec.trustifyda.model.trustify.Vulnerability.StatusEnum.Fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.DependencyReport;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.ProviderStatus;
import io.github.guacsec.trustifyda.api.v5.Remediation;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.api.v5.SeverityUtils;
import io.github.guacsec.trustifyda.api.v5.Source;
import io.github.guacsec.trustifyda.api.v5.SourceSummary;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.Recommendation;
import io.github.guacsec.trustifyda.model.trustify.Vulnerability;

public class ProviderResponseHandlerTest {

  private static final String NPM_PURL_TYPE = "npm";
  private static final String TEST_PROVIDER = "example";
  private static final String TEST_SOURCE = "test-source";

  @ParameterizedTest
  @MethodSource("getSummaryValues")
  public void testSummary(
      Map<String, PackageItem> data, DependencyTree tree, SourceSummary expected, String sourceName)
      throws IOException {

    ProviderResponseHandler handler = new TestResponseHandler();
    ProviderReport response =
        handler.buildReport(
            Mockito.mock(Exchange.class), new ProviderResponse(data, new ProviderStatus()), tree);
    SourceSummary summary = getValidSource(response, sourceName).getSummary();

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

    assertEquals(expected.getUnscanned(), response.getStatus().getWarnings().size());
  }

  private static Stream<Arguments> getSummaryValues() {
    return Stream.of(
        // Case 1: 0 issues 2 recommendations
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1",
                    new PackageItem(
                        "pkg:npm/aa@1",
                        buildRecommendation("pkg:npm/aa@2", Collections.emptyMap()),
                        Collections.emptyList(),
                        Collections.emptyList()),
                "pkg:npm/ab@1",
                    new PackageItem(
                        "pkg:npm/ab@1",
                        buildRecommendation("pkg:npm/ab@2", Collections.emptyMap()),
                        Collections.emptyList(),
                        Collections.emptyList())),
            tree().direct("aa").direct("ab").build(),
            new SourceSummary().direct(0).total(0).dependencies(0).recommendations(2),
            TEST_PROVIDER),
        // Case 2: 2 issues 0 recommendations 3 unscanned
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1",
                new PackageItem(
                    "pkg:npm/aa@1", null, List.of(buildIssue(1, 5f)), Collections.emptyList()),
                "pkg:npm/ab@1",
                new PackageItem(
                    "pkg:npm/ab@1", null, List.of(buildIssue(2, 8f)), Collections.emptyList()),
                "pkg:npm/aaa@1",
                new PackageItem(
                    "pkg:npm/aaa@1", null, List.of(buildIssue(3, 4f)), Collections.emptyList()),
                "pkg:npm/aba@1",
                new PackageItem(
                    "pkg:npm/aba@1", null, List.of(buildIssue(4, 7f)), Collections.emptyList()),
                "pkg:npm/abc@1",
                new PackageItem(
                    "pkg:npm/abc",
                    null,
                    Collections.emptyList(),
                    List.of("missing version component")),
                "pkg:npm/abd@1",
                new PackageItem(
                    "pkg:npm/abd",
                    null,
                    Collections.emptyList(),
                    List.of("missing version component")),
                "pkg:npm/ac@1",
                new PackageItem(
                    "pkg:npm/ac",
                    null,
                    Collections.emptyList(),
                    List.of("missing version component"))),
            tree()
                .direct("aa")
                .withTransitive("aaa")
                .direct("ab")
                .withTransitive("aab", "abc", "abd")
                .direct("ac")
                .build(),
            new SourceSummary()
                .direct(2)
                .transitive(2)
                .total(4)
                .high(2)
                .medium(2)
                .dependencies(4)
                .unscanned(3),
            TEST_SOURCE),
        // Case 3: 2 issues with 1 remediation and 1 recommendation
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1",
                    new PackageItem(
                        "pkg:npm/aa@1",
                        buildRecommendation("pkg:npm/aa@2", Map.of("ISSUE-001", "Fixed")),
                        List.of(buildIssueWithTcRemediation(1, 5f, "pkg:npm/aa@2-redhat-00001")),
                        Collections.emptyList()), // Issue with remediation (ID
                // matches)
                "pkg:npm/ab@1",
                    new PackageItem(
                        "pkg:npm/ab@1",
                        buildRecommendation("pkg:npm/ab@2", Collections.emptyMap()),
                        Collections.emptyList(),
                        Collections.emptyList())), // Recommendation only
            tree().direct("aa").direct("ab").build(),
            new SourceSummary()
                .direct(1)
                .total(1)
                .medium(1)
                .dependencies(1)
                .recommendations(2)
                .remediations(1),
            TEST_SOURCE),
        // Case 4: 2 direct issues with 4 transitive
        Arguments.of(
            Map.of(
                "pkg:npm/aa@1",
                    new PackageItem(
                        "pkg:npm/aa@1", null, List.of(buildIssue(1, 5f)), Collections.emptyList()),
                "pkg:npm/ab@1",
                    new PackageItem(
                        "pkg:npm/ab@1", null, List.of(buildIssue(2, 7f)), Collections.emptyList()),
                "pkg:npm/aaa@1",
                    new PackageItem(
                        "pkg:npm/aaa@1", null, List.of(buildIssue(3, 4f)), Collections.emptyList()),
                "pkg:npm/aab@1",
                    new PackageItem(
                        "pkg:npm/aab@1", null, List.of(buildIssue(4, 6f)), Collections.emptyList()),
                "pkg:npm/aba@1",
                    new PackageItem(
                        "pkg:npm/aba@1", null, List.of(buildIssue(5, 3f)), Collections.emptyList()),
                "pkg:npm/abb@1",
                    new PackageItem(
                        "pkg:npm/abb@1",
                        null,
                        List.of(buildIssue(6, 8f)),
                        Collections.emptyList())),
            tree()
                .direct("aa")
                .withTransitive("aaa", "aab")
                .direct("ab")
                .withTransitive("aba", "abb")
                .build(),
            new SourceSummary()
                .direct(2)
                .transitive(4)
                .total(6)
                .high(2)
                .medium(3)
                .low(1)
                .dependencies(6),
            TEST_SOURCE),
        // Case 5: 0 direct issues, 2 transitive
        Arguments.of(
            Map.of(
                "pkg:npm/aaa@1",
                    new PackageItem(
                        "pkg:npm/aaa@1", null, List.of(buildIssue(1, 5f)), Collections.emptyList()),
                "pkg:npm/aab@1",
                    new PackageItem(
                        "pkg:npm/aab@1",
                        null,
                        List.of(buildIssue(2, 7f)),
                        Collections.emptyList())),
            tree().direct("aa").withTransitive("aaa").direct("ab").withTransitive("aab").build(),
            new SourceSummary().direct(0).transitive(2).total(2).high(1).medium(1).dependencies(2),
            TEST_SOURCE));
  }

  @Test
  public void testSorted() throws IOException {
    Map<String, PackageItem> data =
        Map.of(
            "pkg:npm/aa@1",
                new PackageItem(
                    "pkg:npm/aa@1", null, List.of(buildIssue(1, 4f)), Collections.emptyList()),
            "pkg:npm/aaa@1",
                new PackageItem(
                    "pkg:npm/aaa@1", null, List.of(buildIssue(2, 3f)), Collections.emptyList()),
            "pkg:npm/aab@1",
                new PackageItem(
                    "pkg:npm/aab@1", null, List.of(buildIssue(3, 1f)), Collections.emptyList()),
            "pkg:npm/ab@1",
                new PackageItem(
                    "pkg:npm/ab@1", null, List.of(buildIssue(4, 2f)), Collections.emptyList()),
            "pkg:npm/aba@1",
                new PackageItem(
                    "pkg:npm/aba@1", null, List.of(buildIssue(5, 3f)), Collections.emptyList()),
            "pkg:npm/abb@1",
                new PackageItem(
                    "pkg:npm/abb@1", null, List.of(buildIssue(6, 9f)), Collections.emptyList()),
            "pkg:npm/abc@1",
                new PackageItem(
                    "pkg:npm/abc@1", null, List.of(buildIssue(7, 6f)), Collections.emptyList()));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            Mockito.mock(Exchange.class), new ProviderResponse(data, null), buildTree());

    DependencyReport reportHighest = getValidSource(response, TEST_SOURCE).getDependencies().get(0);
    assertEquals("ab", reportHighest.getRef().name());

    assertEquals("abb", reportHighest.getTransitive().get(0).getRef().name());
    assertEquals("abc", reportHighest.getTransitive().get(1).getRef().name());
    assertEquals("aba", reportHighest.getTransitive().get(2).getRef().name());

    DependencyReport reportLowest = getValidSource(response, TEST_SOURCE).getDependencies().get(1);
    assertEquals("aa", reportLowest.getRef().name());
    assertEquals("aaa", reportLowest.getTransitive().get(0).getRef().name());
    assertEquals("aab", reportLowest.getTransitive().get(1).getRef().name());

    assertEquals("ISSUE-006", reportHighest.getHighestVulnerability().getId());
    assertEquals("ISSUE-001", reportLowest.getHighestVulnerability().getId());
  }

  @Test
  public void testHighestVulnerabilityInDirectDependency() throws IOException {
    Map<String, PackageItem> data =
        Map.of(
            "pkg:npm/aa@1",
            new PackageItem(
                "pkg:npm/aa@1",
                null,
                List.of(buildIssue(1, 4f), buildIssue(2, 9f), buildIssue(3, 1f)),
                Collections.emptyList()));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            Mockito.mock(Exchange.class), new ProviderResponse(data, null), buildTree());

    DependencyReport highest = getValidSource(response, TEST_SOURCE).getDependencies().get(0);
    assertEquals("ISSUE-002", highest.getHighestVulnerability().getId());
    assertEquals(9f, highest.getHighestVulnerability().getCvssScore());
  }

  @Test
  public void testHighestVulnerabilityInTransitiveDependency() throws IOException {
    Map<String, PackageItem> data =
        Map.of(
            "pkg:npm/aa@1",
                new PackageItem(
                    "pkg:npm/aa@1", null, Collections.emptyList(), Collections.emptyList()),
            "pkg:npm/aaa@1",
                new PackageItem(
                    "pkg:npm/aaa@1",
                    null,
                    List.of(buildIssue(1, 4f), buildIssue(2, 9f), buildIssue(3, 1f)),
                    Collections.emptyList()));
    ProviderResponseHandler handler = new TestResponseHandler();

    ProviderReport response =
        handler.buildReport(
            Mockito.mock(Exchange.class), new ProviderResponse(data, null), buildTree());

    DependencyReport highest = getValidSource(response, TEST_SOURCE).getDependencies().get(0);
    assertEquals("ISSUE-002", highest.getHighestVulnerability().getId());
    assertEquals(9f, highest.getHighestVulnerability().getCvssScore());
  }

  private Source getValidSource(ProviderReport report, String sourceName) {
    assertNotNull(report);
    assertNotNull(report.getSources());
    Source source = report.getSources().get(sourceName);
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

  private static DependencyTreeBuilder tree() {
    return new DependencyTreeBuilder();
  }

  private static class DependencyTreeBuilder {
    private final Map<PackageRef, DirectDependency> dependencies = new HashMap<>();
    private PackageRef currentDirect;
    private Set<PackageRef> currentTransitive = new HashSet<>();

    DependencyTreeBuilder direct(String name) {
      return direct(name, "1");
    }

    DependencyTreeBuilder direct(String name, String version) {
      // Save previous direct dependency if exists
      if (currentDirect != null) {
        dependencies.put(
            currentDirect,
            DirectDependency.builder()
                .ref(currentDirect)
                .transitive(
                    currentTransitive.isEmpty()
                        ? Collections.emptySet()
                        : Set.copyOf(currentTransitive))
                .build());
      }
      // Start new direct dependency
      currentDirect =
          PackageRef.builder().name(name).version(version).pkgManager(NPM_PURL_TYPE).build();
      currentTransitive = new HashSet<>();
      return this;
    }

    DependencyTreeBuilder withTransitive(String... names) {
      if (currentDirect == null) {
        throw new IllegalStateException("Must call direct() before withTransitive()");
      }
      for (String name : names) {
        currentTransitive.add(
            PackageRef.builder().name(name).version("1").pkgManager(NPM_PURL_TYPE).build());
      }
      return this;
    }

    DependencyTree build() {
      // Save last direct dependency
      if (currentDirect != null) {
        dependencies.put(
            currentDirect,
            DirectDependency.builder()
                .ref(currentDirect)
                .transitive(
                    currentTransitive.isEmpty()
                        ? Collections.emptySet()
                        : Set.copyOf(currentTransitive))
                .build());
      }
      return DependencyTree.builder().dependencies(dependencies).build();
    }
  }

  /**
   * @param ref - the recommendation reference
   * @param cves - the vulnerabilities map CVE -> Status
   * @return the tc recommendation
   */
  private static Recommendation buildRecommendation(String ref, Map<String, String> cves) {
    return new Recommendation(
        new PackageRef(ref),
        cves.entrySet().stream()
            .map(e -> new Vulnerability(e.getKey(), Fixed, NotProvided))
            .toList());
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

  private static Issue buildIssueWithTcRemediation(int id, Float score, String remediation) {
    var r = new Remediation();
    r.trustedContent(new RemediationTrustedContent().ref(new PackageRef(remediation)));
    return new Issue()
        .id(String.format("ISSUE-00%d", id))
        .title(String.format("ISSUE Example 00%d", id))
        .source(TEST_SOURCE)
        .severity(SeverityUtils.fromScore(score))
        .cves(List.of(String.format("CVE-00%d", id)))
        .cvssScore(score)
        .remediation(r);
  }

  private static class TestResponseHandler extends ProviderResponseHandler {

    @Override
    protected String getProviderName(Exchange exchange) {
      return TEST_PROVIDER;
    }

    @Override
    public ProviderResponse responseToIssues(Exchange exchange) throws IOException {
      throw new IllegalArgumentException("not implemented");
    }
  }

  public static Exchange buildExchange(byte[] response, DependencyTree tree) {
    var exchange = mock(Exchange.class);
    when(exchange.getIn()).thenReturn(mock(Message.class));
    when(exchange.getIn().getBody(byte[].class)).thenReturn(response);
    when(exchange.getProperty(Constants.DEPENDENCY_TREE_PROPERTY, DependencyTree.class))
        .thenReturn(tree);
    return exchange;
  }
}
