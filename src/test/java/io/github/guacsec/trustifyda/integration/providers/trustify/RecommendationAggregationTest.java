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

package io.github.guacsec.trustifyda.integration.providers.trustify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.RemediationTrustedContent;
import io.github.guacsec.trustifyda.api.v5.SeverityUtils;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;
import io.github.guacsec.trustifyda.model.trustify.Vulnerability;

public class RecommendationAggregationTest {

  private final RecommendationAggregation aggregation = new RecommendationAggregation();

  private record TestCase(
      String name, Object oldMessage, Object newMessage, Consumer<ProviderResponse> verifier) {}

  static Stream<Arguments> provideTestCases() {
    return Stream.of(
        // ProviderResponse in oldExchange, recommendations in newExchange, no issues
        Arguments.of(
            "ProviderResponseInOldExchange_RecommendationsInNewExchange_NoIssues",
            new TestCase(
                "ProviderResponseInOldExchange_RecommendationsInNewExchange_NoIssues",
                new ProviderResponse(new HashMap<>(), null),
                createRecommendations(
                    "pkg:npm/package1@1.0.0", "pkg:npm/package1@2.0.0", Collections.emptyMap()),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  assertTrue(result.pkgItems().containsKey("pkg:npm/package1@1.0.0"));
                  PackageItem item = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(item.recommendation());
                  assertTrue(item.issues().isEmpty());
                })),

        // ProviderResponse in newExchange, recommendations in oldExchange, no issues
        Arguments.of(
            "ProviderResponseInNewExchange_RecommendationsInOldExchange_NoIssues",
            new TestCase(
                "ProviderResponseInNewExchange_RecommendationsInOldExchange_NoIssues",
                createRecommendations(
                    "pkg:npm/package1@1.0.0", "pkg:npm/package1@2.0.0", Collections.emptyMap()),
                new ProviderResponse(new HashMap<>(), null),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  assertTrue(result.pkgItems().containsKey("pkg:npm/package1@1.0.0"));
                  PackageItem item = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(item.recommendation());
                  assertTrue(item.issues().isEmpty());
                })),

        // Issues but no recommendations
        Arguments.of(
            "WithIssuesButNoRecommendations",
            new TestCase(
                "WithIssuesButNoRecommendations",
                createProviderResponseWithIssues(List.of(createIssue("CVE-001", "Issue 1", 5.0f))),
                null,
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  PackageItem resultItem = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(resultItem);
                  assertEquals(1, resultItem.issues().size());
                  assertNull(resultItem.recommendation());
                })),

        // Recommendations but no issues
        Arguments.of(
            "WithRecommendationsButNoIssues",
            new TestCase(
                "WithRecommendationsButNoIssues",
                new ProviderResponse(new HashMap<>(), null),
                createRecommendations(
                    "pkg:npm/package1@1.0.0",
                    "pkg:npm/package1@2.0.0",
                    Map.of(
                        "CVE-001", new Vulnerability("CVE-001", "Fixed", "Fixed justification"))),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  PackageItem resultItem = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(resultItem);
                  assertTrue(resultItem.issues().isEmpty());
                  assertNotNull(resultItem.recommendation());
                  assertEquals(
                      "pkg:npm/package1@2.0.0", resultItem.recommendation().packageName().ref());
                })),

        // Issues and recommendations, but no matching vulnerabilities
        Arguments.of(
            "WithIssuesAndRecommendations_NoMatchingVulnerabilities",
            new TestCase(
                "WithIssuesAndRecommendations_NoMatchingVulnerabilities",
                createProviderResponseWithIssues(List.of(createIssue("CVE-001", "Issue 1", 5.0f))),
                createRecommendations(
                    "pkg:npm/package1@1.0.0",
                    "pkg:npm/package1@2.0.0",
                    Map.of(
                        "CVE-002", new Vulnerability("CVE-002", "Fixed", "Fixed justification"))),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  PackageItem resultItem = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(resultItem);
                  assertEquals(1, resultItem.issues().size());
                  assertNull(resultItem.issues().get(0).getRemediation());
                  assertNotNull(resultItem.recommendation());
                })),

        // Issues and recommendations with matching vulnerabilities (remediations)
        Arguments.of(
            "WithIssuesAndRecommendations_WithRemediations",
            new TestCase(
                "WithIssuesAndRecommendations_WithRemediations",
                createProviderResponseWithIssues(
                    List.of(
                        createIssue("CVE-001", "Issue 1", 5.0f),
                        createIssue("CVE-002", "Issue 2", 7.0f))),
                createRecommendations(
                    "pkg:npm/package1@1.0.0",
                    "pkg:npm/package1@2.0.0",
                    Map.of(
                        "CVE-001",
                        new Vulnerability("CVE-001", "Fixed", "Fixed justification"),
                        "CVE-002",
                        new Vulnerability("CVE-002", "NotAffected", "Not affected"))),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  PackageItem resultItem = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(resultItem);
                  assertEquals(2, resultItem.issues().size());

                  // CVE-001 should have remediation
                  Issue issue1Result =
                      resultItem.issues().stream()
                          .filter(i -> "CVE-001".equals(i.getId()))
                          .findFirst()
                          .orElseThrow();
                  var remediation1 = issue1Result.getRemediation();
                  assertNotNull(remediation1);
                  RemediationTrustedContent tcRemediation = remediation1.getTrustedContent();
                  assertNotNull(tcRemediation);
                  var ref = tcRemediation.getRef();
                  assertNotNull(ref);
                  assertEquals("pkg:npm/package1@2.0.0", ref.ref());
                  assertEquals("Fixed", tcRemediation.getStatus());
                  assertEquals("Fixed justification", tcRemediation.getJustification());

                  // CVE-002 should have remediation (even though status is "NotAffected")
                  Issue issue2Result =
                      resultItem.issues().stream()
                          .filter(i -> "CVE-002".equals(i.getId()))
                          .findFirst()
                          .orElseThrow();
                  var remediation2 = issue2Result.getRemediation();
                  assertNotNull(remediation2);
                  RemediationTrustedContent tcRemediation2 = remediation2.getTrustedContent();
                  assertNotNull(tcRemediation2);
                  assertEquals("NotAffected", tcRemediation2.getStatus());

                  assertNotNull(resultItem.recommendation());
                })),

        // Multiple packages
        Arguments.of(
            "WithMultiplePackages",
            new TestCase(
                "WithMultiplePackages",
                createProviderResponseWithMultiplePackages(),
                createMultipleRecommendations(),
                result -> {
                  assertEquals(3, result.pkgItems().size());

                  // Package1: has issue with remediation
                  PackageItem item1Result = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(item1Result);
                  assertEquals(1, item1Result.issues().size());
                  assertNotNull(item1Result.issues().get(0).getRemediation());
                  assertNotNull(item1Result.recommendation());

                  // Package2: has issue without remediation (CVE doesn't match)
                  PackageItem item2Result = result.pkgItems().get("pkg:npm/package2@2.0.0");
                  assertNotNull(item2Result);
                  assertEquals(1, item2Result.issues().size());
                  assertNull(item2Result.issues().get(0).getRemediation());
                  assertNotNull(item2Result.recommendation());

                  // Package3: no issues, only recommendation
                  PackageItem item3Result = result.pkgItems().get("pkg:npm/package3@3.0.0");
                  assertNotNull(item3Result);
                  assertTrue(item3Result.issues().isEmpty());
                  assertNotNull(item3Result.recommendation());
                })),

        // Null pkgItems
        Arguments.of(
            "WithNullPkgItems",
            new TestCase(
                "WithNullPkgItems",
                new ProviderResponse(null, null),
                createRecommendations(
                    "pkg:npm/package1@1.0.0", "pkg:npm/package1@2.0.0", Collections.emptyMap()),
                result -> {
                  assertNotNull(result.pkgItems());
                  assertEquals(1, result.pkgItems().size());
                })),

        // Empty recommendations
        Arguments.of(
            "WithEmptyRecommendations",
            new TestCase(
                "WithEmptyRecommendations",
                createProviderResponseWithIssues(List.of(createIssue("CVE-001", "Issue 1", 5.0f))),
                Collections.emptyMap(),
                result -> {
                  assertEquals(1, result.pkgItems().size());
                  PackageItem resultItem = result.pkgItems().get("pkg:npm/package1@1.0.0");
                  assertNotNull(resultItem);
                  assertEquals(1, resultItem.issues().size());
                  assertNull(resultItem.recommendation());
                })));
  }

  private static Map<PackageRef, IndexedRecommendation> createRecommendations(
      String packageRef, String recommendedPackage, Map<String, Vulnerability> vulnerabilities) {
    Map<PackageRef, IndexedRecommendation> recommendations = new HashMap<>();
    PackageRef recPkgRef = new PackageRef(packageRef);
    IndexedRecommendation recommendation =
        new IndexedRecommendation(new PackageRef(recommendedPackage), vulnerabilities);
    recommendations.put(recPkgRef, recommendation);
    return recommendations;
  }

  private static Map<PackageRef, IndexedRecommendation> createMultipleRecommendations() {
    Map<PackageRef, IndexedRecommendation> recommendations = new HashMap<>();
    // Recommendation for package1 with matching vulnerability
    PackageRef recPkgRef1 = new PackageRef("pkg:npm/package1@1.0.0");
    Map<String, Vulnerability> vulnerabilities1 = new HashMap<>();
    vulnerabilities1.put("CVE-001", new Vulnerability("CVE-001", "Fixed", "Fixed justification"));
    IndexedRecommendation recommendation1 =
        new IndexedRecommendation(new PackageRef("pkg:npm/package1@2.0.0"), vulnerabilities1);
    recommendations.put(recPkgRef1, recommendation1);

    // Recommendation for package2 without matching vulnerability
    PackageRef recPkgRef2 = new PackageRef("pkg:npm/package2@2.0.0");
    Map<String, Vulnerability> vulnerabilities2 = new HashMap<>();
    vulnerabilities2.put("CVE-003", new Vulnerability("CVE-003", "Fixed", "Fixed justification"));
    IndexedRecommendation recommendation2 =
        new IndexedRecommendation(new PackageRef("pkg:npm/package2@3.0.0"), vulnerabilities2);
    recommendations.put(recPkgRef2, recommendation2);

    // Recommendation for package3 (no issues)
    PackageRef recPkgRef3 = new PackageRef("pkg:npm/package3@3.0.0");
    IndexedRecommendation recommendation3 =
        new IndexedRecommendation(new PackageRef("pkg:npm/package3@4.0.0"), Collections.emptyMap());
    recommendations.put(recPkgRef3, recommendation3);
    return recommendations;
  }

  private static ProviderResponse createProviderResponseWithIssues(List<Issue> issues) {
    Map<String, PackageItem> pkgItems = new HashMap<>();
    PackageItem item1 = new PackageItem("pkg:npm/package1@1.0.0", null, issues);
    pkgItems.put("pkg:npm/package1@1.0.0", item1);
    return new ProviderResponse(pkgItems, null);
  }

  private static ProviderResponse createProviderResponseWithMultiplePackages() {
    Map<String, PackageItem> pkgItems = new HashMap<>();
    Issue issue1 = createIssue("CVE-001", "Issue 1", 5.0f);
    PackageItem item1 = new PackageItem("pkg:npm/package1@1.0.0", null, List.of(issue1));
    pkgItems.put("pkg:npm/package1@1.0.0", item1);

    Issue issue2 = createIssue("CVE-002", "Issue 2", 7.0f);
    PackageItem item2 = new PackageItem("pkg:npm/package2@2.0.0", null, List.of(issue2));
    pkgItems.put("pkg:npm/package2@2.0.0", item2);

    return new ProviderResponse(pkgItems, null);
  }

  private static Issue createIssue(String id, String title, float cvssScore) {
    Issue issue = new Issue().id(id).title(title).cvssScore(cvssScore);
    issue.setSeverity(SeverityUtils.fromScore(cvssScore));
    return issue;
  }

  @Test
  void testWithNullOldExchange() {
    Exchange newExchange = mock(Exchange.class);
    Exchange result = aggregation.aggregate(null, newExchange);
    assertEquals(newExchange, result);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("provideTestCases")
  void testAggregation(String name, TestCase testCase) {
    Exchange oldExchange = mock(Exchange.class);
    Exchange newExchange = mock(Exchange.class);
    Message oldMessage = createMessageWithBodyStorage();
    Message newMessage = mock(Message.class);

    // Setup messages with the provided objects
    if (testCase.oldMessage != null) {
      oldMessage.setBody(testCase.oldMessage);
    }
    when(oldExchange.getIn()).thenReturn(oldMessage);
    when(newExchange.getIn()).thenReturn(newMessage);
    when(newMessage.getBody()).thenReturn(testCase.newMessage);

    Exchange result = aggregation.aggregate(oldExchange, newExchange);

    assertNotNull(result);
    ProviderResponse resultResponse = result.getIn().getBody(ProviderResponse.class);
    assertNotNull(resultResponse);
    testCase.verifier().accept(resultResponse);
  }

  /** Creates a mock Message that actually stores and retrieves the body. */
  @SuppressWarnings("unchecked")
  private Message createMessageWithBodyStorage() {
    Message message = mock(Message.class);
    Object[] bodyStorage = new Object[1];

    doAnswer(
            invocation -> {
              bodyStorage[0] = invocation.getArgument(0);
              return null;
            })
        .when(message)
        .setBody(any());

    doAnswer(
            invocation -> {
              Class<?> type = (Class<?>) invocation.getArgument(0);
              Object body = bodyStorage[0];
              if (body != null && type.isInstance(body)) {
                return type.cast(body);
              }
              return body;
            })
        .when(message)
        .getBody(any(Class.class));

    when(message.getBody()).thenAnswer(invocation -> bodyStorage[0]);

    return message;
  }
}
