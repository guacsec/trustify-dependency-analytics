/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package com.redhat.exhort.integration.providers.tpa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.api.v4.Issue;
import com.redhat.exhort.api.v4.Severity;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;
import com.redhat.exhort.model.ProviderResponse;

public class TpaResponseHandlerTest {

  private TpaResponseHandler handler;
  private DependencyTree dependencyTree;

  @BeforeEach
  void setUp() {
    handler = new TpaResponseHandler();
    handler.mapper = new ObjectMapper();

    // Build a simple dependency tree for testing
    var packageRef = new PackageRef("pkg:maven/org.postgresql/postgresql@42.5.0");
    var directDep = new DirectDependency(packageRef, Collections.emptySet());
    var dependencies = Collections.singletonMap(packageRef, directDep);
    dependencyTree = new DependencyTree(dependencies);
  }

  @Test
  void testResponseToIssuesWithValidData() throws IOException {
    // Create test JSON that matches the expected structure
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "SQL Injection vulnerability in PostgreSQL JDBC Driver",
          "description": "The PostgreSQL JDBC driver contains a flaw that allows SQL injection attacks.",
          "status": {
            "affected": [
              {
                "id": "RHSA-2024:1999",
                "title": "Red Hat Security Advisory: postgresql-jdbc security update",
                "source": "Red Hat Product Security",
                "scores": [
                  {
                    "type": "3.1",
                    "value": 9.8,
                    "severity": "critical"
                  },
                  {
                    "type": "2",
                    "value": 8.5,
                    "severity": "high"
                  }
                ],
                "ranges": [
                  {
                    "events": [
                      {
                        "fixed": "42.5.5"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    assertNotNull(result.issues());
    assertEquals(1, result.issues().size());

    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(issues);
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertEquals("CVE-2024-1597", issue.getId());
    assertEquals("SQL Injection vulnerability in PostgreSQL JDBC Driver", issue.getTitle());
    assertEquals(9.8f, issue.getCvssScore());
    assertEquals(Severity.CRITICAL, issue.getSeverity());
    // assertNotNull(issue.getRemediation());
    // assertEquals(List.of("42.5.5"), issue.getRemediation().getFixedIn());
  }

  @Test
  void testResponseToIssuesWithMultipleScoreTypes() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {
            "affected": [
              {
                "scores": [
                  {
                    "type": "4",
                    "value": 7.2,
                    "severity": "high"
                  },
                  {
                    "type": "3.1",
                    "value": 9.8,
                    "severity": "critical"
                  },
                  {
                    "type": "2",
                    "value": 8.5,
                    "severity": "high"
                  }
                ],
                "ranges": [
                  {
                    "events": [
                      {
                        "fixed": "42.5.5"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    Issue issue = issues.get(0);

    // Should prioritize V4 based on SCORE_TYPE_ORDER
    assertEquals(7.2f, issue.getCvssScore());
    assertEquals(Severity.HIGH, issue.getSeverity());
  }

  @Test
  void testResponseToIssuesWithEmptyResponse() throws IOException {
    String jsonResponse = "{}";

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    assertNotNull(result.issues());
    assertTrue(result.issues().isEmpty());
  }

  @Test
  void testResponseToIssuesWithEmptyVulnerabilityArray() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithMissingStatusField() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE"
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithMissingAffectedField() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {}
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithNoScores() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {
            "affected": [
              {
                "id": "advisory-1",
                "ranges": [
                  {
                    "events": [
                      {
                        "fixed": "42.5.5"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithFallbackToDescription() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "description": "This is a description used as title",
          "status": {
            "affected": [
            {
              "scores": [
                {
                  "type": "3.1",
                  "value": 9.8,
                  "severity": "critical"
                }
              ],
              "ranges": [
                {
                  "events": [
                    {
                      "fixed": "42.5.5"
                    }
                  ]
                }
              ]
            }
          ]}
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertEquals("This is a description used as title", issue.getTitle());
  }

  @Test
  void testResponseToIssuesWithMultipleFixedVersions() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {
            "affected": [
              {
                "scores": [
                  {
                    "type": "3.1",
                    "value": 9.8,
                    "severity": "critical"
                  }
                ],
                "ranges": [
                  {
                    "events": [
                      {
                        "fixed": "42.5.5"
                      },
                      {
                        "fixed": "42.6.0"
                      }
                    ]
                  },
                  {
                    "events": [
                      {
                        "fixed": "43.0.0"
                      }
                    ]
                  }
                ]
              }
          ]}
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    List<Issue> issues = result.issues().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertNotNull(issue.getRemediation());
    List<String> fixedVersions = issue.getRemediation().getFixedIn();
    assertEquals(3, fixedVersions.size());
    assertTrue(fixedVersions.contains("42.5.5"));
    assertTrue(fixedVersions.contains("42.6.0"));
    assertTrue(fixedVersions.contains("43.0.0"));
  }

  @Test
  void testResponseToIssuesWithDependencyNotInTree() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/some.other/package@1.0.0": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {
            "affected": [
              {
                "scores": [
                  {
                    "type": "3.1",
                    "value": 9.8,
                    "severity": "critical"
                  }
                ],
                "ranges": [
                  {
                    "events": [
                      {
                        "fixed": "1.0.1"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result = handler.responseToIssues(responseBytes, null, dependencyTree);

    assertNotNull(result);
    assertTrue(result.issues().isEmpty());
  }
}
