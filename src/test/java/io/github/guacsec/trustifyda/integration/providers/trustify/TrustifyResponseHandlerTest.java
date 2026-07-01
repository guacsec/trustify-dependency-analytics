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

import static io.github.guacsec.trustifyda.integration.providers.ProviderResponseHandlerTest.buildExchange;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.guacsec.trustifyda.api.PackageRef;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.RemediationCategory;
import io.github.guacsec.trustifyda.api.v5.Severity;
import io.github.guacsec.trustifyda.integration.Constants;
import io.github.guacsec.trustifyda.integration.providers.trustify.ubi.UBIRecommendation;
import io.github.guacsec.trustifyda.model.DependencyTree;
import io.github.guacsec.trustifyda.model.DirectDependency;
import io.github.guacsec.trustifyda.model.PackageItem;
import io.github.guacsec.trustifyda.model.ProviderResponse;
import io.github.guacsec.trustifyda.model.trustify.IndexedRecommendation;

public class TrustifyResponseHandlerTest {

  private TrustifyResponseHandler handler;
  private DependencyTree dependencyTree;

  private TrustifyIntegration trustifyIntegration;
  private UBIRecommendation ubiRecommendation;

  private static final PackageRef rootPackageRef = new PackageRef("pkg:maven/org.acme/app@1.0");

  @BeforeEach
  void setUp() {
    handler = new TrustifyResponseHandler();
    handler.mapper = new ObjectMapper();

    // Build a simple dependency tree for testing
    var packageRef = new PackageRef("pkg:maven/org.postgresql/postgresql@42.5.0");
    var directDep = new DirectDependency(packageRef, Collections.emptySet());
    var dependencies = Collections.singletonMap(packageRef, directDep);
    dependencyTree =
        DependencyTree.builder()
            .dependencies(dependencies)
            .licenseExpressions(Collections.emptyMap())
            .root(rootPackageRef)
            .build();

    // Setup for TrustifyIntegration.processRecommendations() tests
    trustifyIntegration = new TrustifyIntegration();
    trustifyIntegration.mapper = new ObjectMapper();

    // Create a mock UBIRecommendation
    ubiRecommendation = mock(UBIRecommendation.class);
    Map<String, String> mapping = new HashMap<>();
    mapping.put("alpine", "pkg:oci/ubi@0.0.2");
    when(ubiRecommendation.mapping()).thenReturn(mapping);
    when(ubiRecommendation.purl()).thenReturn(Collections.emptyMap());
    when(ubiRecommendation.catalogurl()).thenReturn(Collections.emptyMap());
    trustifyIntegration.ubiRecommendation = ubiRecommendation;
  }

  private static Stream<String> testResponseToIssuesWithValidData() {
    return Stream.of(
        // v3 response without details field (fallback path)
        """
          {
            "pkg:maven/org.postgresql/postgresql@42.5.0": [
              {
                "normative": true,
                "identifier": "CVE-2022-41946",
                "title": "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
                "description": "pgjdbc is an open source postgresql JDBC Driver. In affected versions a prepared statement using either `PreparedStatement.setText(int, InputStream)` or `PreparedStatemet.setBytea(int, InputStream)` will create a temporary file if the InputStream is larger than 2k. This will create a temporary file which is readable by other users on Unix like systems, but not MacOS. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. Java 1.7 and higher users: this vulnerability is fixed in 4.5.0. Java 1.6 and lower users: no patch is available. If you are unable to patch, or are stuck running on Java 1.6, specifying the java.io.tmpdir system environment variable to a directory that is exclusively owned by the executing user will mitigate this vulnerability.",
                "cwes": [
                  "CWE-200",
                  "CWE-377"
                ],
                "base_score": {
                  "type": "3.1",
                  "score": 5.8,
                  "severity": "medium"
                },
                "purl_statuses": [
                  {
                    "advisory": {
                      "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d99ed",
                      "identifier": "GHSA-562r-vg33-8x8h",
                      "document_id": "GHSA-562r-vg33-8x8h",
                      "title": "TemporaryFolder on unix-like systems does not limit access to created files",
                      "issuer": null
                    },
                    "status": "affected",
                    "version_range": null,
                    "remediations": []
                  }
                ]
              },
              {
                "normative": true,
                "identifier": "CVE-2024-1597",
                "title": "pgjdbc SQL Injection via line comment generation",
                "description": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected.",
                "cwes": [
                  "CWE-89"
                ],
                "base_score": {
                  "type": "3.1",
                  "score": 9.8,
                  "severity": "critical"
                },
                "purl_statuses": [
                  {
                    "advisory": {
                      "uuid": "urn:uuid:020c0585-32db-4949-bd41-87850add2277",
                      "identifier": "https://www.redhat.com/#RHSA-2024_1797",
                      "document_id": "RHSA-2024:1797",
                      "title": "Red Hat Security Advisory: Red Hat build of Quarkus 2.13.9.SP2 release and security update",
                      "issuer": {
                        "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                        "name": "Red Hat Product Security"
                      }
                    },
                    "status": "affected",
                    "version_range": null,
                    "remediations": []
                  },
                  {
                    "advisory": {
                      "uuid": "urn:uuid:ea8dd8f5-40a9-4817-ba11-9606f799fe6e",
                      "identifier": "https://www.redhat.com/#RHSA-2024_1662",
                      "document_id": "RHSA-2024:1662",
                      "title": "Red Hat Security Advisory: Red Hat build of Quarkus 3.2.11 release and security update",
                      "issuer": {
                        "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                        "name": "Red Hat Product Security"
                      }
                    },
                    "status": "affected",
                    "version_range": null,
                    "remediations": []
                  }
                ]
              }
            ]
          }
        """,
        // v3 response with details field
        """
          {
            "pkg:maven/org.postgresql/postgresql@42.5.0": {
              "details": [
                {
                  "normative": true,
                  "identifier": "CVE-2022-41946",
                  "title": "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
                  "description": "pgjdbc is an open source postgresql JDBC Driver. In affected versions a prepared statement using either `PreparedStatement.setText(int, InputStream)` or `PreparedStatemet.setBytea(int, InputStream)` will create a temporary file if the InputStream is larger than 2k. This will create a temporary file which is readable by other users on Unix like systems, but not MacOS. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. Java 1.7 and higher users: this vulnerability is fixed in 4.5.0. Java 1.6 and lower users: no patch is available. If you are unable to patch, or are stuck running on Java 1.6, specifying the java.io.tmpdir system environment variable to a directory that is exclusively owned by the executing user will mitigate this vulnerability.",
                  "cwes": [
                    "CWE-200",
                    "CWE-377"
                  ],
                  "base_score": {
                    "type": "3.1",
                    "score": 5.8,
                    "severity": "medium"
                  },
                  "purl_statuses": [
                    {
                      "advisory": {
                        "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d99ed",
                        "identifier": "GHSA-562r-vg33-8x8h",
                        "document_id": "GHSA-562r-vg33-8x8h",
                        "title": "TemporaryFolder on unix-like systems does not limit access to created files",
                        "issuer": null
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    }
                  ]
                },
                {
                  "normative": true,
                  "identifier": "CVE-2024-1597",
                  "title": "pgjdbc SQL Injection via line comment generation",
                  "description": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected.",
                  "cwes": [
                    "CWE-89"
                  ],
                  "base_score": {
                    "type": "3.1",
                    "score": 9.8,
                    "severity": "critical"
                  },
                  "purl_statuses": [
                    {
                      "advisory": {
                        "uuid": "urn:uuid:020c0585-32db-4949-bd41-87850add2277",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1797",
                        "document_id": "RHSA-2024:1797",
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 2.13.9.SP2 release and security update",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        }
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    },
                    {
                      "advisory": {
                        "uuid": "urn:uuid:ea8dd8f5-40a9-4817-ba11-9606f799fe6e",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1662",
                        "document_id": "RHSA-2024:1662",
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 3.2.11 release and security update",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        }
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    }
                  ]
                }
              ]
            },
            "warnings": []
          },
     """,
        // v3 response with withdrawn field
        """
          {
            "pkg:maven/org.postgresql/postgresql@42.5.0": {
              "details": [
                {
                  "normative": true,
                  "identifier": "CVE-2022-41948",
                  "title": "This CVE is a placeholder for a vulnerability that has been withdrawn",
                  "description": "This CVE is a placeholder for a vulnerability that has been withdrawn",
                  "withdrawn": "2024-01-01T00:00:00Z",
                  "purl_statuses": [
                    {
                      "advisory": {
                        "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d9900",
                        "identifier": "CVE-2022-41948",
                        "document_id": "CVE-2022-41948",
                        "title": "This CVE is a placeholder for a vulnerability that has been withdrawn",
                        "issuer": null
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    }
                  ]
                },
                {
                  "normative": true,
                  "identifier": "CVE-2022-41946",
                  "title": "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
                  "description": "pgjdbc is an open source postgresql JDBC Driver. In affected versions a prepared statement using either `PreparedStatement.setText(int, InputStream)` or `PreparedStatemet.setBytea(int, InputStream)` will create a temporary file if the InputStream is larger than 2k. This will create a temporary file which is readable by other users on Unix like systems, but not MacOS. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. Java 1.7 and higher users: this vulnerability is fixed in 4.5.0. Java 1.6 and lower users: no patch is available. If you are unable to patch, or are stuck running on Java 1.6, specifying the java.io.tmpdir system environment variable to a directory that is exclusively owned by the executing user will mitigate this vulnerability.",
                  "cwes": [
                    "CWE-200",
                    "CWE-377"
                  ],
                  "base_score": {
                    "type": "3.1",
                    "score": 5.8,
                    "severity": "medium"
                  },
                  "purl_statuses": [
                    {
                      "advisory": {
                        "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d99ed",
                        "identifier": "GHSA-562r-vg33-8x8h",
                        "document_id": "GHSA-562r-vg33-8x8h",
                        "title": "TemporaryFolder on unix-like systems does not limit access to created files",
                        "issuer": null
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    },
                    {
                      "advisory": {
                        "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d9908",
                        "identifier": "CVE-2022-41946",
                        "document_id": "CVE-2022-41946",
                        "title": "This CVE is a placeholder for a vulnerability that has been withdrawn",
                        "issuer": null,
                        "withdrawn": "2024-01-01T00:00:00Z"
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    }
                  ]
                },
                {
                  "normative": true,
                  "identifier": "CVE-2024-1597",
                  "title": "pgjdbc SQL Injection via line comment generation",
                  "description": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected.",
                  "cwes": [
                    "CWE-89"
                  ],
                  "base_score": {
                    "type": "3.1",
                    "score": 9.8,
                    "severity": "critical"
                  },
                  "purl_statuses": [
                    {
                      "advisory": {
                        "uuid": "urn:uuid:020c0585-32db-4949-bd41-87850add2277",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1797",
                        "document_id": "RHSA-2024:1797",
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 2.13.9.SP2 release and security update",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        }
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    },
                    {
                      "advisory": {
                        "uuid": "urn:uuid:ea8dd8f5-40a9-4817-ba11-9606f799fe6e",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1662",
                        "document_id": "RHSA-2024:1662",
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 3.2.11 release and security update",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        }
                      },
                      "status": "affected",
                      "version_range": null,
                      "remediations": []
                    }
                  ]
                }
              ]
            },
            "warnings": []
          },
    """);
  }

  @ParameterizedTest
  @MethodSource("testResponseToIssuesWithValidData")
  void testResponseToIssuesWithValidData(String jsonResponse) throws IOException {
    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    assertNotNull(result.pkgItems());
    assertEquals(1, result.pkgItems().size());

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertNotNull(issues);
    assertEquals(2, issues.size());

    var issue =
        issues.stream().filter(i -> i.getId().equals("CVE-2024-1597")).findFirst().orElseThrow();
    assertEquals("CVE-2024-1597", issue.getId());
    assertEquals("pgjdbc SQL Injection via line comment generation", issue.getTitle());
    assertEquals(9.8f, issue.getCvssScore());
    assertEquals(Severity.CRITICAL, issue.getSeverity());

    issue =
        issues.stream().filter(i -> i.getId().equals("CVE-2022-41946")).findFirst().orElseThrow();
    assertEquals("CVE-2022-41946", issue.getId());
    assertEquals(
        "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
        issue.getTitle());
    assertEquals(5.8f, issue.getCvssScore());
    assertEquals(Severity.MEDIUM, issue.getSeverity());
  }

  @Test
  void testResponseToIssuesWithMultipleScoreTypes() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "base_score": {
            "type": "4.0",
            "score": 7.2,
            "severity": "high"
          },
          "purl_statuses": [
            {
              "advisory": {
                "uuid": "urn:uuid:a1",
                "identifier": "RHSA-2024:1662",
                "document_id": "RHSA-2024:1662",
                "title": "Advisory",
                "issuer": {
                  "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                  "name": "Red Hat Product Security"
                }
              },
              "status": "affected",
              "version_range": null,
              "remediations": []
            }
          ]
        }
      ]},
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    Issue issue = issues.get(0);

    // v3 provides pre-computed base_score
    assertEquals(7.2f, issue.getCvssScore());
    assertEquals(Severity.HIGH, issue.getSeverity());
  }

  @Test
  void testResponseToIssuesWithEmptyResponse() throws IOException {
    String jsonResponse = "{}";

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    assertNotNull(result.pkgItems());
    assertTrue(result.pkgItems().isEmpty());
  }

  @Test
  void testResponseToIssuesWithEmptyVulnerabilityArray() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": []
      },
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
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
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithMissingAffectedField() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "purl_statuses": []
        }
      ]},
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertTrue(issues.isEmpty());
  }

  @Test
  void testResponseToIssuesWithNoScores() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "purl_statuses": [
            {
              "advisory": {
                "uuid": "urn:uuid:advisory-1",
                "identifier": "advisory-1",
                "document_id": "advisory-1",
                "title": "Advisory 1",
                "issuer": null
              },
              "status": "affected",
              "version_range": null,
              "remediations": []
            }
          ]
        }
      ]},
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertFalse(issues.isEmpty(), "CVE without scores should still produce an issue");
    assertEquals(1, issues.size());
    assertEquals("CVE-2024-1597", issues.get(0).getId());
    assertNull(issues.get(0).getSeverity(), "Issue without scores should have null severity");
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
          "base_score": {
            "type": "3.1",
            "score": 9.8,
            "severity": "critical"
          },
          "purl_statuses": [
            {
              "advisory": {
                "uuid": "urn:uuid:a1",
                "identifier": "RHSA-2024:1662",
                "document_id": "RHSA-2024:1662",
                "title": "Advisory",
                "issuer": null
              },
              "status": "affected",
              "version_range": null,
              "remediations": []
            }
          ]
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertEquals("This is a description used as title", issue.getTitle());
  }

  @Test
  void testResponseToIssuesWithDefaultSource() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": [
        {
          "identifier": "CVE-2024-1597",
          "description": "This is a description used as title",
          "base_score": {
            "type": "3.1",
            "score": 9.8,
            "severity": "critical"
          },
          "purl_statuses": [
            {
              "advisory": {
                "uuid": "urn:uuid:a1",
                "identifier": "RHSA-2024:1662",
                "document_id": "RHSA-2024:1662",
                "title": "Advisory",
                "issuer": null
              },
              "status": "affected",
              "version_range": null,
              "remediations": []
            }
          ]
        }
      ]
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertEquals("unknown", issue.getSource());
  }

  @Test
  void testResponseToIssuesWithMultipleFixedVersions() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1597",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 9.8,
              "severity": "critical"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "RHSA-2024:1662",
                  "document_id": "RHSA-2024:1662",
                  "title": "Advisory",
                  "issuer": {
                    "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": {
                  "high_version": "42.5.5",
                  "high_inclusive": false
                },
                "remediations": [
                  {
                    "category": "vendor_fix",
                    "details": "Update to version 42.5.5"
                  }
                ]
              }
            ]
          }
        ]
      },
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertNotNull(issue.getRemediation());
    List<String> fixedVersions = issue.getRemediation().getFixedIn();
    assertEquals(1, fixedVersions.size());
    assertEquals("42.5.5", fixedVersions.get(0));
    assertNotNull(issue.getRemediation().getVersionRanges());
    assertEquals(1, issue.getRemediation().getVersionRanges().size());
    assertEquals("42.5.5", issue.getRemediation().getVersionRanges().get(0).getHighVersion());
    assertEquals(false, issue.getRemediation().getVersionRanges().get(0).getHighInclusive());
    assertNotNull(issue.getRemediation().getRemediations());
    assertEquals(1, issue.getRemediation().getRemediations().size());
    assertEquals(
        RemediationCategory.VENDOR_FIX,
        issue.getRemediation().getRemediations().get(0).getCategory());
    assertEquals(
        "Update to version 42.5.5", issue.getRemediation().getRemediations().get(0).getDetails());
  }

  @Test
  void testResponseToIssuesWithHighInclusiveVersionRange() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1597",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 9.8,
              "severity": "critical"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "RHSA-2024:1662",
                  "document_id": "RHSA-2024:1662",
                  "title": "Advisory",
                  "issuer": {
                    "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": {
                  "high_version": "42.5.5",
                  "high_inclusive": true
                },
                "remediations": []
              }
            ]
          }
        ]
      },
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());

    Issue issue = issues.get(0);
    assertNotNull(issue.getRemediation());
    assertNull(issue.getRemediation().getFixedIn());
    assertNotNull(issue.getRemediation().getVersionRanges());
    assertEquals(1, issue.getRemediation().getVersionRanges().size());
    assertEquals("42.5.5", issue.getRemediation().getVersionRanges().get(0).getHighVersion());
    assertEquals(true, issue.getRemediation().getVersionRanges().get(0).getHighInclusive());
  }

  @Test
  void testResponseToIssuesWithDependencyNotInTree() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/some.other/package@1.0.0": {
        "details": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "base_score": {
            "type": "3.1",
            "score": 9.8,
            "severity": "critical"
          },
          "purl_statuses": [
            {
              "advisory": {
                "uuid": "urn:uuid:a1",
                "identifier": "RHSA-2024:1662",
                "document_id": "RHSA-2024:1662",
                "title": "Advisory",
                "issuer": null
              },
              "status": "affected",
              "version_range": null,
              "remediations": []
            }
          ]
        }
      ]},
      "warnings": []
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    assertTrue(result.pkgItems().isEmpty());
  }

  @Test
  void testProcessRecommendationsAggregation() throws IOException {
    Exchange exchange = mock(Exchange.class);
    Message inMessage = mock(Message.class);
    Message outMessage = mock(Message.class);

    when(exchange.getIn()).thenReturn(inMessage);
    when(exchange.getMessage()).thenReturn(outMessage);
    when(exchange.getProperty(Constants.SBOM_ID_PROPERTY, String.class)).thenReturn(null);

    byte[] responseBytes =
        getClass()
            .getClassLoader()
            .getResourceAsStream("__files/trustedcontent/simple.json")
            .readAllBytes();
    when(inMessage.getBody(byte[].class)).thenReturn(responseBytes);

    trustifyIntegration.processRecommendations(exchange);

    @SuppressWarnings("rawtypes")
    ArgumentCaptor<Map> bodyCaptor = forClass(Map.class);
    verify(outMessage).setBody(bodyCaptor.capture());
    @SuppressWarnings("unchecked")
    Map<PackageRef, IndexedRecommendation> recommendations = bodyCaptor.getValue();
    assertNotNull(recommendations);
    assertEquals(3, recommendations.size());

    Map<String, ExpectedRecommendation> expectations = new HashMap<>();
    expectations.put(
        "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
        new ExpectedRecommendation(
            "1.2.5.redhat-00003", Set.of("CVE-2023-2974", "CVE-2023-1584", "CVE-2023-28867")));
    expectations.put(
        "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final?type=jar",
        new ExpectedRecommendation(
            "2.13.8.Final-redhat-00004",
            Set.of("CVE-2020-36518", "CVE-2023-44487", "CVE-2023-4853")));
    expectations.put(
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
        new ExpectedRecommendation("2.13.4.2-redhat-00001", Collections.emptySet()));

    expectations
        .entrySet()
        .forEach(
            e -> {
              var r = recommendations.get(new PackageRef(e.getKey()));
              assertNotNull(r);
              assertEquals(e.getValue().version(), r.packageName().version());
              assertEquals(e.getValue().cves().size(), r.vulnerabilities().size());
              assertTrue(e.getValue().cves().containsAll(r.vulnerabilities().keySet()));
            });
  }

  @Test
  void testResponseToIssuesWithIdentityRecommendation() throws IOException {
    Exchange exchange = mock(Exchange.class);
    Message inMessage = mock(Message.class);
    Message outMessage = mock(Message.class);

    when(exchange.getIn()).thenReturn(inMessage);
    when(exchange.getMessage()).thenReturn(outMessage);
    when(exchange.getProperty(Constants.SBOM_ID_PROPERTY, String.class)).thenReturn(null);

    byte[] responseBytes =
        getClass()
            .getClassLoader()
            .getResourceAsStream("__files/trustedcontent/identity_report.json")
            .readAllBytes();
    when(inMessage.getBody(byte[].class)).thenReturn(responseBytes);

    trustifyIntegration.processRecommendations(exchange);

    @SuppressWarnings("rawtypes")
    ArgumentCaptor<Map> bodyCaptor = forClass(Map.class);
    verify(outMessage).setBody(bodyCaptor.capture());
    @SuppressWarnings("unchecked")
    Map<PackageRef, IndexedRecommendation> recommendations = bodyCaptor.getValue();
    assertNotNull(recommendations);
    assertEquals(0, recommendations.size());
  }

  private static final record ExpectedRecommendation(String version, Set<String> cves) {}

  @Test
  void testProcessRecommendationsEmpty() throws IOException {
    Exchange exchange = mock(Exchange.class);
    Message inMessage = mock(Message.class);
    Message outMessage = mock(Message.class);

    when(exchange.getIn()).thenReturn(inMessage);
    when(exchange.getMessage()).thenReturn(outMessage);
    when(exchange.getProperty(Constants.SBOM_ID_PROPERTY, String.class)).thenReturn(null);

    byte[] responseBytes =
        getClass()
            .getClassLoader()
            .getResourceAsStream("__files/trustedcontent/empty_report.json")
            .readAllBytes();
    when(inMessage.getBody(byte[].class)).thenReturn(responseBytes);

    trustifyIntegration.processRecommendations(exchange);

    @SuppressWarnings("rawtypes")
    ArgumentCaptor<Map> bodyCaptor = forClass(Map.class);
    verify(outMessage).setBody(bodyCaptor.capture());
    @SuppressWarnings("unchecked")
    Map<PackageRef, IndexedRecommendation> recommendations = bodyCaptor.getValue();
    assertNotNull(recommendations);
    assertTrue(recommendations.isEmpty());
  }

  @Test
  void testProcessRecommendationsWithSbomId() throws IOException {
    String sbomId = "pkg:oci/alpine@0.0.1";
    Exchange exchange = mock(Exchange.class);
    Message inMessage = mock(Message.class);
    Message outMessage = mock(Message.class);

    when(exchange.getIn()).thenReturn(inMessage);
    when(exchange.getMessage()).thenReturn(outMessage);
    when(exchange.getProperty(Constants.SBOM_ID_PROPERTY, String.class)).thenReturn(sbomId);

    byte[] responseBytes =
        getClass()
            .getClassLoader()
            .getResourceAsStream("__files/trustedcontent/empty_report.json")
            .readAllBytes();
    when(inMessage.getBody(byte[].class)).thenReturn(responseBytes);

    trustifyIntegration.processRecommendations(exchange);

    @SuppressWarnings("rawtypes")
    ArgumentCaptor<Map> bodyCaptor = forClass(Map.class);
    verify(outMessage).setBody(bodyCaptor.capture());
    @SuppressWarnings("unchecked")
    Map<PackageRef, IndexedRecommendation> recommendations = bodyCaptor.getValue();
    assertNotNull(recommendations);

    PackageRef sbomRef = new PackageRef(sbomId);
    IndexedRecommendation recommendation =
        new IndexedRecommendation(new PackageRef("pkg:oci/ubi@0.0.2"), null, "hardened-images");
    assertEquals(1, recommendations.size());
    assertEquals(recommendation, recommendations.get(sbomRef));
  }

  @Test
  void testResponseToIssuesWithUnscannedRefs() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar": {
        "details": [],
        "warnings": ["Unable to process: missing version component"]
      },
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1597",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 9.8,
              "severity": "critical"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": null
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      },
      "pkg:maven/com.example/package@1.0.0": {
        "details": [],
        "warnings": ["Some warning message"]
      },
      "pkg:maven/com.other/package@2.0.0": {
        "details": [
          {
            "identifier": "CVE-2024-1234",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 7.5,
              "severity": "high"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a2",
                  "identifier": "advisory-2",
                  "document_id": "advisory-2",
                  "title": "Advisory",
                  "issuer": null
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ]
      }
    }
    """;

    // Build dependency tree with all packages
    var packageRef1 = new PackageRef("pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar");
    var packageRef2 = new PackageRef("pkg:maven/org.postgresql/postgresql@42.5.0");
    var packageRef3 = new PackageRef("pkg:maven/com.example/package@1.0.0");
    var packageRef4 = new PackageRef("pkg:maven/com.other/package@2.0.0");
    var dependencies = new HashMap<PackageRef, DirectDependency>();
    dependencies.put(packageRef1, new DirectDependency(packageRef1, Collections.emptySet()));
    dependencies.put(packageRef2, new DirectDependency(packageRef2, Collections.emptySet()));
    dependencies.put(packageRef3, new DirectDependency(packageRef3, Collections.emptySet()));
    dependencies.put(packageRef4, new DirectDependency(packageRef4, Collections.emptySet()));
    var testDependencyTree =
        DependencyTree.builder()
            .dependencies(dependencies)
            .licenseExpressions(Collections.emptyMap())
            .root(rootPackageRef)
            .build();

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, testDependencyTree));

    assertNotNull(result);
    assertNotNull(result.pkgItems());
    assertEquals(4, result.pkgItems().size());

    // Package with empty details and warnings with data should be marked as unscanned
    PackageItem packageItem1 =
        result.pkgItems().get("pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar");
    assertNotNull(packageItem1);
    assertTrue(
        packageItem1.warnings().contains("Unable to process: missing version component"),
        "Package with empty details and warnings should be marked as unscanned");

    // Package with details and warnings with data should be marked as unscanned
    PackageItem packageItem2 = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem2);
    assertTrue(packageItem2.warnings().isEmpty());

    // Package with empty warnings should not be marked as unscanned
    PackageItem packageItem3 = result.pkgItems().get("pkg:maven/com.example/package@1.0.0");
    assertNotNull(packageItem3);
    assertTrue(packageItem3.warnings().contains("Some warning message"));

    // Package without warnings should not be marked as unscanned
    PackageItem packageItem4 = result.pkgItems().get("pkg:maven/com.other/package@2.0.0");
    assertNotNull(packageItem4);
    assertTrue(
        packageItem4.warnings().isEmpty(),
        "Package without warnings should not be marked as unscanned");
  }

  /**
   * Verifies that vulnerabilities with only invalid severity scores (e.g., "none") are skipped, and
   * that valid scores in mixed-score advisories are used correctly.
   */
  @Test
  void testResponseToIssuesWithInvalidSeverity() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1597",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 0.0,
              "severity": "none"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      },
      "pkg:maven/com.other/package@2.0.0": {
        "details": [
          {
            "identifier": "CVE-2024-1234",
            "title": "Test CVE",
            "base_score": {
              "type": "3.1",
              "score": 7.5,
              "severity": "high"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a2",
                  "identifier": "advisory-2",
                  "document_id": "advisory-2",
                  "title": "Advisory",
                  "issuer": {
                    "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ]
      }
    }
    """;

    // Build dependency tree with all packages
    var packageRef1 = new PackageRef("pkg:maven/org.postgresql/postgresql@42.5.0");
    var packageRef2 = new PackageRef("pkg:maven/com.other/package@2.0.0");
    var dependencies = new HashMap<PackageRef, DirectDependency>();
    dependencies.put(packageRef1, new DirectDependency(packageRef1, Collections.emptySet()));
    dependencies.put(packageRef2, new DirectDependency(packageRef2, Collections.emptySet()));
    var testDependencyTree =
        DependencyTree.builder()
            .dependencies(dependencies)
            .licenseExpressions(Collections.emptyMap())
            .root(rootPackageRef)
            .build();

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, testDependencyTree));

    assertNotNull(result);
    assertNotNull(result.pkgItems());
    assertEquals(2, result.pkgItems().size());

    PackageItem packageItem1 = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem1, "Package with no valid scores should be present");
    List<Issue> issues = packageItem1.issues();
    assertFalse(issues.isEmpty(), "CVE with invalid scores should still produce an issue");
    assertEquals(1, issues.size());
    assertEquals(
        0.0f,
        issues.get(0).getCvssScore(),
        "Issue with 'none' severity should still have the score");
    assertEquals(
        Severity.LOW,
        issues.get(0).getSeverity(),
        "Issue with 'none' severity should fall back to score-based severity");

    // Package with mixed valid/invalid scores should use the valid score
    PackageItem packageItem2 = result.pkgItems().get("pkg:maven/com.other/package@2.0.0");
    assertNotNull(packageItem2);
    issues = packageItem2.issues();
    assertFalse(issues.isEmpty(), "Package should have an issue");
    assertEquals(1, issues.size(), "Package should have one issue");
    assertEquals(7.5f, issues.get(0).getCvssScore(), "Issue should have the correct CVSS score");
    assertEquals(
        Severity.HIGH, issues.get(0).getSeverity(), "Issue should have the correct severity");
  }

  @Test
  void testResponseToIssuesWithEmptyScoresArray() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2025-24898",
            "title": "Test CVE with empty scores",
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": null
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    assertNotNull(result);
    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertFalse(issues.isEmpty(), "CVE with empty scores should still produce an issue");
    assertEquals(1, issues.size());
    assertEquals("CVE-2025-24898", issues.get(0).getId());
    assertNull(issues.get(0).getSeverity(), "Issue with empty scores should have null severity");
  }

  @Test
  void testResponseToIssuesWithFallbackToPurlStatusScores() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-9999",
            "title": "CVE with scores only in purlStatus",
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "Test Issuer"
                  }
                },
                "status": "affected",
                "scores": [
                  { "value": 6.5, "severity": "medium" },
                  { "value": 8.1, "severity": "high" }
                ],
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());
    assertEquals(8.1f, issues.get(0).getCvssScore(), "Should pick highest score from purlStatus");
    assertEquals(Severity.HIGH, issues.get(0).getSeverity());
  }

  @Test
  void testResponseToIssuesWithVersionRangeAllFields() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-8888",
            "title": "CVE with full version range",
            "base_score": {
              "type": "3.1",
              "score": 7.0,
              "severity": "high"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "Test Issuer"
                  }
                },
                "status": "affected",
                "version_range": {
                  "version_scheme_id": "semver",
                  "low_version": "42.0.0",
                  "low_inclusive": true,
                  "high_version": "42.5.5",
                  "high_inclusive": false
                },
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    Issue issue = packageItem.issues().get(0);
    assertNotNull(issue.getRemediation());
    var vr = issue.getRemediation().getVersionRanges().get(0);
    assertEquals("semver", vr.getVersionSchemeId());
    assertEquals("42.0.0", vr.getLowVersion());
    assertEquals(true, vr.getLowInclusive());
    assertEquals("42.5.5", vr.getHighVersion());
    assertEquals(false, vr.getHighInclusive());
    assertEquals(List.of("42.5.5"), issue.getRemediation().getFixedIn());
  }

  @Test
  void testResponseToIssuesWithRemediationUrl() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-7777",
            "title": "CVE with remediation URL",
            "base_score": {
              "type": "3.1",
              "score": 5.0,
              "severity": "medium"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "Test Issuer"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": [
                  {
                    "category": "vendor_fix",
                    "details": "Update to latest version",
                    "url": "https://example.com/fix"
                  }
                ]
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    Issue issue = packageItem.issues().get(0);
    assertNotNull(issue.getRemediation());
    var rem = issue.getRemediation().getRemediations().get(0);
    assertEquals(RemediationCategory.VENDOR_FIX, rem.getCategory());
    assertEquals("Update to latest version", rem.getDetails());
    assertEquals("https://example.com/fix", rem.getUrl());
  }

  @Test
  void testResponseToIssuesWithUnknownRemediationCategory() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-6666",
            "title": "CVE with unknown remediation category",
            "base_score": {
              "type": "3.1",
              "score": 5.0,
              "severity": "medium"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "Test Issuer"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": [
                  {
                    "category": "unknown_category",
                    "details": "Some details"
                  }
                ]
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    Issue issue = packageItem.issues().get(0);
    assertNotNull(issue.getRemediation());
    var rem = issue.getRemediation().getRemediations().get(0);
    assertNull(rem.getCategory(), "Unknown category should result in null");
    assertEquals("Some details", rem.getDetails());
  }

  @Test
  void testResponseToIssuesWithNoAdvisory() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-5555",
            "title": "CVE with no advisory in purlStatus",
            "base_score": {
              "type": "3.1",
              "score": 4.0,
              "severity": "medium"
            },
            "purl_statuses": [
              {
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());
    assertEquals("unknown", issues.get(0).getSource());
  }

  @Test
  void testResponseToIssuesWithBlankIssuerName() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-4444",
            "title": "CVE with blank issuer name",
            "base_score": {
              "type": "3.1",
              "score": 6.0,
              "severity": "medium"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "  "
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size());
    assertEquals(
        "unknown", issues.get(0).getSource(), "Blank issuer name should fall back to 'unknown'");
  }

  @Test
  void testResponseToIssuesWithNoSeverityButScorePresent() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-3333",
            "title": "CVE with score but no severity",
            "base_score": {
              "type": "3.1",
              "score": 9.1
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "advisory-1",
                  "document_id": "advisory-1",
                  "title": "Advisory",
                  "issuer": {
                    "id": "id-1",
                    "name": "Test Issuer"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    Issue issue = packageItem.issues().get(0);
    assertEquals(9.1f, issue.getCvssScore());
    assertEquals(
        Severity.CRITICAL, issue.getSeverity(), "Score-based severity should be CRITICAL for 9.1");
  }

  @Test
  void testResponseToIssuesCveDeduplicationBySameSource() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-2222",
            "title": "CVE appearing in multiple advisories from same source",
            "base_score": {
              "type": "3.1",
              "score": 7.5,
              "severity": "high"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "RHSA-2024:001",
                  "document_id": "RHSA-2024:001",
                  "title": "Advisory 1",
                  "issuer": {
                    "id": "id-1",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              },
              {
                "advisory": {
                  "uuid": "urn:uuid:a2",
                  "identifier": "RHSA-2024:002",
                  "document_id": "RHSA-2024:002",
                  "title": "Advisory 2",
                  "issuer": {
                    "id": "id-1",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(1, issues.size(), "Same CVE from same source should be deduplicated to one issue");
    assertEquals("CVE-2024-2222", issues.get(0).getId());
    assertEquals("Red Hat Product Security", issues.get(0).getSource());
  }

  @Test
  void testResponseToIssuesSameCveDifferentSources() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1111",
            "title": "CVE from different sources",
            "base_score": {
              "type": "3.1",
              "score": 6.0,
              "severity": "medium"
            },
            "purl_statuses": [
              {
                "advisory": {
                  "uuid": "urn:uuid:a1",
                  "identifier": "RHSA-2024:001",
                  "document_id": "RHSA-2024:001",
                  "title": "Advisory 1",
                  "issuer": {
                    "id": "id-1",
                    "name": "Red Hat Product Security"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              },
              {
                "advisory": {
                  "uuid": "urn:uuid:a2",
                  "identifier": "GHSA-xxxx",
                  "document_id": "GHSA-xxxx",
                  "title": "GHSA Advisory",
                  "issuer": {
                    "id": "id-2",
                    "name": "GitHub"
                  }
                },
                "status": "affected",
                "version_range": null,
                "remediations": []
              }
            ]
          }
        ],
        "warnings": []
      }
    }
    """;

    byte[] responseBytes = jsonResponse.getBytes();
    ProviderResponse result =
        handler.responseToIssues(buildExchange(responseBytes, dependencyTree));

    PackageItem packageItem = result.pkgItems().get("pkg:maven/org.postgresql/postgresql@42.5.0");
    assertNotNull(packageItem);
    List<Issue> issues = packageItem.issues();
    assertEquals(2, issues.size(), "Same CVE from different sources should produce two issues");
    assertTrue(issues.stream().anyMatch(i -> "Red Hat Product Security".equals(i.getSource())));
    assertTrue(issues.stream().anyMatch(i -> "GitHub".equals(i.getSource())));
  }
}
