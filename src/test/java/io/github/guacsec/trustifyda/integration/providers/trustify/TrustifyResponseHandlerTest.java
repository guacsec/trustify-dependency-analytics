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
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

  @BeforeEach
  void setUp() {
    handler = new TrustifyResponseHandler();
    handler.mapper = new ObjectMapper();

    // Build a simple dependency tree for testing
    var packageRef = new PackageRef("pkg:maven/org.postgresql/postgresql@42.5.0");
    var directDep = new DirectDependency(packageRef, Collections.emptySet());
    var dependencies = Collections.singletonMap(packageRef, directDep);
    dependencyTree = new DependencyTree(dependencies);

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
        // old response without details field
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
                "status": {
                  "affected": [
                    {
                      "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d99ed",
                      "identifier": "GHSA-562r-vg33-8x8h",
                      "document_id": "GHSA-562r-vg33-8x8h",
                      "title": "TemporaryFolder on unix-like systems does not limit access to created files",
                      "labels": {
                        "type": "osv",
                        "file": "github-reviewed/2022/11/GHSA-562r-vg33-8x8h/GHSA-562r-vg33-8x8h.json",
                        "importer": "osv-github",
                        "source": "https://github.com/github/advisory-database"
                      },
                      "scores": [
                        {
                          "type": "3.1",
                          "value": 5.8,
                          "severity": "medium"
                        }
                      ]
                    }
                  ]
                }
              },
              {
                "normative": true,
                "identifier": "CVE-2024-1597",
                "title": "pgjdbc SQL Injection via line comment generation",
                "description": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected.",
                "cwes": [
                  "CWE-89"
                ],
                "status": {
                  "affected": [
                    {
                      "uuid": "urn:uuid:020c0585-32db-4949-bd41-87850add2277",
                      "identifier": "https://www.redhat.com/#RHSA-2024_1797",
                      "document_id": "RHSA-2024:1797",
                      "issuer": {
                        "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                        "name": "Red Hat Product Security"
                      },
                      "title": "Red Hat Security Advisory: Red Hat build of Quarkus 2.13.9.SP2 release and security update",
                      "labels": {
                        "importer": "redhat-csaf",
                        "file": "2024/rhsa-2024_1797.json",
                        "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                        "type": "csaf"
                      },
                      "scores": [
                        {
                          "type": "3.1",
                          "value": 9.8,
                          "severity": "critical"
                        }
                      ]
                    },
                    {
                      "uuid": "urn:uuid:ea8dd8f5-40a9-4817-ba11-9606f799fe6e",
                      "identifier": "https://www.redhat.com/#RHSA-2024_1662",
                      "document_id": "RHSA-2024:1662",
                      "issuer": {
                        "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                        "name": "Red Hat Product Security"
                      },
                      "title": "Red Hat Security Advisory: Red Hat build of Quarkus 3.2.11 release and security update",
                      "labels": {
                        "file": "2024/rhsa-2024_1662.json",
                        "importer": "redhat-csaf",
                        "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                        "type": "csaf"
                      },
                      "scores": [
                        {
                          "type": "3.1",
                          "value": 9.8,
                          "severity": "critical"
                        }
                      ]
                    }
                  ]
                }
              }
            ]}
              "warnings": []
          }
        """,
        // new response with details field
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
                  "status": {
                    "affected": [
                      {
                        "uuid": "urn:uuid:595a7085-f230-42b5-9c8f-ab25939d99ed",
                        "identifier": "GHSA-562r-vg33-8x8h",
                        "document_id": "GHSA-562r-vg33-8x8h",
                        "title": "TemporaryFolder on unix-like systems does not limit access to created files",
                        "labels": {
                          "type": "osv",
                          "file": "github-reviewed/2022/11/GHSA-562r-vg33-8x8h/GHSA-562r-vg33-8x8h.json",
                          "importer": "osv-github",
                          "source": "https://github.com/github/advisory-database"
                        },
                        "scores": [
                          {
                            "type": "3.1",
                            "value": 5.8,
                            "severity": "medium"
                          }
                        ]
                      }
                    ]
                  }
                },
                {
                  "normative": true,
                  "identifier": "CVE-2024-1597",
                  "title": "pgjdbc SQL Injection via line comment generation",
                  "description": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected.",
                  "cwes": [
                    "CWE-89"
                  ],
                  "status": {
                    "affected": [
                      {
                        "uuid": "urn:uuid:020c0585-32db-4949-bd41-87850add2277",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1797",
                        "document_id": "RHSA-2024:1797",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        },
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 2.13.9.SP2 release and security update",
                        "labels": {
                          "importer": "redhat-csaf",
                          "file": "2024/rhsa-2024_1797.json",
                          "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                          "type": "csaf"
                        },
                        "scores": [
                          {
                            "type": "3.1",
                            "value": 9.8,
                            "severity": "critical"
                          }
                        ]
                      },
                      {
                        "uuid": "urn:uuid:ea8dd8f5-40a9-4817-ba11-9606f799fe6e",
                        "identifier": "https://www.redhat.com/#RHSA-2024_1662",
                        "document_id": "RHSA-2024:1662",
                        "issuer": {
                          "id": "aa42c1b1-0591-447c-b2bb-80888252c85f",
                          "name": "Red Hat Product Security"
                        },
                        "title": "Red Hat Security Advisory: Red Hat build of Quarkus 3.2.11 release and security update",
                        "labels": {
                          "file": "2024/rhsa-2024_1662.json",
                          "importer": "redhat-csaf",
                          "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                          "type": "csaf"
                        },
                        "scores": [
                          {
                            "type": "3.1",
                            "value": 9.8,
                            "severity": "critical"
                          }
                        ]
                      }
                    ]
                  }
                }
              ]
            },
            "warnings": []
          }
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
    // assertNotNull(issue.getRemediation());
    // assertEquals(List.of("42.5.5"), issue.getRemediation().getFixedIn());

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
          "status": {
            "affected": [
              {
                "labels": {
                  "file": "2024/rhsa-2024_1662.json",
                  "importer": "redhat-csaf",
                  "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                  "type": "csaf"
                },
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

    // Should prioritize V4 based on SCORE_TYPE_ORDER
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
          "status": {}
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
              "labels": {
                "file": "2024/rhsa-2024_1662.json",
                "importer": "redhat-csaf",
                "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                "type": "csaf"
              },
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
  void testResponseToIssuesWithMultipleFixedVersions() throws IOException {
    String jsonResponse =
        """
    {
      "pkg:maven/org.postgresql/postgresql@42.5.0": {
        "details": [
          {
            "identifier": "CVE-2024-1597",
            "title": "Test CVE",
            "status": {
              "affected": [
                {
                  "labels": {
                    "file": "2024/rhsa-2024_1662.json",
                    "importer": "redhat-csaf",
                    "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                    "type": "csaf"
                  },
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
      "pkg:maven/some.other/package@1.0.0": {
        "details": [
        {
          "identifier": "CVE-2024-1597",
          "title": "Test CVE",
          "status": {
            "affected": [
              {
                "labels": {
                  "file": "2024/rhsa-2024_1662.json",
                  "importer": "redhat-csaf",
                  "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
                  "type": "csaf"
                },
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
        new IndexedRecommendation(new PackageRef("pkg:oci/ubi@0.0.2"), null);
    assertEquals(1, recommendations.size());
    assertEquals(recommendation, recommendations.get(sbomRef));
  }

  private static final record ExpectedRecommendation(String version, Set<String> cves) {}
}
