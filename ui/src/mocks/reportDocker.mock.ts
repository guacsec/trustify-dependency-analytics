import {AppData} from '@app/api/report';

export const dockerReport: AppData = {
  providerPrivateData: null,
  report: {
    "pkg:oci/test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf?repository_url=test.io/test-namespace/test-repository&tag=test-tag&os=linux&arch=amd64": {
      "scanned": {
        "total": 10,
        "direct": 3,
        "transitive": 7
      },
      "providers": {
        "trusted-content": {
          "status": {
            "ok": true,
            "name": "trusted-content",
            "code": 200,
            "message": "OK"
          }
        },
        "tpa": {
          "status": {
            "ok": true,
            "name": "tpa",
            "code": 200,
            "message": "OK"
          },
          "sources": {
            "osv": {
              "summary": {
                "direct": 0,
                "transitive": 8,
                "total": 8,
                "dependencies": 3,
                "critical": 1,
                "high": 5,
                "medium": 2,
                "low": 0,
                "remediations": 2,
                "recommendations": 2,
                "unscanned": 0
              },
              "dependencies": [
                {
                  "ref": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
                  "transitive": [
                    {
                      "ref": "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2024-1597",
                          "title": "pgjdbc SQL Injection via line comment generation",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Changed",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                          },
                          "cvssScore": 10.0,
                          "severity": "CRITICAL",
                          "cves": [
                            "CVE-2024-1597"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2022-41946",
                          "title": "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Local",
                            "attackComplexity": "High",
                            "privilegesRequired": "Low",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "Low",
                            "availabilityImpact": "Low",
                            "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L"
                          },
                          "cvssScore": 5.8,
                          "severity": "MEDIUM",
                          "cves": [
                            "CVE-2022-41946"
                          ],
                          "unique": false
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2024-1597",
                        "title": "pgjdbc SQL Injection via line comment generation",
                        "source": "osv",
                        "cvss": {
                          "attackVector": "Network",
                          "attackComplexity": "Low",
                          "privilegesRequired": "None",
                          "userInteraction": "None",
                          "scope": "Changed",
                          "confidentialityImpact": "High",
                          "integrityImpact": "High",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        },
                        "cvssScore": 10.0,
                        "severity": "CRITICAL",
                        "cves": [
                          "CVE-2024-1597"
                        ],
                        "unique": false
                      }
                    }
                  ],
                  "recommendation": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                  "highestVulnerability": {
                    "id": "CVE-2024-1597",
                    "title": "pgjdbc SQL Injection via line comment generation",
                    "source": "osv",
                    "cvss": {
                      "attackVector": "Network",
                      "attackComplexity": "Low",
                      "privilegesRequired": "None",
                      "userInteraction": "None",
                      "scope": "Changed",
                      "confidentialityImpact": "High",
                      "integrityImpact": "High",
                      "availabilityImpact": "High",
                      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                    },
                    "cvssScore": 10.0,
                    "severity": "CRITICAL",
                    "cves": [
                      "CVE-2024-1597"
                    ],
                    "unique": false
                  }
                },
                {
                  "ref": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
                  "issues": [
                  ],
                  "transitive": [
                    {
                      "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2020-36518",
                          "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2020-36518"
                          ],
                          "unique": false,
                          "remediation": {
                            "trustedContent": {
                              "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                              "status": "NotAffected",
                              "justification": "VulnerableCodeNotPresent"
                            }
                          }
                        },
                        {
                          "id": "CVE-2022-42004",
                          "title": "Uncontrolled Resource Consumption in FasterXML jackson-databind",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2022-42004"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2022-42003",
                          "title": "Uncontrolled Resource Consumption in Jackson-databind",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2022-42003"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2021-46877",
                          "title": "jackson-databind possible Denial of Service if using JDK serialization to serialize JsonNode",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2021-46877"
                          ],
                          "unique": false
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2020-36518",
                        "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                        "source": "osv",
                        "cvss": {
                          "attackVector": "Network",
                          "attackComplexity": "Low",
                          "privilegesRequired": "None",
                          "userInteraction": "None",
                          "scope": "Unchanged",
                          "confidentialityImpact": "None",
                          "integrityImpact": "Low",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                        },
                        "cvssScore": 8.2,
                        "severity": "HIGH",
                        "cves": [
                          "CVE-2020-36518"
                        ],
                        "unique": false,
                        "remediation": {
                          "trustedContent": {
                            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                            "status": "NotAffected",
                            "justification": "VulnerableCodeNotPresent"
                          }
                        }
                      }
                    },
                    {
                      "ref": "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2024-2700",
                          "title": "quarkus-core leaks local environment variables from Quarkus namespace during application's build",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Local",
                            "attackComplexity": "High",
                            "privilegesRequired": "Low",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                          },
                          "cvssScore": 7.0,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2024-2700"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2023-2974",
                          "title": "quarkus-core vulnerable to client driven TLS cipher downgrading",
                          "source": "osv",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "High",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "Low",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L"
                          },
                          "cvssScore": 6.7,
                          "severity": "MEDIUM",
                          "cves": [
                            "CVE-2023-2974"
                          ],
                          "unique": false,
                          "remediation": {
                            "trustedContent": {
                              "ref": "pkg:maven/io.quarkus/quarkus-core@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                              "status": "NotAffected",
                              "justification": "VulnerableCodeNotPresent"
                            }
                          }
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2024-2700",
                        "title": "quarkus-core leaks local environment variables from Quarkus namespace during application's build",
                        "source": "osv",
                        "cvss": {
                          "attackVector": "Local",
                          "attackComplexity": "High",
                          "privilegesRequired": "Low",
                          "userInteraction": "None",
                          "scope": "Unchanged",
                          "confidentialityImpact": "High",
                          "integrityImpact": "High",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                        },
                        "cvssScore": 7.0,
                        "severity": "HIGH",
                        "cves": [
                          "CVE-2024-2700"
                        ],
                        "unique": false
                      }
                    }
                  ],
                  "recommendation": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                  "highestVulnerability": {
                    "id": "CVE-2020-36518",
                    "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                    "source": "osv",
                    "cvss": {
                      "attackVector": "Network",
                      "attackComplexity": "Low",
                      "privilegesRequired": "None",
                      "userInteraction": "None",
                      "scope": "Unchanged",
                      "confidentialityImpact": "None",
                      "integrityImpact": "Low",
                      "availabilityImpact": "High",
                      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                    },
                    "cvssScore": 8.2,
                    "severity": "HIGH",
                    "cves": [
                      "CVE-2020-36518"
                    ],
                    "unique": false,
                    "remediation": {
                      "trustedContent": {
                        "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                        "status": "NotAffected",
                        "justification": "VulnerableCodeNotPresent"
                      }
                    }
                  }
                }
              ]
            },
            "csaf": {
              "summary": {
                "direct": 0,
                "transitive": 134,
                "total": 134,
                "dependencies": 3,
                "critical": 12,
                "high": 109,
                "medium": 13,
                "low": 0,
                "remediations": 26,
                "recommendations": 2,
                "unscanned": 0
              },
              "dependencies": [
                {
                  "ref": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                  "issues": [

                  ],
                  "transitive": [
                    {
                      "ref": "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2024-1597",
                          "title": "pgjdbc SQL Injection via line comment generation",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                          },
                          "cvssScore": 9.8,
                          "severity": "CRITICAL",
                          "cves": [
                            "CVE-2024-1597"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2022-41946",
                          "title": "TemporaryFolder on unix-like systems does not limit access to created files in pgjdbc",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Local",
                            "attackComplexity": "Low",
                            "privilegesRequired": "Low",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "Low",
                            "availabilityImpact": "Low",
                            "cvss": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L"
                          },
                          "cvssScore": 6.6,
                          "severity": "MEDIUM",
                          "cves": [
                            "CVE-2022-41946"
                          ],
                          "unique": false
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2024-1597",
                        "source": "csaf",
                        "cvss": {
                          "attackVector": "Network",
                          "attackComplexity": "Low",
                          "privilegesRequired": "None",
                          "userInteraction": "None",
                          "scope": "Unchanged",
                          "confidentialityImpact": "High",
                          "integrityImpact": "High",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        },
                        "cvssScore": 9.8,
                        "severity": "CRITICAL",
                        "cves": [
                          "CVE-2024-1597"
                        ],
                        "unique": false
                      }
                    }
                  ],
                  "recommendation": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                  "highestVulnerability": {
                    "id": "CVE-2024-1597",
                    "source": "csaf",
                    "cvss": {
                      "attackVector": "Network",
                      "attackComplexity": "Low",
                      "privilegesRequired": "None",
                      "userInteraction": "None",
                      "scope": "Unchanged",
                      "confidentialityImpact": "High",
                      "integrityImpact": "High",
                      "availabilityImpact": "High",
                      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    },
                    "cvssScore": 9.8,
                    "severity": "CRITICAL",
                    "cves": [
                      "CVE-2024-1597"
                    ],
                    "unique": false
                  }
                },
                {
                  "ref": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
                  "issues": [

                  ],
                  "transitive": [
                    {
                      "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2020-36518",
                          "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2020-36518"
                          ],
                          "unique": false,
                          "remediation": {
                            "trustedContent": {
                              "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                              "status": "NotAffected",
                              "justification": "VulnerableCodeNotPresent"
                            }
                          }
                        },
                        {
                          "id": "CVE-2022-42004",
                          "title": "Uncontrolled Resource Consumption in FasterXML jackson-databind",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2022-42004"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2022-42003",
                          "title": "Uncontrolled Resource Consumption in Jackson-databind",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2022-42003"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2021-46877",
                          "title": "jackson-databind possible Denial of Service if using JDK serialization to serialize JsonNode",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "None",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "None",
                            "integrityImpact": "Low",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                          },
                          "cvssScore": 8.2,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2021-46877"
                          ],
                          "unique": false
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2020-36518",
                        "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                        "source": "csaf",
                        "cvss": {
                          "attackVector": "Network",
                          "attackComplexity": "Low",
                          "privilegesRequired": "None",
                          "userInteraction": "None",
                          "scope": "Unchanged",
                          "confidentialityImpact": "None",
                          "integrityImpact": "Low",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                        },
                        "cvssScore": 8.2,
                        "severity": "HIGH",
                        "cves": [
                          "CVE-2020-36518"
                        ],
                        "unique": false,
                        "remediation": {
                          "trustedContent": {
                            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                            "status": "NotAffected",
                            "justification": "VulnerableCodeNotPresent"
                          }
                        }
                      }
                    },
                    {
                      "ref": "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
                      "issues": [
                        {
                          "id": "CVE-2024-2700",
                          "title": "quarkus-core leaks local environment variables from Quarkus namespace during application's build",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Local",
                            "attackComplexity": "High",
                            "privilegesRequired": "Low",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "High",
                            "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                          },
                          "cvssScore": 7.0,
                          "severity": "HIGH",
                          "cves": [
                            "CVE-2024-2700"
                          ],
                          "unique": false
                        },
                        {
                          "id": "CVE-2023-2974",
                          "title": "quarkus-core vulnerable to client driven TLS cipher downgrading",
                          "source": "csaf",
                          "cvss": {
                            "attackVector": "Network",
                            "attackComplexity": "Low",
                            "privilegesRequired": "High",
                            "userInteraction": "None",
                            "scope": "Unchanged",
                            "confidentialityImpact": "High",
                            "integrityImpact": "High",
                            "availabilityImpact": "Low",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L"
                          },
                          "cvssScore": 6.7,
                          "severity": "MEDIUM",
                          "cves": [
                            "CVE-2023-2974"
                          ],
                          "unique": false,
                          "remediation": {
                            "trustedContent": {
                              "ref": "pkg:maven/io.quarkus/quarkus-core@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                              "status": "NotAffected",
                              "justification": "VulnerableCodeNotPresent"
                            }
                          }
                        }
                      ],
                      "highestVulnerability": {
                        "id": "CVE-2024-2700",
                        "title": "quarkus-core leaks local environment variables from Quarkus namespace during application's build",
                        "source": "csaf",
                        "cvss": {
                          "attackVector": "Local",
                          "attackComplexity": "High",
                          "privilegesRequired": "Low",
                          "userInteraction": "None",
                          "scope": "Unchanged",
                          "confidentialityImpact": "High",
                          "integrityImpact": "High",
                          "availabilityImpact": "High",
                          "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                        },
                        "cvssScore": 7.0,
                        "severity": "HIGH",
                        "cves": [
                          "CVE-2024-2700"
                        ],
                        "unique": false
                      }
                    }
                  ],
                  "recommendation": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                  "highestVulnerability": {
                    "id": "CVE-2020-36518",
                    "title": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                    "source": "csaf",
                    "cvss": {
                      "attackVector": "Network",
                      "attackComplexity": "Low",
                      "privilegesRequired": "None",
                      "userInteraction": "None",
                      "scope": "Unchanged",
                      "confidentialityImpact": "None",
                      "integrityImpact": "Low",
                      "availabilityImpact": "High",
                      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
                    },
                    "cvssScore": 8.2,
                    "severity": "HIGH",
                    "cves": [
                      "CVE-2020-36518"
                    ],
                    "unique": false,
                    "remediation": {
                      "trustedContent": {
                        "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                        "status": "NotAffected",
                        "justification": "VulnerableCodeNotPresent"
                      }
                    }
                  }
                }
              ]
            }
          }
        }
      }
    },
    "pkg:oci/alpine@sha256%3A1fafb0905264413501df60d90a92ca32df8a2011cbfb4876ddff5ceb20c8f165?arch=amd64&os=linux&repository_url=test.io%2Ftest%2Falpine&tag=test-version": {
      "scanned": {
        "total": 2,
        "direct": 2,
        "transitive": 0
      },
      "providers": {
        "oss-index": {
          "status": {
            "ok": false,
            "name": "oss-index",
            "code": 401,
            "message": "Unauthorized: Verify the provided credentials are valid."
          }
        },
        "trusted-content": {
          "status": {
            "ok": true,
            "name": "trusted-content",
            "code": 200,
            "message": "OK"
          }
        },
        "tpa": {
          "status": {
            "ok": true,
            "name": "tpa",
            "code": 200,
            "message": "OK"
          },
          "sources": {
            "tpa": {
              "summary": {
                "direct": 0,
                "transitive": 0,
                "total": 0,
                "dependencies": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "remediations": 0,
                "recommendations": 1,
                "unscanned": 0
              },
              "dependencies": [
                {
                  "ref": "pkg:oci/alpine@sha256%3A1fafb0905264413501df60d90a92ca32df8a2011cbfb4876ddff5ceb20c8f165?arch=amd64&os=linux&repository_url=test.io%2Ftest%2Falpine&tag=test-version",
                  "recommendation": "pkg:oci/ubi-minimal@sha256%3A06d06f15f7b641a78f2512c8817cbecaa1bf549488e273f5ac27ff1654ed33f0?arch=amd64&repository_url=registry.access.redhat.com%2Fubi9%2Fubi-minimal&tag=9.3-1552"
                }
              ]
            }
          }
        },
        "snyk": {
          "status": {
            "ok": true,
            "name": "snyk",
            "code": 200,
            "message": "OK"
          },
          "sources": {
            "snyk": {
              "summary": {
                "direct": 0,
                "transitive": 0,
                "total": 0,
                "dependencies": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "remediations": 0,
                "recommendations": 1,
                "unscanned": 1
              },
              "dependencies": [
                {
                  "ref": "pkg:oci/quay.io/default-app@0.0.1",
                  "recommendation": "pkg:oci/quay.io/test-app@0.0.2"
                }
              ],
              "unscanned": [
                {
                  "ref": "pkg:oci/debian@sha256%3A7c288032ecf3319045d9fa538c3b0cc868a320d01d03bce15b99c2c336319994?tag=0.0.1",
                  "reason": "unsupported-pkg-type"
                }
              ]
            }
          }
        }
      }
    }
  },
  nvdIssueTemplate: 'https://nvd.nist.gov/vuln/detail/__ISSUE_ID__',
  cveIssueTemplate: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=__ISSUE_ID__',
  imageMapping: "[\n" +
    "  {\n" +
    "    \"purl\": \"pkg:oci/ubi@sha256:f5983f7c7878cc9b26a3962be7756e3c810e9831b0b9f9613e6f6b445f884e74?repository_url=registry.access.redhat.com/ubi9/ubi&tag=9.3-1552&arch=amd64\",\n" +
    "    \"catalogUrl\": \"https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?architecture=amd64&image=65a82982a10f3e68777870b5\"\n" +
    "  },\n" +
    "  {\n" +
    "    \"purl\": \"pkg:oci/ubi-minimal@sha256:06d06f15f7b641a78f2512c8817cbecaa1bf549488e273f5ac27ff1654ed33f0?repository_url=registry.access.redhat.com/ubi9/ubi-minimal&tag=9.3-1552&arch=amd64\",\n" +
    "    \"catalogUrl\": \"https://catalog.redhat.com/software/containers/ubi9/ubi-minimal/615bd9b4075b022acc111bf5?architecture=amd64&image=65a828e3cda4984705d45d26\"\n" +
    "  }\n" +
    "]",
  userId: 'testUser333',
  anonymousId: null,
  writeKey: '',
  rhdaSource: 'trustify'
};
