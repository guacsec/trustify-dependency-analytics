import {AppData} from '@app/api/report';

export const reportMixed: AppData = {
  providerPrivateData: null,
  report: {
    "scanned": {
        "total": 9,
        "direct": 2,
        "transitive": 7
    },
    "providers": {
        "oss-index": {
            "status": {
                "ok": true,
                "name": "oss-index",
                "code": 200,
                "message": "OK"
            },
            "sources": {
                "oss-index": {
                    "summary": {
                        "direct": 0,
                        "transitive": 3,
                        "total": 3,
                        "dependencies": 1,
                        "critical": 0,
                        "high": 3,
                        "medium": 0,
                        "low": 0,
                        "remediations": 1,
                        "recommendations": 2,
                        "unscanned": 0
                    },
                    "dependencies": [
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
                                            "title": "[CVE-2020-36518] CWE-787: Out-of-bounds Write",
                                            "source": "oss-index",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "Low",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                            },
                                            "cvssScore": 7.5,
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
                                            "id": "CVE-2022-42003",
                                            "title": "[CVE-2022-42003] CWE-502: Deserialization of Untrusted Data",
                                            "source": "oss-index",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "Low",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                            },
                                            "cvssScore": 7.5,
                                            "severity": "HIGH",
                                            "cves": [
                                                "CVE-2022-42003"
                                            ],
                                            "unique": false
                                        },
                                        {
                                            "id": "CVE-2022-42004",
                                            "title": "[CVE-2022-42004] CWE-502: Deserialization of Untrusted Data",
                                            "source": "oss-index",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "Low",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                            },
                                            "cvssScore": 7.5,
                                            "severity": "HIGH",
                                            "cves": [
                                                "CVE-2022-42004"
                                            ],
                                            "unique": false
                                        }
                                    ],
                                    "highestVulnerability": {
                                        "id": "CVE-2020-36518",
                                        "title": "[CVE-2020-36518] CWE-787: Out-of-bounds Write",
                                        "source": "oss-index",
                                        "cvss": {
                                            "attackVector": "Network",
                                            "attackComplexity": "Low",
                                            "privilegesRequired": "None",
                                            "userInteraction": "None",
                                            "scope": "Unchanged",
                                            "confidentialityImpact": "None",
                                            "integrityImpact": "None",
                                            "availabilityImpact": "High",
                                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                        },
                                        "cvssScore": 7.5,
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
                            ],
                            "recommendation": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                            "highestVulnerability": {
                                "id": "CVE-2020-36518",
                                "title": "[CVE-2020-36518] CWE-787: Out-of-bounds Write",
                                "source": "oss-index",
                                "cvss": {
                                    "attackVector": "Network",
                                    "attackComplexity": "Low",
                                    "privilegesRequired": "None",
                                    "userInteraction": "None",
                                    "scope": "Unchanged",
                                    "confidentialityImpact": "None",
                                    "integrityImpact": "None",
                                    "availabilityImpact": "High",
                                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                },
                                "cvssScore": 7.5,
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
                            "ref": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                            "issues": [
                                
                            ],
                            "transitive": [
                                
                            ],
                            "recommendation": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
                        }
                    ]
                }
            }
        },
        "trusted-content": {
            "status": {
                "ok": true,
                "name": "trusted-content",
                "code": 200,
                "message": "OK"
            },
            "sources": {
                
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
                        "transitive": 4,
                        "total": 4,
                        "dependencies": 2,
                        "critical": 0,
                        "high": 1,
                        "medium": 3,
                        "low": 0,
                        "remediations": 1,
                        "recommendations": 2,
                        "unscanned": 0
                    },
                    "dependencies": [
                        {
                            "ref": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
                            "issues": [
                                
                            ],
                            "transitive": [
                                {
                                    "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
                                    "issues": [
                                        {
                                            "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-2421244",
                                            "title": "Denial of Service (DoS)",
                                            "source": "snyk",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "Low",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                            },
                                            "cvssScore": 7.5,
                                            "severity": "HIGH",
                                            "cves": [
                                                "CVE-2020-36518"
                                            ],
                                            "unique": false,
                                            "remediation": {
                                                "fixedIn": [
                                                    "2.12.6.1",
                                                    "2.13.2.1",
                                                    "2.14.0"
                                                ],
                                                "trustedContent": {
                                                    "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                                                    "status": "NotAffected",
                                                    "justification": "VulnerableCodeNotPresent"
                                                }
                                            }
                                        },
                                        {
                                            "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038424",
                                            "title": "Denial of Service (DoS)",
                                            "source": "snyk",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "High",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "exploitCodeMaturity": "Proof of concept code",
                                                "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P"
                                            },
                                            "cvssScore": 5.9,
                                            "severity": "MEDIUM",
                                            "cves": [
                                                
                                            ],
                                            "unique": true,
                                            "remediation": {
                                                "fixedIn": [
                                                    "2.13.4"
                                                ]
                                            }
                                        },
                                        {
                                            "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-3038426",
                                            "title": "Denial of Service (DoS)",
                                            "source": "snyk",
                                            "cvss": {
                                                "attackVector": "Network",
                                                "attackComplexity": "High",
                                                "privilegesRequired": "None",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "None",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "High",
                                                "exploitCodeMaturity": "Proof of concept code",
                                                "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P"
                                            },
                                            "cvssScore": 5.9,
                                            "severity": "MEDIUM",
                                            "cves": [
                                                "CVE-2022-42003"
                                            ],
                                            "unique": false,
                                            "remediation": {
                                                "fixedIn": [
                                                    "2.12.7.1",
                                                    "2.13.4.2"
                                                ]
                                            }
                                        }
                                    ],
                                    "highestVulnerability": {
                                        "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-2421244",
                                        "title": "Denial of Service (DoS)",
                                        "source": "snyk",
                                        "cvss": {
                                            "attackVector": "Network",
                                            "attackComplexity": "Low",
                                            "privilegesRequired": "None",
                                            "userInteraction": "None",
                                            "scope": "Unchanged",
                                            "confidentialityImpact": "None",
                                            "integrityImpact": "None",
                                            "availabilityImpact": "High",
                                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                        },
                                        "cvssScore": 7.5,
                                        "severity": "HIGH",
                                        "cves": [
                                            "CVE-2020-36518"
                                        ],
                                        "unique": false,
                                        "remediation": {
                                            "fixedIn": [
                                                "2.12.6.1",
                                                "2.13.2.1",
                                                "2.14.0"
                                            ],
                                            "trustedContent": {
                                                "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                                                "status": "NotAffected",
                                                "justification": "VulnerableCodeNotPresent"
                                            }
                                        }
                                    }
                                }
                            ],
                            "recommendation": "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                            "highestVulnerability": {
                                "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-2421244",
                                "title": "Denial of Service (DoS)",
                                "source": "snyk",
                                "cvss": {
                                    "attackVector": "Network",
                                    "attackComplexity": "Low",
                                    "privilegesRequired": "None",
                                    "userInteraction": "None",
                                    "scope": "Unchanged",
                                    "confidentialityImpact": "None",
                                    "integrityImpact": "None",
                                    "availabilityImpact": "High",
                                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                },
                                "cvssScore": 7.5,
                                "severity": "HIGH",
                                "cves": [
                                    "CVE-2020-36518"
                                ],
                                "unique": false,
                                "remediation": {
                                    "fixedIn": [
                                        "2.12.6.1",
                                        "2.13.2.1",
                                        "2.14.0"
                                    ],
                                    "trustedContent": {
                                        "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                                        "status": "NotAffected",
                                        "justification": "VulnerableCodeNotPresent"
                                    }
                                }
                            }
                        },
                        {
                            "ref": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                            "issues": [
                                
                            ],
                            "transitive": [
                                {
                                    "ref": "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
                                    "issues": [
                                        {
                                            "id": "SNYK-JAVA-ORGPOSTGRESQL-3146847",
                                            "title": "Information Exposure",
                                            "source": "snyk",
                                            "cvss": {
                                                "attackVector": "Local",
                                                "attackComplexity": "High",
                                                "privilegesRequired": "Low",
                                                "userInteraction": "None",
                                                "scope": "Unchanged",
                                                "confidentialityImpact": "High",
                                                "integrityImpact": "None",
                                                "availabilityImpact": "None",
                                                "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                                            },
                                            "cvssScore": 4.7,
                                            "severity": "MEDIUM",
                                            "cves": [
                                                "CVE-2022-41946"
                                            ],
                                            "unique": false,
                                            "remediation": {
                                                "fixedIn": [
                                                    "42.2.27",
                                                    "42.3.8",
                                                    "42.4.3",
                                                    "42.5.1"
                                                ]
                                            }
                                        }
                                    ],
                                    "highestVulnerability": {
                                        "id": "SNYK-JAVA-ORGPOSTGRESQL-3146847",
                                        "title": "Information Exposure",
                                        "source": "snyk",
                                        "cvss": {
                                            "attackVector": "Local",
                                            "attackComplexity": "High",
                                            "privilegesRequired": "Low",
                                            "userInteraction": "None",
                                            "scope": "Unchanged",
                                            "confidentialityImpact": "High",
                                            "integrityImpact": "None",
                                            "availabilityImpact": "None",
                                            "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                                        },
                                        "cvssScore": 4.7,
                                        "severity": "MEDIUM",
                                        "cves": [
                                            "CVE-2022-41946"
                                        ],
                                        "unique": false,
                                        "remediation": {
                                            "fixedIn": [
                                                "42.2.27",
                                                "42.3.8",
                                                "42.4.3",
                                                "42.5.1"
                                            ]
                                        }
                                    }
                                }
                            ],
                            "recommendation": "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.8.Final-redhat-00006?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar",
                            "highestVulnerability": {
                                "id": "SNYK-JAVA-ORGPOSTGRESQL-3146847",
                                "title": "Information Exposure",
                                "source": "snyk",
                                "cvss": {
                                    "attackVector": "Local",
                                    "attackComplexity": "High",
                                    "privilegesRequired": "Low",
                                    "userInteraction": "None",
                                    "scope": "Unchanged",
                                    "confidentialityImpact": "High",
                                    "integrityImpact": "None",
                                    "availabilityImpact": "None",
                                    "cvss": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                                },
                                "cvssScore": 4.7,
                                "severity": "MEDIUM",
                                "cves": [
                                    "CVE-2022-41946"
                                ],
                                "unique": false,
                                "remediation": {
                                    "fixedIn": [
                                        "42.2.27",
                                        "42.3.8",
                                        "42.4.3",
                                        "42.5.1"
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
},
  ossIssueTemplate: 'http://ossindex.sonatype.org/vulnerability/__ISSUE_ID__',
  snykIssueTemplate: 'https://security.snyk.io/vuln/__ISSUE_ID__',
  nvdIssueTemplate: 'https://nvd.nist.gov/vuln/detail/__ISSUE_ID__',
  snykSignup: 'https://app.snyk.io/login',
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
  userId: 'testUser003',
  anonymousId: null,
  writeKey: '',
  rhdaSource: 'vscode'
};