import {AppData} from '@app/api/report';

export const reportBasic: AppData = {
  providerPrivateData: null,
  report: {
    "scanned" : {
      "total" : 10,
      "direct" : 3,
      "transitive" : 7
    },
    "providers" : {
      "rhtpa" : {
        "status" : {
          "ok" : true,
          "name" : "rhtpa",
          "code" : 200,
          "message" : "OK",
          "warnings" : { }
        },
        "sources" : {
          "osv-github" : {
            "summary" : {
              "direct" : 0,
              "transitive" : 7,
              "total" : 7,
              "dependencies" : 3,
              "critical" : 1,
              "high" : 4,
              "medium" : 2,
              "low" : 0,
              "remediations" : 0,
              "recommendations" : 3,
              "unscanned" : 0
            },
            "dependencies" : [ {
              "ref" : "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
              "transitive" : [ {
                "ref" : "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
                "issues" : [ {
                  "id" : "CVE-2024-1597",
                  "source" : "osv-github",
                  "cvssScore" : 10.0,
                  "severity" : "CRITICAL",
                  "cves" : [ "CVE-2024-1597" ],
                  "unique" : false
                }, {
                  "id" : "CVE-2022-41946",
                  "source" : "osv-github",
                  "cvssScore" : 4.7,
                  "severity" : "MEDIUM",
                  "cves" : [ "CVE-2022-41946" ],
                  "unique" : false
                } ],
                "highestVulnerability" : {
                  "id" : "CVE-2024-1597",
                  "source" : "osv-github",
                  "cvssScore" : 10.0,
                  "severity" : "CRITICAL",
                  "cves" : [ "CVE-2024-1597" ],
                  "unique" : false
                }
              } ],
              "highestVulnerability" : {
                "id" : "CVE-2024-1597",
                "source" : "osv-github",
                "cvssScore" : 10.0,
                "severity" : "CRITICAL",
                "cves" : [ "CVE-2024-1597" ],
                "unique" : false
              }
            }, {
              "ref" : "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
              "transitive" : [ {
                "ref" : "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
                "issues" : [ {
                  "id" : "CVE-2020-36518",
                  "title" : "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                  "source" : "osv-github",
                  "cvssScore" : 7.5,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2020-36518" ],
                  "unique" : false
                }, {
                  "id" : "CVE-2022-42003",
                  "title" : "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
                  "source" : "osv-github",
                  "cvssScore" : 7.5,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2022-42003" ],
                  "unique" : false
                }, {
                  "id" : "CVE-2022-42004",
                  "title" : "In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. An application is vulnerable only with certain customized choices for deserialization.",
                  "source" : "osv-github",
                  "cvssScore" : 7.5,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2022-42004" ],
                  "unique" : false
                } ],
                "highestVulnerability" : {
                  "id" : "CVE-2020-36518",
                  "title" : "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                  "source" : "osv-github",
                  "cvssScore" : 7.5,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2020-36518" ],
                  "unique" : false
                }
              }, {
                "ref" : "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
                "issues" : [ {
                  "id" : "CVE-2024-2700",
                  "source" : "osv-github",
                  "cvssScore" : 7.0,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2024-2700" ],
                  "unique" : false
                }, {
                  "id" : "CVE-2023-2974",
                  "title" : "Quarkus-core: tls protocol configured with quarkus.http.ssl.protocols is not enforced, client can enforce weaker supported tls protocol",
                  "source" : "osv-github",
                  "cvssScore" : 6.5,
                  "severity" : "MEDIUM",
                  "cves" : [ "CVE-2023-2974" ],
                  "unique" : false
                } ],
                "highestVulnerability" : {
                  "id" : "CVE-2024-2700",
                  "source" : "osv-github",
                  "cvssScore" : 7.0,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2024-2700" ],
                  "unique" : false
                }
              } ],
              "highestVulnerability" : {
                "id" : "CVE-2020-36518",
                "title" : "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
                "source" : "osv-github",
                "cvssScore" : 7.5,
                "severity" : "HIGH",
                "cves" : [ "CVE-2020-36518" ],
                "unique" : false
              }
            }, {
              "ref" : "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar",
              "recommendation" : "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00003?classifier=sources&repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            }, {
              "ref" : "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
              "recommendation" : "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2.redhat-00005?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            }, {
              "ref" : "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
              "recommendation" : "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5.redhat-00003?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            } ]
          },
          "redhat-csaf" : {
            "summary" : {
              "direct" : 0,
              "transitive" : 2,
              "total" : 2,
              "dependencies" : 2,
              "critical" : 1,
              "high" : 1,
              "medium" : 0,
              "low" : 0,
              "remediations" : 0,
              "recommendations" : 3,
              "unscanned" : 0
            },
            "dependencies" : [ {
              "ref" : "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
              "transitive" : [ {
                "ref" : "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
                "issues" : [ {
                  "id" : "CVE-2024-1597",
                  "source" : "redhat-csaf",
                  "cvssScore" : 9.8,
                  "severity" : "CRITICAL",
                  "cves" : [ "CVE-2024-1597" ],
                  "unique" : false
                } ],
                "highestVulnerability" : {
                  "id" : "CVE-2024-1597",
                  "source" : "redhat-csaf",
                  "cvssScore" : 9.8,
                  "severity" : "CRITICAL",
                  "cves" : [ "CVE-2024-1597" ],
                  "unique" : false
                }
              } ],
              "highestVulnerability" : {
                "id" : "CVE-2024-1597",
                "source" : "redhat-csaf",
                "cvssScore" : 9.8,
                "severity" : "CRITICAL",
                "cves" : [ "CVE-2024-1597" ],
                "unique" : false
              }
            }, {
              "ref" : "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
              "transitive" : [ {
                "ref" : "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
                "issues" : [ {
                  "id" : "CVE-2024-2700",
                  "source" : "redhat-csaf",
                  "cvssScore" : 7.0,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2024-2700" ],
                  "unique" : false
                } ],
                "highestVulnerability" : {
                  "id" : "CVE-2024-2700",
                  "source" : "redhat-csaf",
                  "cvssScore" : 7.0,
                  "severity" : "HIGH",
                  "cves" : [ "CVE-2024-2700" ],
                  "unique" : false
                }
              } ],
              "highestVulnerability" : {
                "id" : "CVE-2024-2700",
                "source" : "redhat-csaf",
                "cvssScore" : 7.0,
                "severity" : "HIGH",
                "cves" : [ "CVE-2024-2700" ],
                "unique" : false
              }
            }, {
              "ref" : "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar",
              "recommendation" : "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00003?classifier=sources&repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            }, {
              "ref" : "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
              "recommendation" : "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2.redhat-00005?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            }, {
              "ref" : "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
              "recommendation" : "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5.redhat-00003?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            } ]
          }
        }
      }
    },
    "licenses" : [ {
      "status" : {
        "ok" : true,
        "name" : "SBOM",
        "code" : 200,
        "message" : "OK",
        "warnings" : { }
      },
      "summary" : {
        "total" : 12,
        "concluded" : 10,
        "permissive" : 8,
        "weakCopyleft" : 4,
        "strongCopyleft" : 0,
        "unknown" : 0,
        "deprecated" : 2,
        "osiApproved" : 10,
        "fsfLibre" : 10
      },
      "projectLicense" : {
        "identifiers" : [ {
          "id" : "Apache-2.0",
          "name" : "Apache License 2.0",
          "isDeprecated" : false,
          "isOsiApproved" : true,
          "isFsfLibre" : true,
          "category" : "PERMISSIVE"
        } ],
        "expression" : "Apache-2.0",
        "name" : "Apache License 2.0",
        "category" : "PERMISSIVE",
        "source" : "SBOM",
        "sourceUrl" : "https://spdx.org"
      },
      "packages" : {
        "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/org.postgresql/postgresql@42.5.0" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "BSD-2-Clause",
              "name" : "BSD 2-Clause \"Simplified\" License",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "BSD-2-Clause",
            "name" : "BSD 2-Clause \"Simplified\" License",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "BSD-2-Clause",
              "name" : "BSD 2-Clause \"Simplified\" License",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "BSD-2-Clause",
            "name" : "BSD 2-Clause \"Simplified\" License",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SBOM",
            "sourceUrl" : "https://spdx.org"
          } ]
        }
      }
    }, {
      "status" : {
        "ok" : true,
        "code" : 200,
        "message" : "OK",
        "name" : "deps.dev",
        "warnings" : { }
      },
      "summary" : {
        "total" : 12,
        "concluded" : 10,
        "permissive" : 8,
        "weakCopyleft" : 4,
        "strongCopyleft" : 0,
        "unknown" : 0,
        "deprecated" : 2,
        "osiApproved" : 10,
        "fsfLibre" : 10
      },
      "projectLicense" : {
        "identifiers" : [ {
          "id" : "Apache-2.0",
          "name" : "Apache License 2.0",
          "isDeprecated" : false,
          "isOsiApproved" : true,
          "isFsfLibre" : true,
          "category" : "PERMISSIVE"
        } ],
        "expression" : "Apache-2.0",
        "name" : "Apache License 2.0",
        "category" : "PERMISSIVE",
        "source" : "SBOM",
        "sourceUrl" : "https://spdx.org"
      },
      "packages" : {
        "pkg:maven/io.quarkus/quarkus-jdbc-h2@2.13.5.Final?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "non-standard",
              "name" : "non-standard",
              "category" : "UNKNOWN"
            } ],
            "expression" : "non-standard",
            "name" : "non-standard",
            "category" : "UNKNOWN",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "GPL-2.0-only WITH Classpath-exception-2.0",
              "name" : "GNU General Public License v2.0 only with Classpath exception 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "GPL-2.0-only WITH Classpath-exception-2.0",
            "name" : "GNU General Public License v2.0 only with Classpath exception 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "BSD-2-Clause",
              "name" : "BSD 2-Clause \"Simplified\" License",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "BSD-2-Clause",
            "name" : "BSD 2-Clause \"Simplified\" License",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "BSD-2-Clause",
              "name" : "BSD 2-Clause \"Simplified\" License",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "BSD-2-Clause",
            "name" : "BSD 2-Clause \"Simplified\" License",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "BSD-2-Clause",
              "name" : "BSD 2-Clause \"Simplified\" License",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "BSD-2-Clause",
            "name" : "BSD 2-Clause \"Simplified\" License",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "non-standard",
              "name" : "non-standard",
              "category" : "UNKNOWN"
            } ],
            "expression" : "non-standard",
            "name" : "non-standard",
            "category" : "UNKNOWN",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "GPL-2.0-only WITH Classpath-exception-2.0",
              "name" : "GNU General Public License v2.0 only with Classpath exception 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "GPL-2.0-only WITH Classpath-exception-2.0",
            "name" : "GNU General Public License v2.0 only with Classpath exception 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "GPL-2.0-with-classpath-exception",
              "name" : "GNU General Public License v2.0 w/Classpath exception",
              "isDeprecated" : true,
              "isOsiApproved" : false,
              "category" : "WEAK_COPYLEFT"
            }, {
              "id" : "EPL-2.0",
              "name" : "Eclipse Public License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "WEAK_COPYLEFT"
            } ],
            "expression" : "(GPL-2.0-with-classpath-exception AND EPL-2.0)",
            "name" : "GNU General Public License v2.0 w/Classpath exception AND Eclipse Public License 2.0",
            "category" : "WEAK_COPYLEFT",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        },
        "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar" : {
          "concluded" : {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          },
          "evidence" : [ {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "deps.dev",
            "sourceUrl" : "https://api.deps.dev"
          }, {
            "identifiers" : [ {
              "id" : "Apache-2.0",
              "name" : "Apache License 2.0",
              "isDeprecated" : false,
              "isOsiApproved" : true,
              "isFsfLibre" : true,
              "category" : "PERMISSIVE"
            } ],
            "expression" : "Apache-2.0",
            "name" : "Apache License 2.0",
            "category" : "PERMISSIVE",
            "source" : "SPDX",
            "sourceUrl" : "https://spdx.org"
          } ]
        }
      }
    } ]
  },
  remediationTemplate: 'https://deps.dev/__PACKAGE_TYPE__/__PACKAGE_NAME__/__PACKAGE_VERSION__',
  cveIssueTemplate: 'https://nvd.nist.gov/vuln/detail/__ISSUE_ID__',
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
  brandingConfig : {
    imageRecommendation: "Test container image recommendations for enhanced security.",
    exploreDescription: "The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.",
    imageRecommendationLink: "https://test-catalog.example.com/containers/",
    displayName: "Trustify Test",
    exploreTitle: "Learn more about Trustify",
    exploreUrl: "https://guac.sh/trustify/"
  }
};
