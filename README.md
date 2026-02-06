# Dependency Analytics

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/guacsec/trustify-dependency-analytics/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/guacsec/trustify-dependency-analytics/actions/workflows/ci.yaml)

## Dependencies

- Trustify: Provides vulnerability data and recommendations [Trustify](https://github.com/guacsec/trustify)
- Postgres Database: Stores data needed for the Model Cards functionality. See [Model Cards](#model-cards)
- Redis cache: Allows caching licenses, recommendations and remediations. Can be configured with the `quarkus.redis.host` parameter
- Deps.dev: For license information

## Vulnerability providers

It is possible to integrate with any number of vulnerability providers that follow the [Trustify](https://github.com/guacsec/trustify) API specification.

### Configure a Trustify Vulnerability provider

You can define any number of vulnerability providers where the key is the identifier

- `providers.provider1.host` - The base URL of the Trustify provider endpoint (e.g., `https://trustify.example.com`)
- `providers.provider1.auth.server-url` - OIDC/OAuth2 server URL for authentication (e.g., `https://auth.example.com/realms/trustify`)
- `providers.provider1.auth.client-id` - OAuth2 client ID for authenticating with the provider
- `providers.provider1.auth.client-secret` - OAuth2 client secret for authenticating with the provider
- `providers.provider1.auth.token-timeout` - Token request timeout duration (default: `10s`)
- `providers.provider1.auth.client-timeout` - OAuth2 client timeout duration (default: `30s`)
- `providers.provider1.disabled` - Boolean flag to disable this specific provider (default: `false`)

## License providers

We rely on [Deps.dev API](https://docs.deps.dev/api/v3alpha/#purllookupbatch) for retrieving license data

You can use the following configuration properties:

- `api.licenses.depsdev.host`: DepsDev API endpoint (https://api.deps.dev)
- `api.licenses.depsdev.timeout`: Connection timeout (60s)
- `licenses.file`: Relative or absolute path to the licenses configuration file.

## OpenAPI and SwaggerUI

- OpenAPI Spec: There is an [openapi.yaml](https://maven.pkg.github.com/guacsec/trustify-da-api-spec/blob/main/api/v5/openapi.yaml)
- Swagger UI: Available at http://localhost:8080/q/swagger-ui for development or when enabled with the property `quarkus.swagger-ui.always-include=true`

## Recommendations

By default the service will look for Red Hat Trusted Content remmediations and recommendations. If you want to opt out from this service
you can use the `recommend` query parameter and set it to `false`. Example `/analysis?recommend=false`

## Dependency Analytics API

Here you can find the [Dependency Analytics API Specification](https://github.com/guacsec/trustify-da-api-spec) together with
the Java and Javascript generated data model.

## License Analysis `/api/v5/licenses`

The endpoint can be use to only retrieve information about licenses found in the given package urls. It will return a dictionary with the
licenses found in the different License providers (evidences) and then conclude which is the most permissive license that can be used.

### Categories

The system will use the `licenses.file` configuration file to categorized the retrieved licenses into:

- PERMISSIVE
- WEAK_COPYLEFT
- STRONG_COPYLEFT
- UNKNOWN

It will also use the `exception-suffixes` to decide if a `STRONG_COPYLEFT` license can be categorized as `WEAK_COPYLEFT`. The other
suffixes will be ignored and the category will not be changed. Example `GPL-3.0-only`.

### License evidences and concluded license.

All licenses found in the license provider response will be considered as evidences. Then the system will conclude which is the most suitable
license that can be used. It will be the more permissive license that is allowed. Some exceptions must be declared for multi-license declaration.

- If multiple licenses are found, the backend doesn't decide which source is more reliable or if one should invalidate another. It just takes
**the more permissive** license.
- If the SPDX expression defines an `OR` clause, the system will conclude that the **more permissive can be used**.
- If the SPDX expression defines an `AND` clause, the system will conclude that the **more restrictive must be used**.
- If the SPDX license is categorized as `STRONG_COPYLEFT` but defines an exception that makes it less restrictive, the system will adapt the category to `WEAK_COPYLEFT`. Example `GPL-3.0 with classpath Exception`.

The report will also provide a summary of the different licenses found.

```bash
echo '{
  "purls": [
    "pkg:npm/atob@2.1.2",
    "pkg:npm/node-forge@1.3.0",
    "pkg:npm/rc@1.2.8",
    "pkg:npm/dompurify@2.3.0",
    "pkg:npm/diff-lcs@1.3.0",
    "pkg:npm/type-fest@0.20.2",
    "pkg:npm/path-is-inside@1.0.0"
  ]
}' | http -v :8080/api/v5/licenses
```

### Summary
```json
        "summary": {
            "concluded": 7, // number of concluded licenses
            "permissive": 8, // total number of permissive licenses found. Including the declared but not concluded.
            "strong-copyleft": 1, // total number of strong-copyleft licenses found. Including the declared but not concluded.
            "total": 12, // total number of declared licenses found.
            "unknown": 2, // total number of unknown licenses found. Including the declared but not concluded.
            "weak-copyleft": 1 // total number of weak-copyleft licenses found. Including the declared but not concluded.
        }
```

### Result example
```json
            "pkg:npm/rc@1.2.8": {
                "concluded": {
                    "category": "PERMISSIVE",
                    "expression": "Apache-2.0 OR BSD-2-Clause OR MIT",
                    "identifiers": [
                        "Apache-2.0",
                        "BSD-2-Clause",
                        "MIT"
                    ],
                    "name": "Apache-2.0 OR BSD-2-Clause OR MIT",
                    "source": "deps.dev",
                    "sourceUrl": "https://api.deps.dev"
                },
                "evidence": [
                    {
                        "category": "PERMISSIVE",
                        "expression": "Apache-2.0 OR BSD-2-Clause OR MIT",
                        "identifiers": [
                            "Apache-2.0",
                            "BSD-2-Clause",
                            "MIT"
                        ],
                        "name": "Apache-2.0 OR BSD-2-Clause OR MIT",
                        "source": "deps.dev",
                        "sourceUrl": "https://api.deps.dev"
                    }
                ]
            },
```


## Dependency Analysis `/api/v5/analysis`

The expected input data format is a Software Bill of Materials (SBOM) containing the aggregate of all direct and transitive
dependencies of a project. The license information will also be added to this report. See [License Analysis](#license-analysis-apiv5licenses).

The `Content-Type` HTTP header will allow Dependency Analytics distinguish between the different supported SBOM formats.

- [CycloneDX](https://cyclonedx.org/specification/overview/): `application/vnd.cyclonedx+json`
- [SPDX](https://spdx.dev/specifications/): `application/vnd.spdx+json`

### Example

You can generate a CycloneDx JSON SBOM with the following command:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:2.7.6:makeBom -DoutputFormat=json -DexcludeTestProject
```

The generated file will be located under `./target/bom.json`. Make sure the request `Content-Type` is set to `application/vnd.cyclonedx+json`.
Then you can analyze the vulnerabilities with the following command:

```bash
$ http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"application/json" @'target/bom.json'
```

### Verbose Mode

When the Dependency Graph Analysis returns a JSON report it contains all vulnerability data by default. The _Verbose mode_ can be disabled
in order to retrieve just a Summary. Use the `verbose=false` Query parameter to disable it.

```bash
$ http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"application/json" @'target/sbom.json' verbose==false

{
    "licenses": [
        {
            "packages": {},
            "status": {
                "message": "OK",
                "name": "deps.dev",
                "ok": true,
                "warnings": {}
            },
            "summary": {
                "concluded": 10,
                "permissive": 8,
                "strong-copyleft": 0,
                "total": 12,
                "unknown": 2,
                "weak-copyleft": 2
            }
        }
    ],
    "providers": {
        "rhtpa": {
            "sources": {
                "osv-github": {
                    "summary": {
                        "critical": 1,
                        "dependencies": 3,
                        "direct": 0,
                        "high": 4,
                        "low": 0,
                        "medium": 2,
                        "recommendations": 3,
                        "remediations": 0,
                        "total": 7,
                        "transitive": 7,
                        "unscanned": 0
                    }
                },
                "redhat-csaf": {
                    "summary": {
                        "critical": 1,
                        "dependencies": 2,
                        "direct": 0,
                        "high": 1,
                        "low": 0,
                        "medium": 0,
                        "recommendations": 3,
                        "remediations": 0,
                        "total": 2,
                        "transitive": 2,
                        "unscanned": 0
                    }
                }
            },
            "status": {
                "code": 200,
                "message": "OK",
                "name": "rhtpa",
                "ok": true,
                "warnings": {}
            }
        }
    },
    "scanned": {
        "direct": 3,
        "total": 10,
        "transitive": 7
    }
}
```

### Client Token Authentication

If clients don't provide the token to authenticate against the Vulnerability Provider the default one will be used instead but vulnerabilities unique to
that specific provider will not show all the details.

To provide the client authentication tokens use HTTP Headers in the request. The format for the tokens Headers is `ex-provider-token`. e.g. `ex-trustify-token`:

```bash
http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json' ex-trustify-token:the-client-token
```

In case the vulnerability provider requires of Basic Authentication the headers will be `ex-provider-user` and `ex-provider-token`.

```bash
http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json' ex-oss-index-user:the-client-username ex-oss-index-token:the-client-token
```

### HTML Report

By default the response Content-Type will be `application/json` but if the `text/html` media type is requested instead, the response
will be processed and converted into HTML.

The HTML report will show limited information:

- Public vulnerabilities retrieved with the default token will not show the _Exploit Maturity_
- Private vulnerabilities (i.e. vulnerabilities reported by the provider) will not be displayed.

```bash
$ http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json'

<html>
...
</html>
```

### Mime-Multipart response

It is also possible to get a MIME Multipart response containing a JSON report with the HTML attached.
For that, use the `Accept: multipart/mixed` request header.


```bash
http :8080/api/v5/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"multipart/mixed" @'target/sbom.json'
HTTP/1.1 200 OK
    boundary="----=_Part_2_2047647971.1682593849895"
Content-Type: multipart/mixed;
MIME-Version: 1.0
Message-Id: <49857413.3.1682593849896@granada>
User-Agent: HTTPie/3.2.1
transfer-encoding: chunked
x-quarkus-hot-deployment-done: true

------=_Part_2_2047647971.1682593849895
Content-Type: application/json
Content-Transfer-Encoding: binary

{
{
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
            sources": {
                "oss-index": {
                    "summary": {
                        ...
                    },
                    "dependencies": [
                        {
                        "ref": {
                            "name": "log4j:log4j",
                            "version": "1.2.17"
                        },
                        ...
                    }
                }
            }
        }
    }
}
------=_Part_2_2047647971.1682593849895
Content-Type: text/html
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment; filename=report.html

<html>
    <header>
        <title>Dependency Analytics Report</title>
    </header>
    <body>
        <h1>Dependency Report</h1>
        <p>This is an example</p>
    </body>
</html>
------=_Part_2_2047647971.1682593849895--

```

### Batch Dependency Analysis `/api/v5/batch-analysis`

This API performs dependency analysis for multiple projects.

The expected input data format is a dictionary. The keys are the package urls of the projects, while the values are the SBOMs of the projects.

All the parameters for the Dependency Analysis API are applicable to the Batch Dependency Analysis API.

The expected response varies based on the media type of the request:
- When media type `application/json` is requested, the response will be a dictionary of JSON reports.
- When media type `text/html` is requested, the response will be an html report with vulnerability information for all the requested projects.
- When media type `multipart/mixed` is requested, the response will contain both the dictionary of JSON reports and the html report.

## Token validation

Clients are allowed to validate the vulnerability provider token with a specific endpoint. That will allow IDEs and the CLI to persist the different
tokens and validate them when saving them.

The request will be a GET to the `/token` path containing the HTTP header with the token. The header format will follow the same rules as for the
other HTTP requests. i.e. `ex-<provider>-token`

```bash
http -v :8080/api/v5/token ex-trustify-token==example-token
```

The possible responses are:

- 200 - Token validated successfully
- 400 - Missing provider authentication headers
- 401 - Invalid auth token provided or Missing required authentication header (trust-da-token)
- 403 - The token is not authorized
- 429 - Rate limit exceeded
- 500 - Server error

## Model Cards

These API endpoints provide security and safety metrics about Large Language Models
coming from different sources together with recommendations that will help users make
informed decisions about which LLM is more suitable to their needs and how to increase
the security with the use of recommended guardrails.

See [Model Cards Readme](docs/model-cards.md) for more details.

## Telemetry

API Clients are expected to send the following HTTP Headers in order to help observe the use of the Backend service:

- `trust-da-token` HTTP Header that will be used to correlate different events related to the same user. If the header
is not provided an anonymous event with a generated UUID will be sent instead.
- `trust-da-source` The client consuming the Dependency Analytics API. It will default to the `User-Agent` HTTP Header
- `trust-da-operation-type` When performing an analysis, clients might specify whether it is a component-analysis or a stack-analysis
- `trust-da-pkg-manager` The Package manager that the SBOM was generated from (examples: `maven`, `gradle-kotlin`)

Telemetry connects to [Segment](https://segment.com/) for sending events from the HTML Report.
The connection can be configured with the following properties.

- `telemetry.disabled`: To completely disable telemetry
- `telemetry.write-key`: Authentication key to connect to Segment

## Monitoring

We are using Sentry (GlitchTip) to report errors for troubleshooting. By default monitoring
is disabled but you can enabled it with:

```
monitoring.enabled=true
```

To configure Sentry use the following properties:

```
# Get the DSN Url in your project settings
monitoring.sentry.dsn=<your_dsn_url>
# Server Name to use as a tag
monitoring.sentry.servername=localhost
# Environment to use as a tag. Defaults to production
monitoring.sentry.environment=production
```

Three different error types can be reported:

- Client Exceptions: Bad requests from clients
- Server Errors: Unexpected errors
- Provider Errors: Errors coming from the providers responses

In all cases, the original request and headers are logged for the SRE Team to review.

## Deploy on OpenShift

The required parameters can be injected as environment variables through a secret. Create the `trust-da-secret` Secret before deploying the application.

```bash
oc create secret generic -n trust-da --from-literal=api-trustify-token=<api_token> trust-da-secret
```

After that you can use the [trust-da.yaml](./deploy/trust-da.yaml)

```bash
oc apply -f deploy/trust-da.yaml
```

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:
```shell script
./mvnw compile quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at http://localhost:8080/q/dev/.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _uber-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _uber-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _uber-jar_, is now runnable using `java -jar target/*-runner.jar`.

To disable frontend production bundle files creation and copying into the freemarker/generated directory execute the following command:
```shell script
./mvnw package -P dev
```

## Creating a native executable

You can create a native executable using:
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using:
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/exhort-0.0.1-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

## Running the Frontend react application

You can run the frontend as a stand-alone application in dev mode by switching to the UI folder and executing the following command:
```shell script
yarn start
```
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

Once ready to build for production, from the UI folder execute:
```shell script
yarn build
```
This will create 4 bundle files and copy it into the freemarker/generated directory.:

- main.js - This is all the code under the ui/src directory
- vendor.js - these are the dependencies we pull in from node_modules, like react, and @patternfly
- main.css  - styles under the ui/src directory
- vendor.css  - styles coming from node_modules, like all the PatternFly styles

These files are included in the freemarker template file (report.ftl) via [#include] statements.
