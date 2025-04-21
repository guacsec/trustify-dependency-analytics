# Exhort

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/trustification/exhort/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/trustification/exhort/actions/workflows/ci.yaml)

## Dependencies

- Redis cache: Allows caching Red Hat recommendations and remediations. Can be configured with the `quarkus.redis.host` parameter
- TrustedContent: Provides Red Hat recommendations and remediations.
- External Vulnerability providers enabled.

## Required parameters

- `api.tpa.host` The host of the Trusted Profile Analyzer service. Used as a Vulnerability Provider.
- `api.tpa.token` The TPA token for default authentication to use when the `ex-tpa-token` header is not provided
- `api.snyk.token` Snyk API token for default authentication when the Snyk integration is enabled

## OpenAPI and SwaggerUI

- OpenAPI Spec: There is an [openapi.yaml](https://github.com/trustification/exhort-api-spec/blob/main/api/v4/openapi.yaml)
- Swagger UI: Available at http://localhost:8080/q/swagger-ui for development or when enabled with the property `quarkus.swagger-ui.always-include=true`

## Providers

Currently these are the available providers that will provide a vulnerability report for your components or full dependency graph.

- TPA ([`Trusted Profile Analyzer`](https://www.trustification.io/))
- Snyk (`snyk`)
- OSS Index (`oss-index`)

You can disable a given provider for the dependency graph analysis by using `api.<provider>.disabled=true` property at startup.

Providers should be defined as a multi-valued list in the `providers` Query Parameter. e.g. `/analysis?providers=snyk&providers=oss-index`

## Package URL Types

The supported Package URL types depends on each external provider.

- TPA and OSS Index don't have any limitation on the type used.
- Snyk: Given the limitations of the API endpoint currently being used only supports the following PackageURL types:
  - Maven (`maven`)
  - Gradle (`gradle`)
  - NPM (`npm`)
  - Go Modules (`gomodules`)
  - Pip (`pip`)
  - RPM (`rpm`)
  - Cocoapods (`cocoapods`)
  - Gem (`gem`)
  - NuGet (`nuget`)
  - Debian (`deb`)

## Exhort API

Here you can find the [Exhort API Specification](https://github.com/trustification/exhort-api-spec) together with
the Java and Javascript generated data model.

## Dependency Analysis `/api/v4/analysis`

The expected input data format is a Software Bill of Materials (SBOM) containing the aggregate of all direct and transitive
dependencies of a project.

The `Content-Type` HTTP header will allow Exhort distinguish between the different supported SBOM formats.

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
$ http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"application/json" @'target/bom.json'
```

### Verbose Mode

When the Dependency Graph Analysis returns a JSON report it contains all vulnerability data by default. The _Verbose mode_ can be disabled
in order to retrieve just a Summary. Use the `verbose=false` Query parameter to disable it.

```bash
$ http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"application/json" @'target/sbom.json' verbose==false

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
                        "remediations": 0,
                        "recommendations": 0
                    },
                    "dependencies": []
                }
            }
        }
    }
}
```

### Client Token Authentication

If clients don't provide the token to authenticate against the Vulnerability Provider the default one will be used instead but vulnerabilities unique to
that specific provider will not show all the details.

To provide the client authentication tokens use HTTP Headers in the request. The format for the tokens Headers is `ex-provider-token`. e.g. `ex-snyk-token`:

```bash
http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json' ex-snyk-token:the-client-token
```

In case the vulnerability provider requires of Basic Authentication the headers will be `ex-provider-user` and `ex-provider-token`.

```bash
http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json' ex-oss-index-user:the-client-username ex-oss-index-token:the-client-token
```

### V3 Support

As long as clients consume V3 we will keep backwards compatible responses. The main difference between V4 and V3 is the multisource data model where providers
can report vulnerabilities from multiple sources. In V3, all vulnerabilities will be merged and counted together.

The HTML report will always be multisource using V4 data.

### HTML Report

By default the response Content-Type will be `application/json` but if the `text/html` media type is requested instead, the response
will be processed and converted into HTML.

The HTML report will show limited information:

- Public vulnerabilities retrieved with the default token will not show the _Exploit Maturity_
- Private vulnerabilities (i.e. vulnerabilities reported by the provider) will not be displayed.

```bash
$ http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"text/html" @'target/sbom.json'

<html>
...
</html>
```

### Mime-Multipart response

It is also possible to get a MIME Multipart response containing a JSON report with the HTML attached.
For that, use the `Accept: multipart/mixed` request header.


```bash
http :8080/api/v4/analysis Content-Type:"application/vnd.cyclonedx+json" Accept:"multipart/mixed" @'target/sbom.json'
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
        <title>Exhort Dependency Report</title>
    </header>
    <body>
        <h1>Dependency Report</h1>
        <p>This is an example</p>
    </body>
</html>
------=_Part_2_2047647971.1682593849895--

```

### Batch Dependency Analysis `/api/v4/batch-analysis`

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
http -v :8080/api/v4/token ex-snyk-token==example-token
```

The possible responses are:

- 200 - Token validated successfully
- 400 - Missing provider authentication headers
- 401 - Invalid auth token provided or Missing required authentication header (rhda-token)
- 403 - The token is not authorized
- 429 - Rate limit exceeded
- 500 - Server error

## Telemetry

API Clients are expected to send the following HTTP Headers in order to help observe the use of the Backend service:

- `rhda-token` HTTP Header that will be used to correlate different events related to the same user. If the header
is not provided an anonymous event with a generated UUID will be sent instead.
- `rhda-source` The client consuming the Exhort API. It will default to the `User-Agent` HTTP Header
- `rhda-operation-type` When performing an analysis, clients might specify whether it is a component-analysis or a stack-analysis

Telemetry connects to [Segment](https://segment.com/) for sending events.
The connection can be configured with the following properties.

- `telemetry.disabled`: To completely disable telemetry
- `telemetry.write-key`: Authentication key to connect to Segment
- `quarkus.rest-client.segment-api.url`: Segment API endpoint

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

The required parameters can be injected as environment variables through a secret. Create the `exhort-secret` Secret before deploying the application.

```bash
oc create secret generic -n exhort --from-literal=api-snyk-token=<snyk_api_token> exhort-secret
```

After that you can use the [exhort.yaml](./deploy/exhort.yaml)

```bash
oc apply -f deploy/exhort.yaml
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
