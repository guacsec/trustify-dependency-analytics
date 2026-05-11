# Project Overview

## Purpose
Trustify Dependency Analytics is a Java/Quarkus backend service for dependency analysis. 
It accepts SBOMs (CycloneDX/SPDX), queries vulnerability providers (Trustify), resolves 
licenses via deps.dev, and returns analysis results as JSON, HTML (self-contained React app 
via Freemarker), or multipart/mixed.

## Tech Stack
- **Language**: Java 21
- **Framework**: Quarkus 3.31.3
- **Routing**: Apache Camel for Quarkus
- **REST**: JAX-RS / Jakarta RESTful Web Services with Jackson
- **ORM**: Hibernate ORM with Panache, PostgreSQL, Flyway
- **Cache**: Redis
- **Build**: Maven, Spotless (Google Java Format), Frontend Maven Plugin (Node/Yarn for UI)
- **Testing**: JUnit 5, REST Assured, WireMock 3.4.2, HTMLUnit
- **API Models**: `trustify-da-api-model` artifact (version 2.0.7) provides generated model classes
- **UI**: React 18 + PatternFly 5 + TypeScript (compiled into Freemarker template)
- **Monitoring**: Sentry 7.8.0

## Package Structure
Base package: `io.github.guacsec.trustifyda`
- `integration/backend/` — Camel REST routes (ExhortIntegration)
- `integration/providers/trustify/` — Trustify provider (OAuth2, vulnerabilities, recommendations)
- `integration/licenses/` — deps.dev license integration
- `integration/sbom/` — SBOM parsing (CycloneDX, SPDX)
- `integration/report/` — Report generation (JSON, HTML, multipart)
- `integration/cache/` — Redis caching
- `model/` — Domain models (DependencyTree, etc.)
- `config/` — Configuration, exception handling
- `service/` — OIDC, auth services
- `monitoring/` — Sentry

## API Versions
- v4: `/api/v4/analysis`, `/api/v4/batch-analysis`, `/api/v4/token`
- v5: `/api/v5/analysis`, `/api/v5/batch-analysis`, `/api/v5/licenses`, `/api/v5/token`

## Data Flow
Client Request (SBOM) -> ExhortIntegration -> SbomParser -> DependencyTree
  -> analyzeSbom multicast: [findVulnerabilities, getLicensesFromSbom] in parallel
  -> findVulnerabilities -> split by provider -> trustifyScan -> trustifyRequest
     -> multicast: [vulnerabilities, recommendations] in parallel
  -> ReportIntegration (JSON/HTML/Multipart) -> Response
