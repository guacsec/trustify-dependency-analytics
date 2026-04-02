# Coding Conventions

<!-- This file documents project-specific coding standards for trustify-dependency-analytics. -->

## Language and Framework

- **Primary Language**: Java 21
- **Framework**: Quarkus 3.31.3
- **Integration**: Apache Camel for Quarkus (routing and integration patterns)
- **REST**: JAX-RS / Jakarta RESTful Web Services with Jackson
- **ORM**: Hibernate ORM with Panache
- **Database**: PostgreSQL with Flyway migrations
- **Cache**: Redis
- **Build Tool**: Maven
- **Monitoring**: Sentry 7.8.0
- **SBOM**: CycloneDX and SPDX libraries

## Code Style

- **Formatter**: Spotless Maven Plugin with Google Java Format (GOOGLE style, `reflowLongStrings` enabled)
- **Indentation**: 4 spaces per tab
- **Import order**: `java|javax, org, com, io`
- **Unused imports**: Automatically removed
- **License header**: Apache 2.0 required on all Java files (`src/license/java_header.txt`)
  - Format: `Copyright 2023-2025 Trustify Dependency Analytics Authors`
- **Formatter toggle**: `// fmt:off` / `// fmt:on` to disable formatting (used in Camel DSL code)
- **Encoding**: UTF-8
- **Line endings**: LF, trim trailing whitespace, final newline

## Naming Conventions

- **Packages**: `io.github.guacsec.trustifyda.<feature>` (domain-driven)
  - Subpackages: `integration.providers`, `integration.licenses`, `integration.backend`, `integration.sbom`
- **Classes**: PascalCase
  - Services: `*Service` (`ModelCardService`, `CacheService`, `SpdxLicenseService`)
  - Repositories: `*Repository` (`ModelCardRepository`, `GuardrailRepository`)
  - Route Builders: `*Integration` (`ExhortIntegration`, `LicensesIntegration`)
  - Exceptions: `*Exception` (`DetailedException`, `SbomValidationException`)
  - Utility: Private constructor, `final` class (e.g., `ExceptionUtils`)
- **Methods**: camelCase, verb-first (`get*`, `find*`, `process*`, `validate*`, `is*`)
- **Constants**: SCREAMING_SNAKE_CASE (`PROVIDERS_PARAM`, `TRUSTIFY_TOKEN_HEADER`, `CYCLONEDX_MEDIATYPE_JSON`)
- **HTTP headers**: lowercase-with-hyphens (`ex-trustify-token`, `ex-request-id`)
- **Query parameters**: camelCase (`providers`, `recommend`, `verbose`)
- **Records**: Used for immutable data (`PackageItem`, `DependencyTree`)

## File Organization

```
src/main/java/io/github/guacsec/trustifyda/
├── config/                         # Configuration and exceptions
│   ├── exception/                  # Exception hierarchy
│   └── metrics/
├── integration/
│   ├── backend/                    # REST routing (Camel)
│   ├── cache/                      # Redis, cache services
│   ├── licenses/                   # License integration (deps.dev)
│   ├── providers/                  # Vulnerability providers
│   │   └── trustify/
│   ├── report/                     # Report generation
│   ├── sbom/                       # SBOM parsing
│   │   ├── cyclonedx/
│   │   └── spdx/
│   └── Constants.java
├── model/                          # Domain models
│   ├── trustify/
│   ├── modelcards/
│   └── licenses/
├── modelcards/                     # Model card service layer
├── monitoring/                     # Sentry, observability
└── service/                        # Service classes

src/main/resources/
├── application.properties
├── db/migration/                   # Flyway SQL migrations
├── freemarker/templates/           # Freemarker report templates
│   ├── report.ftl                  # Main HTML report template
│   └── generated/                  # Compiled React assets (do not edit manually)
└── license-categories.yaml

ui/                                 # React frontend for HTML report
├── src/                            # TypeScript/React source code
├── craco.config.js                 # Webpack configuration override
├── package.json                    # Dependencies and build scripts
└── tsconfig.json
```

- Feature/capability-based organization, not layered
- Integration routes separated from business logic

## Error Handling

- **Exception hierarchy**:
  - `DetailedException` (base) — runtime exception with optional details and status code
  - `ClientDetailedException` — client-facing errors
    - `SbomValidationException`, `CycloneDXValidationException`, `SpdxValidationException`
    - `PackageValidationException`, `UnexpectedProviderException`
- **Camel exception handling**: `onException(TimeoutException.class).handled(true).process(responseHandler::processResponseError)`
- **HTTP status mapping**: 400 (validation), 401 (unauthorized), 422 (unsupported provider), 504 (timeout), 500 (internal)
- **Error responses**: `text/plain` for validation errors, JSON for complex errors, all include `ex-request-id` header
- **Utilities**: `ExceptionUtils.findInChain()`, `ExceptionUtils.getLongestMessage()`

## Testing Conventions

- **Frameworks**: JUnit 5 (Jupiter), Quarkus Test, Mockito (via `quarkus-junit5-mockito`)
- **HTTP testing**: REST Assured for API tests, WireMock 3.4.2 for mocking external services
- **HTML validation**: HTMLUnit 4.11.1
- **Test naming**: `*Test.java` (unit), `*IT.java` (integration)
- **Annotations**: `@QuarkusTest`, `@QuarkusTestResource`, `@ParameterizedTest`, `@Nested`
- **Custom extensions**: `WiremockExtension`, `OidcWiremockExtension`, `@InjectWireMock`
- **REST Assured pattern**: `given().header(...).body(...).when().post(...).then().assertThat().statusCode(...)`
- **Cache testing**: Two-request pattern to verify cache hits; `server.resetRequests()` between tests
- **Test data**: JSON fixtures in `src/test/resources/{format}/`
- **Assertions**: JUnit static imports + Hamcrest matchers

## Commit Messages

- Conventional Commits: `<type>(<scope>): <description>`
- Release commits: `build(release): <message>` (configured in Maven Release Plugin)
- Tags: `v<semver>` (e.g., `v2.0.0`)

## HTML Report Generation

The HTML report is a self-contained, single-page React application embedded into a Freemarker template. All CSS and JS assets are inlined so the resulting HTML can be viewed offline or attached to emails.

### Architecture

1. **React UI** (`ui/`): Built with React 18 + PatternFly 5, TypeScript, and Craco (webpack wrapper). Yarn 4 is the package manager.
2. **Build pipeline** (Maven `frontend-maven-plugin`): During the `compile` phase, Maven installs Node + corepack and runs `yarn install && yarn build`. The Craco config splits output into `main.js`, `vendor.js`, `main.css`, and `vendor.css`.
3. **Asset copy**: The build script copies compiled bundles from `ui/build/static/` into `src/main/resources/freemarker/templates/generated/`.
4. **Freemarker template** (`src/main/resources/freemarker/templates/report.ftl`): Inlines the generated CSS/JS and passes analysis data to the React app via `window.appData`. Uses square-bracket tag syntax (`[#if]`, `[=var]`).
5. **Camel route** (`ReportIntegration`): The `htmlReport` direct route sets `Content-Type: text/html`, calls `ReportTemplate.setVariables()`, and processes through the Freemarker template.
6. **Trigger**: Clients request an HTML report by sending `Accept: text/html` (or `multipart/mixed` for both HTML + JSON) to `/api/v4/analysis` or `/api/v5/analysis`.

### Generated assets

```
src/main/resources/freemarker/templates/generated/
├── main.js        # React application code
├── vendor.js      # Third-party dependencies
├── main.css       # Application styles
└── vendor.css     # PatternFly & dependency styles
```

These files are committed to the repository. If you change anything under `ui/`, you must rebuild them before committing (see Pre-Commit Checklist below).

## Pre-Commit Checklist

Before committing code, always verify the following:

1. **Format the code**: Run `mvn spotless:apply` to auto-format all Java sources (Google Java Format).
2. **Lint and rebuild the UI** (if `ui/` was modified):
   - Run `yarn lint` (or `yarn lint:fix`) inside `ui/` to check ESLint + Prettier rules.
   - Run `yarn build` inside `ui/` (or let `mvn compile` do it) to recompile the React app.
   - Ensure the regenerated files under `src/main/resources/freemarker/templates/generated/` are included in the commit.
3. **Run the tests**: Execute `mvn verify` (or at minimum `mvn test`) and ensure all tests pass.

## Dependencies

- **BOM pattern**: Quarkus BOM + Quarkus Camel BOM imported via `<scope>import</scope>`
- **Version management**: All versions in `<properties>` section of pom.xml
- **Quarkus extensions**: `quarkus-rest-jackson`, `quarkus-hibernate-orm-panache`, `quarkus-oidc-client`, `quarkus-redis-client`
- **Camel extensions**: `camel-quarkus-*` (not plain camel)
- **Native image**: `@RegisterForReflection` annotations, `native` Maven profile for GraalVM builds
- **Build plugins**: Spotless, Flatten Maven Plugin, Maven Release Plugin, Frontend Maven Plugin (Node/Yarn for UI)
- **Distribution**: Maven Central with GPG signing
