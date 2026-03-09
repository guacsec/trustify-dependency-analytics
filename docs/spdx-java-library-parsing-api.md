# SPDX license handling in Trustify DA (SpdxLicenseService)

This document describes how **Exhort / Trustify Dependency Analytics** uses the **spdx-java-library** (on the classpath via `spdx-jackson-store`) for parsing SPDX license expressions and identifying licenses. The implementation lives in `io.github.guacsec.trustifyda.integration.licenses.SpdxLicenseService`.

## Overview

The service:

- **Parses** SPDX expressions (deprecated and modern forms, AND/OR/WITH) using the SPDX library.
- **Normalizes** deprecated compound IDs to the modern “license WITH exception” form before parsing.
- **Identifies** licenses from license file text by matching the first 5 lines of the header against a hash map built from bundled SPDX license texts.
- **Resolves categories** (permissive, weak copyleft, strong copyleft, unknown) from `license-categories.yaml`.

## Initialization

The service initializes the SPDX library on Quarkus startup:

```java
void onStart(@Observes StartupEvent ev) {
  SpdxModelFactory.init();
  // ... load header map and license-categories.yaml in parallel
}
```

Optional: to avoid network and use only the JAR-bundled license list:

- `-Dorg.spdx.useJARLicenseInfoOnly=true`  
  or set in `/resources/spdx-java-library.properties`.

## Parsing

Only **LicenseInfoFactory** is used; there is no use of `LicenseExpressionParser` or `InMemSpdxStore`.

Deprecated compound IDs are normalized **before** parsing so the library returns the canonical “license WITH exception” structure:

```java
private static final Map<String, String> DEPRECATED_TO_CANONICAL =
    Map.of(
        "GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0",
        "GPL-2.0-with-classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0");

String toParse = DEPRECATED_TO_CANONICAL.getOrDefault(trimmed, trimmed);
AnyLicenseInfo root = LicenseInfoFactory.parseSPDXLicenseString(toParse);
```

Accepted inputs include:

- **Deprecated**: `GPL-2.0-with-classpath-exception` (normalized then parsed).
- **Modern**: `GPL-2.0-only WITH Classpath-exception-2.0`.
- **Multi**: `MIT AND GPL-2.0-only`, `MIT OR Apache-2.0`, `(A AND B) OR C`.

Invalid expressions that do not contain AND/OR/WITH are treated as unknown single IDs and return a `LicenseInfo` with category `UNKNOWN` and a single identifier; otherwise `InvalidSPDXAnalysisException` is turned into `NotFoundException`.

## AST types and accessors (spdx-java-library v3)

The root type is **AnyLicenseInfo** (`org.spdx.library.model.v3_0_1.simplelicensing`). The service branches on these types from `org.spdx.library.model.v3_0_1.expandedlicensing`:

| Type | Meaning | What the service uses |
|------|--------|------------------------|
| **ListedLicense** | Single listed license (after normalization, deprecated compound IDs are parsed as WITH form) | `toString()` → license ID; `getName().orElse(...)`; `getIsOsiApproved().orElse(null)`, `getIsFsfLibre().orElse(null)`, `getIsDeprecatedLicenseId().orElse(null)` |
| **WithAdditionOperator** | License WITH exception (modern form) | `getSubjectExtendableLicense()` → license (e.g. ListedLicense); `getSubjectAddition()` → exception (e.g. **ListedLicenseException**: `toString()` for id, `getName().orElse(...)` for name) |
| **ConjunctiveLicenseSet** | AND | `getMembers()` → iterate and recurse |
| **DisjunctiveLicenseSet** | OR | `getMembers()` → iterate and recurse |

Any other node type (e.g. **OrLaterOperator**) is treated as unknown and turned into a `LicenseIdentifier` with `LicenseCategory.UNKNOWN` via `toUnknownLicenseIdentifier(node.toString())`.

## Service API

### identifyLicense(String licenseFile)

Identifies a license from raw license file text:

1. **Extract header**: First 5 lines of the file, normalized (CRLF → LF, trim), stopping at the first blank line if present.
2. **Hash**: SHA-256 of the header string.
3. **Lookup**: The header hash map is built at startup from bundled resources `spdx-licenses/{licenseId}.json`; each file’s `licenseText` is used to compute the same header and hash.
4. Returns a **LicenseIdentifier** for the matched listed license (no exception); throws `NotFoundException` if the header does not match.

### fromLicenseId(String expression, String sourceId, String sourceUrl)

Builds a **LicenseInfo** from an SPDX expression:

1. Normalize deprecated IDs with `DEPRECATED_TO_CANONICAL`.
2. Parse with `LicenseInfoFactory.parseSPDXLicenseString(toParse)`.
3. Normalized expression: `root.toString()`.
4. Human-readable name: tree walk (`toHumanReadableName`) over ConjunctiveLicenseSet / DisjunctiveLicenseSet / WithAdditionOperator / ListedLicense; AND/OR joined with `" AND "` / `" OR "`; WITH → subject name + `" with "` + exception name.
5. Collect identifiers: tree walk `collectIdentifiers` → list of **LicenseIdentifier** (id, name, OSI/FSF/deprecated, category).
6. Category: `resolveCategoryFromIdentifiers(identifiers, isOr)` using `license-categories.yaml` and “more permissive” ordering (OR: pick most permissive; AND: pick least permissive).
7. Return **LicenseInfo** (identifiers, category, name, source, sourceUrl, expression).

## Categories (license-categories.yaml)

Categories are resolved by **LicenseConfig** (YAML with optional aliases):

- **permissive**, **weak-copyleft**, **strong-copyleft**: lists of base license IDs (e.g. after stripping `-only` / `-or-later`).
- **weak-copyleft-exceptions**: exception IDs that, when applied to a strong copyleft license, downgrade it to weak copyleft.

Expression normalization for category lookup:

- Split on ` WITH ` or `-with-` to get base license and exception suffix.
- Strip `-only` and `-or-later` from the base license.
- Look up base in permissive / weakCopyleft / strongCopyleft; if strong copyleft and exception is in weakCopyleftExceptions, use weak copyleft; otherwise UNKNOWN.

## Helpers used from the library

- **LicenseInfoFactory.parseSPDXLicenseString(String)** – parse expression to `AnyLicenseInfo`.
- **LicenseInfoFactory.getListedLicenseById(String)** – resolve a single ID to `ListedLicense` (used after header lookup in `identifyLicense`).
- **LicenseInfoFactory.getSpdxListedLicenseIds()** – list of IDs used to load `spdx-licenses/{id}.json` and build the header hash map.

## Summary

- **Parsing**: Deprecated compound IDs are normalized to “license WITH exception”, then **LicenseInfoFactory.parseSPDXLicenseString** only; no LicenseExpressionParser / InMemSpdxStore.
- **AST**: ConjunctiveLicenseSet / DisjunctiveLicenseSet (`getMembers()`), WithAdditionOperator (`getSubjectExtendableLicense()`, `getSubjectAddition()`), ListedLicense (id, name, OSI, FSF, deprecated); other types → unknown identifier.
- **Identification**: Header (first 5 lines) → SHA-256 → lookup in map built from bundled `spdx-licenses/*.json`.
- **Categories**: From `license-categories.yaml` (LicenseConfig); AND/OR resolution uses “more permissive” ordering and weak-copyleft exceptions for strong copyleft + exception.
