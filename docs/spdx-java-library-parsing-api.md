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

The service calls **LicenseInfoFactory.parseSPDXLicenseString** with a fresh **InMemSpdxStore**.
It does not call `LicenseExpressionParser` directly. The `spdx-jackson-store` dependency version is 2.0.4 (see `pom.xml`);
the returned objects use the SPDX 3.0.1 model packages.

Deprecated compound IDs are normalized **before** parsing so the library returns the canonical “license WITH exception” structure:

```java
private static final Map<String, String> DEPRECATED_TO_CANONICAL =
    Map.of(
        "GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0",
        "GPL-2.0-with-classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0");

String toParse = DEPRECATED_TO_CANONICAL.getOrDefault(trimmed, trimmed);
toParse = toParse.replaceAll("([A-Za-z][A-Za-z0-9.-]*\\d)\\+", "$1-or-later");
AnyLicenseInfo root =
    LicenseInfoFactory.parseSPDXLicenseString(toParse, new InMemSpdxStore(), null, null, null);
```

Accepted inputs include:

- **Deprecated**: `GPL-2.0-with-classpath-exception` (normalized then parsed).
- **Modern**: `GPL-2.0-only WITH Classpath-exception-2.0`.
- **Or later**: `LGPL-3.0+` (normalized to `LGPL-3.0-or-later` before parsing).
- **Multi**: `MIT AND GPL-2.0-only`, `MIT OR Apache-2.0`, `(GPL-3.0 AND MIT) OR Apache-2.0`.

Invalid expressions that do not contain AND/OR/WITH are treated as unknown single IDs and return a `LicenseInfo` with category `UNKNOWN` and a single identifier; otherwise `InvalidSPDXAnalysisException` is turned into `NotFoundException`.

## AST types and accessors (SPDX 3.0.1 model)

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

1. Normalize single deprecated compound IDs with `DEPRECATED_TO_CANONICAL`, then normalize `+` suffixes to `-or-later`.
2. Parse with `LicenseInfoFactory.parseSPDXLicenseString(toParse, new InMemSpdxStore(), null, null, null)`.
3. Normalized expression: `root.toString()`.
4. Human-readable name: tree walk (`toHumanReadableName`) over ConjunctiveLicenseSet / DisjunctiveLicenseSet / WithAdditionOperator / ListedLicense; AND/OR joined with `" AND "` / `" OR "`; WITH → subject name + `" with "` + exception name.
5. Collect identifiers: `parseExpressionToIdentifiers` parses the normalized expression and walks it with `collectIdentifiers` → list of **LicenseIdentifier** (id, name, OSI/FSF/deprecated, category). Collection order is not a category-selection rule.
6. Category: recursively evaluate the existing parsed `root` with `resolveCategory`. Each AND node selects the least permissive child category; each OR node selects the most permissive child category. Leaves reuse `collectIdentifiers` and its existing category/exception rules. Unsupported leaves remain `UNKNOWN`.
7. Return **LicenseInfo** (identifiers, category, name, source, sourceUrl, expression).

## Categories (license-categories.yaml)

Categories are resolved by **LicenseConfig** (YAML with optional aliases):

- **permissive**, **weak-copyleft**, **strong-copyleft**: lists of base license IDs (e.g. after stripping `-only` / `-or-later`).
- **weak-copyleft-exceptions**: exception IDs that, when applied to a strong copyleft license, downgrade it to weak copyleft.

Expression normalization for category lookup:

- Split on ` WITH ` or `-with-` to get base license and exception suffix.
- Strip `-only` and `-or-later` from the base license.
- Strip a remaining deprecated `+` suffix for category lookup.
- Look up the base in permissive / weakCopyleft / strongCopyleft. A configured exception changes a strong-copyleft base to weak copyleft; an unlisted exception leaves the base category unchanged. Unmapped bases are `UNKNOWN`.

### Recursive expression categories

At every AND/OR node, child categories use the existing ordering
`PERMISSIVE > WEAK_COPYLEFT > STRONG_COPYLEFT > UNKNOWN`. Parentheses and nesting are retained by
the parsed tree; an OR anywhere in the expression does not turn the whole expression into a choice.

| Expression | Aggregate category |
|------------|--------------------|
| `GPL-3.0 AND (MIT OR Apache-2.0)` | `STRONG_COPYLEFT` |
| `(GPL-3.0 AND MIT) OR Apache-2.0` | `PERMISSIVE` |
| `(MIT OR Apache-2.0) AND (GPL-3.0 OR LGPL-2.1)` | `WEAK_COPYLEFT` |
| `GPL-3.0 AND (Unicode-DFS-2016 OR LGPL-2.1)` | `STRONG_COPYLEFT` |
| `(GPL-2.0-only WITH Classpath-exception-2.0) AND (MIT OR Apache-2.0)` | `WEAK_COPYLEFT` |
| `LicenseRef-MIT-License AND (MIT OR Apache-2.0)` | `UNKNOWN` |
| `GPL-3.0 AND (LicenseRef-MIT-License OR MIT)` | `STRONG_COPYLEFT` |

The `LicenseRef` leaves in these examples remain `UNKNOWN`; this does not infer a license from their names.
Aggregate evaluation does not overwrite leaf categories, metadata, normalized expression, or source fields.
It is separate from `getConcluded(List<LicenseInfo>)`, which still selects the most permissive evidence
object among package/provider results. Neither operation is legal compatibility analysis.

Changing classifier semantics can change cached categories even with identical YAML. Cache compatibility
must account for algorithm changes as well as mapping changes; see the README's cache/rollout guidance.

## Helpers used from the library

- **LicenseInfoFactory.parseSPDXLicenseString(expression, new InMemSpdxStore(), null, null, null)** – parse an expression to `AnyLicenseInfo` with a fresh store and null optional context arguments.
- **LicenseInfoFactory.getListedLicenseById(String)** – resolve a single ID to `ListedLicense` (used after header lookup in `identifyLicense`).
- **LicenseInfoFactory.getSpdxListedLicenseIds()** – list of IDs used to load `spdx-licenses/{id}.json` and build the header hash map.

## Summary

- **Parsing**: Single deprecated compound IDs are normalized to “license WITH exception”, and `+` suffixes to `-or-later`, then **LicenseInfoFactory.parseSPDXLicenseString** parses using an **InMemSpdxStore**; no direct `LicenseExpressionParser` call.
- **AST**: ConjunctiveLicenseSet / DisjunctiveLicenseSet (`getMembers()`), WithAdditionOperator (`getSubjectExtendableLicense()`, `getSubjectAddition()`), ListedLicense (id, name, OSI, FSF, deprecated); other types → unknown identifier.
- **Identification**: Header (first 5 lines) → SHA-256 → lookup in map built from bundled `spdx-licenses/*.json`.
- **Categories**: From `license-categories.yaml` (LicenseConfig); recursive AND/OR resolution applies the existing ranking separately at every tree node, preserving leaf metadata and configured weak-copyleft exceptions.
