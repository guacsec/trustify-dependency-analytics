# Glossary

## Licenses

This glossary describes the license categories used by the license analysis endpoints
(`/api/v5/licenses` and `/api/v5/licenses/{licenseId}`) and by SBOM/package license
aggregation. It describes the classification model, the evidence expected for new
mappings, and the rationale for the reviewed mappings below.

The categories are a **copyright/copyleft categorization aid**. They are not legal
advice, legal clearance, organizational dependency-use approval, or proof that a
dependency is compatible with a given project license. See
[What categories do and do not mean](#what-categories-do-and-do-not-mean).

### Four-category model

| Category | Meaning | Illustrative examples |
|---|---|---|
| `PERMISSIVE` | Licenses that permit use, modification, and redistribution with limited obligations. Permissive is **not obligation-free**: notice/attribution and other stated conditions still apply. | MIT, Apache-2.0 (includes an express patent grant), BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS-2016 |
| `WEAK_COPYLEFT` | Reciprocal obligations scoped to individual files or libraries rather than the whole combined work, subject to the license terms. | MPL-2.0, LGPL-2.1, LGPL-3.0, EPL-1.0/2.0, CDDL-1.0/1.1 |
| `STRONG_COPYLEFT` | Broader reciprocal obligations that can extend to distribution of a combined work, subject to the license terms. | GPL-2.0, GPL-3.0, AGPL-3.0 |
| `UNKNOWN` | The license was **not classified by this mapping/analysis**. It does not necessarily mean the license is invalid, proprietary, unrecognized, or forbidden. | An SPDX-recognized license whose normalized base ID is absent from the configured category lists, or an unrecognized single license ID |

The authoritative per-license configuration is
[`src/main/resources/license-categories.yaml`](src/main/resources/license-categories.yaml),
selected by the `categories.file` setting (default: `license-categories.yaml`). For
category lookup, the backend separates any exception and strips `-only`, `-or-later`,
or the legacy `+` suffix from the base license ID before checking category-list
membership. For example, `GPL-3.0-only` uses the `GPL-3.0` entry. An unmapped base ID
falls back to `UNKNOWN`; normalization does not rewrite the returned SPDX metadata.

Expressions are categorized from their identifiers, not by looking up the complete
expression in the YAML. For example, `MIT AND Apache-2.0` is `PERMISSIVE` because both
identifiers are permissive. See the README's
[license evidence and conclusion rules](README.md#license-evidences-and-concluded-license)
and [SPDX license handling](docs/spdx-java-library-parsing-api.md) for implementation
details.

### License exceptions

License exceptions are license-specific additional permissions or conditions that
modify a base license, expressed with SPDX `WITH`. The backend currently downgrades a
`STRONG_COPYLEFT` license to `WEAK_COPYLEFT` only when the exception is explicitly
listed in the configuration's `weak-copyleft-exceptions` entry, for example
`GPL-2.0-only WITH Classpath-exception-2.0`.

Exceptions require license-specific review. There is no blanket rule that any
exception makes a strong-copyleft license weak, and an unlisted exception leaves the
base license category in effect.

### What categories do and do not mean

- Categories summarize **copyright/copyleft obligations**. They do not resolve
  patents, trademarks, third-party rights, or jurisdictional questions.
- **SPDX recognition is not categorization.** SPDX provides the identifier and the
  canonical license text; it does not classify licenses as permissive or copyleft.
  An identifier can be SPDX-recognized and still be `UNKNOWN` here because it has no
  category mapping.
- **OSI approval is not categorization.** OSI approval alone does not imply
  `PERMISSIVE`: some OSI-approved licenses are copyleft, and map membership is
  independent of the OSI flag. Conversely, `CC0-1.0` is not OSI-approved but is mapped
  to `PERMISSIVE` under the explicit convention described below. Mapping does not
  rewrite SPDX metadata; `isOsiApproved` remains `false` for `CC0-1.0`.
- **Permissiveness, patent coverage, license-selection recommendations,
  organizational acceptance, and actual compatibility are separate questions.** A
  copyright/copyleft category does not establish patent coverage, recommend a
  license, or establish organizational acceptance or actual compatibility.
- **`UNKNOWN` means "not classified by this mapping/analysis".** It is a
  needs-review signal, not a finding that a license is invalid or unusable.

Current consumers derive behavior from these categories using a heuristic, not a
complete legal compatibility analysis. The JavaScript client's `getCompatibility()`
treats an `UNKNOWN` dependency as incompatible when the project category is known;
`runLicenseCheck()` turns that into incompatible-dependency results; and the VS Code
extension displays the resulting warnings. That
[warning policy](https://github.com/guacsec/trustify-da-javascript-client/pull/548)
is intentional and remains in force for every license that stays `UNKNOWN`.
Mapping an identifier to `PERMISSIVE` removes its
`UNKNOWN`-triggered warning under the existing heuristic without changing consumer
code, but it does not by itself prove compatibility.

### Mapping evidence and inclusion criteria

New mappings require review of the license obligations plus corroborating sources.
The expected evidence is:

1. The canonical SPDX license text and identifier (the reference text, not a
   categorization).
2. A corroborating classification source, such as the
   [ScanCode LicenseDB](https://scancode-licensedb.aboutcode.org/), reviewed against
   the actual grant and conditions.
3. A recorded rationale for why the obligations fit the target category.
4. Preserved SPDX metadata (id, name, deprecation flag, OSI/FSF flags). Category
   membership must not depend on OSI approval or rewrite SPDX metadata.

OSI approval alone is not sufficient evidence. Exceptions require license-specific
review rather than a blanket downgrade rule.

### Reviewed mappings

The following three reviewed identifiers are included in the `permissive` list in
`license-categories.yaml`:

| Identifier | Rationale | SPDX metadata (preserved) |
|---|---|---|
| `Unicode-DFS-2016` | Permissive Unicode data-files-and-software license. Corroborated by ScanCode (`Permissive`). | OSI-approved; not deprecated |
| `Unlicense` | Public-domain dedication with a broad permission statement; grouped under `PERMISSIVE` by the explicit product convention below. ScanCode lists it as `Public Domain`, not `Permissive`. | OSI-approved; not deprecated |
| `CC0-1.0` | Public-domain dedication; grouped under `PERMISSIVE` by the explicit product convention below. ScanCode lists it as `Public Domain`, not `Permissive`. | **Not** OSI-approved; not deprecated; CC0 section 4(a) caveat below |

References: [SPDX Unicode-DFS-2016](https://spdx.org/licenses/Unicode-DFS-2016.html),
[SPDX Unlicense](https://spdx.org/licenses/Unlicense.html),
[SPDX CC0-1.0](https://spdx.org/licenses/CC0-1.0.html),
[ScanCode Unicode-DFS-2016](https://scancode-licensedb.aboutcode.org/unicode-dfs-2016.html),
[ScanCode Unlicense](https://scancode-licensedb.aboutcode.org/unlicense.html),
[ScanCode CC0-1.0](https://scancode-licensedb.aboutcode.org/cc0-1.0.html).

The metadata above is preserved from the backend's bundled SPDX data. These
mappings do not establish a general rule for additional identifiers.

### Public-domain dedications: Unlicense and CC0-1.0

The product categorization convention groups two **reviewed** public-domain
dedications, `Unlicense` and `CC0-1.0`, under `PERMISSIVE` for copyright/copyleft
categorization. Their reviewed terms permit use, modification, and redistribution
without copyleft or source-disclosure requirements, so they fit the `PERMISSIVE`
category in this four-category model. `UNKNOWN` remains a needs-review signal, not
a finding that a license imposes copyleft obligations.

This is an explicit, review-based convention, **not a blanket Public Domain rule**:

- It applies only to the two instruments listed above, after review of their texts.
- Other public-domain dedications or content licenses are not automatically mapped;
  each requires separate review and authorization.
- It is not legal clearance, not a conclusion that every use is unconstrained, and
  not organizational dependency-use approval.

CC0-specific caveat: CC0 section 4(a) expressly leaves patent and trademark rights
unaffected. This differs from licenses such as MIT or BSD that simply remain silent
about patents. `Unlicense` likewise contains no express patent grant. Categorization
is separate from patent coverage and from any organizational policy about either
instrument.

Fedora's [allowed-license list](https://docs.fedoraproject.org/en-US/legal/allowed-licenses/)
permits `Unlicense` generally but treats `CC0-1.0` as content-only with specified code
exceptions, under its [license approval rules](https://docs.fedoraproject.org/en-US/legal/license-approval/).
That is Fedora's policy and is **not** this product's policy; it is cited only as
context for the distinction between categorization and organizational acceptance.
This glossary documents the categorization convention, not an organizational
dependency-use policy.

This convention does not change the client compatibility/warning policy for
remaining `UNKNOWN` licenses.

### Package cache and rollout

License results computed for packages are cached in Redis. The relevant behavior is:

- `RedisCacheService.cacheLicenses` stores the categorized `PackageLicenseResult`
  under `licenses:<package coordinates>` using `psetex`.
- `licenses.cache.ttl` defaults to `1d`. Reads do not renew the TTL.
- After deploying a category mapping change, **previously cached package results can
  continue to report the old category (`UNKNOWN`) until their actual configured TTL
  expires**. The TTL in effect at write time, not a fixed value, determines when they
  refresh.
- Direct license-ID lookup (`GET /api/v5/licenses/{licenseId}`) bypasses the package
  cache and reflects the current mapping immediately.
- If immediate freshness is required, use operator-approved targeted invalidation of
  the affected license keys. Do not run a broad Redis flush. No durable database
  migration is needed for these mapping updates: license classification does not
  write these categories to a durable database.
