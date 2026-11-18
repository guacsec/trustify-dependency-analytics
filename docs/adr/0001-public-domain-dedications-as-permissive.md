# Public-domain dedications as PERMISSIVE

## Decision

Group the reviewed `Unlicense` and `CC0-1.0` instruments under `PERMISSIVE` in the four-category copyright/copyleft model.
Unlicense dedicates copyright to the public domain with broad permission to copy, modify, and distribute; CC0 combines
a public-domain waiver with a fallback license. Both permit use, modification, and redistribution without copyleft or
source-disclosure requirements. ScanCode classifies both as **Public Domain**; this product groups their reviewed terms as `PERMISSIVE`.
`Unicode-DFS-2016` follows the ordinary evidence path: its broad grant requires preservation of the copyright and
permission notice in copies or associated documentation, and ScanCode corroborates its **Permissive** classification.

| Identifier | Bundled SPDX OSI approval | Bundled SPDX deprecation |
|---|---|---|
| `Unicode-DFS-2016` | true | false |
| `Unlicense` | true | false |
| `CC0-1.0` | false | false |

## Alternatives

- Retain `UNKNOWN`: leaves reviewed copyright terms unclassified and triggers the existing client's needs-review warning.
- Add `PUBLIC_DOMAIN`: expands the category contract and requires API, client, and UI handling for a separate category;
  the existing model can already express these instruments' copyright/copyleft obligations.

## Consequences

- This decision covers only these two reviewed dedications. Other dedications and content licenses require separate review.
- Preserve SPDX identifiers, names, and metadata flags, including the values above; categorization is independent of OSI approval.
- CC0 section 4(a) expressly leaves patent and trademark rights unaffected. MIT and BSD are silent on patents;
  [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) includes an express patent grant. `Unlicense` contains no express patent grant.
- Patent coverage, third-party rights, jurisdiction, license selection, legal clearance, and organizational acceptance require separate assessment.
- Fedora allows `Unlicense` generally and lists `CC0-1.0` as allowed-content with specified code exceptions. Its policy is
  context for distinguishing categorization from organizational acceptance, not this product's dependency-use policy.
- The [client heuristic](../../README.md#license-evidences-and-concluded-license) remains in force for other `UNKNOWN` results;
  mapping these identifiers removes their UNKNOWN-triggered warnings. See [cache and rollout](../../README.md#license-cache-and-rollout) for operational effects.

## References

- SPDX texts and metadata: [Unicode-DFS-2016](https://spdx.org/licenses/Unicode-DFS-2016.html), [Unlicense](https://spdx.org/licenses/Unlicense.html), [CC0-1.0](https://spdx.org/licenses/CC0-1.0.html).
- ScanCode: [Unicode-DFS-2016](https://scancode-licensedb.aboutcode.org/unicode-dfs-2016.html), [Unlicense](https://scancode-licensedb.aboutcode.org/unlicense.html), [CC0-1.0](https://scancode-licensedb.aboutcode.org/cc0-1.0.html).
- Fedora: [allowed licenses](https://docs.fedoraproject.org/en-US/legal/allowed-licenses/), [license approval](https://docs.fedoraproject.org/en-US/legal/license-approval/).
