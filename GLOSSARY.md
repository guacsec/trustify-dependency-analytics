# License Categories

How this product labels the licenses it reports for identifiers, expressions, and packages.
A category describes copyright/copyleft obligations; patent and trademark scope, legal clearance,
license choice, organizational acceptance, and actual compatibility require separate assessment.

## Language

**Category**:
The copyright/copyleft obligation class of a license. The same four values describe
an identifier, an SPDX expression, a package, and the project's own license.
_Avoid_: classification, rating, status, approval, compatibility

**PERMISSIVE**:
A license class permitting use, modification, and redistribution with limited obligations,
including notice, attribution, or other stated conditions (e.g. MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC).
_Avoid_: approved, allowed, safe, permitted, obligation-free

**WEAK_COPYLEFT**:
A license class with reciprocal obligations scoped to covered files or libraries rather than
the whole combined work (e.g. MPL-2.0, LGPL-2.1, LGPL-3.0, EPL-1.0, EPL-2.0, CDDL-1.0, CDDL-1.1).
_Avoid_: file-level copyleft, conditional, lesser

**STRONG_COPYLEFT**:
A license class whose reciprocal obligations can extend to distribution of a combined work
(e.g. GPL-2.0, GPL-3.0, AGPL-3.0).
_Avoid_: viral, restrictive

**UNKNOWN**:
The absence of a category assigned by this product's mapping or analysis, including
unmapped identifiers and unsupported or unrecognized inputs. A needs-review signal.
_Avoid_: unrecognized, invalid, proprietary, forbidden, failed

**Category mapping**:
The reviewed, hand-curated assignment of license identifiers to categories.
Membership is independent of SPDX recognition and OSI approval.
_Avoid_: license list, allowlist, approved list

**Evidence**:
A license reported for a package by a license provider, before any conclusion is drawn.
_Avoid_: finding, result, detection

**Concluded license**:
The license information selected from a package's evidence, including its expression,
identifiers, source, and category.
_Avoid_: aggregate license, final license, resolved license

**License exception**:
A license-specific additional permission or condition that modifies a base license,
expressed with SPDX WITH.
_Avoid_: suffix, modifier, rider

## Where the rules live

- Behavior and operations: [README](README.md#categories).
- Adding mappings: [CONVENTIONS](CONVENTIONS.md#license-category-mappings).
- Public-domain categorization: [ADR 0001](docs/adr/0001-public-domain-dedications-as-permissive.md).
