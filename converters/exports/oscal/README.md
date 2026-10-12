# Rego → OSCAL catalogs

**Status:** shipping (catalog). Component-definition and assessment-results: planned.
**Kind:** export (Tier 1)
**Covers:** every framework — 125 catalogs, 5,559 distinct controls (the 7,867 control-level checks collapse onto them; the same id in two modules of one framework is one control)
**Spec:** [OSCAL 1.2.3](https://pages.nist.gov/OSCAL/), JSON; schemas vendored in `schema/`

## Use it

```bash
# one framework
curl -sLO https://raw.githubusercontent.com/ynotbhatc/rego_policy_libraries/main/converters/exports/oscal/dist/catalogs/gdpr.json
# everything in one catalog (attached to each release)
gh release download v2.2.0 --repo ynotbhatc/rego_policy_libraries --pattern oscal-catalogs.tar.gz
```

`dist/catalogs/index.json` lists every catalog with its uuid and control count. Importers tested so far: the
NIST JSON schema only; compliance-trestle / RegScale / Xacta imports are the next thing to prove.

## What is in a catalog

| OSCAL | from the library |
|---|---|
| catalog | one framework; uuid is `uuid5(framework, version)` so it is stable across builds |
| group (class `rego-module`) | one Rego file; `rego-package` / `rego-file` props |
| control | one control id; `label` and `alt-identifier` keep the original id (`CIS 1.3.1`, `§7122(a)(1)`, `9.1.5`); class from METADATA |
| part `statement` | the first check message for the control |
| part `assessment-objective` | every further check message for the same control |
| link rel `implementation` | the back-matter resource for the Rego file (rlink to the file at the release tag) |

Control ids are OSCAL tokens: `<framework>-<id>` with anything outside `[A-Za-z0-9._-]` folded to `-`
(`cis_rhel_9-CIS-1.3.1`, `ccpa-CCPA-7122-a-1`). The same id appearing in two modules of one framework is one
control with both modules linked.

## Build and test

```bash
make oscal                 # regenerates dist/catalogs (commit it) and out/all.json
bash test/roundtrip.sh     # inventory ↔ catalog equality, links resolve, schema validation (needs: pip install jsonschema)
```

CI runs the round-trip on every PR and fails if `dist/` is stale or any catalog fails the schema. The
inventory is the same code path as the README count, so the catalogs cannot drift from the number we publish.

## Not yet

- **component-definition**: the library as a component whose `implemented-requirements` point at these controls.
- **assessment-results**: emitted from `compliance_report` output at evaluation time.
- Proven imports into compliance-trestle, RegScale, Xacta.
