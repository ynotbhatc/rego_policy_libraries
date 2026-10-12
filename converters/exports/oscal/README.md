# Rego → OSCAL catalogs

**Status:** shipping — catalog, component-definition, assessment-results.
**Kind:** export (Tier 1)
**Covers:** every framework — 121 catalogs, 6,076 distinct controls (the 7,560 control-level checks collapse onto them; the same id in two modules of one framework is one control)
**Spec:** [OSCAL 1.2.3](https://pages.nist.gov/OSCAL/), JSON; schemas vendored in `schema/`

## Use it

```bash
# one framework
curl -sLO https://raw.githubusercontent.com/ynotbhatc/rego_policy_libraries/main/converters/exports/oscal/dist/catalogs/gdpr.json
# everything in one catalog (attached to each release)
gh release download v2.3.0 --repo ynotbhatc/rego_policy_libraries --pattern oscal-catalogs.tar.gz
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

## component-definition

`dist/component-definition.json` (committed): the library as one software component with one
control-implementation per framework (source = that catalog's raw URL at the release tag) and one
implemented-requirement per control, saying which Rego package and file evaluates it. `make oscal` rebuilds it.

## assessment-results

```bash
opa eval -f json -d benchmarks/cis/rhel_9 -i facts.json 'data.cis_rhel9.main.compliance_report' > report.json
python3 converters/exports/oscal/build_assessment_results.py report.json -o results.json --subject host01 [--time 2026-10-12T00:00:00Z]
```

One result per run: `reviewed-controls` lists every control of the frameworks that reported; one observation
and one finding (`not-satisfied`, target = the control's statement part in the catalog) per distinct violation.
Controls without a finding are **not** asserted satisfied: a report says which checks failed and fail-closed
sections appear as violations, so absence of a finding is not evidence. Finding and observation uuids are
uuid5 of (framework, control, message), so re-running on the same facts yields the same ids. Violations whose
prefix is not a catalog control (section-level fail-closed notices) target a `statement-id` and carry
`control-mapped: false`.

## Not yet

- Proven imports into compliance-trestle, RegScale, Xacta.
- Pass findings (`satisfied`) for table-driven modules whose reports list attested controls.
