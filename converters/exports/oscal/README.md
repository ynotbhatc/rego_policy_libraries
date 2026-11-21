# Rego → OSCAL catalogs

**Status:** shipping — catalog, component-definition, assessment-results, imported baseline profiles.
**Kind:** export (Tier 1)
**Covers:** every framework — 150 catalogs, 11,539 distinct controls (the 14,318 control-level checks collapse onto them; the same id in two modules of one framework is one control)
**Spec:** [OSCAL 1.2.3](https://pages.nist.gov/OSCAL/), JSON; schemas vendored in `schema/`

## Use it

```bash
# one framework
curl -sLO https://raw.githubusercontent.com/ynotbhatc/rego_policy_libraries/main/converters/exports/oscal/dist/catalogs/gdpr.json
# everything in one catalog (attached to each release)
gh release download v2.3.3 --repo ynotbhatc/rego_policy_libraries --pattern oscal-catalogs.tar.gz
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
implemented-requirement per control, saying which Rego package and file evaluates it, plus one control-implementation per imported
baseline listing the baseline controls the library evaluates (see baseline coverage). `make oscal` rebuilds it.

## assessment-results

Any framework key, from the command line, schema-validated:

```bash
opa eval -f json -d . -i facts.json 'data.<key>.main.compliance_report' > report.json        # e.g. nist_800_53, cis_rhel9
python3 converters/exports/oscal/build_assessment_results.py report.json --key <key> -o results.json --validate \
    --subject host01 [--time 2026-10-12T00:00:00Z]
# also accepted: the OPA REST response of POST /v1/data/<key>/main/compliance_report, or the bare report
```

`--key` names the package for REST and bare reports (the `opa eval` shape already carries it). `--validate` checks the
document against `schema/oscal_assessment-results_schema.json` and exits 1 when it does not validate, 2 when
`jsonschema` is missing. Several inputs make one result. The `<key>.main` entrypoints are bridges with no controls of
their own (`nist_800_53.main` imports `nist.sp800_53.main`); the reader follows their imports to the framework.

One result per run: `reviewed-controls` lists every control of the frameworks that reported.

| report | assessment-results |
|---|---|
| `control_results` row `pass` | finding `satisfied` (reason `pass`) on the control's statement part; method `EXAMINE` when the row's basis is attestation, else `TEST` |
| row `fail`, `evidence_missing`, `not_attested`, any other status | finding `not-satisfied`, the status as `reason`; `not_attested` is `EXAMINE` |
| row `not_applicable` | an observation, no finding: neither satisfied nor failed |
| row `pass` contradicted by a violation for the same control | `not-satisfied` (fail closed) |
| row findings, and violations that map to the row's control | the finding's observations |
| violation with no row (reports without `control_results`) | one observation and one `not-satisfied` finding (`reason: evidence_missing` when the message says so) |
| row or violation id that is not a catalog control | target `statement-id`, `control-mapped: false`; kept, never dropped |

A control is asserted `satisfied` only from a `control_results` `pass` row (NIST SP 800-53; CIS Windows, RHEL family
and M365 v7): absence of a finding is not evidence. Finding and observation uuids are uuid5 of (framework, control,
message), so re-running on the same facts yields the same ids.

`../_lib/test/roundtrip.sh` (in `make check-converters`) evaluates every framework key on empty input in one `opa eval`,
converts each bare report with `--key`, validates SARIF and OSCAL against the vendored schemas, checks every violation
is a result and an observation and nothing is satisfied, and runs a fixture with every `control_results` status.

## profiles

`dist/profiles/<key>.json` (committed, plus `index.json`): eight OSCAL profiles of ours, one per imported baseline. Each
imports the NIST SP 800-53 Rev 5 catalog (pinned raw URL) and selects exactly the controls the source baseline
selects (`include-controls` / `with-ids`, copied verbatim and in source order), `merge` is `as-is`. Props on the profile
record the source URL, commit, sha256, OSCAL version, uuid and title; back-matter links the source profile and the catalog.

| Key | Source | Controls |
|---|---|---|
| `nist_800_53_rev5_low` | NIST SP 800-53 Rev 5 Low | 149 |
| `nist_800_53_rev5_moderate` | NIST SP 800-53 Rev 5 Moderate | 287 |
| `nist_800_53_rev5_high` | NIST SP 800-53 Rev 5 High | 370 |
| `nist_800_53_rev5_privacy` | NIST SP 800-53 Rev 5 Privacy | 96 |
| `fedramp_rev5_low` | FedRAMP Rev 5 Low | 156 |
| `fedramp_rev5_moderate` | FedRAMP Rev 5 Moderate | 323 |
| `fedramp_rev5_high` | FedRAMP Rev 5 High | 410 |
| `fedramp_rev5_li_saas` | FedRAMP Rev 5 LI-SaaS | 156 |

Sources, both pinned by commit and sha256 (`SOURCES` in `build_profiles.py`):

- NIST: `usnistgov/oscal-content` at `78650f02ad9321bb7b817846f8fbd4f2bcd620de`, `nist.gov/SP800-53/rev5/json/`
  (the four baseline profiles and `NIST_SP-800-53_rev5_catalog.json`).
- FedRAMP Rev 5: the GSA `fedramp-automation` repository no longer exists, so this uses the OSCAL Compass project's
  mirror, `oscal-compass-lab/fedramp-automation` at `76d0473eafe60676d4acbd6cd76362092c389c46`,
  `dist/content/rev5/baselines/json/`.

**Only the control selection is carried.** FedRAMP parameter settings and control alterations (`modify`,
`set-parameters`, `alters`) are not copied; the profile says so in its `remarks`. Take those from the FedRAMP source
profile if you need them.

```bash
python3 converters/exports/oscal/build_profiles.py   # or: make oscal (also builds catalogs and the component-definition)
```

The build downloads each source once into `profiles/cache/` (git-ignored), verifies the sha256 and fails loudly on a
mismatch; a cached file with a matching hash is not fetched again. Without network and cache it exits 3 with a `SKIP:`
line. The round-trip proves every selected control id exists in the cached NIST catalog (including enhancements like
`ac-2.1`), that the counts match `index.json` and the source profile, and validates each profile against the
vendored schema.

## baseline coverage

Which controls of each imported baseline does the library evaluate with at least one executable check, and which not.
`dist/profiles/coverage.csv` (one row per baseline and control, in the profile's order: `baseline_key, control_id, kind,
covered, check_count, checks, sources`) and `dist/profiles/coverage_summary.json` (totals, base / enhancement split,
percentages, `excluded_topic_rows`, the library version it was generated from). `make oscal` rebuilds both
(`build_baseline_coverage.py`, after the profiles and before the component-definition).

Covered means a check maps to that exact control id; it says the library has a check that bears on the control, not that the control is satisfied
or that the checks are sufficient. The component-definition carries the same answer: one extra control-implementation per
baseline (source = that dist profile at the release tag) with one implemented-requirement per **covered** control
(`library-checks`, `mapping-sources`, `granularity` props). Uncovered controls get no requirement: absence is the statement.

Three mapping sources, nothing else (a check is `<framework>:<label>`):

1. `stig-cci`: `crosswalk/stig_800_53/data.json` maps a STIG rule id to 800-53 controls; each `stig_*` catalog control's label is the rule id
   (1246 of 1587 STIG catalog controls are in the map; 341 are not, and
   3191 of the map's 4437 rules have no catalog control).
2. `label-is-800-53`: a library control whose label is itself an 800-53 id (`AC-2`, `AC-2(1)`; cjis, irs_1075, cyber_essentials, ...), the same rule
   as `library_controls` in `crosswalk_csv` `spine_800_53.csv` (the round-trip asserts they are equal).
3. `nist-800-53-module`: our own `nist_sp_800_53` module, labels `NIST AC-2`, `NIST IA-2(1)`, `NIST SC-7/8` (two controls).

**Excluded:** the 65 `nist.sp800_53.access_control#N` topic rows (a topic, not a control). `crosswalk/framework_maps` contributes
nothing: its three 800-53B maps are baseline membership, not library mappings, and the five framework maps (800-171 R3, CSF 2.0, ISO 27001,
PCI DSS v4, CIS Controls v8.1) are `pending` with no rows. **No ISO 27001, PCI DSS, CSF or 800-171 coverage is counted here.**

**Granularity.** STIG rules map to 800-53 *base* controls only (the CCI join does not distinguish enhancements), so they never cover an
enhancement: an enhancement is covered only by an exact `(n)` mapping from source 2 or 3. Hence the enhancement figures are low and a base
control covered by one STIG rule is covered by that rule alone, not by every enhancement of the control. Rows with several sources show all of them.

| Baseline | Controls | Covered | Base covered / total | Enhancements covered / total |
|---|---|---|---|---|
| NIST SP 800-53 Rev 5 Low | 149 | 149 (100.0%) | 131 / 131 (100.0%) | 18 / 18 (100.0%) |
| NIST SP 800-53 Rev 5 Moderate | 287 | 287 (100.0%) | 177 / 177 (100.0%) | 110 / 110 (100.0%) |
| NIST SP 800-53 Rev 5 High | 370 | 370 (100.0%) | 188 / 188 (100.0%) | 182 / 182 (100.0%) |
| NIST SP 800-53 Rev 5 Privacy | 96 | 77 (80.2%) | 75 / 75 (100.0%) | 2 / 21 (9.5%) |
| FedRAMP Rev 5 Low | 156 | 156 (100.0%) | 135 / 135 (100.0%) | 21 / 21 (100.0%) |
| FedRAMP Rev 5 Moderate | 323 | 323 (100.0%) | 181 / 181 (100.0%) | 142 / 142 (100.0%) |
| FedRAMP Rev 5 High | 410 | 410 (100.0%) | 191 / 191 (100.0%) | 219 / 219 (100.0%) |
| FedRAMP Rev 5 LI-SaaS | 156 | 156 (100.0%) | 135 / 135 (100.0%) | 21 / 21 (100.0%) |

Percentages are of the controls the baseline selects. FedRAMP Low and LI-SaaS select the same ids in the pinned source, so their rows are equal.

## Not yet

- Proven imports into compliance-trestle, RegScale, Xacta.
- Pass findings (`satisfied`) for table-driven modules whose reports list attested controls.
- Resolved profile catalogs (a profile applied to the catalog) are not committed: the NIST catalog is 10 MB. The round-trip proves resolvability instead.
