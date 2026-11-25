# crosswalk — the 800-53 control spine

Joins the library's standards onto a shared NIST SP 800-53 substrate so a
control is **assessed once and reported against every standard that inherits
it**. See `docs/CONTROL_CORRELATION_PATTERN.md` for the measured pattern this
implements.

- `stig_800_53/data.json` — `stig_id → [800-53 control]` for 17 STIG
  platform prefixes (4,610 rules) (loads at `data.crosswalk.stig_800_53`). Provenance in `.meta`.
- `correlation.rego` (`package crosswalk.correlation`) — given
  `input.findings` (any stig aggregator's finding list), emits
  `control_status[<800-53>] = "satisfied" | "gap"` (absent = not evaluated)
  and a `summary`. Gap wins; unassessed controls are never reported as passed.
  It also accepts `input.reports` (whole STIG `compliance_report` objects, read from `rule_results`), and
  `control_status` can be `not_reviewed` or `not_applicable` as well.
- `framework_overlay.rego` (`package crosswalk.framework_overlay`) reports the frameworks in
  `framework_maps/data.json` from the same spine (authoritative maps only).
- `framework_maps/data.json` (loads at `data.crosswalk.framework_maps`): `maps.<key>.map` is
  `framework control id → [800-53 ids]`; `catalog_800_53` lists every control and enhancement id of the
  NIST SP 800-53 Rev 5.2.0 catalog (1,014 active, 182 withdrawn) so a mapped id can be checked against it.

## What is in `framework_maps`, and what is not

| Map key | Framework ids | Pairs | Source | Status |
|---|---|---|---|---|
| `nist_800_53b_low` / `_moderate` / `_high` | 131 / 177 / 188 base controls | identity | NIST OSCAL baseline profiles | authoritative |
| `fedramp_rev5_low` / `_moderate` / `_high` / `_li_saas` | 156 / 323 / 410 / 156 | identity | FedRAMP OSCAL baseline profiles (below) | authoritative |
| `nist_csf_2_0` | 106 Subcategories | 736 | NIST OLIR informative reference 186, CSF 2.0 → SP 800-53 Rev 5.2.0 (posted 2025-11-17) | authoritative |
| `nist_800_171_r3` | 97 requirements | 157 | NIST CPRT export of SP 800-171 Rev 3: each requirement's source controls (published May 2024) | authoritative |
| `iso_27001_2022` | 91 Annex A controls + 30 clauses | 643 | NIST OLIR informative reference 155, SP 800-53 Rev 5 → ISO/IEC 27001:2022, inverted (posted 2023-11-13) | authoritative |
| `cis_controls_v8` | 0 shipped | 0 | CIS Controls v8.1 → SP 800-53 Rev 5 workbook, CC BY-NC-ND 4.0 | **pending**: not redistributable here; build it locally (below) |
| `pci_dss_v4` | 0 | 0 | none whose licence allows it | **pending** |

The three NIST-published maps are written by `scripts/gen_nist_framework_maps.py`: download, verify against a
pinned sha256, parse, write. Nothing in them is typed by hand or recalled. Each map's `meta` records the source
URL, its sha256, the publication date, the publisher and licence (works of NIST, a US government agency), the
relationship NIST states, the counts, and a `map_sha256` over the map itself. `make check-generated` runs the
script with `--check`: offline it fails when a map no longer matches its `map_sha256` (a hand edit) or the pins;
when the verified sources are in the local cache it also rebuilds and compares the whole file. A source that
changes upstream no longer matches its pin and stops the build until someone reviews it.

What the generator does with the sources, so the numbers can be checked against them:

- **CSF 2.0.** Subcategory rows only. Nine rows are not carried and are listed in `meta.not_carried`: three
  Subcategory references to a whole 800-53 family (`GV.OC-03 → PT`, `PR.IR-03 → CP`, `PR.IR-03 → IR`) and six
  Category-level rows (`RS.MA`, `RC.RP`). One reference is to a control the catalog marks withdrawn
  (`DE.AE-06 → RA-4`); it is listed in `meta.withdrawn_references_not_carried` and is not redirected to the
  control that replaced it, because NIST's file does not say that. The OLIR catalog records a different sha256
  for this reference than the file NIST serves; the file's Subcategory pairs were checked equal to the
  "SP 800-53 Rev 5.2.0" references in NIST's CSF 2.0 Reference Tool export (2026-11-24). Both hashes are in `meta`.
- **SP 800-171 Rev 3.** The 97 current requirements (`03.01.01` … `03.17.03`); the 33 withdrawn ones are not in
  the map. The export references SP 800-53 Rev 5.1.1; every id is also active in the 5.2.0 catalog.
- **ISO/IEC 27001:2022.** NIST's table runs 800-53 control → ISO element; the map is that table inverted. Keys are
  written as NIST writes them: `A.5.1` … `A.8.33` for Annex A, `4.1` … `10.2` for clauses. NIST maps no 800-53
  control to `A.7.6` or `A.8.34`, so 91 of the 93 Annex A controls have an entry. The file carries ISO
  identifiers only: no ISO text is in the source and none is reproduced. NIST's own caution applies and is kept in
  `meta.relationship`: the mappings are not always one-to-one and control equivalency must not be assumed. The
  file's sha256 equals the hash the OLIR catalog records for it.
- **CIS Controls v8.1 (not shipped).** The workbook's "License for Use" sheet states CC BY-NC-ND 4.0:
  non-commercial redistribution only, and modified material may not be distributed. An id map extracted from it is
  a derivative, and this repository is Apache-2.0, so the map is not vendored. Download the workbook from CIS
  yourself (the entry's `source` has the page) and build a local copy of the data file:

  ```bash
  python3 scripts/gen_nist_framework_maps.py --cis-file <workbook.xlsx> --out /somewhere/outside/the/repo/data.json
  ```

  Load that file at `data.crosswalk.framework_maps` in place of the shipped one. The script refuses an `--out`
  inside the repository. On the workbook CIS served on 2026-11-24 it gives 143 of 153 Safeguards mapped, 367 pairs.
- **PCI DSS v4 (pending).** PCI SSC publishes no PCI DSS → SP 800-53 mapping. The one PCI DSS 4.0.1 → CSF 2.0
  reference in NIST's OLIR catalog (id 183) is from an independent submitter, not PCI SSC or NIST; chaining it
  through CSF to 800-53 would be a derived mapping from a non-authoritative source, so it is not used.

### Reading a non-identity map

The baselines and FedRAMP maps are the identity. The NIST-published maps send one framework id to several 800-53
controls **and enhancements**, and the STIG spine is at base-control granularity. The overlay's rules do not
change, and that has consequences worth knowing before a framework module leans on them:

- One **gap** among the mapped controls is a gap on the framework id. This is the verdict a module can act on.
- **Satisfied** needs every mapped id evaluated and satisfied. A mapped enhancement is never evaluated, so an id
  that maps to one reads `not_covered`, with the satisfied base controls under `spine` and the rest under
  `not_evaluated`. `03.01.08 → [AC-7]` can be satisfied; `03.01.01 → [AC-2, AC-2(3), AC-2(5), AC-2(13)]` cannot.
- A mapping is the publisher's statement that the controls *relate* to the framework id (informative reference,
  source control, or NIST's ISO table). It is not a statement that they are the whole of it. Benchmark results
  never turn a framework control into a pass.

`framework_overlay.inherited_by[<key>][<800-53 id>]` is the reverse index (the framework ids a spine verdict lands
on) and `framework_overlay.map_info[<key>]` is the map's citation (name, source, granularity, `meta`) for a
module to print beside the verdicts it takes.

Worked example (asserted in `tests/test_framework_maps_nist.rego` against the shipped data): the RHEL 9 STIG
account-lockout rule `RHEL-09-411075` maps to `AC-7` (DISA). `AC-7` is the source control of 171 requirement
`03.01.08`, an informative reference of CSF `PR.AA-03`, and one of four controls NIST maps to ISO `A.8.5`.

| `RHEL-09-411075` is | `03.01.08` | `PR.AA-03` | `A.8.5` |
|---|---|---|---|
| Open | gap | gap | gap |
| Not_a_Finding | satisfied (AC-7 is all it maps to) | not_covered: AC-7 satisfied, 9 controls not evaluated | not_covered: AC-7 satisfied, 3 not evaluated |

Measured reach (shipped maps, 2026-11-24; the spine's 4,610 STIG rules reach 65 base controls):

| Map | Framework ids | reached by at least one STIG rule | can read satisfied (every mapped id is a spine control) |
|---|---|---|---|
| `nist_csf_2_0` | 106 | 30 | 2 |
| `nist_800_171_r3` | 97 | 42 | 26 |
| `iso_27001_2022` | 121 | 38 | 11 |

Reach is not compliance: it counts framework ids a rule can speak to, not ids that are met.

**Not wired yet.** The CSF 2.0 module (`nist.csf.main`, key `nist_csf`) and the SP 800-171 Rev 3 module
(`nist_800_171.main`, key `nist_800_171`) do not read these maps; their reports are what they were. Only NIST SP
800-53 and FedRAMP Rev 5 take benchmark verdicts today. The ids already agree: the maps' keys are exactly the 106
Subcategory ids and the 97 requirement ids those modules use (`tests/crosswalk_framework_maps`), so wiring needs
no id translation. The ISO/IEC 27001 module is not checked against `iso_27001_2022` here.

## Framework modules read the spine

A framework module can take a control's technical verdict from benchmark results instead of only from declared
evidence. NIST SP 800-53 (`frameworks/federal/nist/sp_800_53`, key `nist_800_53`) is the first to do so; FedRAMP
Rev 5 follows through its baseline maps (below).

The input is the framework's usual input plus benchmark results in the two shapes above, and no other:

```json
{
  "ac_controls": { "...": "the framework's own facts" },
  "reports":  [ { "facts_supplied": true, "rule_results": [ {"rule": "RHEL-09-255010", "status": "Open"} ] } ],
  "findings": [ {"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"} ]
}
```

What a module reads:

| Rule | Gives |
|---|---|
| `correlation.control_evidence[<800-53 id>]` | `{status, rules, open_rules, not_reviewed_rules}`: the verdict with the rule ids behind it |
| `framework_overlay.control_evidence[<map key>][<framework control id>]` | `{status, spine, not_evaluated}` through `framework_maps`: `gap`, `satisfied` or `not_covered`, the evaluated 800-53 controls with their rules, and the mapped controls nothing spoke to |
| `correlation.evidence_supplied` | whether the input carries `reports` or `findings` at all |
| `correlation.spine_loaded` | whether the map is present in `data` |
| `correlation.unmapped_rules`, `correlation.reports_without_facts` | what could not be used |

The combination rule, as NIST SP 800-53 implements it:

1. A benchmark **gap** fails the control, whatever its declared evidence or attestation says.
2. A benchmark **satisfied** verdict is recorded on the control and changes nothing else. The control's own
   evidence and attestation still apply, so benchmark results never turn a control into a pass.
3. A control no supplied rule maps to stays **not evaluated** and is shown as such.
4. With no benchmark results in the input, the framework's report is what it was before.

Fail closed: a report with `facts_supplied: false` counts every rule in it as Open; a rule id the map does not
know speaks to no control; benchmark results that cannot be read, or that arrive when this package or its data is
not loaded, are a `FAIL-CLOSED` finding in the framework's report. Verdicts are carried through the maps as they
are. Nothing here scores, weights or ranks.

Loading: a framework module refers to `data.crosswalk.correlation` by reference only, so it still loads and
evaluates without this directory. To use benchmark results, load `correlation.rego` into the same OPA as the
framework and the map at `data.crosswalk.stig_800_53` (from the repository root `opa eval -d .` does that; for a
single file use `-d crosswalk.stig_800_53:crosswalk/stig_800_53/data.json`, or `PUT /v1/data/crosswalk/stig_800_53`
on a server). The map is at base-control granularity: an enhancement such as AC-2(1) never gets a verdict.

### FedRAMP Rev 5 reads the spine through its baseline maps

FedRAMP (`frameworks/federal/fedramp`, key `fedramp`) is the second module, and the first to go through
`framework_maps`. `framework_maps/data.json` carries one map per FedRAMP Rev 5 baseline (`fedramp_rev5_low`,
`fedramp_rev5_moderate`, `fedramp_rev5_high`, `fedramp_rev5_li_saas`). FedRAMP selects NIST SP 800-53 Rev 5
controls under the catalog's own ids, so each map is the identity (`"AC-7": ["AC-7"]`) for exactly the controls
and enhancements the baseline's OSCAL profile selects: 156, 323, 410 and 156 ids. The maps are generated by
`scripts/gen_fedramp_framework_maps.py` from `converters/exports/oscal/dist/profiles/fedramp_rev5_*.json`; each
cites the pinned source profile (URL, commit, sha256) and is `authoritative`. `make check-generated` fails when
they no longer match the profiles. Do not edit them by hand.

```json
{
  "impact_level": "moderate",
  "authorization": { "...": "the FedRAMP module's own facts" },
  "reports":  [ { "facts_supplied": true, "rule_results": [ {"rule": "RHEL-09-211010", "status": "Open"} ] } ],
  "findings": [ {"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"} ]
}
```

`fedramp.main.compliance_report` reads `framework_overlay.control_evidence["fedramp_rev5_<level>"]` for the
declared impact level (the High baseline until a level is declared) and applies the same combination rule:

- A gap fails the baseline control: a `FedRAMP <id>: benchmark results show a gap ...` finding, `compliant: false`,
  the id in `failed_control_ids`. This holds for a control the module has its own check for (CA-2, RA-5, ...)
  and for one it has none for (AC-7, CM-6, ...).
- Satisfied, not reviewed and not applicable are recorded on the control's row and change nothing. No control
  passes on benchmark results.
- A spine verdict on a control the baseline does not select (AC-6 at Low, for example) is not a FedRAMP finding
  at that level. It is listed under `benchmark_evidence.controls_not_in_baseline`, and under
  `gap_not_in_baseline` when it is a gap.
- Fail closed, as above. "Not loaded" here means any of `correlation.rego`, `framework_overlay.rego`,
  `stig_800_53/data.json` or the baseline's map in `framework_maps/data.json`.

With benchmark results the report gains `benchmark_evidence`, `control_results` and `control_result_counts`.
The FedRAMP module evaluates 10 to 13 checks of its own, not the baseline, so its rows are its own: one per
control of the baseline plus one per check, in natural id order, each `{id, status, checked, findings,
benchmark}`. `status` is `pass` (a check of the module with no finding), `fail` (a finding names the control: the
module's own or a benchmark gap) or `not_evaluated` (the module has no check for the control and the benchmark
found no gap; never a pass). `total_controls`, `failed_controls` and `area_summary` keep their meaning: the
module's own checks. Without benchmark results the report has none of the three additions and is unchanged.
For per-control results from 800-53 evidence across a FedRAMP baseline, use the NIST SP 800-53 module's
`baseline_results.fedramp_*`; FedRAMP 20x (`fedramp_20x`) is indicator-based and does not read the spine.

Measured reach (shipped maps, 2026-11-22): the RHEL 9 STIG V2R10 module's 445 rules all map, to 47 base controls
of 800-53. Of those:

| FedRAMP Rev 5 baseline | ids selected | base controls | reached by the RHEL 9 STIG | reached, outside the baseline |
|---|---|---|---|---|
| Low (and LI-SaaS) | 156 | 135 | 27 | 20 |
| Moderate | 323 | 181 | 41 | 6 |
| High | 410 | 191 | 45 | 2 (AU-14, SC-11) |

Reach is the number of baseline controls at least one rule maps to, not a share of the baseline that is met: a
reached control is only as covered as the rules DISA maps to it, and no enhancement is reached.
`tests/crosswalk_fedramp` asserts these figures against the shipped data.

Loading for FedRAMP adds two things to the list above: `framework_overlay.rego`, and the maps at
`data.crosswalk.framework_maps` (`-d crosswalk.framework_maps:crosswalk/framework_maps/data.json`, or
`PUT /v1/data/crosswalk/framework_maps`).

### Where the data lands in a bundle

The modules read `data.crosswalk.stig_800_53` and `data.crosswalk.framework_maps`. From the repository root
(`opa eval -d .`, `opa test .`, `opa build -b .`) the data files land there by their path. Passing the directory
by itself (`-d crosswalk`, `opa build crosswalk`) roots them at `data.stig_800_53` and `data.framework_maps`,
the crosswalk reads as not loaded, and a framework given benchmark results reports `FAIL-CLOSED`. Use the
prefixed form, `-d crosswalk:crosswalk`. The wasm bundles (`converters/packaging/wasm/build.py`) do, and check it
on every build; `make check-converters` runs the same check without the wasm compile
(`build.py --check-data-paths`). The bundle published to GHCR does not carry `crosswalk/` yet: its build step still
passes `--ignore crosswalk` and `--ignore '*.json'` (`.github/workflows/publish-ghcr.yml`). Built without those two
flags the bundle carries the three data files under the `crosswalk` root the manifest already declares.

Add a standard: ship its `<id> → 800-53` map in the same shape, then the
overlap analysis in the pattern doc §7 applies unchanged.
