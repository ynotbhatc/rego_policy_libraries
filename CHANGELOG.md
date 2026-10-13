# Changelog

All notable changes to this library will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

## [2.3.6] - 2026-10-12

### Changed — citations read from every message shape; the last six fail-open modules

- The control-id reader now sees `sprintf` built messages in a rule head (`violations contains sprintf("CIS
  4.1.3.x: ...", [x]) if`) and object-valued violations (`v := {"standard": "CIP-002", "requirement": ...}`,
  `{"control_id": ..., "finding": ...}`), citing them from the id the module already carries. Uncited violation
  rules fall from 1,272 to 803 with no policy edited; cited controls rise from 8,966 to 9,354. The 803 left either
  build their message from data at evaluation time or carry no standard reference by design (GEISA, OWASP LLM,
  admission gates). Count: 13,775.
- Six modules whose reports were undefined until 2.3.5 turned out to be fail-open once they evaluated (the Amazon
  Linux filesystem and network sections, the RHEL 8 and Rocky 8 and 9 network sections, the Oracle legacy
  user-account module). Each now carries the fail-closed notice; `docs/TEST_GENERATION.md`: undefined reports 1,
  unguarded fail-open 0; suite 3520 tests.
- **Declared totals from the standards' own text** (`standard_total` in the report literal, compared in control
  ids, cited to where the number was counted): CIS Controls v8.1 **153 safeguards** — 153 of 153 cited, full;
  NIST CSF 2.0 **106 subcategories** (NIST CSWP 29: GV 31, ID 21, PR 22, DE 11, RS 13, RC 8) — 87 cited, partial,
  19 to write; NIST SP 800-171 **Rev 2, 110 requirements** (the numbering the module cites; Rev 3 has 97 active
  `03.xx.yy` ids, 130 in the text with 33 withdrawn, migration pending) — 88 cited, partial. Both NIST gaps are
  named in `KNOWN_GAPS` so CI keeps judging them; 45 of 49 declaring modules are within 10 %.

## [2.3.5] - 2026-10-12

### Fixed — the fail-closed contract, module by module

- **58 reports that were undefined on empty input now evaluate.** Three causes, each fixed at the source: CIS
  section reports echoed raw `input.x.y` facts (any missing fact voided the whole report) — every echo inside a
  report or summary literal is now `object.get(input, [...], null)`, `[]` where it is counted or iterated; NERC CIP
  reports embedded boolean rules that were undefined rather than false — each gets `default := false`; counted
  collections assigned from input get `default := []`. The one left is `enforcement/git/playbook_documentation.rego`,
  a protected path for its owner.
- **The 18 unguarded fail-open modules fail closed.** Modules with a `violations` set gain a `FAIL-CLOSED` notice
  when the facts they key on are absent; modules that aggregate arrays make those facts a precondition of
  `compliant` with a `false` default; CMMC's `compliant` gains the default it lacked; GEISA VEE's "not required"
  answer now needs a discovery response to say so. The test generator now asserts fail-closed for them
  (`docs/TEST_GENERATION.md`: undefined reports 1, unguarded fail-open 6; suite 3514 tests).
- **Strict mode is clean.** 31 `opa check --strict` errors fixed (unused imports, arguments, assignments; FinOps
  `is_past_date` now compares the date instead of `year < 2025`); every tree except `enforcement/git` (pending its
  owner) passes `opa check --strict`. The CI step that enforces it follows in its own PR.
- Control-level checks: 13,758 → 13,771 (the fail-closed notices are cited checks).


## [2.3.4] - 2026-10-12

### Added — a smoke test for every module, roles and a measured fail-closed guard in the coverage scan

- `scripts/gen_tests.py` wrote a smoke test for every module that had none (554 files under `tests/`). Each
  asserts only what its module was proven to do on empty input: it evaluates without a runtime error; its report
  is an object; its report is not compliant (fail-closed); its violations are non-empty. The suite grows from
  1,954 to 3375 tests; the CI discovery floor is ratcheted to 3,000.
- The coverage scan stamps roles — `section` (a small module an orchestrator in the same tree aggregates),
  `orchestrator`, `overlay` (supply-chain scoring, crosswalk), `gate` (enforcement and governance decisions) —
  and a measured **`guard`**: one evaluation of the whole tree on empty input says, per module, whether
  fail-closed is enforced by the module itself (`self`, 543), by a fail-closed orchestrator that references it
  (`orchestrator`, 24), by nothing (`none`, 35) or does not apply (`n/a`). Of the 165 modules that looked sparse
  by size, 147 are one of those roles by design; 18 are genuinely thin and `docs/COVERAGE_SCAN.md` names them.
- `docs/TEST_GENERATION.md` lists what the generator could **not** assert, classified by guard. The findings
  worth acting on: **60 modules whose report is undefined on empty input** (the `{}` collapse the contract
  forbids: a member of the report literal is undefined without facts, so a consumer gets nothing); **18
  modules that report compliant on empty input with no orchestrator guarding them** (fail-open); 19 that are
  compliant alone but guarded by their orchestrator (by design); 2 whose report says compliant while the
  module emits violations (the report's `compliant` is computed from a subset of the checks).

## [2.3.3] - 2026-10-12

### Changed — a check is a distinct check, not a distinct citation: 13,758, validated against 47 declared totals

Trying to fill the "sparse" modules showed they were not sparse. NIS2 holds 35 checks and declares 34; the SEC
rule module holds 23 and declares 22; FDA Part 11 holds 42 and declares 43; GLBA 34 and declares 33. The 2.3.2
rule reported 14, 8, 30 and 26 because it folded every check citing the same article paragraph into one
("Art.21(2)(c): BCP not documented" and "Art.21(2)(c): BCP not tested annually" became one control). A check is
now a distinct (control id, text) pair per module; a row re-listed with identical text is still one.

The rule is now validated by evidence outside itself: 47 modules declare their own total in their report
literal, and 45 are within 10 % of it under this rule (NSA/CISA Kubernetes 43/43, PostgreSQL 15 172/172, CSA CCM
185/197 across its domain modules ...). The two below are licensed texts we could only partly transcribe
(ISO/IEC 27701 67/134, CIS Windows 11 210/267) and are named in `scripts/coverage_stamp.py`; `make
check-coverage` fails if any other declaring module falls below 90 %, so a counter regression cannot pass CI.

| | checks |
|---|---|
| 2.2.0 regex | 7,867 |
| 2.3.0 AST, one shape | 7,560 |
| 2.3.1 AST, six shapes | 11,645 |
| 2.3.2 exclusion fix | 11,693 |
| **2.3.3 distinct checks, validated** | **13,758** |

11,693 module-level controls and 11,124 distinct controls across 143 frameworks are unchanged; the OSCAL
catalogs, crosswalk CSV and XCCDF table are keyed on controls and do not move.


## [2.3.2] - 2026-10-12

### Changed — verification pass on the 2.3.1 count: 11,693

Re-checking 2.3.1 by hand against seven modules of different shapes found one defect: the check-map shape dropped
names that merely *contained* a plumbing word (`shared_accounts_managed` matched `count`). The exclusion list is
now anchored on whole words; 48 checks return. 2.3.1's stamping also left a second, misplaced `coverage:` block at
the end of every stamped module (harmless to OPA, wrong all the same); the stamper now removes every existing
block before writing one, and `make check-coverage` fails unless exactly one sits inside `custom:`.

Reproducibility, on today's tree: the 2.2.0 counter says 7,912, the 2.3.0 counter says 7,560, the 2.3.1 counter
says 11,645, this one says 11,693. Each earlier number is what its rule could see, not a different library.


## [2.3.1] - 2026-10-12

### Changed — the count reads every policy shape: 11,645 control-level checks

2.3.0 fixed *how* the counter read a line; this release fixes *what* it looks for. The 2.3.0 rule saw only
violation sets named `violations`/`deny` and top-level control tables, so 233 real modules counted as zero:
every STIG core module (`findings := [finding_r_<id>, ...]`), the PostgreSQL / MySQL / Oracle / Windows 11
benchmarks (`<section>_violations := [v | arrays := [["1.1: ..." | not check], ...]]`), the sectioned CIS host
modules (`config_violations contains "CIS 4.1.1: ..." if`), the SOC 2 and CAF modules (check maps
`findings := {"mfa_for_privileged_access": mfa_for_privileged_access, ...}`), the CMMC practice tables and the
Sentinel gates (`violation_df_003 contains msg if`). `scripts/rego_ast.py` now reads all six shapes from OPA's AST
and counts, per module, every distinct control id it evaluates plus each check that carries no id. Report
plumbing (`compliance_summary`, `total_controls`, section aggregates) is excluded by name.

| | 2.2.0 | 2.3.0 | 2.3.1 |
|---|---|---|---|
| control-level checks | 7,867 (regex, over- and under-counted) | 7,560 (AST, one shape) | **11,645 (AST, every shape)** |
| modules counted as zero | 233 | 233 | 55 (42 orchestrators, 13 pure-boolean modules) |

### Added — coverage stamped into every module's METADATA

`make coverage` (`scripts/coverage_stamp.py`) scans every module and writes `custom.coverage` into its
`# METADATA` block: checks, cited ids, the total the module itself declares, density (`full` / `partial` /
`sparse` against a declared total; `sized` / `sparse` / `stub` by size; `orchestrator`; `unrecognised`),
whether a test file exists, the entrypoint, and the library version of the scan. `make check-coverage` (in CI)
fails when a stamp is stale, so density and gaps are validated on every change instead of rediscovered.
`docs/COVERAGE_SCAN.md` is the human report: distribution, per-family totals, modules below their own declared
total (the provable missing controls), sparse modules without a declared total, unrecognised shapes, untested
modules.


## [2.3.0] - 2026-10-12

### Changed — the control-level count is now exact, and lower

**7,560 control-level checks** (was 7,867 at 2.2.0). No policy changed; the counter did. The old `make count`
read source lines with regular expressions and had two faults that partly cancelled: it counted the fields inside
multi-line table rows (`"text": "..."`) and the rows of report scaffolding (`report := Ellipsis`) as checks (+945),
and it missed every violation rule whose set element is a string literal or an object rather than a bare
variable (`violations contains "CIS L2 1.5: ..." if`, `deny contains {"msg": m} if`) (−638). The count now comes
from OPA's own parser (`scripts/rego_ast.py`, `opa parse --format json`): a multi-value violation rule, a leaf
object row of a top-level table, or a string row of a check table is one check; fields and scaffolding never are.
`scripts/inventory_controls.py` reads the same AST under the same rule, so the exports and the published number
cannot drift (7,560 checks → 6,076 distinct controls across 121 frameworks with controls).

We say "largest executable compliance library anyone can verify" and that claim must be exact; the next largest
public rule set we measured, Azure Policy built-ins, holds 5,130 definitions.

### Added
- **OSCAL 1.2.3 catalog export** (`converters/exports/oscal`): one catalog per framework (121) built from the new shared control inventory `scripts/inventory_controls.py` (7,560 checks → 6,076 distinct controls); committed under `dist/catalogs/`, combined `all.json` attached to releases, every catalog validated against the NIST schema in CI with a round-trip test proving no control is lost or invented.
- **SARIF 2.1.0 and OCSF 1.9.0 exports** (`converters/exports/sarif`, `converters/exports/ocsf`): convert any `compliance_report` output (an `opa eval -f json` file) into SARIF results for GitHub code scanning and every SARIF viewer, and into OCSF `compliance_finding` events for Security Lake, Splunk and Sentinel. Both use the OSCAL control id as the rule / finding uid, read one shared findings reader (`converters/exports/_lib/findings.py`), and are schema-validated with round-trip tests in CI.
- **Crosswalk CSVs** (`converters/exports/crosswalk_csv/dist`): `controls.csv` (every control with its OSCAL id), `stig_to_800_53.csv` (2,767 STIG rules), `framework_to_800_53.csv`, and `spine_800_53.csv`, the SCF-style pivot on the 800-53 spine (baseline membership, STIG rules per platform, library controls). **CIS-CAT / XCCDF join table** (`converters/exports/xccdf_ids/dist/cis_xccdf_ids.csv`): 1,126 CIS sections on 15 platforms with the XCCDF rule-id prefix to join CIS-CAT results on. Both committed, round-trip tested, kept fresh by CI.
- **OSCAL component-definition and assessment-results** (`converters/exports/oscal`): `dist/component-definition.json` (one implemented-requirement per catalog control) and `build_assessment_results.py` (from `compliance_report` output: one finding and observation per distinct violation targeting the catalog statement; controls without a finding are not asserted satisfied). Schema-validated and round-trip tested with the catalogs.

_Nothing yet._

---

## [2.2.0] - 2026-10-12

The Asia-Pacific release. **740 policy files** (996 including tests, counted at main 2026-10-12),
**7,867 control-level checks** (`make count`, new in this release; 7,104 at 2.1.1). 1,945 tests pass. No policy is removed or renamed; `enforcement/aap` is unchanged. Eleven new
frameworks in one day: the CCPA 2025 regulations (three modules) and seven Asia-Pacific regimes —
Singapore, India (two), Japan, Australia, Hong Kong, Malaysia — each written from the regulator's own
text, each an attestation module that fails closed and reports gaps by chapter or section.
Metadata vocabulary gains sources `mas`, `cert-in`, `meity`, `meti`, `apra`, `hkma`, `bnm` and domains
`singapore`, `india`, `japan`, `hong-kong`, `malaysia`.

### Added
- **Bank Negara Malaysia — Risk Management in Technology (RMiT), 25 September 2026** —
  `frameworks/financial/bnm_rmit/`, `bnm_rmit.main`, written from BNM/RH/PD 028-98 as published: one control
  per mandatory **S paragraph of Part B §§8–15 (99 standards)** — governance, technology risk management,
  technology operations, cybersecurity management, digital services, technology audits, external party
  assurance, awareness. Cloud, third-party, NCII and digital-services paragraphs are gated by flags that must
  be declared true or false. The report carries the 2027 dated obligations and the 4-hour / 120-minute
  availability targets. 11 tests. Vocabulary gains source `bnm` and domain `malaysia`.
- **HKMA Supervisory Policy Manual TM-G-1 General Principles for Technology Risk Management + TM-C-1
  Supervisory Approach on Cyber Risk Management (Hong Kong)** — `frameworks/financial/hkma_trm/`,
  `hkma_trm.main`, written from the HKMA texts: one control per TM-G-1 paragraph that sets an expectation
  across IT governance, security management, system development and change, information processing,
  communications networks and service providers (62), plus the five duties TM-C-1 (29 Nov 2024, statutory)
  places on AIs: proportionate framework, prompt incident reporting to the HKMA, regular C-RAF assessments,
  Secure Tertiary Data Backup, CISP intelligence sharing. WLAN, technology outsourcing and overseas-IT
  paragraphs are gated by flags that must be declared true or false. 9 tests. Vocabulary gains source
  `hkma` and domain `hong-kong`.
- **APRA Prudential Standard CPS 234 Information Security (Australia, July 2019)** —
  `frameworks/financial/apra_cps234/`, `apra_cps234.main`, written from the APRA text: one control per
  requirement paragraph 13–36 (24 controls) across roles, capability, policy framework, classification,
  controls, incident management, testing, internal audit and APRA notification. The four paragraphs that
  condition on related-party or third-party management of information assets (16, 22, 28, 34) are gated by
  `third_party_managed_assets`, which must be declared true or false. The 72-hour incident and
  10-business-day control-weakness notification clocks are in the report. 8 tests. Vocabulary gains source `apra`.
- **METI Cybersecurity Management Guidelines Ver. 3.0 (Japan, 2023)** — `frameworks/regional/meti_csm/`,
  `meti_csm.main`, written from the METI/IPA English text: Appendix A-1 (the three principles
  management must recognise, 9 items) and A-2 (the ten directions, 40 items), **49 items** each carrying
  the NIST CSF subcategory references the Guidelines print beside it. Attestation shape with a
  per-principle / per-direction gap report. Fail-closed; nothing can be scoped out. 10 tests.
  Vocabulary gains source `meti` and domain `japan`.
- **India — Digital Personal Data Protection Act, 2023 + DPDP Rules, 2025** — `frameworks/privacy/dpdp_india/`,
  `dpdp.main`, written from the Act and the Rules as gazetted (G.S.R. 846(E), 13 November 2025):
  s.4 lawful basis, s.5/Rule 3 notice, s.6 consent, s.8 general obligations, **Rule 6 reasonable security
  safeguards** (encryption/masking/tokens, access control, access logs, backups, one-year log retention,
  processor contracts), **Rule 7 breach intimation** (Data Principals without delay; Board without delay and
  the detailed report within 72 hours), Rule 8 retention and Third Schedule three-year erasure with the
  48-hour notice, s.9/Rules 10–12 children (verifiable parental consent with identity due diligence, no
  tracking or targeted ads), s.10/Rule 13 Significant Data Fiduciary (DPO in India, independent auditor,
  annual DPIA and audit, algorithmic due diligence, data-localisation of notified data), ss.11–14/Rule 14
  rights, s.16/Rule 15 transfers, Rule 23 Government requests. Four scope flags must be declared true or
  false. The report carries the phased commencement dates (substantive duties 2027-05-13) and the Schedule
  penalty tiers. 10 tests. Vocabulary gains source `meity`.
- **CERT-In Directions under s.70B(6) of the IT Act (India, 28 April 2022)** — `frameworks/regional/cert_in/`,
  `cert_in.main`. Directions (i)–(vi) and Annexures I–III from the CERT-In text: NIC/NPL time
  synchronisation, **6-hour incident reporting** with all **twenty Annexure I incident types** as
  individual checks, CERT-In orders and the Annexure II Point of Contact, **180-day rolling logs kept
  within India**, subscriber registration (7 fields, 5-year retention) for data centre / VPS / cloud /
  VPN providers, and KYC + reconstructable transaction records for virtual asset service providers.
  The two sector flags must be declared true or false; undeclared is a violation. 12 tests. Vocabulary
  gains source `cert-in` and domain `india`.
- **MAS Technology Risk Management Guidelines (Singapore, January 2021)** — `frameworks/financial/mas_trm/`,
  `mas_trm.main`. One control per Guidelines paragraph that states a "should": **237 controls across
  chapters 3–15** (governance, TRM framework, project management and security-by-design, software
  development, IT service management, IT resilience, access control, cryptography, data and
  infrastructure security, cyber security operations, cyber security assessment, online financial
  services, IT audit), attested from the FI's evidence as `input.mas_trm.controls["<paragraph>"]`.
  Per-chapter report with gaps; chapter 14 is scoped out by `online_financial_services=false` and
  nothing else can be excluded. Fail-closed on absent/non-true attestations, unknown ids and a
  malformed container. 14 tests. First Asia-Pacific framework beyond ACSC Essential Eight; metadata
  vocabulary gains source `mas` and domain `singapore`.
- **CCPA — the 2025 CPPA regulations (effective 2026-01-01)** as three new modules under
  `frameworks/privacy/ccpa/`, written from the OAL-approved text (approved 2025-09-22):
  - `ccpa.cybersecurity_audits` — Article 9, §§7120–7124: §7120 applicability thresholds
    (with a contradiction check when a business declares itself out of scope), §7121 first-report
    deadlines by revenue tier (2028/2029/2030-04-01, date-gated), §7122 auditor qualification and
    independence (internal-auditor reporting line), all **18 §7123(c) components** (each may be
    recorded not-applicable by the auditor), the §7123(e) report contents, and §7124 certification
    to the Agency. 44 checks.
  - `ccpa.risk_assessments` — Article 10, §§7150–7157: the six §7150(b) triggering activities
    (each must be declared in_use true/false — undeclared is a violation), §7151 stakeholder
    involvement, the nine §7152(a) report requirements plus the ADMT logic/output requirement,
    §7153 provider duties, §7155 timing (three-year review, 45-day material-change update, legacy
    processing by 2027-12-31, five-year retention) and §7157 submission to the Agency. 26 checks.
  - `ccpa.admt` — Article 11, §§7200–7222: Pre-use Notice contents (§7220), the opt-out right
    with the three §7221(b) exceptions and their conditions, sixteen §7221 opt-out mechanics
    (two methods, named link, no cookie-banner-only, no verification, 15-business-day cessation,
    service-provider notification), and the §7222 access right. Compliance date 2027-01-01 is
    reported, and gaps are reported before it. 36 checks.
  - `ccpa.main` now orchestrates 7 modules (was 4). 27 new tests in
    `frameworks/privacy/ccpa/tests/test_ccpa_2026_regulations.rego`.

### Changed
- `STANDARDS_UPDATE_REGISTRY.md`: CCPA row moved from "rulemaking ongoing" to implemented;
  COBIT row records COBIT 7's publication (ISACA, Foundation cutover 2026-10-27) and that the
  module stays COBIT 2019 until the COBIT 7 content is published and regenerated.

---

## [2.1.1] - 2026-10-10

Two days after 2.1.0, for the first consumer's second finding. **729 policy files**
(977 including tests, counted at main 2026-10-10). 1,845 tests pass. No policy is
removed or renamed; `enforcement/aap` is unchanged.


### Added
- **Package-scoped `# METADATA` on every policy.** All 729 policy files now resolve to an OPA
  annotation block carrying `title` and `custom.{class, framework, source, domains}`, so a
  consumer classifies a policy from `opa inspect -a` instead of parsing directory names. `class`
  is a closed set (`security`, `compliance`, `ot`, `governance`, `enforcement`,
  `threat-detection`) that maps to the OPA container; `source` and `domains` come from the
  controlled vocabulary in `scripts/metadata_vocabulary.json`. `scripts/check_metadata.py`
  (`make metadata`, now part of `make check`) fails when a block is missing or off-vocabulary.
  `scripts/backfill_metadata.py` is the directory-driven bootstrap for new trees. OPA permits one
  package-scoped block per package, so the two multi-file packages (`aac.aap.policy`,
  `supply_chain.slsa`) have one owning file and pointer comments in the rest.

### Fixed
- **`eu_ai_act` reported compliant on empty input (fail-open, #186).** A missing classification
  was given the strictest tier and then judged on the absence of evidence: no prohibited-practice
  fact is `true`, so the module has zero violations and `overall_compliant` was `true` on `{}`.
  `eu_ai_act.main` now carries the same fail-closed gate as `cis_rhel9.main`: `input.eu_ai_act`
  must be a non-empty object and `system_classification.risk_tier` one of the five tiers before
  anything can pass; each failure is an explicit `FAIL-CLOSED:` violation. The report gains a
  `compliant` key (one key across frameworks), `facts_supplied` and `classified`; `violations`,
  `violation_count` and `total_violations` now carry the real aggregate instead of the literal
  `[]` / `0` they were hard-coded to. Tests: `governance/eu_ai_act/tests/test_eu_ai_act_main.rego`.
- **DISA STIG RHEL 8 / RHEL 9 were unreachable from the uniform entrypoint.** Both bundles
  exposed only `stig_assessment` and had no `stig.<platform>.main` alias, so a caller using the
  library-wide `data.<package>.main.compliance_report` contract got `undefined` back. Added the
  uniform `compliance_report` contract to `stig_rhel8_complete.rego` / `stig_rhel9_complete.rego`
  and the fail-closed `stig.rhel_8.main` / `stig.rhel_9.main` aliases
  (`benchmarks/stig/rhel_8/stig_rhel_8_main.rego`, `benchmarks/stig/rhel_9/stig_rhel_9_main.rego`),
  matching the other 13 STIG platforms: empty input reports `compliant=false`,
  `facts_supplied=false`, 0% with an explicit FAIL-CLOSED CAT I finding. `total_controls` is derived
  from the module finding arrays (73 for RHEL 8 V1R13, 143 for RHEL 9 V2R2), not hard-coded.
  Tests: `tests/test_stig_rhel_8_main.rego`, `tests/test_stig_rhel_9_main.rego`.

---

## [2.1.0] - 2026-10-08

Seventeen days of additions since 2.0.0, and the first release consumed by Red Hat's AAP
Policy as Code in a live environment (ericcames/sales.demos#841). The library grew from 638 to
**729 policy files** (976 including tests, counted at main 2026-10-08). 1,837 tests pass.

### Fixed — fail closed, everywhere it was not
- **CIS RHEL 9 sections fail closed on missing facts** (#183). `filesystem`, `network` and
  `user_group` reported compliant with no facts at all, so `cis_rhel9/compliance_assessment`
  scored 21.4% with 3/14 sections compliant on empty input. Each now emits a `FAIL-CLOSED`
  violation per missing required fact object; `{}` reports `compliant=false, score=0, 0/14`.
  The guard clears when the fact objects are supplied and names each missing key. Reported by
  Eric Ames while attaching the policy to AAP.
- **STIG RHEL 8 / RHEL 9 gain `.main` aggregators** (#182), so `stig.rhel_8.main` (73 rules)
  and `stig.rhel_9.main` (143 rules) answer the uniform `compliance_report` entrypoint and fail
  closed on `{}` (every rule failed, 0%). They were previously unreachable by key.
- **AAP Policy as Code: AAP 2.7's team objects accepted** (#161), with a real AAP 2.7 input
  document captured from a live decision log as a test fixture.
- `is_object` guard on `_attest` in the CJIS, Zero Trust and Essential Eight orchestrators (#143);
  governance time-box clamp, approval expiry enforced, registry shape guard (#138).

### Added — new frameworks
- **AI governance:** ISO/IEC 42005:2025 AI impact assessment and the OWASP LLM Top 10 (2026)
  with a MITRE ATLAS crosswalk (#181); governance self-protecting MCP gate, load-bearing agent
  identity, crown-jewels tier (#136); group-membership read tools approved for agent inventory
  lookups (#146).
- **Federal:** FedRAMP 20x Key Security Indicators, 46 KSIs with Class B/C profiles (#180);
  PQC Readiness — FIPS 203/204/205, EO 14412, CNSA 2.0 (#165); FBI CJIS Security Policy, 13
  policy areas (#135); Zero Trust — CISA ZTMM v2.0 + NIST SP 800-207 (#132); IRS Publication
  1075, 8 safeguard areas (#140).
- **Regional:** UK MoD DCC — DEF STAN 05-138 Issue 4, all 148 controls (#166); BSI C5:2020
  (#142); UK Cyber Essentials (Willow) (#141); ACSC Essential Eight Maturity Model (#133).
- **Benchmarks:** CIS MCP Server Benchmark v1.0.0, 46/55 recommendations (#145).
- **Supply chain:** SSDF-GenAI, NIST SP 800-161 and S2C2F on a shared spine with a measured
  collapse metric (#111).
- **DORA level-2 RTS modules:** subcontracting (2025/532) and TLPT (2025/1190) (#177).

### Changed — reconciled with the standards as published
- EU AI Act: Digital Omnibus Reg. (EU) 2026/1744 dates and new Art. 5 prohibitions (#175).
- CRA: reconciled with the final Regulation (EU) 2024/2847 text (#167). ITAR: 2025–2026 final
  rules, §120.54 cites, AUKUS §126.7 (#178). NY DFS second amendment final tranche: universal
  MFA, 500.13(a) asset inventory (#176). CISA CPG titles aligned to the 2025-12-11 publication
  (#179). Standards registry 2026-10 sweep triage (#174).

### Changed — distribution and CI
- The bundle declares explicit roots so a consumer can compose site config beside it (#164).
- CI tests on OPA 1.10.0, the version the bundle publishes for (#163), and `opa check` runs
  package-aware per directory (#162). `actions/checkout` v7 (#134).
- A pre-merge Rego review skill tuned to this library's failure classes (#137, #139).

### Known limitations
- Seven `.main` entrypoints still answer `{}` on empty input: `digital_sovereignty`, `fisma`,
  `gdpr`, `hipaa`, `pci_dss`, `soc2`, `sox`. A consumer must treat an empty report as a failed
  assessment, never as a pass.
- The CIS RHEL 9 input is a custom document (about 60 top-level keys), not raw Ansible facts
  or OpenSCAP output; no shipped collector produces all of it yet. The section-level guards
  above make a partial input report what it did not evaluate.

---

## [2.0.0] - 2026-09-21

Six months of additions since the initial extraction. The library grew from 327 to
**638 policy files** (796 including tests), roughly doubling framework coverage and adding a
production distribution path, Level 2 hardening profiles, and a standards-update registry.

### Added — new frameworks
- **AI governance:** EU AI Act (Regulation 2024/1689) suite (`governance/eu_ai_act/`) and
  ISO/IEC 42001:2023 AIMS (`governance/iso_42001/`), completing the AI trio with NIST AI RMF.
- **Privacy:** ISO/IEC 27701:2019 PIMS; CCPA / CPRA; FERPA (20 U.S.C. §1232g) and
  COPPA (16 CFR Part 312) — 53 controls across the two education/children's-privacy rules.
- **Federal:** NIST SP 800-171 Rev 3 (14 families, 110 CUI requirements); CISA CPG 2.0
  (34 goals across the six CSF-2.0 functions incl. GOVERN).
- **Management:** CSA CCM v4.0 (16 domains, 197 controls); COBIT 2019 governance-system attestation.
- **Security program:** **CIS Controls v8.1** — the 18 Critical Security Controls / 153 safeguards,
  Implementation-Group tiered (cumulative IG1 ⊆ IG2 ⊆ IG3 scoring) with a fail-closed report
  (`frameworks/management/cis_controls_v8/`). Distinct from the CIS *Benchmarks* the library already ships.
- **SaaS security posture:** CISA SCuBA Microsoft 365 Secure Configuration Baselines — 104 policies
  across 7 products (Entra ID, Exchange Online, SharePoint/OneDrive, Teams, Defender, Power Platform,
  Power BI).
- **Financial:** GLBA Safeguards Rule (16 CFR 314).
- **Regulatory:** ITAR (22 CFR 120–130) data-safeguarding slice; DORA; NIS2.
- **Critical infrastructure:** NERC-CIP **CIP-015 INSM**; TSA Pipeline Security Directives
  (SD Pipeline-2021-01G/02G, 112 requirements); NCSC CAF 4.0 (23 Cyber Outcomes).

### Added — platform coverage
- **DISA STIGs expanded from 8 to 19 current platforms** — RHEL 8/9, Ubuntu 20.04/22.04,
  Amazon Linux 2023, SLES 15, Windows 10/11, Windows Server 2016/2019/2022/2025, SQL Server 2016,
  PostgreSQL 16, Apache 2.4, Cisco IOS-XE Router, Kubernetes, OpenShift 4, and VMware vSphere 8 —
  with XCCDF-verified rule IDs and fail-closed entrypoints.
- **Kubernetes hardening** — CIS managed-Kubernetes benchmarks (EKS v1.8.0, AKS v1.8.0,
  GKE v1.9.0; 145 controls), the NSA/CISA Kubernetes Hardening Guide v1.2 (43 controls), and
  Pod Security Standards (baseline + restricted profiles).
- **CIS Level 2 hardening profiles** for RHEL 9, Ubuntu 22.04, and Windows Server 2022.
- CIS benchmark content refreshed to May 2026 releases; added CIS Microsoft 365 (SaaS),
  PostgreSQL, and additional network devices.

### Added — distribution & governance
- **OCI bundle distribution** via GitHub Container Registry
  (`ghcr.io/ynotbhatc/rego_policy_libraries`) — pull and load without cloning.
- **`STANDARDS_UPDATE_REGISTRY.md`** — pinned version, upstream revision cadence, and watch URL
  per standard, so modules regenerate when a standard changes instead of drifting silently.
- Enforcement: CI/CD pipeline gating, SLSA supply-chain governance, and a broad Terraform plan
  **pre-apply** ruleset (`enforcement/terraform/`) that blocks non-compliant plans before apply.
- Governance: OIDC token validation, FinOps tagging, GEISA (API / ADM / LEE / VEE).
- Waiver / exceptions handling across frameworks.

### Changed
- Documented the uniform entrypoint convention: `data.<package>.main.compliance_report` for every
  framework, so a caller evaluates one by name without learning its internal layout.
- README rewritten with per-standard coverage tables, reproducible count commands, and fail-closed
  documentation.

### Corrected
- **CIS RHEL 9 coverage claim corrected** from the 1.0.0 "338/338 (100%)" to the reproducible,
  defensible figure: **224+ distinct CIS control IDs**, counted from the violation messages the
  modules emit (a floor — one rule can satisfy multiple controls). The library now publishes the
  number it can prove rather than a headline percentage.

### Notes
- All policies remain Rego v1 (`import rego.v1`), vendor-neutral, Apache 2.0.

---

## [1.0.0] - 2026-03-26

### Added
- Initial extraction from [ynotbhatc/compliance](https://github.com/ynotbhatc/compliance) AAC project
- 327 Rego policy files reorganized into a three-axis taxonomy:
  - `benchmarks/` — CIS Benchmarks (200+ files) and DISA STIGs (8 files)
  - `frameworks/` — Regulatory frameworks (NIST, FISMA, FedRAMP, CMMC, ISO 27001,
    SOC 2, PCI-DSS, SOX, GDPR, HIPAA, NERC-CIP, IEC 62443, AMI/NIST IR 7628,
    Digital Sovereignty)
  - `enforcement/` — Gate-style enforcement (Ansible, Terraform, Dockerfile,
    Kubernetes, Git)
  - `governance/` — AI governance and MCP tool-call enforcement
  - `threat_detection/` — Crypto miner detection
- README with taxonomy explanation and OPA usage examples
- Makefile with `test`, `lint`, `check` targets
- GitHub Actions CI: `opa check` on every PR and push to main

### CIS Coverage at v1.0.0
| Platform | Controls |
|----------|----------|
| RHEL 9 | 338/338 (100%) |
| RHEL 8 | Full |
| Ubuntu 22.04 | Full |
| Ubuntu 20.04 | Full |
| Ubuntu 24.04 | Full |
| Debian 11 | Full |
| Rocky Linux 8 | Full |
| Rocky Linux 9 | Full |
| Amazon Linux 2023 | Full |
| Windows Server 2016/2019/2022 | Full (modular) |
| Windows 10/11 | Full |
| AWS/Azure/GCP Foundations | Full |
| Docker, Kubernetes, OpenShift | Full |
| MySQL, Oracle, PostgreSQL | Full |
| Apache, Nginx | Full |
| Cisco, Juniper, Palo Alto, Fortinet, Arista | Full |
