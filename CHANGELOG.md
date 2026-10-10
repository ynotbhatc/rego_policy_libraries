# Changelog

All notable changes to this library will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

_Nothing yet._

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
