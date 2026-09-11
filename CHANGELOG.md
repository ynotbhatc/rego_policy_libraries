# Changelog

All notable changes to this library will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] - 2026-09-11

Six months of additions since the initial extraction. The library grew from 327 to
**603 policy files** (711 including tests), roughly doubling framework coverage and adding a
production distribution path, Level 2 hardening profiles, and a standards-update registry.

### Added — new frameworks
- **AI governance:** EU AI Act (Regulation 2024/1689) suite (`governance/eu_ai_act/`) and
  ISO/IEC 42001:2023 AIMS (`governance/iso_42001/`), completing the AI trio with NIST AI RMF.
- **Privacy:** ISO/IEC 27701:2019 PIMS; CCPA / CPRA.
- **Federal:** NIST SP 800-171 Rev 3 (14 families, 110 CUI requirements); CISA CPG 2.0
  (34 goals across the six CSF-2.0 functions incl. GOVERN).
- **Management:** CSA CCM v4.0 (16 domains, 197 controls); COBIT 2019 governance-system attestation.
- **Financial:** GLBA Safeguards Rule (16 CFR 314).
- **Regulatory:** ITAR (22 CFR 120–130) data-safeguarding slice; DORA; NIS2.
- **Critical infrastructure:** NERC-CIP **CIP-015 INSM**; TSA Pipeline Security Directives
  (SD Pipeline-2021-01G/02G, 112 requirements); NCSC CAF 4.0 (23 Cyber Outcomes).

### Added — platform coverage
- **DISA STIGs expanded from 8 to 13 current platforms** — added Windows Server 2025, Windows 11,
  Ubuntu 22.04, Amazon Linux 2023, SLES 15, Kubernetes, OpenShift 4, Crunchy Postgres 16,
  SQL Server 2016, Apache 2.4, Cisco IOS-XE, and vSphere 8 ESXi — with XCCDF-verified rule IDs
  and fail-closed entrypoints.
- **CIS Level 2 hardening profiles** for RHEL 9, Ubuntu 22.04, and Windows Server 2022.
- CIS benchmark content refreshed to May 2026 releases; added CIS Microsoft 365 (SaaS),
  PostgreSQL, and additional network devices.

### Added — distribution & governance
- **OCI bundle distribution** via GitHub Container Registry
  (`ghcr.io/ynotbhatc/rego_policy_libraries`) — pull and load without cloning.
- **`STANDARDS_UPDATE_REGISTRY.md`** — pinned version, upstream revision cadence, and watch URL
  per standard, so modules regenerate when a standard changes instead of drifting silently.
- Enforcement: CI/CD pipeline gating and SLSA supply-chain governance.
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
