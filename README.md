# Rego Policy Libraries

> **505 production-ready OPA policies** covering CIS Benchmarks (with Level 2 hardening profiles), DISA STIGs, NIST, SOC 2, PCI-DSS, ISO 27001, NERC-CIP (with full data-source reference), IEC 62443, HIPAA, FedRAMP, CSA CCM, CCPA/CPRA, EU AI Act, GEISA, and more — all in Rego v1 syntax, ready to load into any OPA instance.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.60%2B-blue)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-green)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![CIS RHEL 9](https://img.shields.io/badge/CIS%20RHEL%209-338%2F338%20(100%25)-brightgreen)](benchmarks/cis/os/linux/rhel_9/)
[![GitHub Stars](https://img.shields.io/github/stars/ynotbhatc/rego_policy_libraries?style=social)](https://github.com/ynotbhatc/rego_policy_libraries/stargazers)

---

## Why this repo?

Writing compliance policies from scratch is expensive and error-prone. A typical enterprise deploying OPA for CIS RHEL 9 alone needs 338 individual control checks — and that's one framework for one OS.

This library gives you a **complete, working policy set on day one**, covering 22 platforms, 50+ regulatory frameworks, and every major compliance standard from CIS and DISA STIGs to NERC-CIP and IEC 62443. All policies:

- Use **Rego v1 syntax** (`import rego.v1`) — no deprecation warnings, forward-compatible
- Return **structured JSON reports** (compliant, score, violations list) — wire directly to dashboards or CI
- Are **independently loadable** — use one framework or all 505 policies; no coupling
- Are **Apache 2.0 licensed** — use commercially without restriction

> **Why not build your own?** You can — but CIS RHEL 9 alone has 338 controls across 14 sections. NERC-CIP covers 14 standards (CIP-002 through CIP-015) with 200+ requirements. IEC 62443 adds 51 System Requirements across 7 Foundational Requirements. Starting from scratch takes months. This library is that months-of-work already done.

---

## Coverage at a glance

| Standard / Framework | Path | Controls / Requirements |
|---------------------|------|------------------------|
| **CIS RHEL 9 v2.0.0** | `benchmarks/cis/os/linux/rhel_9/` | **338/338 (100%)** ✅ |
| CIS RHEL 8 | `benchmarks/cis/os/linux/rhel_8/` | Full |
| CIS Ubuntu 22.04/24.04/20.04 | `benchmarks/cis/os/linux/ubuntu_*/` | Full |
| CIS Windows Server 2019/2022 | `benchmarks/cis/os/windows/` | 9 sections |
| CIS AWS / Azure / GCP | `benchmarks/cis/cloud/` | Foundations |
| CIS Docker / Kubernetes / OpenShift | `benchmarks/cis/containers/` | Full |
| DISA STIG RHEL 8/9, Ubuntu, Windows, OpenShift 4, Kubernetes | `benchmarks/stig/` | Full |
| NIST 800-53 rev5 | `frameworks/federal/nist_800_53/` | All control families |
| NIST 800-82 (OT) | `frameworks/federal/nist_800_82/` | Full |
| FISMA / FedRAMP / CMMC | `frameworks/federal/` | Full |
| ISO 27001:2022 | `frameworks/management/iso27001/` | Full ISMS |
| SOC 2 Type II | `frameworks/management/soc2/` | All TSCs |
| PCI-DSS v4.0 | `frameworks/financial/pci_dss/` | All 12 requirements |
| SOX ITGC | `frameworks/financial/sox/` | Full |
| HIPAA | `frameworks/privacy/hipaa/` | Full |
| GDPR | `frameworks/privacy/gdpr/` | Full |
| NERC-CIP (CIP-002 – CIP-015) | `frameworks/critical_infrastructure/nerc_cip/` | 14 standards |
| IEC 62443 (all parts) | `frameworks/critical_infrastructure/iec_62443/` | 51 SRs, SL 1–4 |
| NIST IR 7628 (AMI / Smart Grid) | `frameworks/critical_infrastructure/ami/` | Full |
| DORA / NIS2 | `frameworks/regulatory/` | Full |
| NCSC CAF 4.0 | `frameworks/management/ncsc_caf/` | 23 Cyber Outcomes |
| Digital Sovereignty | `frameworks/sovereignty/` | 7 domains |
| **CSA CCM v4.0** | `frameworks/management/csa_ccm/` | 16 domains, 197 controls |
| **ISO/IEC 27701:2019** | `frameworks/privacy/iso27701/` | PIMS, PII Controller, PII Processor, DSR |
| **NIST SP 800-171 Rev 3** | `frameworks/federal/nist/sp_800_171/` | 14 families, 110 CUI requirements |
| **CCPA / CPRA** | `frameworks/privacy/ccpa/` | Consumer rights, sensitive PI, data practices |
| **EU AI Act (2024/1689)** | `governance/eu_ai_act/` | Prohibited, High-Risk, Transparency, GPAI, Governance |

---

## What's in the box

| Domain | Policies | Coverage |
|--------|----------|----------|
| **CIS Benchmarks + DISA STIGs** | 246 | 22 platforms: Linux, Windows, Cloud, Containers, Databases, Network + RHEL 8/9 & Windows 2022 STIGs. CIS benchmark versions updated to May 2026 releases; **Level 2 hardening profiles** for high-value targets (RHEL 9, Ubuntu 22.04, Windows Server 2022) |
| **Regulatory Frameworks** | 186 | ISO 27001, SOC 2, PCI-DSS, SOX, FISMA, FedRAMP, CMMC, GDPR, HIPAA, NERC-CIP, IEC 62443, DORA, NIS2, NY DFS, SEC Cyber, SWIFT CSP, HITRUST, TISAX, CFR Part 11, NCSC CAF, Digital Sovereignty, CSA CCM v4.0, ISO 27701, NIST SP 800-171 r3, CCPA/CPRA |
| **Enforcement** | 9 | Ansible, Terraform, Dockerfile, Kubernetes admission, Git approval/playbook docs, **CI/CD pipeline gating**, **SLSA supply-chain governance** |
| **Governance** | 19 | AI agent authorization, MCP tool-call enforcement, GEISA (API/ADM/LEE/VEE), **EU AI Act (Regulation 2024/1689)** suite, **OIDC token validation**, **FinOps tagging** |
| **Threat Detection** | 1 | Cryptocurrency miner detection |

**Highlight:** CIS RHEL 9 v2.0.0 — **338/338 controls (100%)** across 14 modules.

---

## Quick Start

### Option A — OCI bundle (recommended for production)

Pull the pre-built bundle directly from GitHub Container Registry — no clone needed:

```bash
# Pull the full 505-policy bundle
oras pull ghcr.io/ynotbhatc/rego_policy_libraries:latest

# Start OPA with the bundle
podman run -d --name opa -p 8181:8181 \
  -v "$(pwd)/bundle.tar.gz:/bundle.tar.gz:ro" \
  openpolicyagent/opa:1.10.0 run --server --addr :8181 --bundle /bundle.tar.gz
```

Versioned tags are available: `ghcr.io/ynotbhatc/rego_policy_libraries:v1.0.0`

Install `oras`: https://oras.land/docs/installation

---

### Option B — Git clone

```bash
# Clone
git clone https://github.com/ynotbhatc/rego_policy_libraries.git
cd rego_policy_libraries

# Start OPA
podman run -d --name opa -p 8181:8181 openpolicyagent/opa run --server --addr :8181

# Load all CIS RHEL 9 policies
for f in benchmarks/cis/os/linux/rhel_9/*.rego; do
  curl -s -X PUT --data-binary @"$f" \
    "http://localhost:8181/v1/policies/$(basename $f .rego)"
done

# Evaluate against your system facts
curl -s -X POST http://localhost:8181/v1/data/cis_rhel9/compliance_assessment \
  -H 'Content-Type: application/json' \
  -d '{"input": {"os_family": "RedHat", ...}}'
```

---

## Policy Taxonomy

```
rego_policy_libraries/
├── benchmarks/                  # Technical security baselines
│   ├── cis/
│   │   ├── os/linux/            # RHEL 8/9/10, Ubuntu 20/22/24, Debian, Rocky, Amazon Linux
│   │   ├── os/windows/          # Windows Server 2016/2019/2022, Windows 10/11
│   │   ├── cloud/               # AWS, Azure, GCP Foundations
│   │   ├── containers/          # Docker, Kubernetes, OpenShift
│   │   ├── databases/           # MySQL 8, Oracle 19c, PostgreSQL 13/14/15
│   │   ├── web_servers/         # Apache 2.4, Nginx 1.20
│   │   └── network/             # Cisco IOS, Juniper Junos, Palo Alto, Fortinet, Arista
│   └── stig/                    # DISA STIGs — RHEL 8/9, Ubuntu, Windows
│
├── frameworks/                  # Regulatory compliance
│   ├── federal/                 # NIST 800-53/171/800-82, CSF 2.0, AI RMF, FISMA, FedRAMP, CMMC
│   ├── management/              # ISO 27001, SOC 2, Corporate, NCSC CAF 4.0
│   ├── financial/               # PCI-DSS, SOX, SWIFT CSP, NY DFS, SEC Cyber
│   ├── privacy/                 # GDPR, HIPAA, HITRUST, CFR Part 11, TISAX
│   ├── regulatory/              # DORA, NIS2
│   ├── critical_infrastructure/ # NERC-CIP (CIP-002–CIP-015), IEC 62443, NIST IR 7628
│   └── sovereignty/             # Digital Sovereignty (7 domains)
│
├── enforcement/                 # Gate-style policy enforcement
│   ├── ansible/                 # Block non-compliant playbooks at check-in and runtime
│   ├── terraform/               # Validate plans before apply
│   ├── dockerfile/              # Lint Dockerfiles at build time
│   ├── kubernetes/              # Admission control for K8s manifests
│   ├── git/                     # Approval and playbook-documentation policies
│   ├── cicd/                    # CI/CD pipeline gating
│   └── supply_chain/            # SLSA-style supply-chain governance
│
├── governance/                  # AI and operational governance
│   ├── ai/                      # AI agent action classification and authorization
│   ├── mcp/                     # MCP server tool-call enforcement
│   ├── eu_ai_act/               # EU AI Act (Regulation 2024/1689) — prohibited, high-risk, GPAI, transparency
│   ├── geisa/                   # GEISA runtime compliance (API, ADM, LEE, VEE)
│   ├── oidc/                    # OIDC token validation for portal/MCP access control
│   └── finops/                  # Resource tagging policies
│
└── threat_detection/
    └── crypto_mining/           # Detect unauthorized cryptocurrency miners
```

---

## CIS Benchmark Coverage

| Platform | Path | Controls |
|----------|------|----------|
| **RHEL 9** | `benchmarks/cis/os/linux/rhel_9/` | **338/338 (100%)** ✅ |
| RHEL 8 | `benchmarks/cis/os/linux/rhel_8/` | Full |
| Ubuntu 22.04 | `benchmarks/cis/os/linux/ubuntu_22_04/` | Full |
| Ubuntu 20.04 / 24.04 | `benchmarks/cis/os/linux/ubuntu_20_04/` | Full |
| Debian 11 | `benchmarks/cis/os/linux/debian_11/` | Full |
| Rocky Linux 8 / 9 | `benchmarks/cis/os/linux/rocky_linux_8/` | Full |
| Amazon Linux 2023 | `benchmarks/cis/os/linux/amazon_linux_2023/` | Full |
| Windows Server 2019/2022 | `benchmarks/cis/os/windows/` | Modular (9 sections) |
| AWS / Azure / GCP | `benchmarks/cis/cloud/` | Foundations |
| Docker / Kubernetes / OpenShift | `benchmarks/cis/containers/` | Full |
| MySQL / Oracle / PostgreSQL | `benchmarks/cis/databases/` | Full |
| Cisco / Juniper / Palo Alto / Fortinet / Arista | `benchmarks/cis/network/` | Full |

---

## IEC 62443 Coverage

Full library for IEC 62443 Industrial Automation and Control Systems (IACS) Security — all 51 System Requirements (SRs) from Part 3-3 plus Part 2 management requirements.

| File | Part | Title | SRs |
|------|------|-------|-----|
| `fr1_identification_authentication.rego` | 3-3 FR 1 | Identification & Authentication Control (IAC) | SR 1.1–1.13 (13) |
| `fr2_use_control.rego` | 3-3 FR 2 | Use Control (UC) | SR 2.1–2.12 (12) |
| `fr3_system_integrity.rego` | 3-3 FR 3 | System Integrity (SI) | SR 3.1–3.9 (9) |
| `fr4_data_confidentiality.rego` | 3-3 FR 4 | Data Confidentiality (DC) | SR 4.1–4.3 (3) |
| `fr5_restricted_data_flow.rego` | 3-3 FR 5 | Restricted Data Flow / Zone & Conduit (RDF) | SR 5.1–5.4 (4) |
| `fr6_timely_response.rego` | 3-3 FR 6 | Timely Response to Events (TRE) | SR 6.1–6.2 (2) |
| `fr7_resource_availability.rego` | 3-3 FR 7 | Resource Availability (RA) | SR 7.1–7.8 (8) |
| `part2_security_management.rego` | 2-1 | Security Management System (CSMS) | — |
| `part2_patch_management.rego` | 2-3 | Patch Management in IACS Environments | — |
| `part2_service_provider.rego` | 2-4 | Security Program for IACS Service Providers (SP.01–SP.10) | — |
| `part3_risk_assessment.rego` | 3-2 | Security Risk Assessment (ZCR 1–5) | — |
| `iec_62443_main.rego` | All | Main orchestrator — aggregates all parts | 51 total |

**Security Level (SL) tiering:** All FR modules enforce SL-differentiated requirements — violations are tagged with the SL at which they apply (SL 1 baseline through SL 4 state-sponsored threat protection).

**OPA endpoint:** `POST /v1/data/iec_62443_main/iec_62443_compliance_report`

```json
{
  "standard": "IEC 62443",
  "target_sl": 2,
  "compliant": false,
  "fr_compliance_score": 71,
  "sr_compliance_score": 84,
  "passing_frs": 5,
  "total_frs": 7,
  "passing_srs": 43,
  "total_srs": 51,
  "part3_3_foundational_requirements": {
    "FR1_identification_authentication": { "compliant": true, "passing_srs": 13 },
    "FR5_restricted_data_flow": { "compliant": false, "violations": ["..."] }
  }
}
```

---

## NERC-CIP Coverage

Full library covering all active CIP standards (CIP-002 through CIP-015) in `frameworks/critical_infrastructure/nerc_cip/`.

**OPA endpoint:** `POST /v1/data/nerc_cip_main`

**Data sources:** Every `input.*` field used by the 14 CIP policies is documented in [`frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md`](frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md) — each entry lists the real-world source system (GRC, CMDB, LMS, PACS, SIEM, INSM platform, vulnerability scanner, etc.), the collection method (Ansible module or REST endpoint), and whether the integration is currently live or stubbed.

---

## Loading Policies into OPA

### Single policy
```bash
curl -X PUT --data-binary @benchmarks/cis/os/linux/rhel_9/pam_validation.rego \
  http://localhost:8181/v1/policies/cis_rhel9_pam
```

### All policies in a directory
```bash
for f in benchmarks/cis/os/linux/rhel_9/*.rego; do
  curl -s -X PUT --data-binary @"$f" \
    "http://localhost:8181/v1/policies/$(basename $f .rego)"
done
```

### Recommended 3-container pattern (domain isolation)
```bash
# Security benchmarks (CIS, NIST, DISA STIGs)
podman run -d --name opa-security -p 8181:8181 openpolicyagent/opa run --server --addr :8181

# Regulatory frameworks (ISO 27001, SOC 2, PCI-DSS, SOX, FISMA, GDPR, HIPAA)
podman run -d --name opa-compliance -p 8182:8182 openpolicyagent/opa run --server --addr :8182

# OT / Critical infrastructure (NERC-CIP, IEC 62443, NIST IR 7628, AMI)
podman run -d --name opa-ot -p 8183:8183 openpolicyagent/opa run --server --addr :8183
```

Load `benchmarks/` into `:8181`, `frameworks/` (minus critical_infrastructure) into `:8182`, `frameworks/critical_infrastructure/` + `governance/` into `:8183`.

---

## Input / Output Contract

Each policy exposes a `compliance_assessment` rule that accepts system facts as input and returns a structured report:

```json
{
  "compliant": false,
  "summary": {
    "total_controls": 338,
    "passing_controls": 301,
    "failing_controls": 37,
    "compliance_percentage": 89.05,
    "overall_compliance": "FAIL"
  },
  "violations": [
    "1.1.1 Ensure mounting of cramfs filesystems is disabled",
    "5.2.4 Ensure SSH X11 forwarding is disabled"
  ],
  "section_compliance": {
    "1_filesystem": true,
    "2_services": false,
    ...
  }
}
```

---

## Use as a Git Submodule

```bash
# Add to your project
git submodule add https://github.com/ynotbhatc/rego_policy_libraries.git policies
git submodule update --init --recursive

# Update to latest
git submodule update --remote policies
git add policies && git commit -m "Update policy library"
```

---

## Requirements

- [Open Policy Agent](https://www.openpolicyagent.org/) v0.60+
- All policies use `import rego.v1` (Rego v1 syntax)

---

## Part of Ansible Automated Compliance (AAC)

This library is the policy engine behind [AAC](https://github.com/ynotbhatc/compliance) — a compliance automation platform built on Ansible Automation Platform + OPA + PostgreSQL. AAC uses these policies to continuously assess infrastructure against CIS, NIST, SOC 2, PCI-DSS, and 30+ other frameworks, storing historical results for audit evidence.

---

## Related Rego Policy Repositories

Other OPA/Rego policy repositories in the Ansible / policy-as-code space. This library focuses on **compliance and security assessment** (does the infrastructure meet a framework?); the repositories below complement it with **automation-platform governance** (should this automation be allowed to run?).

| Repository | Focus | Scope |
|---|---|---|
| [raedrizk/ansible-policy-as-code](https://github.com/raedrizk/ansible-policy-as-code/blob/main/policies/README.md) | **AAP governance / pipeline enforcement** — job-template naming standards, execution-environment security (registry validation, version pinning), fork/resource limits, time-based access controls, SCM branch enforcement, and superuser restrictions, aggregated under a single master policy. | ~11 active policies + legacy examples |

> Adding a repository? Keep this list to actively-maintained Rego policy sets relevant to Ansible / OPA compliance and governance, with a one-line focus description and scope.

---

## Contributing

1. Place new `.rego` files in the appropriate taxonomy path
2. Add `import rego.v1` at the top
3. Expose a `compliance_assessment` rule with the standard output structure
4. Open a PR

---

## License

Apache 2.0
