# Rego Policy Libraries

> **363 production-ready OPA policies** covering CIS Benchmarks, DISA STIGs, NIST, SOC 2, PCI-DSS, ISO 27001, NERC-CIP, IEC 62443, HIPAA, FedRAMP, and more — all in Rego v1 syntax, ready to load into any OPA instance.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.60%2B-blue)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-green)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![CIS RHEL 9](https://img.shields.io/badge/CIS%20RHEL%209-338%2F338%20(100%25)-brightgreen)](benchmarks/cis/os/linux/rhel_9/)

---

## What's in the box

| Domain | Policies | Coverage |
|--------|----------|----------|
| **CIS Benchmarks + DISA STIGs** | 237 | 22 platforms: Linux, Windows, Cloud, Containers, Databases, Network + RHEL 8/9 & Windows 2022 STIGs |
| **Regulatory Frameworks** | 114 | ISO 27001, SOC 2, PCI-DSS, SOX, FISMA, FedRAMP, CMMC, GDPR, HIPAA, NERC-CIP, IEC 62443, Digital Sovereignty |
| **Enforcement** | 6 | Ansible, Terraform, Dockerfile, Kubernetes, Git |
| **Governance** | 4 | AI agent authorization, MCP tool-call enforcement |
| **Threat Detection** | 2 | Cryptocurrency miner detection |

**Highlight:** CIS RHEL 9 v2.0.0 — **338/338 controls (100%)** across 14 modules.

---

## Quick Start

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
│   ├── federal/                 # NIST 800-53/171, CSF 2.0, AI RMF, FISMA, FedRAMP, CMMC
│   ├── management/              # ISO 27001, SOC 2, Corporate
│   ├── financial/               # PCI-DSS, SOX
│   ├── privacy/                 # GDPR, HIPAA
│   ├── critical_infrastructure/ # NERC-CIP (CIP-002–CIP-015), IEC 62443, NIST IR 7628
│   └── sovereignty/             # Digital Sovereignty (7 domains)
│
├── enforcement/                 # Gate-style policy enforcement
│   ├── ansible/                 # Block non-compliant playbooks at check-in and runtime
│   ├── terraform/               # Validate plans before apply
│   ├── dockerfile/              # Lint Dockerfiles at build time
│   └── kubernetes/              # Admission control for K8s manifests
│
├── governance/                  # AI and operational governance
│   ├── ai/                      # AI agent action classification and authorization
│   └── mcp/                     # MCP server tool-call enforcement
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

## Contributing

1. Place new `.rego` files in the appropriate taxonomy path
2. Add `import rego.v1` at the top
3. Expose a `compliance_assessment` rule with the standard output structure
4. Open a PR

---

## License

Apache 2.0
