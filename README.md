# Rego Policy Libraries

> **332 production-ready OPA policies** covering CIS Benchmarks, NIST, SOC 2, PCI-DSS, ISO 27001, NERC-CIP, HIPAA, FedRAMP, and more — all in Rego v1 syntax, ready to load into any OPA instance.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.60%2B-blue)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-green)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![CIS RHEL 9](https://img.shields.io/badge/CIS%20RHEL%209-338%2F338%20(100%25)-brightgreen)](benchmarks/cis/os/linux/rhel_9/)

---

## What's in the box

| Domain | Policies | Coverage |
|--------|----------|----------|
| **CIS Benchmarks** | 217 | 22 platforms: Linux, Windows, Cloud, Containers, Databases, Network |
| **Regulatory Frameworks** | 103 | ISO 27001, SOC 2, PCI-DSS, SOX, FISMA, FedRAMP, CMMC, GDPR, HIPAA, NERC-CIP, IEC 62443, Digital Sovereignty |
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
docker run -d --name opa -p 8181:8181 openpolicyagent/opa run --server --addr :8181

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
# Security benchmarks
podman run -d --name opa-security -p 8181:8181 openpolicyagent/opa run --server --addr :8181

# Regulatory frameworks
podman run -d --name opa-compliance -p 8182:8182 openpolicyagent/opa run --server --addr :8182

# OT / Critical infrastructure
podman run -d --name opa-ot -p 8183:8183 openpolicyagent/opa run --server --addr :8183
```

Load `benchmarks/` into `:8181`, `frameworks/` into `:8182`, `frameworks/critical_infrastructure/` + `governance/` into `:8183`.

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
