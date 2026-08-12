# Rego Policy Libraries

> **545 production-ready Rego policies** for OPA and Enterprise OPA (EOPA), covering CIS Benchmarks (with Level 2 hardening profiles), DISA STIGs, NIST, SOC 2, PCI-DSS, ISO 27001, NERC-CIP (with full data-source reference), IEC 62443, HIPAA, FedRAMP, CSA CCM, CCPA/CPRA, EU AI Act, GEISA, and more — all in Rego v1 syntax, ready to load into any OPA or EOPA instance.
>
> Standalone and dependency-free: no orchestrator, no agent, no vendor runtime. Clone it, load it, query it.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/OPA-v0.60%2B-blue)](https://www.openpolicyagent.org/)
[![Rego](https://img.shields.io/badge/Rego-v1-green)](https://www.openpolicyagent.org/docs/latest/policy-language/)
[![CIS RHEL 9](https://img.shields.io/badge/CIS%20RHEL%209-v2.0.0%20%C2%B7%2017%20modules-brightgreen)](benchmarks/cis/rhel_9/)
[![GitHub Stars](https://img.shields.io/github/stars/ynotbhatc/rego_policy_libraries?style=social)](https://github.com/ynotbhatc/rego_policy_libraries/stargazers)

---

## Why this repo?

Writing compliance policies from scratch is expensive and error-prone. A typical enterprise deploying OPA for CIS RHEL 9 alone needs 338 individual control checks — and that's one framework for one OS.

This library gives you a **complete, working policy set on day one**, covering 22 platforms, 50+ regulatory frameworks, and every major compliance standard from CIS and DISA STIGs to NERC-CIP and IEC 62443. All policies:

- Use **Rego v1 syntax** (`import rego.v1`) — no deprecation warnings, forward-compatible
- Return **structured JSON reports** (compliant, score, violations list) — wire directly to dashboards or CI
- Are **independently loadable** — use one framework or all 545 policies; no coupling
- Expose a **uniform entrypoint** — `data.<package>.main.compliance_report` for every framework, so you can evaluate one by name without learning its internal layout
- **Fail closed** — a framework given no facts reports non-compliant with an explicit reason, never a silent pass (see below)
- Are **vendor-neutral** — no orchestrator, deployment topology, or caller vocabulary baked in
- Are **Apache 2.0 licensed** — use commercially without restriction

> **Why not build your own?** You can — but CIS RHEL 9 alone has 338 controls across 14 sections. NERC-CIP covers 14 standards (CIP-002 through CIP-015) with 200+ requirements. IEC 62443 adds 51 System Requirements across 7 Foundational Requirements. Starting from scratch takes months. This library is that months-of-work already done.

---

## Coverage at a glance

| Standard / Framework | Path | Controls / Requirements |
|---------------------|------|------------------------|
| **CIS RHEL 9 v2.0.0** | `benchmarks/cis/rhel_9/` | 17 modules · **224+ control IDs** ✅ |
| CIS RHEL 8 | `benchmarks/cis/rhel_8/` | Full |
| CIS RHEL 10 | `benchmarks/cis/rhel_10/` | Full |
| CIS Ubuntu 22.04/24.04/20.04 | `benchmarks/cis/ubuntu_*/` | Full |
| CIS Rocky Linux 8/9 | `benchmarks/cis/rocky_linux_*/` | Full |
| CIS Debian 11 | `benchmarks/cis/debian_11/` | Full |
| CIS Amazon Linux 2023 | `benchmarks/cis/amazon_linux_2023/` | Full |
| CIS Windows Server 2019/2022 | `benchmarks/cis/windows_server_2022_modular/` | 9 sections |
| CIS Windows 10/11 | `benchmarks/cis/windows_10/` | Full |
| CIS Microsoft 365 (SaaS) | `benchmarks/cis/saas/m365/` | Identity, Defender, Purview |
| CIS PostgreSQL | `benchmarks/cis/postgresql/` | Full |
| Network devices — VyOS, pfSense | `benchmarks/cis/network_devices/` | Full |
| CIS AWS / Azure / GCP | `benchmarks/cis/cloud/` | Foundations |
| CIS Docker / Kubernetes / OpenShift | `benchmarks/cis/containers/` | Full |
| DISA STIG RHEL 8/9, Ubuntu, Windows, OpenShift 4, Kubernetes | `benchmarks/stig/` | Full |
| NIST 800-53 rev5 | `frameworks/federal/nist/sp_800_53/` | All control families |
| NIST 800-82 (OT) | `frameworks/critical_infrastructure/nist_800_82/` | Full |
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
| NCSC CAF 4.0 | `frameworks/compliance/ncsc_caf/` | 23 Cyber Outcomes |
| Digital Sovereignty | `frameworks/sovereignty/` | 7 domains |
| **CSA CCM v4.0** | `frameworks/management/csa_ccm/` | 16 domains, 197 controls |
| **ISO/IEC 27701:2019** | `frameworks/privacy/iso27701/` | PIMS, PII Controller, PII Processor, DSR |
| **NIST SP 800-171 Rev 3** | `frameworks/federal/nist/sp_800_171/` | 14 families, 110 CUI requirements |
| **CCPA / CPRA** | `frameworks/privacy/ccpa/` | Consumer rights, sensitive PI, data practices |
| **EU AI Act (2024/1689)** | `governance/eu_ai_act/` | Prohibited, High-Risk, Transparency, GPAI, Governance |
| **TSA Pipeline Security Directives** | `frameworks/critical_infrastructure/tsa_pipeline/` | SD Pipeline-2021-01G + 02G, 12 sections, 112 requirements |

---

## What's in the box

| Domain | Policies | Coverage |
|--------|----------|----------|
| **CIS Benchmarks + DISA STIGs** | 273 | 22 platforms: Linux, Windows, Cloud, Containers, Databases, Network + RHEL 8/9 & Windows 2022 STIGs. CIS benchmark versions updated to May 2026 releases; **Level 2 hardening profiles** for high-value targets (RHEL 9, Ubuntu 22.04, Windows Server 2022) |
| **Regulatory Frameworks** | 238 | ISO 27001, SOC 2, PCI-DSS, SOX, FISMA, FedRAMP, CMMC, GDPR, HIPAA, NERC-CIP, IEC 62443, DORA, NIS2, NY DFS, SEC Cyber, SWIFT CSP, HITRUST, TISAX, CFR Part 11, NCSC CAF, Digital Sovereignty, CSA CCM v4.0, ISO 27701, NIST SP 800-171 r3, CCPA/CPRA |
| **Enforcement** | 14 | Ansible, Terraform, Dockerfile, Kubernetes admission, Git approval/playbook docs, **CI/CD pipeline gating**, **SLSA supply-chain governance** |
| **Governance** | 19 | AI agent authorization, MCP tool-call enforcement, GEISA (API/ADM/LEE/VEE), **EU AI Act (Regulation 2024/1689)** suite, **OIDC token validation**, **FinOps tagging** |
| **Threat Detection** | 1 | Cryptocurrency miner detection |

**Highlight:** CIS RHEL 9 v2.0.0 — **224+ distinct CIS control IDs** across 17 modules
(14 core CIS sections plus 3 extended-hardening modules for STIG/NIST drift detection).

> **On coverage numbers.** The control IDs above are counted from the violation messages
> the modules actually emit, so the figure is reproducible from a clone:
> ```bash
> grep -rhoE 'CIS (L2 )?[0-9]+(\.[0-9]+)*' benchmarks/cis/rhel_9 --include='*.rego' \
>   | sed -E 's/CIS L2 /CIS /' | sort -u | wc -l
> ```
> It is a **floor, not a ceiling** — a single rule often satisfies more than one CIS control,
> so true coverage is higher. We publish the number we can prove rather than a headline
> percentage we cannot.

---

## Quick Start

### Option A — OCI bundle (recommended for production)

Pull the pre-built bundle directly from GitHub Container Registry — no clone needed:

```bash
# Pull the full 545-policy bundle
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
for f in benchmarks/cis/rhel_9/*.rego; do
  curl -s -X PUT --data-binary @"$f" \
    "http://localhost:8181/v1/policies/$(basename $f .rego)"
done

# Evaluate against your system facts — uniform entrypoint, same for every framework
curl -s -X POST http://localhost:8181/v1/data/cis_rhel9/main/compliance_report \
  -H 'Content-Type: application/json' \
  -d '{"input": {"os_family": "RedHat", ...}}'
```

> Query with **no** input and you get `compliant: false` with an explicit
> `FAIL-CLOSED` violation — not a 100% pass. That is deliberate; see
> [Framework entrypoints](#framework-entrypoints).

---

## Policy Taxonomy

```
rego_policy_libraries/
├── benchmarks/                  # Technical security baselines
│   ├── cis/
│   │   ├── rhel_8/ rhel_9/ rhel_10/
│   │   ├── ubuntu_20_04/ ubuntu_22_04/ ubuntu_24_04/
│   │   ├── debian_11/ rocky_linux_8/ rocky_linux_9/ amazon_linux_2023/
│   │   ├── windows_server_2016/ windows_server_2019_modular/
│   │   ├── windows_server_2022/ windows_server_2022_modular/
│   │   ├── windows_10/ windows_11/
│   │   ├── aws/ azure/ gcp/     # Cloud Foundations
│   │   ├── docker/ kubernetes/  # Containers
│   │   ├── postgresql/ databases/
│   │   ├── saas/m365/           # SaaS (Microsoft 365)
│   │   ├── network_devices/     # VyOS, pfSense
│   │   ├── os/linux/            # legacy/simple RHEL 9 variants — superseded
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
│   ├── critical_infrastructure/ # NERC-CIP (CIP-002–CIP-015), IEC 62443, NIST IR 7628,
│   │                            # NIST 800-82, TSA Pipeline Security Directives
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
| **RHEL 9** | `benchmarks/cis/rhel_9/` | 17 modules · **224+ control IDs** ✅ |
| RHEL 8 | `benchmarks/cis/rhel_8/` | Full |
| Ubuntu 22.04 | `benchmarks/cis/ubuntu_22_04/` | Full |
| Ubuntu 20.04 / 24.04 | `benchmarks/cis/ubuntu_20_04/` | Full |
| Debian 11 | `benchmarks/cis/debian_11/` | Full |
| Rocky Linux 8 / 9 | `benchmarks/cis/rocky_linux_8/` | Full |
| Amazon Linux 2023 | `benchmarks/cis/amazon_linux_2023/` | Full |
| Windows Server 2019/2022 | `benchmarks/cis/windows_server_2022_modular/` | Modular (9 sections) |
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

## TSA Pipeline Security Directives Coverage

Both currently-effective TSA pipeline cybersecurity directives, in
`frameworks/critical_infrastructure/tsa_pipeline/` — 12 section modules plus an
orchestrator, covering 112 directive subparagraphs.

| Directive | Effective | Sections covered |
|---|---|---|
| **SD Pipeline-2021-01G** — *Enhancing Pipeline Cybersecurity* | 2026-01-16 → 2027-01-15 | II.B Cybersecurity Coordinator · II.C Incident reporting to CISA · II.D Vulnerability assessment |
| **SD Pipeline-2021-02G** — *Pipeline Cybersecurity Mitigation Actions, Contingency Planning, and Testing* | 2026-05-03 → 2027-05-02 | II.A/III.A Critical Cyber Systems · II.B/VI Implementation Plan + amendments · III.B Network segmentation · III.C Access control · III.D Continuous monitoring · III.E Patch management · III.F Incident Response Plan · III.G Assessment Plan · IV/V Records + SSI |

**OPA endpoint:** `POST /v1/data/tsa_pipeline/main/compliance_report`

The directives are largely deadline-driven, and the deadlines are what these
policies assert — each is pinned by a test in
`tests/test_tsa_pipeline_deadlines.rego`:

| Clock | Directive |
|---|---|
| 72 hours — report incident to CISA | SD-01G II.C.3 |
| 24 hours — supplemental information | SD-01G II.C.5.f |
| 7 days — Coordinator info change | SD-01G II.B.1.e |
| 60 days — "no Critical Cyber Systems" notice | SD-02G II.A.5 |
| 45 / 50 / 30 days — permanent change · amendment filing · reconsideration petition | SD-02G VI.C / VI.D / VI.F |
| 12 months, ≥ 2 objectives — Incident Response Plan exercise | SD-02G III.F.1.e |
| 24 months — cybersecurity architecture design review | SD-02G III.G.2.b |
| ⅓ per year, 100% over 3 years — assessment coverage | SD-02G III.G.2.d |
| 12 months — Assessment Plan and report submission | SD-02G III.G.3–4 |
| 24 hours — maximum packet capture period | SD-02G IV.C.2.e.ii |

> **No fact source exists yet.** Both directives are overwhelmingly plan-,
> attestation-, and recordkeeping-driven ("is there a TSA-approved Cybersecurity
> Implementation Plan", "was the Assessment Plan submitted within 12 months").
> None of that comes from host fact-gathering, and nothing currently emits the
> `input` documented in each module header. On absent input this framework
> reports **fully non-compliant across all 12 sections** — correct fail-closed
> behavior for an audit framework, but not a working assessment until an
> attestation intake or GRC export is wired up. Don't demo it as one.

---

## NERC-CIP Coverage

Full library covering all active CIP standards (CIP-002 through CIP-015) in `frameworks/critical_infrastructure/nerc_cip/`.

**OPA endpoint:** `POST /v1/data/nerc_cip_main`

**Data sources:** Every `input.*` field used by the 14 CIP policies is documented in [`frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md`](frameworks/critical_infrastructure/nerc_cip/DATA_SOURCES.md) — each entry lists the real-world source system (GRC, CMDB, LMS, PACS, SIEM, INSM platform, vulnerability scanner, etc.), the collection method (Ansible module or REST endpoint), and whether the integration is currently live or stubbed.

---

## Loading Policies into OPA

### Single policy
```bash
curl -X PUT --data-binary @benchmarks/cis/rhel_9/pam_validation.rego \
  http://localhost:8181/v1/policies/cis_rhel9_pam
```

### All policies in a directory
```bash
for f in benchmarks/cis/rhel_9/*.rego; do
  curl -s -X PUT --data-binary @"$f" \
    "http://localhost:8181/v1/policies/$(basename $f .rego)"
done
```

### Optional: splitting by domain

A single OPA instance serves this entire library comfortably — start there. If you later want
blast-radius or access isolation between domains, you can run several instances and load a
subtree into each:

```bash
# e.g. one instance per domain, each on its own port
podman run -d --name opa-benchmarks  -p 8181:8181 openpolicyagent/opa run --server --addr :8181
podman run -d --name opa-frameworks  -p 8182:8181 openpolicyagent/opa run --server --addr :8181
podman run -d --name opa-governance  -p 8183:8181 openpolicyagent/opa run --server --addr :8181
```

Then load `benchmarks/` into the first, `frameworks/` into the second, and
`governance/` + `enforcement/` into the third.

The split is entirely your choice — the policies neither know nor care which instance they
are loaded into, and no policy references another instance. Pick whatever grouping matches
how you want to control access; there is nothing special about the one above.

---

## Framework entrypoints

Every framework exposes a uniform entrypoint:

```
data.<package>.main.compliance_report
```

so you can evaluate any framework by name without learning how its modules are organised
internally. Some frameworks are a single module, others aggregate a dozen; the entrypoint
looks the same either way.

**Entrypoints are named after the package that holds the policy** — never after a caller's
own vocabulary. If your system spells a framework differently (`cis_ubuntu_2204` where this
library says `cis_ubuntu_22_04`), write a thin alias on your side:

```rego
package cis_ubuntu_2204.main

import rego.v1

compliance_report := data.cis_ubuntu_22_04.main.compliance_report
```

Keeping that translation in your repo is what lets this one stay generic.

### Fail closed

Most controls are phrased *"violate if the fact says X"*. Given **no facts**, nothing
iterates, nothing violates — and a naive report would announce near-total compliance for an
assessment that measured nothing. That result is indistinguishable from a genuinely clean
system, and it is exactly the kind of thing that quietly lands in an audit record.

Every entrypoint therefore gates on whether facts were supplied at all:

| input | result |
|---|---|
| no facts | `compliant: false`, 0%, all controls counted failed, explicit `FAIL-CLOSED` violation |
| real facts | normal assessment; the gate is transparent |

```bash
opa eval -d . -f pretty 'data.cis_rhel9.main.compliance_report'
# compliant: false, compliance_percentage: 0, violations: ["FAIL-CLOSED: no facts supplied ..."]
```

An empty report is never a passing report. **Limitation:** the gate detects a completely
empty input, not a partial one — sparse or wrong-shaped facts still evaluate normally and can
under-report violations.

---

## Input / Output Contract

Each framework's entrypoint accepts system facts as input and returns a structured report.
Individual modules additionally expose their own `compliance_assessment` / `compliance_report`
rules if you want a single section rather than the whole framework:

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

- [Open Policy Agent](https://www.openpolicyagent.org/) v0.60+, or
  [Enterprise OPA (EOPA)](https://www.styra.com/enterprise-opa/) — the policies use only
  standard Rego and built-ins, so either runtime works
- All policies use `import rego.v1` (Rego v1 syntax)
- Continuously tested against OPA v0.68 in CI and OPA v1.x locally
- No other dependencies — no sidecar, no data documents, no external services. Policies are
  pure functions of their input and perform no I/O (no `http.send`).

---

## Consumers

This library is standalone. It has no opinion about who calls it, how facts are gathered, or
where results are stored — it is a tree of `.rego` files and their tests, and nothing else.

Anything specific to a particular caller — framework-key naming, routing tables, result
schemas, fact collection — belongs in that caller, not here. If you find something in this
repo that only makes sense for one consumer, that is a bug worth reporting.

**Known consumers:**

- **AAC (Ansible Automated Compliance)** — a compliance automation platform on Ansible
  Automation Platform + OPA + PostgreSQL. It consumes this library as a git submodule and
  keeps its own key-translation aliases and routing config on its side. (The orchestration
  repo is private; this policy library is the open component.)

Using it somewhere else? Open an issue — the goal is that nothing in here requires knowing
about any of the above.

---

## More Rego Policies on GitHub

Pointers to other great policy-as-code work in the community — **full credit to the owners and authors** of each project below. These are references, not vendored copies: we link to them so you can find them; the policies stay in their home repositories under their own maintainers and licenses.

### Policy libraries

| Repository | Owner / Author | What it covers |
|---|---|---|
| [redhat-cop/rego-policies](https://github.com/redhat-cop/rego-policies) | Red Hat Community of Practice | Kubernetes/OpenShift + general config-compliance policies for OPA, Gatekeeper, and Conftest |
| [kubewarden/rego-policies-library](https://github.com/kubewarden/rego-policies-library) | Kubewarden project (SUSE) | Kubernetes security & compliance admission policies (Gatekeeper/Kubewarden-compatible, compiled to Wasm) |
| [conforma/policy](https://github.com/conforma/policy) | Conforma / Konflux-CI (Enterprise Contract) | Software supply-chain verification — image attestations, build provenance, pipeline-definition validation |
| [raedrizk/ansible-policy-as-code](https://github.com/raedrizk/ansible-policy-as-code) | Raed Rizk ([@raedrizk](https://github.com/raedrizk)) | AAP governance / pipeline enforcement — job-template naming, EE security, fork limits, time-based access, SCM branch enforcement, superuser restrictions |

### Style, linting & tooling

| Repository | Owner / Author | What it is |
|---|---|---|
| [open-policy-agent/rego-style-guide](https://github.com/open-policy-agent/rego-style-guide) | Open Policy Agent maintainers | Official Rego style guide / authoring best practices (complements the Regal linter) |
| [open-policy-agent/rego-python](https://github.com/open-policy-agent/rego-python) | Open Policy Agent | Python library for working with Rego ASTs |
| [itaysk/regogo](https://github.com/itaysk/regogo) | Itay Shakury ([@itaysk](https://github.com/itaysk)) | Go library wrapping the Rego engine for general-purpose JSON querying (jq-style) |

> Credit to each project's maintainers and authors. Adding a repository? Link to it (don't copy the policies), name the owner/author, and give a one-line description.

---

## Contributing

1. Place new `.rego` files in the appropriate taxonomy path
2. Add `import rego.v1` at the top
3. Expose a `compliance_assessment` rule with the standard output structure
4. Open a PR

---

## License

Apache 2.0
