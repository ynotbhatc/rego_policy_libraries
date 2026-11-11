# Repository layout and loading options

<!-- Moved out of README.md on 2026-11-11 so the front page stays short. Content unchanged except headings. -->

## Policy taxonomy

```
rego_policy_libraries/
├── benchmarks/                  # Technical security baselines
│   ├── cis/
│   │   ├── rhel_8/ rhel_9/ rhel_10/
│   │   ├── ubuntu_20_04/ ubuntu_22_04/ ubuntu_24_04/
│   │   ├── debian_11/ rocky_linux_8/ rocky_linux_9/ amazon_linux_2023/
│   │   ├── windows_server_2016/ windows_server_2019_modular/
│   │   ├── windows_server_2022/ windows_server_2022_modular/
│   │   ├── windows_10_modular/ windows_11_modular/
│   │   ├── aws/ azure/ gcp/     # Cloud Foundations
│   │   ├── docker/ kubernetes/  # Containers
│   │   ├── eks/ aks/ gke/       # Managed Kubernetes (EKS v1.8.0, AKS v1.8.0, GKE v1.9.0)
│   │   ├── postgresql/ databases/
│   │   ├── saas/m365_v7/        # SaaS — CIS Microsoft 365 Foundations v7 (m365/ = v6 legacy)
│   │   ├── network_devices/     # Cisco, Juniper, Palo Alto, Fortinet, Arista, VyOS, pfSense
│   │   ├── vmware/              # ESXi 8, vCenter
│   │   ├── mobile_devices/      # Android, iOS
│   │   ├── os/linux/            # legacy/simple RHEL 9 variants — superseded
│   │   ├── cloud/               # AWS, Azure, GCP Foundations
│   │   ├── containers/          # Docker, Kubernetes, OpenShift
│   │   ├── databases/           # MySQL 8, Oracle 19c, PostgreSQL 13/14/15
│   │   ├── web_servers/         # Apache 2.4, Nginx 1.20
│   │   └── network/             # Cisco IOS, Juniper Junos, Palo Alto, Fortinet, Arista
│   ├── stig/                    # DISA STIGs — 25 platforms (Linux, Windows, K8s/RKE2/OpenShift,
│   │                            # databases, Apache, Cisco IOS-XE, vSphere)
│   ├── scuba/m365/              # CISA SCuBA M365 baselines — 104 policies, 7 products (BOD 25-01)
│   ├── nsa_cisa/kubernetes/     # NSA/CISA Kubernetes Hardening Guidance v1.2 — 43 controls
│   ├── pss/kubernetes/          # K8s Pod Security Standards — baseline + restricted, manifest-evaluated
│   └── sap/abap/                # SAP Security Baseline Template v2.6 (ABAP) — 355-check registry, 138 host-decided
│
├── frameworks/                  # Regulatory compliance
│   ├── federal/                 # NIST 800-53/171/800-82, CSF 2.0, AI RMF, SSDF, FISMA, FedRAMP,
│   │                            # CMMC, Zero Trust (ZTMM v2.0 + 800-207), CJIS, IRS Pub 1075
│   ├── management/              # ISO 27001, SOC 2, CSA CCM, COBIT 2019, CIS Controls v8.1,
│   │                            # Corporate, NCSC CAF 4.0
│   ├── financial/               # PCI-DSS, SOX, SWIFT CSP, NY DFS, SEC Cyber, GLBA
│   ├── privacy/                 # GDPR, HIPAA, ISO 27701, CCPA/CPRA, FERPA, COPPA
│   ├── regulatory/              # DORA, NIS2, ITAR
│   ├── regional/                # ACSC Essential Eight, UK Cyber Essentials, BSI C5, UK MoD DCC, CERT-In (India), METI CSM (Japan)
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

## Loading policies into OPA

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

## Use as a Git submodule

```bash
# Add to your project
git submodule add https://github.com/ynotbhatc/rego_policy_libraries.git policies
git submodule update --init --recursive

# Update to latest
git submodule update --remote policies
git add policies && git commit -m "Update policy library"
```
