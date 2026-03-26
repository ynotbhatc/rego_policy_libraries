# Rego Policy Libraries

A standalone library of Open Policy Agent (OPA) Rego policies for infrastructure
compliance automation. Extracted from the
[Ansible Automated Compliance (AAC)](https://github.com/ynotbhatc/compliance) project.

## Library Taxonomy

Policies are organized across five domains:

```
benchmarks/         Technical security baselines (CIS, STIG)
frameworks/         Regulatory compliance frameworks
enforcement/        Gate-style policy-as-code checks (Ansible, Terraform, Git)
governance/         AI and operational governance decisions
threat_detection/   Active threat detection rules
```

### Benchmarks

| Path | Standard | Coverage |
|------|----------|----------|
| `benchmarks/cis/os/linux/rhel_9/` | CIS RHEL 9 v2.0.0 | 338/338 (100%) |
| `benchmarks/cis/os/linux/rhel_8/` | CIS RHEL 8 | Full |
| `benchmarks/cis/os/linux/ubuntu_22_04/` | CIS Ubuntu 22.04 | Full |
| `benchmarks/cis/os/linux/ubuntu_20_04/` | CIS Ubuntu 20.04 | Full |
| `benchmarks/cis/os/linux/ubuntu_24_04/` | CIS Ubuntu 24.04 | Full |
| `benchmarks/cis/os/linux/debian_11/` | CIS Debian 11 | Full |
| `benchmarks/cis/os/linux/rocky_linux_8/` | CIS Rocky Linux 8 | Full |
| `benchmarks/cis/os/linux/rocky_linux_9/` | CIS Rocky Linux 9 | Full |
| `benchmarks/cis/os/linux/amazon_linux_2023/` | CIS Amazon Linux 2023 | Full |
| `benchmarks/cis/os/windows/` | CIS Windows Server 2016/2019/2022, Win 10/11 | Full |
| `benchmarks/cis/cloud/aws/` | CIS AWS Foundations | Full |
| `benchmarks/cis/cloud/azure/` | CIS Azure Foundations | Full |
| `benchmarks/cis/cloud/gcp/` | CIS GCP Foundations | Full |
| `benchmarks/cis/containers/docker/` | CIS Docker | Full |
| `benchmarks/cis/containers/kubernetes/` | CIS Kubernetes | Full |
| `benchmarks/cis/containers/openshift/` | CIS OpenShift 4 | Full |
| `benchmarks/cis/databases/mysql/` | CIS MySQL 8 | Full |
| `benchmarks/cis/databases/oracle/` | CIS Oracle 19c | Full |
| `benchmarks/cis/databases/postgresql/` | CIS PostgreSQL 13/14/15 | Full |
| `benchmarks/cis/web_servers/apache/` | CIS Apache 2.4 | Full |
| `benchmarks/cis/web_servers/nginx/` | CIS Nginx 1.20 | Full |
| `benchmarks/cis/network/` | CIS Cisco, Juniper, Palo Alto, Fortinet, Arista | Full |
| `benchmarks/stig/` | DISA STIGs — RHEL 8/9, Ubuntu, Windows | Full |

### Frameworks

| Path | Standard |
|------|----------|
| `frameworks/federal/nist/` | NIST 800-53, 800-171, CSF 2.0, AI RMF |
| `frameworks/federal/fisma/` | FISMA |
| `frameworks/federal/fedramp/` | FedRAMP |
| `frameworks/federal/cmmc/` | CMMC |
| `frameworks/management/iso27001/` | ISO 27001 |
| `frameworks/management/soc2/` | SOC 2 |
| `frameworks/management/corporate/` | Organization-specific policies |
| `frameworks/financial/pci_dss/` | PCI-DSS |
| `frameworks/financial/sox/` | Sarbanes-Oxley |
| `frameworks/privacy/gdpr/` | GDPR |
| `frameworks/privacy/hipaa/` | HIPAA |
| `frameworks/critical_infrastructure/nerc_cip/` | NERC-CIP CIP-002 through CIP-015 |
| `frameworks/critical_infrastructure/iec_62443/` | IEC 62443 |
| `frameworks/critical_infrastructure/ami/` | NIST IR 7628, AMI Device & Head-End |
| `frameworks/sovereignty/digital_sovereignty/` | Digital Sovereignty (7 domains) |

### Enforcement

| Path | Use Case |
|------|----------|
| `enforcement/ansible/` | Gate Ansible playbook check-ins and runtime |
| `enforcement/terraform/` | Validate Terraform plans before apply |
| `enforcement/dockerfile/` | Lint Dockerfiles at build time |
| `enforcement/kubernetes/` | Admission control for K8s manifests |
| `enforcement/git/` | Git approval workflow policies |

### Governance

| Path | Use Case |
|------|----------|
| `governance/ai/` | AI agent action classification and authorization |
| `governance/mcp/` | MCP server tool-call enforcement |

### Threat Detection

| Path | Use Case |
|------|----------|
| `threat_detection/crypto_mining/` | Detect unauthorized cryptocurrency miners |

---

## Using with OPA

### Load a single policy

```bash
curl -X PUT --data-binary @benchmarks/cis/os/linux/rhel_9/pam_validation.rego \
  http://localhost:8181/v1/policies/cis_rhel9_pam_validation
```

### Load all CIS RHEL 9 policies

```bash
for f in benchmarks/cis/os/linux/rhel_9/*.rego; do
  curl -X PUT --data-binary @"$f" \
    "http://localhost:8181/v1/policies/$(basename $f .rego)"
done
```

### OPA container routing (3-container AAC pattern)

| Container | Port | Load from |
|-----------|------|-----------|
| `opa-security` | 8181 | `benchmarks/` |
| `opa-compliance` | 8182 | `frameworks/` + `enforcement/` |
| `opa-ot` | 8183 | `frameworks/critical_infrastructure/` + `governance/` + `threat_detection/` |

---

## Using with AAC (git submodule)

This library is consumed by AAC as a git submodule at `policies/`:

```bash
# Clone AAC with submodules
git clone --recurse-submodules https://github.com/ynotbhatc/compliance.git

# Update submodule to latest
cd compliance
git submodule update --remote policies
git add policies
git commit -m "Update policy library to latest"
```

---

## Adding a New Policy

1. Place the `.rego` file in the appropriate taxonomy path
2. Ensure `import rego.v1` is at the top of the file
3. Run `make test` to validate syntax
4. Open a PR — CI runs `opa check` on all policies

---

## Requirements

- [Open Policy Agent](https://www.openpolicyagent.org/) v0.60+
- Rego v1 syntax (`import rego.v1` required in all files)

---

## License

Apache 2.0 — see LICENSE
