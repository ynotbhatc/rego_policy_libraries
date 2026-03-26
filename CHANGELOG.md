# Changelog

All notable changes to this library will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
