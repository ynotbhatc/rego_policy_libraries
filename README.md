# Rego Policy Libraries

Ready-to-run compliance checks for [Open Policy Agent](https://www.openpolicyagent.org/), written in Rego. Give a framework your system facts and it tells you which controls pass, which fail, and why. No agent, no orchestrator, no vendor runtime: clone it or pull the bundle, load it into OPA, query it.

It covers the benchmarks and regulations most teams are asked about: CIS Benchmarks and DISA STIGs for Linux, Windows, cloud, containers, databases and network gear; NIST, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR, NERC CIP, IEC 62443, FedRAMP, CMMC, the EU AI Act, and regional rules from the UK, EU, India, Japan, Singapore, Malaysia, Hong Kong and Australia. The full list is in [docs/FRAMEWORKS.md](docs/FRAMEWORKS.md).

**953 production-ready Rego policies** (2,265 including tests) holding **24,009 control-level checks** across 185 framework catalogs. CI recounts these numbers on every merge and fails if this line drifts. How that compares with other open libraries: [docs/COMPARISON.md](docs/COMPARISON.md).

[![control-level checks](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fynotbhatc%2Frego_policy_libraries%2Fmain%2Fdocs%2Fmetrics.json)](docs/COMPARISON.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rego](https://img.shields.io/badge/Rego-v1-green)](https://www.openpolicyagent.org/docs/latest/policy-language/)

## Try it in two minutes

```bash
git clone https://github.com/ynotbhatc/rego_policy_libraries.git
cd rego_policy_libraries

# Ask the CIS RHEL 9 benchmark for a report with no facts at all
opa eval -d benchmarks/cis/rhel_9 -f pretty 'data.cis_rhel9.main.compliance_report'
```

You get a report that is **not** compliant:

```
"compliant": false,
"compliance_percentage": 0,
"total_controls": 263,
"failed_controls": 263,
"violations": [
  "FAIL-CLOSED: no facts supplied for cis_rhel9 — the assessment could not be evaluated. ...",
  "1.1.1.1: evidence missing — disabled_filesystem_modules.modules[cramfs] not collected",
  ...
]
```

That is the one rule every framework here follows: no facts means non-compliant with a reason, never a silent pass. Feed it real facts and the same query returns the real result.

```bash
opa eval -d benchmarks/cis/rhel_9 -i facts.json -f pretty 'data.cis_rhel9.main.compliance_report'
```

Prefer a running server? Pull the pre-built bundle instead of cloning:

```bash
oras pull ghcr.io/ynotbhatc/rego_policy_libraries:latest
podman run -d --name opa -p 8181:8181 -v "$(pwd)/bundle.tar.gz:/bundle.tar.gz:ro" \
  openpolicyagent/opa:1.10.0 run --server --addr :8181 --bundle /bundle.tar.gz
curl -s -X POST http://localhost:8181/v1/data/cis_rhel9/main/compliance_report \
  -H 'Content-Type: application/json' -d @facts.json
```

Wiring it into a CI job, Conftest, Gatekeeper or Kubewarden: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## How it works

- **One entrypoint per framework.** `data.<key>.main.compliance_report`, where `<key>` is the framework's name (`cis_rhel9`, `stig_rhel9`, `nist_800_53`, `pci_dss`, `as9100d` …). You do not need to know how a framework is organised inside.
- **One report shape.** `compliant`, counts of passed and failed controls, a percentage, and a `violations` list that names each control. Sections are reported separately when a framework has them.
- **Facts in, decisions out.** Policies read only their input. They perform no I/O, call no services and need no data documents, so they run the same in OPA, Enterprise OPA, Conftest, Gatekeeper, Kubewarden and Trivy.
- **Fails closed.** Missing facts fail. A control whose evidence is absent fails with an "evidence missing" violation rather than passing by default. The gate catches empty input; sparse or wrongly shaped input still evaluates, so send what the module header asks for.
- **Loadable in any slice.** Load one benchmark, one directory or the whole tree. Nothing references another instance.

A typical report:

```json
{
  "compliant": false,
  "total_controls": 352,
  "passed_controls": 301,
  "failed_controls": 51,
  "compliance_percentage": 86,
  "violations": [
    "1.1.1.1: evidence missing — disabled_filesystem_modules.modules[cramfs] not collected",
    "5.1.7: X11Forwarding is yes; expected no"
  ],
  "section_results": { "1": {"compliant": false, "...": "..."}, "...": "..." }
}
```

## What's inside

| Domain | Policies | Coverage |
|--------|----------|----------|
| **CIS Benchmarks + DISA STIGs** | 486 | CIS for Linux, Windows, cloud, containers, managed Kubernetes, databases, web servers, network devices, VMware and Microsoft 365, with Level 2 profiles; DISA STIGs — 25 platforms on the October 2026 library |
| **Federal & K8s hardening baselines** | 19 | CISA SCuBA M365, NSA/CISA Kubernetes Hardening, Kubernetes Pod Security Standards |
| **Application suite baselines** | 7 | SAP Security Baseline Template v2.6 (ABAP) |
| **Regulatory Frameworks** | 389 | NIST (800-53, 800-171, CSF 2.0, AI RMF, SSDF, Zero Trust), ISO 27001 and 27701, SOC 2, PCI DSS, SOX, HIPAA, GDPR, CCPA, NERC CIP, IEC 62443, FedRAMP, CMMC, CJIS, DORA, NIS2, NY DFS, SWIFT CSP, HITRUST, TISAX, COBIT, CIS Controls v8.1, UK Cyber Essentials, BSI C5, Essential Eight, MAS TRM, APRA CPS 234, HKMA, BNM RMiT, DPDP, CERT-In, METI, SAE AS9100D, and more |
| **Enforcement** | 22 | Gates for Ansible, Terraform, Dockerfiles, Kubernetes admission, Git approvals, AAP jobs, CI/CD pipelines, SLSA supply chain |
| **Governance** | 26 | AI agent authorisation, MCP tool calls, EU AI Act, ISO/IEC 42001 and 42005, OIDC tokens, FinOps tagging, estate continuity |
| **Crosswalks** | 2 | STIG ↔ NIST 800-53 and framework-to-framework maps |
| **Threat Detection** | 2 | Cryptocurrency miner indicators |

Every framework, its path and what it covers: [docs/FRAMEWORKS.md](docs/FRAMEWORKS.md). The directory layout and ways to load it: [docs/TAXONOMY.md](docs/TAXONOMY.md). Which version of each standard is implemented and when it is next expected to change: [STANDARDS_UPDATE_REGISTRY.md](STANDARDS_UPDATE_REGISTRY.md).

## Find your way in

| You are | Start here |
|---|---|
| Running OPA and want checks for a platform | [docs/FRAMEWORKS.md](docs/FRAMEWORKS.md), then `opa eval` as above |
| Gating CI, Terraform, containers or Ansible | [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) and [`enforcement/`](enforcement/) |
| Writing or fixing a policy | [CONTRIBUTING.md](CONTRIBUTING.md), [CLAUDE.md](CLAUDE.md) for the house rules, `make test` |
| Preparing an audit or an authorisation package | [docs/FRAMEWORKS.md](docs/FRAMEWORKS.md) for scope, the OSCAL exports below for evidence |
| Using it from another engine or format | [`converters/`](converters/) |

## Machine-readable outputs

The evaluation output and the policy source generate the artefacts an authorisation package needs, validated in CI against the OSCAL 1.2.3 schemas and committed under [`converters/exports/oscal/dist/`](converters/exports/oscal/): catalogs (one per framework, 185 catalogs, 19,412 controls, each with the Rego file that evaluates it), NIST and FedRAMP profiles, a component definition, and assessment results built from any `compliance_report` run. SARIF and OCSF exports sit beside them. Control mappings come only from authoritative tables (DISA's CCI map, NIST's baselines), never by hand. [`converters/README.md`](converters/README.md) lists every packaging target, interchange format and per-engine generator (WASM, signed bundles, Ansible, SCAP, InSpec, Wazuh, CEL/Kyverno, Azure Policy, AWS Config, Steampipe, Sentinel, Sigma, Prowler).

## Requirements

- Open Policy Agent or Enterprise OPA. Tested in CI on OPA 1.10.0 and 1.22.0; the published bundle is built with 1.10.0. Other Rego engines are not supported ([docs/ENGINE_COMPATIBILITY.md](docs/ENGINE_COMPATIBILITY.md)).
- Nothing else. Policies use `import rego.v1` and standard built-ins only.

## Who uses it

The library is standalone and has no opinion about who calls it. Its first consumer is [Ansible Automated Compliance](https://github.com/Ansible-Automated-Compliance/aac), which gathers facts with Ansible, evaluates them here and stores the results. Framework-key aliases, routing tables and result schemas belong to the caller, not to this repo. Other Rego policy projects worth knowing: [docs/COMMUNITY.md](docs/COMMUNITY.md).

## Contributing

Put new `.rego` files on the right taxonomy path, start them with `import rego.v1`, expose `compliance_report` from a `.main` package that fails closed on empty input, add tests, and open a PR. [CONTRIBUTING.md](CONTRIBUTING.md) has the walk-through, including the rule that no benchmark text is copied verbatim.

## License

Apache 2.0
