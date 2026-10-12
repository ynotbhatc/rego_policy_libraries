# Converters — Rego → X

This directory is the library's second product: every way the policies leave Rego so that other engines,
scanners, GRC platforms and SIEMs can use them. The policies themselves never change here; a converter
either **packages** Rego for an engine that already runs it, **exports** the metadata and control tables
into an interchange format, or **generates** an equivalent check in another engine's language for the
subset of policies whose input that engine can gather.

Layout: three tiers, one subdirectory per target —

```
converters/
├── packaging/    Tier 0 — Rego runs as-is: wasm, bundles, gatekeeper, kubewarden, iac_scanners, terraform_platforms
├── exports/      Tier 1 — interchange from METADATA and the control tables: oscal, sarif, ocsf, crosswalk_csv, xccdf_ids
└── generators/   Tier 2 — per-engine equivalents: ansible, scap, inspec, wazuh_sca, cel_kyverno, azure_policy,
                  aws_config_guard, steampipe, sentinel, sigma, prowler
```

Each target directory has its own README stating status (`planned`, `building`,
`shipping`), what it covers, how to run it, and its round-trip test. The contract every converter must
meet is in [`CONTRACT.md`](CONTRACT.md). Status at a glance is the table in §2 below.

| Status | Targets |
|---|---|
| shipping | **Tier 0 complete:** `packaging/wasm` (4 bundles, 92 entrypoints, round-trip), `packaging/bundles` (GHCR publish; signing planned), `packaging/gatekeeper` (2 ConstraintTemplates + Constraints, round-trip, Artifact Hub metadata), `packaging/kubewarden` (3 policies, round-trip), `packaging/iac_scanners` (Conftest layout, round-trip with conftest), `packaging/terraform_platforms` (TFC/Spacelift/env0 policy set, round-trip) |
| shipping | Tier 1: **oscal catalog** (`exports/oscal/dist/catalogs/<framework>.json`, 125 catalogs, OSCAL 1.2.3) |
| planned | Tier 1 next: oscal component-definition + assessment-results, sarif, ocsf, crosswalk_csv, xccdf_ids; then Tier 2 generators; Trivy/KICS/Regula/Snyk adapters inside iac_scanners |

## 1. Where the checks are, and what shape their input takes

| Area | Checks | Input shape | What that means for conversion |
|---|---|---|---|
| `benchmarks/cis` | 2,096 | host and cloud facts (`input.initial_setup`, `input.pam`, `input.cron`, cloud API objects) | fact-driven: converts to any engine that can gather the same facts (SCAP, InSpec, Wazuh, Steampipe, Azure Policy) |
| `frameworks/*` | 5,272 | attested facts and control tables (`input.<fw>.controls["9.1.5"]`, named check maps) | attestation-driven: converts mechanically to any catalogue, questionnaire or GRC format, and to any engine that evaluates booleans |
| `benchmarks/scuba`, `nsa_cisa`, `pss`, `enforcement/kubernetes` | ~150 | M365 Graph objects, Kubernetes manifests (`input.kind`) | object-driven: converts to CEL, Kyverno, Gatekeeper, Kubewarden |
| `enforcement/terraform`, `ansible`, `aap`, `git`, `dockerfile`, `cicd` | ~35 | plans, playbooks, job objects | gate-driven: Sentinel, cfn-guard, Checkov, Conftest already native |
| `governance`, `threat_detection`, `supply_chain` | ~275 | AI/MCP decision records, event streams | decision-driven: OCSF, Sigma, SARIF |

Two facts drive the whole roadmap. Rego is already the native language of a dozen engines, so the biggest reach comes from **packaging**, not translation. And two thirds of the checks are attestation tables, which convert to anything with a script, not a compiler.

## 2. The list

Effort: S = days, M = weeks, L = a quarter. Reach = who can consume the library afterwards that cannot today.

### Tier 0 — packaging, no logic changes (Rego runs as-is)

| # | Rego → | Mechanism | Covers | Effort | Reach |
|---|---|---|---|---|---|
| 1 | **WASM modules + language SDK examples** | `opa build -t wasm` per entrypoint; publish `.wasm` per class with Go, JavaScript, Python, Java, .NET and Rust SDK snippets | all 7,867 | S | any application in any language evaluates the library without running OPA. The single largest reach item. |
| 2 | **Signed OPA bundles per class** (`opa-security`, `opa-compliance`, `opa-ot`) | extend `scripts/gen_bundle_manifest.py`: build, sign, publish to the GitHub release and an OCI registry (`oras`) | all | S | OPA, Enterprise OPA, Styra DAS, Envoy/Istio ext_authz, Terraform Cloud and Spacelift pull a versioned bundle |
| 3 | **Gatekeeper ConstraintTemplates** | wrap each Kubernetes-input policy in a `ConstraintTemplate` with a `Constraint` example | pss, nsa_cisa, enforcement/kubernetes (~60) | S | every Gatekeeper cluster |
| 4 | **Kubewarden policies** | same policies as wasm with Kubewarden `metadata.yml`, published to a registry | ~60 | S | Kubewarden clusters, Rancher |
| 5 | **Conftest / Trivy / KICS / Regula / Snyk IaC module layout** | directory and metadata conventions, `avd` ids for Trivy, `conftest pull` layout | enforcement/*, cis cloud (~200) | S | IaC scanners that already execute Rego pick the library up as a plugin |
| 6 | **Terraform Cloud / Spacelift / env0 policy sets** | OPA policy set manifest for `enforcement/terraform` | 17 | S | Terraform platforms |

### Tier 1 — interchange exports, generated from METADATA and the control tables

| # | Rego → | Mechanism | Covers | Effort | Reach |
|---|---|---|---|---|---|
| 7 | **OSCAL catalog** — **shipping** (`exports/oscal`) | one catalog per framework from the shared control inventory (`scripts/inventory_controls.py`); committed under `dist/catalogs/`, schema-validated in CI | all frameworks (5,559 distinct controls) | M | compliance-trestle, RegScale, Xacta, Telos, FedRAMP automation, any OSCAL importer. Puts us beside SCF on the interchange axis while staying executable. |
| 8 | **OSCAL component-definition** | the library as a component with `implemented-requirements` linking each control to its Rego rule | all | S after 7 | SSP generators |
| 9 | **OSCAL assessment-results** | emit from `compliance_report` output at evaluation time | all | S | audit evidence that GRC tools ingest directly |
| 10 | **SARIF** | `compliance_report` → SARIF 2.1 (rule = control id, result = violation) | all | S | GitHub code scanning, Azure DevOps, every SARIF viewer |
| 11 | **OCSF Compliance Finding** | `compliance_report` → OCSF 1.x `compliance_finding` class | all | S | Splunk, Microsoft Sentinel, Amazon Security Lake, Google SecOps |
| 12 | **Crosswalk CSV in SCF / NIST CSF column layout** | from the registry and the `crosswalk/` tree | all frameworks | S | GRC platforms (Vanta, Drata, Secureframe, Hyperproof) that import control mappings |
| 13 | **CIS-CAT / XCCDF profile ids** | emit the XCCDF rule ids each CIS policy implements so CIS-CAT results can be joined to ours | cis (2,096) | S | CIS-CAT users compare their scan to our evaluation |

### Tier 2 — transpilers, per engine, for the subset whose input the engine can gather

| # | Rego → | Mechanism | Covers | Effort | Reach |
|---|---|---|---|---|---|
| 14 | **Ansible `assert` playbooks** | generate one playbook per attestation table and one per fact-driven CIS module (facts gathered with the same role the compliance repo uses) | all frameworks + cis (≈7,300) | M | AAP shops that will not run OPA at all. Our own ecosystem's second path, and the one Red Hat field teams will ask for first. |
| 15 | **SCAP: XCCDF + OVAL via ComplianceAsCode YAML** | generate `rule.yml` with OVAL checks for the CIS host modules | cis host (≈1,500) | L | OpenSCAP, CIS-CAT, Satellite, every SCAP scanner; also lets ComplianceAsCode upstream adopt our rules |
| 16 | **Chef InSpec profiles** | Ruby DSL controls from the fact-driven modules | cis host + stig (≈1,600) | M | InSpec and Chef Automate users |
| 17 | **Wazuh SCA YAML** | SCA checks from the host modules | cis host | M | Wazuh deployments |
| 18 | **CEL (Kubernetes ValidatingAdmissionPolicy) and Kyverno** | hand-written CEL per Kubernetes policy (CEL is less expressive than Rego; mechanical transpile is not safe) | ~60 | M | clusters that refuse Gatekeeper and OPA |
| 19 | **Azure Policy definitions** | JSON definitions for the Azure CIS checks | cis azure (~150) | M | Azure Policy and Defender for Cloud regulatory compliance |
| 20 | **AWS Config / cfn-guard rules** | Guard rules for the AWS CIS checks and Terraform gates | cis aws + terraform (~150) | M | AWS Config conformance packs, CloudFormation gates |
| 21 | **Steampipe / Powerpipe mods** | SQL controls for cloud checks | cis cloud (~300) | M | Powerpipe users |
| 22 | **HashiCorp Sentinel** | Sentinel policies for the Terraform gates | 17 | S | Terraform Enterprise customers on Sentinel |
| 23 | **Sigma rules** | `threat_detection/` indicators as Sigma | 8 | S | every SIEM via sigma-cli |
| 24 | **Prowler custom checks** | Python checks from the cloud modules | cis cloud | M | Prowler users; also the path to KISA ISMS-P mappings Prowler already ships |

### Not worth building

- **Cedar, XACML, Casbin, Cerbos:** authorization languages, not compliance evaluation. Wrong domain.
- **Checkov custom Python checks:** KICS, Trivy and Regula already run our Rego natively; Checkov's YAML custom policies cover a subset. Low reach per effort.
- **A general Rego-to-anything compiler:** Rego's set semantics and iteration do not map to CEL, Sentinel or SQL mechanically. Per-engine generators from the tables and fact modules are safer and cheaper than a compiler that would be wrong at the edges.

## 3. Recommended order

1. **WASM + signed bundles (1, 2).** Two weeks. Every language and every OPA-based platform can consume the library on day one, versioned by release tag.
2. **OSCAL trio + SARIF + OCSF (7–11).** Four to six weeks. GRC platforms, FedRAMP tooling, GitHub, and the SIEMs all open up, and the library gains the interchange format SCF competes on.
3. **Gatekeeper + Kubewarden wrappers (3, 4).** One week. Kubernetes shops.
4. **Ansible assert generator (14).** Four weeks. The AAP-native path, which the AAC story sells on its own.
5. **SCAP via ComplianceAsCode (15).** A quarter. The largest single audience for host benchmarks, and the route to upstream adoption of our CIS rules.
6. The rest (16–24) as customers ask, each one to three weeks.

## 4. What every converter must preserve

- The control id and the message text, verbatim: the message is the citation.
- Fail-closed semantics: absent evidence is a violation in every target that can express it, and a documented caveat in the ones that cannot (OSCAL, SARIF are results formats and carry whatever we evaluated).
- The `# METADATA` block: class, framework, source, domains ride along as tags in every format.
- A round-trip test per converter: generate, evaluate the same fixture in the target engine, compare violation ids with the Rego result. A converter without that test does not ship.

---

