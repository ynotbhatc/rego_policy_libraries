# rego_policy_libraries — CLAUDE.md

## Purpose

This repository is the **shared Rego policy library** consumed by every AAC (Ansible Automated Compliance) deployment and by the AAC Customer Portal. Every Rego policy here gets loaded into one of three OPA containers and queried by Ansible playbooks (compliance repo) or directly by the portal API.

This is a **library**, not an application. It produces no binaries, runs no servers, and ships no playbooks. Its only deliverable is a tree of `.rego` files plus the unit tests that prove they evaluate correctly.

Consumers pull this repo as a git submodule at a pinned commit. Today there are two consumers in the AAC ecosystem:

- **`ynotbhatc/compliance`** → submodule at `policies/`
- **`ynotbhatc/AAC_Customer_Portal`** → reads policies via the loader playbook

## Repository structure

```
benchmarks/                    Per-platform configuration baselines
├── cis/                       CIS Benchmarks (200+ files)
│   ├── rhel_9/ rhel_8/        RHEL by version, modules per section
│   │   rhel_10/               (os/linux/ holds only legacy/simple variants)
│   ├── ubuntu_20_04/          Ubuntu, one directory per version
│   │   ubuntu_22_04/ ubuntu_24_04/
│   ├── debian_11/ rocky_linux_8/ rocky_linux_9/ amazon_linux_2023/
│   ├── windows_server_2016/   Windows, one directory per version;
│   │   windows_server_2019_modular/  *_modular are the current ones
│   │   windows_server_2022/ windows_server_2022_modular/
│   │   windows_10/ windows_11/
│   ├── cloud/                 AWS / Azure / GCP foundations
│   ├── container/             Docker / Kubernetes
│   ├── saas/                  M365 (this is where the SaaS pattern lives)
│   ├── network/cisco/         Network device baselines
│   └── mobile/ios/            Mobile platforms
└── stig/                      DISA STIGs — RHEL/Win/Kubernetes/OpenShift

frameworks/                    Regulatory + management frameworks
├── federal/                   NIST 800-53, NIST 800-171, NIST CSF, NIST RMF,
│                              FISMA, FedRAMP, CMMC, NIST AI RMF
├── financial/                 PCI-DSS, SOX, DORA, NY DFS, SEC Cyber,
│                              SWIFT CSP
├── management/                ISO 27001, SOC 2, HITRUST, TISAX, CSA CCM,
│                              corporate, technical_debt
├── privacy/                   GDPR, HIPAA, ISO 27701, CCPA
├── compliance/                NCSC CAF, NIS2
├── critical_infrastructure/   NERC-CIP, AMI/NIST IR 7628, IEC 62443,
│                              NIST 800-82
├── regulatory/                CFR Part 11
└── sovereignty/               Digital Sovereignty

governance/                    Cross-cutting governance
├── ai/                        AI governance controls
├── eu_ai_act/                 EU AI Act
├── finops/                    FinOps governance
├── geisa/                     Grid Edge Interoperability + Security
├── mcp/                       MCP tool-call governance
└── oidc/                      OIDC enforcement

enforcement/                   Policy-as-Code gatekeepers (Sentinel-style)
├── ansible/                   Block bad Ansible playbooks
├── terraform/                 Block bad Terraform plans
├── dockerfile/                Block bad Dockerfiles
├── kubernetes/                Block bad K8s manifests
├── aap/                       AAP job gating — Policy as Code decision set
│                              (maintenance windows, owner scope, labels,
│                              extra_vars, naming, source control)
└── git/                       Git change approval policy (used for repo
                               protection — see Approved-By convention)

threat_detection/              Behavioral threat patterns
└── crypto_mining/             Crypto-miner indicators
```

Headline count: **532 policy files** (613 including tests) across the above directories.
Count it, never quote it — `git ls-tree -r HEAD --name-only | grep '\.rego$' | grep -vcE '(^|/)(test_|.*_test\.rego$)'` — the number drifts with every merge.

## Skill: Rego v1 syntax (MANDATORY)

Every policy in this library **MUST** use Rego v1. The mandatory shape:

```rego
package <domain>.<section>

import rego.v1

default compliant := false

violation contains msg if {
    condition
    msg := "control_id: description — what's wrong"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "section": "1.1",
    "name": "Initial Setup",
    "controls_evaluated": <int>,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
```

### Critical Rego v1 rules

1. `import rego.v1` at top of every file
2. Use `if` keyword on rule heads: `compliant if { ... }`
3. Use `contains` for partial sets: `violation contains msg if { ... }`
4. Use `in` for iteration: `some item in collection`
5. `default rule := false` is **required** — without it, a never-firing rule is `undefined`, and an `undefined` field in an object literal turns the entire object into `{}` at the endpoint
6. `array.concat()` takes **exactly 2 arrays** — for 3+ arrays, nest:

   ```rego
   # ✗ WRONG
   all := array.concat([v | some v in a], [v | some v in b], [v | some v in c])

   # ✓ CORRECT — nested
   ab := array.concat([v | some v in a], [v | some v in b])
   all := array.concat(ab, [v | some v in c])
   ```

7. Set → array: `[v | some v in <set>]` (sets and arrays aren't interchangeable)

## Skill: testing locally

```bash
# Test a single policy + its tests
opa test benchmarks/cis/rhel_9/pam_validation.rego \
         benchmarks/cis/rhel_9/tests/test_pam.rego -v

# Test an entire framework
opa test benchmarks/cis/rhel_9/ -v --coverage

# Full repo (ignore the .github/ directory that lives inside the
# benchmarks tree — opa tries to parse the YAML otherwise)
opa test . --ignore .github -v
```

Tests live next to the policies they exercise (e.g., `benchmarks/cis/saas/m365/tests/test_identity_validation.rego`).

## Skill: file + package naming

- File: `<section>_validation.rego` (e.g., `pam_validation.rego`)
- Package: `<framework>.<section>` (e.g., `cis_rhel9.pam`)
- Test file: `tests/test_<section>_validation.rego`
- Test package: `<framework>.<section>_test`

## Skill: writing a violation message

Every violation message includes:
- The control identifier (`CIS 1.1.1`, `NIST SC-28`, etc.)
- A short description
- The specific failure detail when possible

```rego
violation contains msg if {
    not input.filesystem.tmp_nodev
    msg := "CIS 1.1.6: /tmp must be mounted with nodev — currently mounted without it"
}
```

Don't write generic "compliance check failed" — auditors read these messages, not the source.

## Skill: input contract

Every policy file documents its input shape at the top in a header comment. Inputs come from one of:

- **Ansible fact-gathering modules** (compliance repo) for host-level benchmarks (CIS RHEL, STIG, etc.)
- **The aac.m365 collection** (compliance repo, Microsoft Graph) for the SaaS benchmarks
- **AAP REST API extracts** for ansible/terraform enforcement
- **The portal's policy_ingestion pipeline** for tenant-uploaded policies

The policy doesn't care where the facts came from — only that the shape matches. Don't reach into a policy and rewrite to match a new fact source; add a transformation step in the Ansible side or document a coverage gap.

## Skill: master orchestrators

Each multi-section framework has a master file that aggregates per-section reports:

- `benchmarks/cis/rhel_9/cis_rhel9_complete.rego` — RHEL 9
- `frameworks/critical_infrastructure/nerc_cip/nerc_cip_main.rego` — NERC-CIP
- `frameworks/management/iso27001/iso27001_policy.rego` — ISO 27001 ISMS
- `frameworks/financial/sox/sox_main.rego` — SOX ITGC

When you add new sections, also wire them into the master orchestrator's `violations` aggregation (remember the 2-arg `array.concat` rule).

## Conventions

- **Naming**: `cis_<distro>_<version>` for CIS OS benchmarks; `<framework>_main` for orchestrators
- **Versions**: pin the benchmark version (e.g., "CIS RHEL 9 v2.0.0") in a comment at the top of the orchestrator; bump explicitly when migrating
- **Violations as messages, not severity**: violations are currently a list of strings. There's no per-violation severity field. If a control is critical, say so in the message ("CRITICAL: ...")
- **No execution**: Rego files do not produce side effects. If you find yourself wanting `http.send` or similar, that logic belongs in the Ansible playbook calling OPA, not in policy

## CI

`.github/workflows/ci.yml` runs `opa test` on every PR via the `Check and Test Rego Policies` job. PRs are merged when CI is green.

The compliance repo has its own CI that validates the submodule pointer; bumping the submodule there pulls in this library at the SHA you committed.

## Conventions for new contributions

1. New benchmark version: add as a new directory (`benchmarks/cis/rhel_10/`); do NOT mutate the previous version
2. New framework: pick a parent under `frameworks/` (federal / financial / management / privacy / compliance / sovereignty / critical_infrastructure / regulatory) and ship a `<framework>_main.rego` master
3. Always update the consumer side: bumping a policy doesn't help anyone until the compliance repo's submodule pointer advances and the loader playbook references it

## Cross-cutting conventions (apply across all AAC repos)

- **podman not docker** — every container example here uses `podman`. If a vendor README says `docker run`, translate to `podman run`. No exceptions.
- **RHEL not Ubuntu/Debian** — when a test fixture or example needs a host OS, default to RHEL 9 unless the policy specifically targets another distro.
- **No lab IPs in policies or tests** — IPs like `192.168.4.62` (lab AAP) and `192.168.4.26` (lab utility host) are **lab-only**. They must never appear in:
  - Rego sample inputs (`sample_*_facts.json`)
  - Test fixtures
  - README examples
  Use `<host>`, `192.0.2.x` (RFC 5737 documentation block), or `localhost` instead. The lab, demo (RHPDS), and customer environments are strictly separated; bleed-over of any one's specifics into another is a bug.

## Generated document handling

If you produce a customer-facing or auditor-facing document from this repo (compliance report, policy attestation, etc.):

1. Write the canonical version to the repo location it belongs in
2. Save a copy to `~/Downloads/<name>.md` AND a second timestamped copy to `~/Downloads/<name>-<YYYY-MM-DD>.md` so the operator has both the current version and a dated snapshot
3. **ALWAYS also save a DOCX with the version number in the filename** — required for every generated document, not only customer-facing ones: `~/Downloads/<name>-v<X.Y>.docx` and `~/Downloads/<name>-v<X.Y>-<YYYY-MM-DD>.docx`. Generate with pandoc: `pandoc <name>.md -o <name>-v<X.Y>.docx`.

## Documentation pointers

- **OPA Rego language reference**: https://www.openpolicyagent.org/docs/latest/policy-language/
- **OPA testing docs**: https://www.openpolicyagent.org/docs/latest/policy-testing/
- **Rego v1 migration guide**: https://www.openpolicyagent.org/docs/latest/opa-1/
- **Consumer (compliance repo)**: https://github.com/ynotbhatc/compliance
- **Consumer (portal repo)**: https://github.com/ynotbhatc/AAC_Customer_Portal
