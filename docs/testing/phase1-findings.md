# Phase 1 contract smoke tests — findings

**Date:** 2026-07-02
**Branch/PR:** `test/phase1-contract-smoke-tests`

## What Phase 1 did

Added a **contract smoke test** for every consumer-facing orchestrator endpoint: evaluate the
aggregate report rule with empty input and assert it returns a **well-formed object** (`is_object`,
`count > 0`), never the Rego-v1 `undefined → {}` collapse (CLAUDE.md rule #5). 50 new tests.

Result: **169 pass, 0 fail, 20 skipped.** The 20 skips are `todo_`-prefixed tests parked against
**broken endpoints** — they encode the correct contract and flip green the moment the endpoint is
fixed. Nothing is green-washed; nothing red breaks CI.

## Headline finding

The smoke tests uncovered a **systemic `undefined → {}` collapse across ~30 consumer endpoints** —
the same bug class PRs #29–#35 fixed one at a time. Two mechanisms:

- **Missing `default` on a rule referenced by the report object** (e.g. `compliant`, a score, a
  wrapper boolean). Because the rule is `undefined` whenever the system is *non-compliant*, these
  endpoints return `{}` in normal operation — exactly when the report matters most.
- **Unguarded `input.*` inside the report object literal** (e.g. `"hostname": input.system_info.hostname`).
  One missing fact makes the whole report `undefined`.

## Broken endpoints

### HIGH — returns `{}` whenever non-compliant (missing `default`)
| Endpoint | File | Missing default |
|---|---|---|
| cis windows_11 | benchmarks/cis/windows_11/cis_windows_11.rego | `compliant` |
| cis postgresql_13/14/15 | benchmarks/cis/postgresql/* | `compliant` |
| cis mysql_8 | benchmarks/cis/mysql/cis_mysql_8.rego | `compliant` |
| cis oracle_19c | benchmarks/cis/oracle/cis_oracle_19c.rego | `compliant` |
| cis apache_2_4 | benchmarks/cis/apache/cis_apache_2_4.rego | `compliant` |
| fisma | frameworks/federal/fisma/fisma_main.rego | `fisma_compliant` |
| cmmc | frameworks/federal/cmmc/cmmc_main.rego | sub-module reports |
| pci_dss | frameworks/financial/pci_dss/pci_dss_main.rego | per-req scores |
| sox | frameworks/financial/sox/sox_main.rego | `sox_compliance_score` |
| iso27001 | frameworks/management/iso27001/iso27001_policy.rego | `allow` |
| gdpr | frameworks/privacy/gdpr/gdpr_main.rego | module `*_compliant` wrappers |
| hipaa | frameworks/privacy/hipaa/hipaa_main.rego | module `*_compliant` wrappers |
| eu_ai_act | governance/eu_ai_act/eu_ai_act_main.rego | `risk_tier` |
| oidc | governance/oidc/* | `summary` defaults to `{}` |

### MEDIUM — returns `{}` on incomplete facts (unguarded `input.*` in report literal)
STIG `stig_assessment` (8): rhel_8, rhel_9, windows_10, windows_11, windows_server_2016/2019/2022,
ubuntu_20_04 — all embed `input.system_info.hostname` in metadata.
OT/gov: nerc_cip cip015 (`input.insm.systems`), ami device (`total_devices`), iec_62443
(`input.target_sl`), ai_governance (`input.action`), mcp (`input.tool`), finops (`total_resources`),
digital_sovereignty (sub-domain `input.*`).

### MISSING — no aggregate report endpoint at all
- **soc2** (`frameworks/management/soc2/soc2_main.rego`) — no `compliance_report` rule.
- **cis_m365** (`benchmarks/cis/saas/m365/`) — only per-section reports; no orchestrator.

### STRUCTURAL — shared `package cis` collision
`windows_10, windows_server_2016, docker, kubernetes, aws, azure, gcp` all declare `package cis`
with their own `compliance_summary`. Querying `cis.compliance_summary` tree-wide raises
`eval_conflict_error`. Latent today (nothing queries it), but blocks smoke tests and would break a
combined query. Fix: give each its own package (`cis.windows_10`, `cis.docker`, …).

### CONTRACT DRIFT — documented endpoint dead, working alternative exists
- **cis_rhel9** — the compliance repo CLAUDE.md documents `POST /v1/data/cis_rhel9/compliance_assessment`,
  but that rule and `cis_rhel9.main.compliance_report` both return `{}`. `executive_summary` works and
  is what the live playbooks actually query. Reconcile docs ↔ policy (ties into the RHEL 9 consolidation).
- **cis ubuntu 20.04/22.04/24.04, debian_11** — `compliance_assessment` undefined on empty input;
  `compliance_summary` works and was tested instead.

## Recommended follow-up (Phase 1.5)

Fix the collapse bugs, which flips the 20 `todo_` tests green:
1. **HIGH batch** — add `default <rule> := false/0` to each rule the report references. Mechanical, low-risk.
2. **MEDIUM batch** — wrap in-literal input refs with `object.get(input, [...], "unknown")`.
3. **soc2 / cis_m365** — add an aggregate `compliance_report` orchestrator.
4. **`package cis` split** — repackage the 7 colliding CIS frameworks.

Then Phase 4: wire a CI gate that fails if any P0 endpoint evaluates to `{}` on empty input.
