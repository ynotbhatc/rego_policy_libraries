# CIS Microsoft 365 Foundations Benchmark v7.0.0 — coverage

**Version:** v3.0
**Benchmark:** CIS Microsoft 365 Foundations Benchmark **v7.0.0**, released 2026-05-20

| Bucket | Controls | Meaning |
|---|---|---|
| Evaluated | **144** | assessed from collected facts |
| Requires attestation | 6 | verified to have no app-only read path |
| Unresolved | 10 | collectability unestablished; parked pending a live-tenant probe |
| Not implemented | 0 | automatable, the collector does not make the call yet |
| **Total** | **160** | the whole benchmark |

**Coverage: 144 of 160 (90%)** — the ceiling
`docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md` §8 states for this tenant
model. Everything still unevaluated is either verified uncollectable or
parked pending a live tenant; nothing remains that we know how to collect
and simply have not built.

The four buckets must sum to 160 — every recommendation is claimed by
exactly one. `scripts/check_cis_coverage.py` fails CI otherwise, and
`compliance_report.coverage_accounting` publishes the sum so a reader can
check it without running anything.

What that guard does **not** establish: the evaluated bucket is read from
the section modules' own `controls` arrays, so it proves the declared ids
partition the benchmark, not that each id has a violation rule behind it.
An id added to a `controls` array with no logic would still be counted.
`check_cis_ids.py` catches the common case — a control with a real
violation message has its id and wording checked against the benchmark —
but an id present only in a `controls` array and a lookup table passes
both guards. Treat the count as "declared and cross-checked", not
"proven executable".

> **Corrected 2026-08-25.** Through v2.1 this file read
> "138 evaluated + 6 attestation + 10 unresolved" — which is 154, not 160.
> Six controls (`1.2.2`, `1.3.3`, `2.4.1`, `5.1.6.1`, `5.3.4`, `5.3.5`)
> were in no bucket: not evaluated, not attested, not flagged, and so
> absent from the assessment entirely. Two of them were described in a
> module comment as already reported here; they were not. An omitted
> control is indistinguishable from a passing one, which is the same
> defect class this rewrite exists to correct — so the partition is now
> machine-checked rather than restated.

This file exists because a partial assessment that does not say it is
partial reads as a clean bill of health. Everything below is measured, not
estimated: the control count comes from the benchmark's own enumeration
(`data/cis_m365_v7_index.json`), and the evaluated ids come from the
modules themselves.

## Per-section coverage

| § | Section | Controls | Evaluated | Module |
|---|---|---|---|---|
| 1 | Microsoft 365 admin center | 15 | **13** | `admin_center_validation.rego` |
| 2 | Microsoft Defender | 21 | **18** | `defender_validation.rego` |
| 3 | Microsoft Purview | 5 | **5** | `purview_validation.rego` |
| 4 | Microsoft Intune admin center | 2 | 2 | `intune_validation.rego` |
| 5 | Microsoft Entra admin center | 63 | **53** | `entra_validation.rego` |
| 6 | Exchange admin center | 13 | **13** | `exchange_validation.rego` |
| 7 | SharePoint admin center | 12 | **12** | `sharepoint_validation.rego` |
| 8 | Microsoft Teams admin center | 17 | **16** | `teams_validation.rego` |
| 9 | Microsoft Fabric | 12 | **12** | `fabric_validation.rego` |
| | **Total** | **160** | **144** | |

The authoritative list of evaluated ids is the report itself — this file
does not restate it, because a hand-maintained copy drifts:

```bash
opa eval -d benchmarks/cis/saas/m365_v7 -I <<<'{}' \
  'data.cis_m365_v7.main.compliance_report.evaluated_control_ids' --format raw
```

## Why coverage is 90%, not 100%

Coverage is bounded by **fact collection**, not by policy. The `aac.m365`
collection currently issues ten Microsoft Graph calls. Four of its seven
modules return only **Microsoft Secure Score**, which is Microsoft's own
scoring model with its own control set — it is not the CIS benchmark, and
a Secure Score `implementationStatus` does not establish a CIS
recommendation. Those were not carried into v7.

| Section | Blocker |
|---|---|
| 4 — Intune | **Now collected.** Requires the `DeviceManagementConfiguration.Read.All` application permission — without it both controls report unavailable, never pass. |
| 8 — Teams | Collector returns a Teams app count and Secure Score. Real coverage needs Teams PowerShell or Graph beta. |
| 9 — Fabric | Collector returns Secure Score. Fabric tenant settings are only exposed by the Fabric Admin REST API, not Graph. |
| 2 — Defender (18 of 21) | Collected via Exchange Online PowerShell, plus Security & Compliance PowerShell for `2.4.1`'s alert policies. Only 2.2.1, 2.4.3 and 2.4.5 outstanding — all Manual in CIS with no PowerShell audit procedure. |
| 5 — Entra (53 of 63) | The 10 outstanding are 6 attestation-only and 4 unresolved — no section 5 control is now blocked purely on a call we have not written. `graph.py` takes `beta=True` per call, so `/beta` endpoints are reachable where a control needs one. |
| 6 — Exchange | **Complete.** All 13 controls via Exchange Online PowerShell in `aac-m365-ee`. |

## Evidence-strength caveats

**`6.1.1` is now measured directly.** It was previously a Graph-sourced
proxy; `Get-OrganizationConfig` reads the tenant `AuditDisabled` flag,
which is what the benchmark's own audit procedure does.

Two caveats remain, both surfaced at runtime under `evidence_strength`:

- **`6.1.2` is sampled.** Mailbox audit actions are checked across a
  bounded sample, not every mailbox. The sample size and limit appear in
  the report so a reader can judge the result's strength.
- **All of §7 uses `Get-PnPTenant`, not the `Get-SPOTenant` CIS documents.**
  `Microsoft.Online.SharePoint.PowerShell` is Windows-only and cannot be
  installed in a Linux execution environment — verified absent from
  `aac-m365-ee`. The same CSOM tenant properties are read, but the tool is
  not the benchmark's, and that is permanent rather than a gap to close.
- **`5.1.2.1` uses `/beta`.** Microsoft documents `/beta` as subject to
  change and unsupported for production, and CIS marks the control Manual
  with no automated procedure — so this reaches past the benchmark's own
  audit steps.

## What is deliberately absent

- **No tenant-wide `compliant` boolean.** The orchestrator exposes
  `assessed_controls_compliant`, which is scoped to `evaluated_control_ids`
  only. A partial assessment has no business emitting a benchmark verdict,
  and 144 of 160 is still partial.
- **Fail-closed everywhere.** Missing facts produce a violation stating the
  control could not be evaluated. Absent facts never read as a pass.

## Controls dropped from the pre-v7 library

`Security Defaults` has **no counterpart in v7.0.0**. The nearest control,
`5.1.2.1` (*Per-user MFA*), is a different requirement and is not
established by the facts collected. The check was **removed rather than
renumbered** — inventing a plausible id is the exact defect this rewrite
exists to correct.

## Relationship to `benchmarks/cis/saas/m365/`

The older directory targets v3.1.0 and its control numbering does not
correspond to any CIS benchmark: of 46 citations, 20 name ids that do not
exist and 22 name real ids whose requirement is unrelated to the message.
It is retained per repo convention (a new benchmark version is a new
directory, never a mutation) but **must not be used for new assessments**.
`scripts/check_cis_ids.py` fails against it by design.


## Controls with no collector path

Handled by `attestation_validation.rego`, which reports them as violations
until an operator attests with dated, attributed evidence. An omitted
control is indistinguishable from a passing one, so they are never simply
dropped.

Three categories, deliberately not merged — the distinction between "the
platform will not tell us", "we have not checked" and "we have not built
it" is the whole value of the ledger:

- **Requires attestation (6)** — verified to have no app-only read path.
  The five SSPR controls (`5.2.4.1`–`5.2.4.5`) have no API at all; `5.1.2.4`
  has one (`/beta/admin/entra/uxSetting`) but it is **delegated-only**, so
  it cannot run unattended.
- **Unresolved (10)** — not yet checked against a live tenant. These are
  **not** claimed as limits; several may prove collectable. Parked pending a
  POC probe with app-only credentials.
- **Not implemented (0)** — automatable, and our own analysis names the
  audit path, but the collector does not make the call. **Empty as of
  2026-08-25.** The bucket is retained because the category is real and
  will recur: the next control we know how to collect but have not built
  belongs here, not in *unresolved*, which would understate what we know.

  The six that were here — `1.2.2`, `1.3.3`, `2.4.1`, `5.1.6.1`, `5.3.4`,
  `5.3.5` — were built and moved into their section modules, taking
  coverage from 138 to 144. Each query was written from the benchmark's
  own Audit procedure rather than inferred from the control title:

  | Control | Audit path now implemented |
  |---|---|
  | `1.2.2` | `Get-EXOMailbox -RecipientTypeDetails SharedMailbox` joined to Graph `accountEnabled` on the directory object id — the key CIS itself joins on |
  | `1.3.3` | `Get-SharingPolicy`; every policy is checked, not only the default one the benchmark names |
  | `2.4.1` | `Get-EmailTenantSettings` for the tenant toggle **and** `Get-ProtectionAlert` (Security & Compliance PowerShell) for the phishing and malware alert policies |
  | `5.1.6.1` | `/beta/legacy/policies` → `B2BManagementPolicy`, whose `definition` is a JSON string |
  | `5.3.4` / `5.3.5` | `roleManagementPolicyAssignments` → `policyId` → `.../rules/Approval_EndUser_Assignment` |

  **These are measurable, not yet measured.** Whether each endpoint
  returns data under *app-only* credentials is established only against a
  live tenant — the same gate that keeps the 10 unresolved controls
  parked. Until that probe runs, every one of the six fails closed with
  "could not be evaluated" rather than passing.

An attestation missing `attested_by`, `attested_on` or `evidence_ref` is
rejected as inadmissible rather than accepted. The report marks
`evidence_source: "attested"` so a measured result and a human assertion
are never conflated.

Full derivation, including how each limit was established, is in
`docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md` in the compliance repo.
