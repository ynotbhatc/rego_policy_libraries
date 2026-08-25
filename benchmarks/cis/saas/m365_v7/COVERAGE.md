# CIS Microsoft 365 Foundations Benchmark v7.0.0 — coverage

**Version:** v2.2
**Benchmark:** CIS Microsoft 365 Foundations Benchmark **v7.0.0**, released 2026-05-20

| Bucket | Controls | Meaning |
|---|---|---|
| Evaluated | **138** | assessed from collected facts |
| Requires attestation | 6 | verified to have no app-only read path |
| Unresolved | 10 | collectability unestablished; parked pending a live-tenant probe |
| Not implemented | 6 | automatable, the collector does not make the call yet |
| **Total** | **160** | the whole benchmark |

**Coverage: 138 of 160 (86%).** The four buckets must sum to 160 — every
recommendation is claimed by exactly one. `scripts/check_cis_coverage.py`
fails CI otherwise, and `compliance_report.coverage_accounting` publishes
the sum so a reader can check it without running anything.

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
| 1 | Microsoft 365 admin center | 15 | **11** | `admin_center_validation.rego` |
| 2 | Microsoft Defender | 21 | **17** | `defender_validation.rego` |
| 3 | Microsoft Purview | 5 | **5** | `purview_validation.rego` |
| 4 | Microsoft Intune admin center | 2 | 2 | `intune_validation.rego` |
| 5 | Microsoft Entra admin center | 63 | **50** | `entra_validation.rego` |
| 6 | Exchange admin center | 13 | **13** | `exchange_validation.rego` |
| 7 | SharePoint admin center | 12 | **12** | `sharepoint_validation.rego` |
| 8 | Microsoft Teams admin center | 17 | **16** | `teams_validation.rego` |
| 9 | Microsoft Fabric | 12 | **12** | `fabric_validation.rego` |
| | **Total** | **160** | **138** | |

Evaluated ids: `1.1.1`, `1.1.3`, `1.1.4`, `1.2.1`, `1.3.1`, `1.3.2`, `1.3.4`,
`1.3.5`, `1.3.7`, `4.1`, `4.2`, `2.1.8`, `2.1.9`, `2.1.10`, `3.1.1`, `5.2.2.1`,
`5.2.2.2`, `5.2.2.3`, `5.3.1`, `6.1.1`, `7.2.1`, `7.2.6`, `7.2.7`, `7.2.11`.

## Why coverage is 86%

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
| 2 — Defender (4 of 21) | **Now collected** via Exchange Online PowerShell. Only 2.2.1, 2.4.3 and 2.4.5 outstanding — all Manual in CIS with no PowerShell audit procedure. |
| 5 — Entra (59 of 63) | Most section 5 controls need Graph endpoints the collector does not call yet; several are only on `/beta`, and `graph.py` pins `GRAPH_BASE` to `/v1.0`. |
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
  only. A 14-of-160 assessment has no business emitting a benchmark verdict.
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
- **Not implemented (6)** — automatable, and our own analysis names the
  audit path. This is our backlog, not a platform limit, and each entry
  carries the call that would close it:

  | Control | Subject | What the collector must add |
  |---|---|---|
  | `1.2.2` | sign-in to shared mailboxes is blocked | `Get-EXOMailbox -RecipientTypeDetails SharedMailbox` joined to the Entra `accountEnabled` flag — today the mailbox query selects only audit properties and `/users` selects only `id` and `userPrincipalName` |
  | `1.3.3` | external calendar sharing is not available | `Get-SharingPolicy`, not among the nine Exchange cmdlets run |
  | `2.4.1` | priority account protection | Defender priority-account configuration |
  | `5.1.6.1` | invitations only to allowed domains | the Graph B2B management policy carrying the domain allow/block list |
  | `5.3.4` | approval required to activate Global Administrator | Graph PIM role-management policy rules |
  | `5.3.5` | approval required to activate Privileged Role Administrator | same call as `5.3.4` |

  Closing all six moves coverage to **144 of 160 (90%)**, the ceiling
  `docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md` §8 already states. The work
  is collector-side, in the `aac.m365` collection in the compliance repo —
  not in this library.

An attestation missing `attested_by`, `attested_on` or `evidence_ref` is
rejected as inadmissible rather than accepted. The report marks
`evidence_source: "attested"` so a measured result and a human assertion
are never conflated.

Full derivation, including how each limit was established, is in
`docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md` in the compliance repo.
