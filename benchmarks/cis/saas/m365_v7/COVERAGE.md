# CIS Microsoft 365 Foundations Benchmark v7.0.0 — coverage

**Version:** v1.1
**Benchmark:** CIS Microsoft 365 Foundations Benchmark **v7.0.0**, released 2026-05-20
**Evaluated:** **24 of 160** recommendations (**15%**)
**Requires attestation:** 6 (verified to have no app-only read path)
**Unresolved:** 10 (parked pending a live-tenant probe during the POC)

This file exists because a partial assessment that does not say it is
partial reads as a clean bill of health. Everything below is measured, not
estimated: the control count comes from the benchmark's own enumeration
(`data/cis_m365_v7_index.json`), and the evaluated ids come from the
modules themselves.

## Per-section coverage

| § | Section | Controls | Evaluated | Module |
|---|---|---|---|---|
| 1 | Microsoft 365 admin center | 15 | 9 | `admin_center_validation.rego` |
| 2 | Microsoft Defender | 21 | 3 | `defender_validation.rego` |
| 3 | Microsoft Purview | 5 | 1 | `purview_validation.rego` |
| 4 | Microsoft Intune admin center | 2 | 2 | `intune_validation.rego` |
| 5 | Microsoft Entra admin center | 63 | 4 | `entra_validation.rego` |
| 6 | Exchange admin center | 13 | 1 | `exchange_validation.rego` |
| 7 | SharePoint admin center | 12 | 4 | `sharepoint_validation.rego` |
| 8 | Microsoft Teams admin center | 17 | **0** | — |
| 9 | Microsoft Fabric | 12 | **0** | — |
| | **Total** | **160** | **24** | |

Evaluated ids: `1.1.1`, `1.1.3`, `1.1.4`, `1.2.1`, `1.3.1`, `1.3.2`, `1.3.4`,
`1.3.5`, `1.3.7`, `4.1`, `4.2`, `2.1.8`, `2.1.9`, `2.1.10`, `3.1.1`, `5.2.2.1`,
`5.2.2.2`, `5.2.2.3`, `5.3.1`, `6.1.1`, `7.2.1`, `7.2.6`, `7.2.7`, `7.2.11`.

## Why coverage is 9%

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
| 2 — Defender (18 of 21) | Safe Links, Safe Attachments, anti-phishing, anti-spam and connection filtering need Exchange Online PowerShell. |
| 5 — Entra (59 of 63) | Most section 5 controls need Graph endpoints the collector does not call yet; several are only on `/beta`, and `graph.py` pins `GRAPH_BASE` to `/v1.0`. |
| 6 — Exchange (12 of 13) | Transport rules and mail-flow controls need Exchange Online PowerShell. |

## Evidence-strength caveat

**`6.1.1` is a proxy, not a direct measurement.** Graph v1.0 does not
expose the tenant-wide `AuditDisabled` organization flag, so the collector
samples per-user `mailboxSettings` instead. It can demonstrate that
auditing is off for sampled mailboxes; it cannot prove the organization
flag is `False`. The benchmark's own audit procedure uses Exchange Online
PowerShell. This is surfaced at runtime in the section 6 report under
`evidence_strength` so a reader cannot miss it.

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

Two categories, deliberately not merged:

- **Requires attestation (6)** — verified to have no app-only read path.
  The five SSPR controls (`5.2.4.1`–`5.2.4.5`) have no API at all; `5.1.2.4`
  has one (`/beta/admin/entra/uxSetting`) but it is **delegated-only**, so
  it cannot run unattended.
- **Unresolved (10)** — not yet checked against a live tenant. These are
  **not** claimed as limits; several may prove collectable. Parked pending a
  POC probe with app-only credentials.

An attestation missing `attested_by`, `attested_on` or `evidence_ref` is
rejected as inadmissible rather than accepted. The report marks
`evidence_source: "attested"` so a measured result and a human assertion
are never conflated.

Full derivation, including how each limit was established, is in
`docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md` in the compliance repo.
