> ## ⚠️ DEPRECATED — DO NOT USE FOR NEW ASSESSMENTS
>
> **The control numbers in this directory do not correspond to any CIS
> benchmark.** Measured 2026-08-14 against the CIS Microsoft 365
> Foundations Benchmark v7.0.0: of 46 control-id citations, **20 name ids
> that do not exist** and **22 name real ids whose requirement is unrelated
> to the message**. Only 3 distinct ids of 40 are correct.
>
> The section topology assumed here (7 sections) is wrong; the benchmark
> has **9**. Entra is section 5 (not 1), Exchange 6 (not 4), SharePoint 7
> (not 6), Teams 8 (not 7), Fabric 9 (not 5). Sub-numbering is
> independently wrong even where the section number happens to match.
>
> The 36/36 passing unit tests do not contradict this — they assert
> against the same invented numbers.
>
> **Use [`../m365_v7/`](../m365_v7/) instead.** This directory is retained
> only because repo convention treats a benchmark version as immutable.
> `scripts/check_cis_ids.py` fails against this tree by design.

# CIS Microsoft 365 Foundations Benchmark — Rego Library

Policies evaluating a Microsoft 365 tenant's compliance against the
[**CIS Microsoft 365 Foundations Benchmark v3.1.0**](https://www.cisecurity.org/benchmark/microsoft_365).

## Section coverage

| Section | Area | Rego module | Package |
|---|---|---|---|
| 1 | Microsoft Entra (Identity) | [`identity_validation.rego`](identity_validation.rego) | `cis_m365.identity` |
| 2 | Microsoft Defender | [`defender_validation.rego`](defender_validation.rego) | `cis_m365.defender` |
| 3 | Microsoft Purview | [`purview_validation.rego`](purview_validation.rego) | `cis_m365.purview` |
| 4 | Microsoft Exchange | [`exchange_validation.rego`](exchange_validation.rego) | `cis_m365.exchange` |
| 5 | Microsoft Fabric | [`fabric_validation.rego`](fabric_validation.rego) | `cis_m365.fabric` |
| 6 | Microsoft SharePoint | [`sharepoint_validation.rego`](sharepoint_validation.rego) | `cis_m365.sharepoint` |
| 7 | Microsoft Teams | [`teams_validation.rego`](teams_validation.rego) | `cis_m365.teams` |

Every module exposes a `compliance_report` rule with this shape:

```
{
  "section": "<num>",
  "name": "<section name>",
  "controls_evaluated": <int>,
  "violations": [<str>, ...],
  "violation_count": <int>,
  "compliant": <bool>
}
```

OPA query path: `/v1/data/cis_m365/<section>/compliance_report`.

## Input contract

Facts arrive from the
[`aac.m365` Ansible collection](https://github.com/ynotbhatc/compliance/tree/main/collections/ansible_collections/aac/m365)
in the AAC compliance repo. Each module's expected input shape is
documented at the top of its Rego file. The fact-collection modules
pull state from Microsoft Graph; the Rego doesn't care how the
state was obtained, only that the shape matches.

## Coverage gaps

These are documented in the relevant module's `compliance_report`
or surfaced explicitly as violations so the operator knows what
ISN'T being evaluated:

- **Section 5 (Fabric)**: most tenant settings need the Fabric
  Admin REST API, not Graph. The `compliance_report` carries a
  `coverage_note`; `violation_coverage` fires if fewer than 3
  controls are evaluable from Graph alone.
- **Section 4 (Exchange)**: mailbox audit toggle isn't surfaced
  tenant-wide in Graph v1.0; the Ansible module samples per-user
  audit settings as a proxy.
- **Sections needing Exchange Online PowerShell** (transport rules,
  anti-phishing policy detail): not currently evaluated. A future
  `aac.m365` PowerShell-wrapper module would supplement.

## Running the tests

The Rego unit tests live in [`tests/`](tests/):

```bash
opa test benchmarks/cis/saas/m365/ benchmarks/cis/saas/m365/tests/ -v
```

End-to-end smoke tests (load all modules into a live OPA, POST
synthetic facts, assert report shape) live in the AAC compliance
repo at `demos/m365/tests/smoke_test.py`.

## Benchmark version

Pinned to **CIS Microsoft 365 Foundations Benchmark v3.1.0**.
Each violation message references the CIS control number it
implements so the trace is auditable.
