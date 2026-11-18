# CIS Microsoft 365 Foundations Benchmark v7.0.0 — Rego Library

**Version:** v1.3
**Benchmark:** CIS Microsoft 365 Foundations Benchmark **v7.0.0** (released 2026-05-20)
**Coverage:** 144 of 160 recommendations evaluated (90%); the remaining 16
are each claimed by a named bucket — see [COVERAGE.md](COVERAGE.md)

## Sections

The benchmark defines **nine** sections. Getting this topology right
matters: the pre-v7 library assumed seven and renumbered them, which is
why its control ids named different requirements than the checks they
labelled.

| § | Section | Package | Module |
|---|---|---|---|
| 1 | Microsoft 365 admin center | `cis_m365_v7.admin_center` | `admin_center_validation.rego` |
| 2 | Microsoft Defender | `cis_m365_v7.defender` | `defender_validation.rego` |
| 3 | Microsoft Purview | `cis_m365_v7.purview` | `purview_validation.rego` |
| 4 | Microsoft Intune admin center | — | not evaluated |
| 5 | Microsoft Entra admin center | `cis_m365_v7.entra` | `entra_validation.rego` |
| 6 | Exchange admin center | `cis_m365_v7.exchange` | `exchange_validation.rego` |
| 7 | SharePoint admin center | `cis_m365_v7.sharepoint` | `sharepoint_validation.rego` |
| 8 | Microsoft Teams admin center | — | not evaluated |
| 9 | Microsoft Fabric | — | not evaluated |

Note that **SPF, DKIM and DMARC are section 2 (Defender)** controls in
v7.0.0, not Exchange controls.

## Query paths

```
/v1/data/cis_m365_v7/main/compliance_report        # orchestrator (start here)
/v1/data/cis_m365_v7/<package>/compliance_report   # a single section
```

The orchestrator reports `assessed_controls_compliant`, **not** a bare
`compliant`. That is deliberate — see COVERAGE.md.

## The control-id guard

Unit tests cannot catch a violation message that cites the wrong CIS
control number, because the tests assert against the same wrong number.
The guard checks citations against the benchmark's own enumeration:

```bash
python3 scripts/check_cis_ids.py \
  --enumeration benchmarks/cis/saas/m365_v7/data/cis_m365_v7_index.json \
  --policy-dir  benchmarks/cis/saas/m365_v7
```

It applies two checks:

1. **Existence** — every cited id must appear in the benchmark.
2. **Coherence** — the message must share a substantive word with the
   benchmark's own title for that id. This is the check that catches
   `"CIS 1.1.1: Security Defaults..."` when `1.1.1` is actually about
   administrative accounts being cloud-only.

It runs in CI on every PR touching this tree.

### `data/cis_m365_v7_index.json`

The enumeration ships as a **keyword digest**: control ids, section names,
assessment status, profile levels, and a sorted set of substantive words
from each title. It deliberately carries **no verbatim CIS recommendation
titles** — CIS terms of use require contacting CIS Legal before
reproducing portions of a benchmark, and this repository is public and
Apache-2.0. The digest is derived data and is all the coherence check
needs.

Regenerate it from a local copy of the PDF (the PDF itself is not
redistributable and is not vendored here):

```bash
pdftotext -layout CIS_Microsoft_365_Foundations_Benchmark_v7.0.0.pdf m365_v7.txt
python3 parse_m365_v7.py m365_v7.txt
```

## Per-control results

`compliance_report.control_results` has one object per recommendation, all 160 in natural id order:
`{id, status, basis, in_scope, profile, evidence}`. `control_result_counts` counts each status, and
`control_results_profile` states the scope that was applied.

| status | meaning here |
|---|---|
| `pass` | a section evaluated it from collected facts, its gate held and no violation names it; or a ledger control that was attested (`basis: attestation`) |
| `fail` | a violation of its section names it and is not an evidence message |
| `evidence_missing` | its section's gate says a fact it reads was not collected, is not a list where a list is read, or lacks a field the control compares; an evidence message ("CIS <id>: evidence missing -- ... (this is not a pass)") always names it. Also a not-implemented ledger control (none today), because it is not evaluated at all |
| `not_attested` | one of the 16 ledger controls without an admissible attestation. That is the six that require attestation and the ten whose collectability is unresolved; CIS marks all 16 Manual. A ledger control attested with `observed: false` is `fail` |
| `not_applicable` | outside `input.cis_profile` |

Each section file declares `decidable` (the controls whose facts were all collected, with the type each
rule compares) and `CONTROL_EVIDENCE` (the input paths each control reads) beside its rules. Every control
that is not decidable is named by an evidence message: a section that was not collected or an
`unavailable` key names every control it blocks ("CIS 2.1.2/2.1.3/2.1.11: evidence missing -- ..."), and
any other gap names the control and its paths. So every control whose status is not `pass` is named by a
violation; `tests/test_control_results.rego` asserts that on empty and on mixed input.

`total_controls` (in scope for the profile) and `failed_controls` (fail + evidence_missing +
not_attested) follow the library contract; `controls_evaluated` / `evaluated_control_ids` are the
controls decided from evidence for this input (0 on empty input), `implemented_controls` /
`implemented_control_ids` the static 144.

Scope: `input.cis_profile` is `{licence: "E3" | "E5", level: 1 | 2}`. With no profile it is E5 Level 2,
which puts all 160 in scope (E3 L1 100, E3 L2 137, E5 L1 114). The profile changes only
`control_results`; `violations` and the other fields are the same with or without it.

`control_index.rego` (ids and licence/level tags) is written from `data/cis_m365_v7_index.json` by
`tools/cis_generators/gen_m365_v7_control_index.py`.

## Input contract

Facts come from the `aac.m365` Ansible collection in the AAC compliance
repo, which reads Microsoft Graph. Each module documents its expected
input shape in its header comment. The Rego does not care how the state
was obtained, only that the shape matches.

Every module is **fail-closed**: absent facts produce a violation saying
the control could not be evaluated. A missing fact never reads as a pass.

Facts read since v1.3 (the collector follows): `defender.dkim_signing_configs[]`
{Domain or Name, Enabled, Status} (2.1.9), `defender.malware_filter_policies[].FileTypes`
(2.1.11; `FileTypeFilter` only as a fallback), `defender.outbound_spam_policies[]`
`RecipientLimitInternalPerHour`, `RecipientLimitPerDay`, `ActionWhenThresholdReached`,
`NotifyOutboundSpamRecipients` (2.1.15), `defender.eop_protection_rules[]` and the new
`defender.atp_protection_rules[]` {Name or Identity, State, SentTo, SentToMemberOf,
RecipientDomainIs} (2.4.2), `admin_center.activity_based_timeout_policies[].definition` and
`.is_organization_default` (1.3.2, which also reads `entra.conditional_access_policies`),
`exchange.owa_mailbox_policies[]` `IsDefault`, `PersonalAccountsEnabled`,
`PersonalAccountCalendarsEnabled` (6.3.2). `attestations[].observed` must be a boolean.

## Tests

```bash
opa test benchmarks/cis/saas/m365_v7/ benchmarks/cis/saas/m365_v7/tests/ -v
```

Tests cover each control's violation path, its passing path, the
fail-closed path, and the orchestrator's coverage accounting.

Tests alone cannot establish coverage — they assert against the ids the
modules declare, so a control no module mentions is invisible to them.
Two CI guards check the modules against the benchmark's own enumeration:

```bash
# every cited id exists, and its message matches the control it names
python3 scripts/check_cis_ids.py \
  --enumeration benchmarks/cis/saas/m365_v7/data/cis_m365_v7_index.json \
  --policy-dir benchmarks/cis/saas/m365_v7

# all 160 recommendations are claimed by exactly one bucket
python3 scripts/check_cis_coverage.py \
  --enumeration benchmarks/cis/saas/m365_v7/data/cis_m365_v7_index.json \
  --policy-dir benchmarks/cis/saas/m365_v7
```

## Relationship to `../m365/`

`../m365/` targets v3.1.0 and its numbering does not correspond to any CIS
benchmark. It is retained because repo convention treats a new benchmark
version as a new directory, but it must not be used for new assessments.
