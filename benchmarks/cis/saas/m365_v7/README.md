# CIS Microsoft 365 Foundations Benchmark v7.0.0 — Rego Library

**Version:** v1.0
**Benchmark:** CIS Microsoft 365 Foundations Benchmark **v7.0.0** (released 2026-05-20)
**Coverage:** 14 of 160 recommendations — see [COVERAGE.md](COVERAGE.md)

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
   `"CIS 1.1.1: Security Defaults..."` when `1.1.1` is actually
   *"Ensure Administrative accounts are cloud-only"*.

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

## Input contract

Facts come from the `aac.m365` Ansible collection in the AAC compliance
repo, which reads Microsoft Graph. Each module documents its expected
input shape in its header comment. The Rego does not care how the state
was obtained, only that the shape matches.

Every module is **fail-closed**: absent facts produce a violation saying
the control could not be evaluated. A missing fact never reads as a pass.

## Tests

```bash
opa test benchmarks/cis/saas/m365_v7/ benchmarks/cis/saas/m365_v7/tests/ -v
```

31 tests covering each control's violation path, its passing path, the
fail-closed path, and the orchestrator's coverage accounting.

## Relationship to `../m365/`

`../m365/` targets v3.1.0 and its numbering does not correspond to any CIS
benchmark. It is retained because repo convention treats a new benchmark
version as a new directory, but it must not be used for new assessments.
