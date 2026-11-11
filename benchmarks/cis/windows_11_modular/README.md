# CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0

**Version:** v1.0 · generated 2026-11-10 by `tools/cis_generators/gen_windows_11.py` from the CIS workbook

All 535 recommendations: 533 evaluated from facts, and the 2 that CIS marks Manual (1.2.3, 2.3.11.5)
reported as requiring operator attestation. CI checks every cited id and its wording against the benchmark's
enumeration (`data/cis_windows_11_v5_1_index.json`, keyword digest, no CIS prose) and proves the evaluated rows and the attestation
ledger account for every recommendation exactly once.

Query: `POST /v1/data/cis_windows_11/main/compliance_report`

## Sections

| Section | Module | Recommendations |
|---|---|---|
| 1 Account Policies | `account_policies_validation.rego` | 11 (1 Manual) |
| 2 Local Policies | `local_policies_validation.rego` | 100 (1 Manual) |
| 5 System Services | `system_services_validation.rego` | 44 |
| 9 Windows Defender Firewall with Advanced Security | `firewall_validation.rego` | 23 |
| 17 Advanced Audit Policy Configuration | `advanced_audit_validation.rego` | 27 |
| 18 Administrative Templates | `admin_templates_computer_validation.rego` | 319 |
| 19 Administrative Templates | `admin_templates_user_validation.rego` | 11 |

Each section module is a `controls` table, one row per recommendation; `lib.rego` evaluates every row by its
`kind`. The section names come from the workbook.

## Profile

`input.cis_profile` selects the recommendations in scope. The workstation benchmarks have no server role.

| Field | Values | When absent |
|---|---|---|
| `level` | `1`, `2` (Level 2 includes Level 1) | `2`, the stricter selection; the report says `level_defaulted: true` |
| `bitlocker` | `true` to add the BitLocker profile (45 recommendations) | off: CIS publishes it as a separate profile |
| `next_generation` | accepted for parity with the Windows 10 module; this benchmark publishes no Next Generation profile | off |

`total_controls` is the number in scope: 373 at Level 1, 490 at Level 2, every opt-in adds its own, out of
`benchmark_total_controls` 535.

## Facts

The same shape the Windows Server modules and the Windows STIG modules read, so one collector feeds them all.
`data/collector_manifest.json` lists every value the checks read.

| Input | Shape | Source |
|---|---|---|
| `registry` | `{"HKLM\\<path>": {"<value>": <int, string or list>}}`, paths exactly as listed in the manifest | registry |
| `registry_users` | `{"<user SID>": {"<path below HKU\\<SID>>": {"<value>": ...}}}`, every loaded user hive | section 19 |
| `audit_policy` | `{"<subcategory GUID, lower case, braces>": <0 none, 1 success, 2 failure, 3 both>}` | `auditpol /backup` |
| `secedit` | `{"system_access": {<key>: <value>}, "privilege_rights": {<constant>: [<SID>]}}` | `secedit /export` |
| `attestations` | `[{control_id, attested_by, attested_on, evidence_ref}]`, each a non-empty string | operator, for the 2 Manual recommendations |

A recommendation whose input is missing or empty is **not assessed** (counted as failed, and the section is
listed in `sections_not_assessed` with the missing input). A value missing from a collected key fails: the
benchmark's state is a configured value, not the operating system default.

## How each recommendation is decided

- **Registry** (430 single values, 9 multi-value, 4 must-not-exist, 11 per-user, 1 numbered-values key). The value is the one
  the audit procedure states; the operator comes from the title: "or more" `>=`, "or fewer" `<=`, "but not 0"
  excludes 0 (and negatives), "between 5 and 14" a range, "NOT set to" a numeric must-not-equal, otherwise
  equality. Where the audit procedure lists several accepted values, any of them passes. Numbers held as `REG_SZ`
  compare numerically. "Is configured" text values pass when non-empty; the two remotely accessible registry path
  lists are compared as sets. Per-user values must hold in every loaded user hive.
- **Account policy and secedit-backed security options** (13): the `[System Access]` key named in
  `SECEDIT` in the generator. `LockoutDuration` 0 or -1 (locked until an administrator unlocks) passes the
  "15 or more minutes" recommendation. Names are compared without secedit's double quotes.
- **User rights** (38): Microsoft's privilege constants and well-known SIDs. "Is set to" lists the only principals
  allowed to hold the right (a narrower assignment passes); "to include" needs every named principal; "No One"
  needs an empty assignment.
- **Audit policy** (27): the subcategory GUID from the audit procedure. The setting is a minimum.

## Regenerating

```
python3 tools/cis_generators/gen_windows_11.py <workbook>.xlsx
python3 scripts/coverage_stamp.py
```

The workbook is CIS-licensed and is not committed. The generator aborts if the recommendation count, a Manual
status, a section or a hand-written entry's title keyword differs from the workbook, if a recommendation has no
logic, if a check names a registry value its audit procedure does not, or if the compliant fixture it
synthesises for the tests would need two values for one fact.

## Tests

`tests/` (generated): a compliant workstation with every profile opted in, on which every recommendation passes and
the report counts the whole benchmark; per recommendation, the same host with that recommendation's facts broken
(must fail) and with its input not collected (must be not assessed); profile scopes against the workbook's
counts; empty input fails closed; attestation behaviour. `tests/test_lib.rego` pins the evaluator's comparisons.

Co-authored with Claude (Anthropic).
