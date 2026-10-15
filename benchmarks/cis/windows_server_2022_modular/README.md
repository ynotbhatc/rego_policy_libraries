# CIS Microsoft Windows Server 2022 Benchmark v5.1.0

**Version:** v1.0 · generated 2026-10-15 by `tools/cis_generators/gen_windows_server_2022.py` from the CIS workbook

All 408 recommendations: 406 evaluated from facts, and the 2 that CIS marks Manual (1.2.3, 2.3.11.6) reported
as requiring operator attestation. CI checks every cited id and its wording against the benchmark's enumeration
(`data/cis_windows_server_2022_v5_1_index.json`, keyword digest, no CIS prose) and proves the evaluated rows and
the attestation ledger account for every recommendation exactly once.

Query: `POST /v1/data/cis_windows_server_2022/main/compliance_report`

## Sections

| Section | Module | Recommendations |
|---|---|---|
| 1 Account Policies | `account_policies_validation.rego` | 11 (1 Manual) |
| 2 Local Policies | `local_policies_validation.rego` | 118 (1 Manual) |
| 5 System Services | `system_services_validation.rego` | 2 |
| 9 Windows Defender Firewall with Advanced Security | `firewall_validation.rego` | 23 |
| 17 Advanced Audit Policy Configuration | `advanced_audit_validation.rego` | 34 |
| 18 Administrative Templates (Computer) | `admin_templates_computer_validation.rego` | 209 |
| 19 Administrative Templates (User) | `admin_templates_user_validation.rego` | 11 |

Each section module is a `controls` table, one row per recommendation; `lib.rego` evaluates every row by its
`kind`. The section names come from the workbook.

## Profile

`input.cis_profile` selects the recommendations in scope:

| Field | Values | When absent |
|---|---|---|
| `role` | `member_server`, `domain_controller` | Recommendations for one role only are **not assessed** and counted as failed; those for both roles are evaluated |
| `level` | `1`, `2` (Level 2 includes Level 1) | `2`, the stricter selection; the report says `level_defaulted: true` |
| `next_generation` | `true` to add the Next Generation Windows Security profile | off: CIS publishes it as a separate profile |

`total_controls` is the number in scope (378 for a Level 2 member server with Next Generation, 373 for a domain
controller), out of `benchmark_total_controls` 408.

## Facts

The same shape the Windows STIG modules read, so one collector feeds both. `data/collector_manifest.json` lists
every value the checks read.

| Input | Shape | Source |
|---|---|---|
| `registry` | `{"HKLM\\<path>": {"<value>": <int, string or list>}}`, paths exactly as listed in the manifest | registry |
| `registry_users` | `{"<user SID>": {"<path below HKU\\<SID>>": {"<value>": ...}}}`, every loaded user hive | section 19 |
| `audit_policy` | `{"<subcategory GUID, lower case, braces>": <0 none, 1 success, 2 failure, 3 both>}` | `auditpol /backup` (the GUID and number are locale-independent) |
| `secedit` | `{"system_access": {<key>: <value>}, "privilege_rights": {<constant>: [<SID>]}}` | `secedit /export` |
| `attestations` | `[{control_id, attested_by, attested_on, evidence_ref}]`, each a non-empty string | operator, for the 2 Manual recommendations |

Only `S-1-5-21-*` user hives count for `registry_users` (HKU's `.DEFAULT`, service-account and `_Classes`
keys carry no user policy). User rights need `secedit.privilege_rights` and account policy
`secedit.system_access`; each is judged collected on its own.

A recommendation whose input is missing or empty is **not assessed** (counted as failed, and the section is
listed in `sections_not_assessed` with the missing input). A value missing from a collected key fails: the
benchmark's state is a configured value, not the operating system default.

## How each recommendation is decided

- **Registry** (287 single values, 9 multi-value, 4 must-not-exist, 11 per-user). The value is the one the audit
  procedure states; the operator comes from the title: "or more" `>=`, "or fewer" `<=`, "but not 0" excludes 0
  (and negatives), "between 5 and 14" a range, otherwise equality. Where the audit procedure lists several
  accepted values ("`1` or `2`", 14 recommendations, mostly titles ending "or higher"), any of them passes. Numbers held as `REG_SZ` compare numerically.
  "Is configured" text values (logon banner, firewall log path) pass when non-empty. Per-user values must hold in
  every loaded user hive.
- **Account policy and secedit-backed security options** (13): the `[System Access]` key named in
  `SECEDIT` in the generator. `LockoutDuration` 0 (the workbook: locked out until an administrator unlocks)
  or -1 passes the "15 or more minutes" recommendation. Names are compared without secedit's double quotes.
- **User rights** (48): Microsoft's privilege constants and well-known SIDs. "Is set to" lists the only principals
  allowed to hold the right: a host that grants it to fewer (for example no Hyper-V group on a host without
  Hyper-V) passes, one that grants it to anyone else fails. "To include" (the deny rights) needs every named
  principal. "No One" needs an empty assignment.
- **Audit policy** (34): the subcategory GUID from the audit procedure. The setting is a minimum: "Success" passes
  on Success or Success and Failure.

## Cross-check against the Windows Server 2022 STIG

The values were compared with `benchmarks/stig/windows_server_2022/` on (registry path, value name), the one
source in the repository that is not the workbook: 87 of the 92 shared settings accept the STIG's required value.
The other five: the logon banner text and title (the STIG's are placeholders; CIS needs any text), the SAM
restriction string (identical), Credential Guard (CIS 18.9.5.6 disables it on domain controllers; the STIG item is
for member servers) and the boot-start driver policy (CIS 18.9.13.1 "Good, unknown and bad but critical", 3; the
STIG module checks 1).

## Regenerating

```
python3 tools/cis_generators/gen_windows_server_2022.py CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.xlsx
python3 scripts/coverage_stamp.py
```

The workbook is CIS-licensed and is not committed. The generator aborts if a recommendation has no logic, if
hand-written logic names an id the workbook does not contain, if a check names a registry value its audit
procedure does not, or if the compliant fixtures it synthesises for the tests would need two values for one fact.

## Tests

`tests/` (generated): per role, a compliant host on which every in-scope recommendation passes and the report
counts exactly the workbook's profile; per recommendation, the same host with that recommendation's facts broken,
on which it must fail; empty input fails closed; role, level, Next Generation, missing input and attestation
behaviour. `tests/test_lib.rego` pins the evaluator's comparisons.

Co-authored with Claude (Anthropic).
