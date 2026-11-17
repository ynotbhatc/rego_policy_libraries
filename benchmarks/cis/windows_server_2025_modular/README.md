# CIS Microsoft Windows Server 2025 Benchmark v2.1.1

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_windows_server_2025.py` from the CIS workbook

All 428 recommendations: 426 evaluated from facts, and the 2 that CIS marks Manual (1.2.3, 2.3.11.5) reported
as requiring operator attestation. `data/cis_windows_server_2025_v2_1_index.json` enumerates the benchmark (ids, Automated or
Manual, profiles and a keyword digest of each title; no CIS prose), which `scripts/check_cis_ids.py` and
`scripts/check_cis_coverage.py` check the module against.

Query: `POST /v1/data/cis_windows_server_2025/main/compliance_report`
(`/v1/data/cis_windows_server_2025/compliance_assessment` gives the same figures in the summary shape the Windows
Server 2019 module exposes).

## Sections

| Section | Module | Recommendations |
|---|---|---|
| 1 Account Policies | `account_policies_validation.rego` | 11 (1 Manual) |
| 2 Local Policies | `local_policies_validation.rego` | 118 (1 Manual) |
| 5 System Services | `system_services_validation.rego` | 2 |
| 9 Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security) | `firewall_validation.rego` | 23 |
| 17 Advanced Audit Policy Configuration | `advanced_audit_validation.rego` | 34 |
| 18 Administrative Templates (Computer) | `admin_templates_computer_validation.rego` | 229 |
| 19 Administrative Templates (User) | `admin_templates_user_validation.rego` | 11 |

Each section module is a `controls` table, one row per recommendation; `lib.rego` evaluates every row by its
`kind`. The section names come from the workbook.

## Profile

`input.cis_profile` selects the recommendations in scope:

| Field | Values | When absent |
|---|---|---|
| `role` | `member_server`, `domain_controller` | Recommendations for one role only are **not assessed** and counted as failed; those for both roles are evaluated |
| `level` | `1`, `2` (Level 2 includes Level 1) | `2`, the stricter selection; the report says `level_defaulted: true` |
| `next_generation` | `true` to add the Next Generation Windows Security profile (8 recommendations: 18.9.5.1, 18.9.5.2, 18.9.5.3, 18.9.5.4, 18.9.5.5, 18.9.5.6, 18.9.5.7, 18.9.27.2) | off: CIS publishes it as a separate profile |

`total_controls` is the number in scope, out of `benchmark_total_controls` 428:

| Role | Level 1 | Level 2 | Level 2 + Next Generation |
|---|---|---|---|
| Member server | 312 | 390 | 397 |
| Domain controller | 310 | 385 | 392 |

With no role supplied (and on empty input) every Level 1 and Level 2 recommendation of either role is in scope:
420, all counted as failed.

## Facts

The input contract of the Windows Server 2016, 2019 and 2022 modules, unchanged, so one collector feeds all four.
`data/collector_manifest.json` lists every value this module reads.

| Input | Shape | Source |
|---|---|---|
| `registry` | `{"HKLM\\<path>": {"<value>": <int, string or list>}}`, paths exactly as listed in the manifest | registry |
| `registry_users` | `{"<user SID>": {"<path below HKU\\<SID>>": {"<value>": ...}}}`, every loaded user hive | section 19 |
| `audit_policy` | `{"<subcategory GUID, lower case, braces>": <0 none, 1 success, 2 failure, 3 both>}` | `auditpol /backup` |
| `secedit` | `{"system_access": {<key>: <value>}, "privilege_rights": {<constant>: [<SID>]}}` | `secedit /export` |
| `attestations` | `[{control_id, attested_by, attested_on, evidence_ref}]`, each a non-empty string | operator, for the 2 Manual recommendations |

A recommendation whose input was not collected is **not assessed** and counted as failed, with an
"evidence missing" finding that names the input. A value missing from a collected key fails the same way: the
benchmark's state is a configured value, not the operating system default.

## How each recommendation is decided

- **Registry** (307 single values, 9 several-value, 4 must-not-exist, 11 per-user): the value the audit
  procedure states; the operator comes from the title ("or more", "or fewer", "but not 0", "between"), and
  where the procedure lists several accepted values any of them passes. Numbers held as `REG_SZ` compare
  numerically. Per-user values must hold in every loaded user hive. A row that states a location for the
  native and the 32-bit registry view (18.4.4, `Wow6432Node`) requires both.
- **Account policy and secedit-backed security options** (13): the `[System Access]` key named in `SECEDIT`
  in the generator.
- **User rights** (48): Microsoft's privilege constants and well-known SIDs. "Is set to" lists the only
  principals allowed to hold the right (fewer passes, anyone else fails); "to include" needs every named
  principal; "No One" needs an empty assignment.
- **Audit policy** (34): the subcategory GUID from the audit procedure; the setting is a minimum.

Specific to this release:

- 18.9.41.1 (domain controller) and 18.9.41.2 (member server) read the same SAM change-password RPC value with
  different required settings, as do 18.9.5.6 (domain controller) and 18.9.5.5 (member server) for Credential
  Guard. Each is evaluated for its own role only.
- 18.5.11 (security log warning threshold) and 18.9.26.6 (LAPS password age) are upper bounds that 0 does not
  satisfy: 0 turns the warning off, and is not a valid password age.
- 2.2.26 states the member-server deny-RDP right as an exact list; it is evaluated as "to include" (both
  principals must be denied, denying more is allowed), because a shorter deny list is the weaker state.
- 2.3.10.7 passes only when no named pipe is listed; the legacy Computer Browser exception is not modelled.

## Regenerating

```
python3 tools/cis_generators/gen_windows_server_2025.py CIS_Microsoft_Windows_Server_2025_Benchmark_v2.1.1.xlsx
python3 scripts/coverage_stamp.py
```

The generator runs `opa fmt -w` on the directory when `opa` is on the path.

The workbook is CIS-licensed and is not committed. The generator aborts if the recommendation count changes, if
a recommendation has no logic, if hand-written logic names an id the workbook does not contain or whose title
no longer carries its keyword, if the Manual set changes, if a check names a registry value its audit procedure
does not, or if the compliant test fixtures would need two values for one fact. It removes and rewrites only
files that carry its own header.

## Tests

`tests/` (generated): per role, a compliant host on which every in-scope recommendation passes and the report
counts exactly the workbook's profile; per recommendation, a pass on that host, a fail with its facts broken and
a not-assessed result with its input removed; empty input fails closed; role, level, Next Generation, missing
input and attestation behaviour; the per-role pairs and both registry views of 18.4.4. `tests/test_lib.rego`
pins the evaluator's comparisons.

Co-authored with Claude (Anthropic).
