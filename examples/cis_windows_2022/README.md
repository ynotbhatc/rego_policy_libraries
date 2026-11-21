# A sample Windows Server 2022 member server

`facts.json` is the input for one fictional member server, `app02.example.com` (192.0.2.20), in the shape the
CIS Microsoft Windows Server 2022 Benchmark v5.1.0 module in this library reads
(`benchmarks/cis/windows_server_2022_modular/`): registry values, user hives, the advanced audit policy, the
`secedit` export and the two sign-offs for the Manual recommendations. Nothing in it comes from a real machine;
it starts from the module's compliant test fixture with five values changed.

## Run it

From the repository root:

```bash
opa eval -d benchmarks/cis/windows_server_2022_modular --ignore tests -i examples/cis_windows_2022/facts.json \
  -f pretty 'data.cis_windows_2022.main.compliance_report'
```

`bash examples/cis_windows_2022/check.sh` asserts the result below, so the sample cannot rot.

## What the output means

- `compliant` is `false`: at least one recommendation failed.
- `total_controls` is 378: the file sets `cis_profile` to a Level 2 member server with the Next Generation
  profile, so 378 of the benchmark's 408 recommendations are in scope (`benchmark_total_controls`). The 30 for
  domain controllers only are `not_applicable` in `control_result_counts`.
- `failed_controls` is 5 and `passed_controls` is 373. No control is evidence missing and
  `sections_not_assessed` is empty, because every input was collected.
- `violations` has one line per failing recommendation, starting with `CIS <id>:` and the value found.
- `control_results` lists all 378 in id order with their status, passes included.

Only the failures:

```bash
opa eval -d benchmarks/cis/windows_server_2022_modular --ignore tests -i examples/cis_windows_2022/facts.json \
  -f json 'data.cis_windows_2022.main.compliance_report' | jq -r '.result[0].expressions[0].value.violations[]'
```

## What is wrong with this server

- **1.1.4**: passwords may be as short as 8 characters
- **1.2.2**: accounts never lock out, however many wrong passwords are tried
- **9.3.1**: the Windows Firewall is off for the public network profile
- **18.10.26.2.2**: the Security event log is capped at 20 MB, so audit history rolls over quickly
- **18.10.57.3.9.1**: Remote Desktop accepts saved credentials instead of always asking for the password

Fix one and run again: set `secedit.system_access.MinimumPasswordLength` to `14` and `failed_controls` drops
to 4. Delete `audit_policy` and the 27 advanced-audit recommendations are not passes: they are reported
`evidence missing` with a `NOT ASSESSED` finding for the section, because a policy that was not collected is not
a policy that passed.

## Where facts come from

The module README lists each input and the Windows tool that produces it (registry reads, `auditpol /backup`,
`secedit /export`); `benchmarks/cis/windows_server_2022_modular/data/collector_manifest.json` lists every value
the checks read. The AAC product collectors produce this shape.
