# CIS Rocky Linux 9 Benchmark v3.0.0

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_rocky_linux_9.py` from the CIS workbook

All 352 recommendations: the 329 that CIS marks Automated are decided from collected facts, and the 23 it
marks Manual are operator attestations (`input.attest.<name>`). Ids, Automated/Manual status and profiles are
the workbook's; the wording of every message is ours.

This module replaces the earlier contents of this directory, which were a copy of the Rocky Linux 8 controls
and did not implement this benchmark. The `derived` flags that copy reported are gone with it.

Query: `POST /v1/data/cis_rocky_linux_9/main/compliance_report`

## Relation to the RHEL 9 module

CIS Rocky Linux 9 v3.0.0 and CIS Red Hat Enterprise Linux 9 v3.0.0 are sibling benchmarks. The generator
does not take that on trust: it reads the Rocky workbook and aborts unless every id, status and title
keyword matches the logic table, and unless the audit procedures are the ones that logic was written from
(a digest; see the generator's docstring). Layout and input contract are those of `benchmarks/cis/rhel_9/`,
so one collector feeds both modules. The STIG / NIST extended-hardening modules that sit beside the RHEL 9
controls are not CIS recommendations and are not part of this module.

## Sections

| Benchmark sections | Package `cis_rocky_linux_9.` | File | Recommendations |
|---|---|---|---|
| 1.1 Filesystem | `filesystem` | `filesystem_validation.rego` | 37 (1 Manual) |
| 1.2, 1.6-1.8 Packages, crypto policy, banners, GDM | `initial_setup` | `initial_setup_validation.rego` | 26 (5 Manual) |
| 1.3 SELinux | `selinux` | `selinux_validation.rego` | 8 (1 Manual) |
| 1.4, 1.5, 6.3 Bootloader, process hardening, AIDE | `boot_security` | `boot_security_validation.rego` | 19 |
| 2.1-2.3 Services, clients, time synchronization | `services` | `service_validation.rego` | 30 (1 Manual) |
| 2.4 Job schedulers | `cron` | `cron_validation.rego` | 10 |
| 3, 4 Network, firewalld | `network` | `network_validation.rego` | 48 (5 Manual) |
| 5.1 SSH server | `ssh` | `ssh_validation.rego` | 23 |
| 5.2 Privilege escalation | `sudo` | `sudo_validation.rego` | 12 |
| 5.3, 5.4 PAM, user accounts and environment | `pam` | `pam_validation.rego` | 43 (2 Manual) |
| 6.1 Logging (journald, rsyslog) | `logging` | `logging_validation.rego` | 20 (7 Manual) |
| 6.2 auditd | `auditd` | `auditd_validation.rego` | 54 |
| 7.1 System file permissions | `file_permissions` | `file_permissions_validation.rego` | 13 (1 Manual) |
| 7.2 Local users and groups | `user_group` | `user_group_validation.rego` | 9 |

`cis_rocky_linux_9_complete.rego` (package `cis_rocky_linux_9`) is the roll-up: the `controls` table, profile
scoping, section results. `cis_rocky_linux_9_main.rego` is the entrypoint. `l2_validation.rego`
(`cis_rocky_linux_9.l2`) is a view of the Level 2 - Server recommendations.

## Profile

`input.profile` selects the recommendations in scope; a Level 2 profile includes Level 1 of the same platform.

| `input.profile` | `total_controls` |
|---|---|
| `level1_server` (default; `level1` is accepted) | 263 |
| `level2_server` (`level2` is accepted) | 352 |
| `level1_workstation` | 252 |
| `level2_workstation` | 341 |

`standard_total` is always 352.

## Fail closed

Every Automated recommendation has two rules: `e_<id>` (its facts were collected) and `p_<id>` (the
requirement is met). Facts not collected give `<id>: evidence missing — <input path> not collected`, never a
pass. A Manual recommendation fails until its attestation is `true`. With no input at all the report is
`compliant: false`, `failed_controls == total_controls`, and carries a FAIL-CLOSED notice. A section that
received none of its input keys is listed in `sections_not_assessed`.

## Facts

The shared Linux input contract of the RHEL 9 module; no fact path is specific to Rocky. Top-level keys:
`ansible_facts`, `packages`, `services`, `mount_options`, `disabled_filesystem_modules`,
`disabled_network_modules`, `usb_storage`, `sticky_bit`, `initial_setup`, `crypto_policy`, `selinux`,
`boot_security`, `bootloader`, `chronyd`, `client_packages`, `autofs`, `mta`, `gui`, `x11`, `webserver`,
`cron`, `sysctl_parameters`, `ipv6`, `wireless_interfaces`, `firewall`, `ssh`, `sudo`, `pam`, `user_group`,
`rsyslog`, `journald`, `log_file_permissions`, `auditd`, `critical_files`, `world_writable`, `unowned_files`,
`ungrouped_files`, and `attest` for the Manual recommendations. The optional second argument of the generator
writes the input paths each recommendation reads, and a passing input per section.

## Regenerating

```
python3 tools/cis_generators/gen_rocky_linux_9.py CIS_Rocky_Linux_9_Benchmark_v3.0.0.xlsx
opa fmt -w benchmarks/cis/rocky_linux_9
python3 scripts/coverage_stamp.py
```

Needs openpyxl. The workbook is CIS-licensed and is not committed.

## Tests

`tests/` (generated): per recommendation a pass and a fail case, an evidence-missing case for every Automated
one, and a hollow-evidence case where blank strings or empty lists must not pass; per section, all
recommendations satisfied at once; profile counts against the workbook; empty input fails closed.

Co-authored with Claude (Anthropic).
