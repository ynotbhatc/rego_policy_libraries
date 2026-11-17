# CIS Rocky Linux 8 Benchmark v3.0.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_rocky_linux_8.py` from the CIS workbook

All 322 recommendations: the 299 that CIS marks Automated are decided from collected facts, and the 23 it
marks Manual are operator attestations (`input.attest.<name>`). Ids, Automated/Manual status and profiles are
the workbook's; the wording of every message is ours.

This module replaces the earlier hand-written contents of this directory under the same packages
(`cis_rocky_linux_8.<section>`, roll-up `cis_rocky_linux_8`, bridge `cis_rocky_linux_8.main`) and section keys,
and adds the Level 2 view `cis_rocky_linux_8.l2`. The earlier hand-written tests tested rules that no longer
exist and were removed with them.

Query: `POST /v1/data/cis_rocky_linux_8/main/compliance_report`

## Relation to the RHEL 8 module

CIS Rocky Linux 8 v3.0.0 and CIS Red Hat Enterprise Linux 8 v4.0.0 carry the same 322 ids, titles, statuses,
profiles and audit procedures (compared field by field; the Rocky workbook adds only a License sheet). The
generator does not take that on trust: it reads the Rocky workbook and aborts unless every id, status and title
keyword matches the logic table of `gen_rhel_8.py` and a digest of the audit procedures equals the one that
table was written from. Logic, layout and input contract are those of `benchmarks/cis/rhel_8/`, so one
collector feeds both modules; see that README for which checks differ from RHEL 9 and the fact paths added.

## Sections

| Benchmark sections | Package `cis_rocky_linux_8.` | File | Recommendations |
|---|---|---|---|
| 1.1 Filesystem | `filesystem` | `filesystem_validation.rego` | 37 (1 Manual) |
| 1.2, 1.6-1.8 Packages, crypto policy, banners, GDM | `initial_setup` | `initial_setup_validation.rego` | 25 (6 Manual) |
| 1.3 SELinux | `selinux` | `selinux_validation.rego` | 8 (1 Manual) |
| 1.4, 1.5, 6.1 Bootloader, process hardening, AIDE | `boot_security` | `boot_security_validation.rego` | 15 |
| 2.1-2.3 Services, clients, time synchronization | `services` | `services_validation.rego` | 32 (1 Manual) |
| 2.4 Job schedulers | `cron` | `cron_validation.rego` | 10 |
| 3, 4 Network, firewalld | `network` | `network_validation.rego` | 42 (4 Manual) |
| 5.1 SSH server | `ssh` | `ssh_validation.rego` | 24 |
| 5.2 Privilege escalation | `sudo` | `sudo_validation.rego` | 7 |
| 5.3, 5.4 PAM, user accounts and environment | `pam` | `pam_validation.rego` | 41 (2 Manual) |
| 6.2 Logging (journald, rsyslog) | `logging` | `logging_validation.rego` | 19 (6 Manual) |
| 6.3 auditd | `auditd` | `auditd_validation.rego` | 40 (1 Manual) |
| 7.1 System file permissions | `file_permissions` | `file_permissions_validation.rego` | 13 (1 Manual) |
| 7.2 Local users and groups | `user_group` | `user_group_validation.rego` | 9 |

`cis_rocky_linux_8_complete.rego` (package `cis_rocky_linux_8`) is the roll-up: the `controls` table, profile scoping, section
results. `cis_rocky_linux_8_main.rego` is the entrypoint. `l2_validation.rego` (`cis_rocky_linux_8.l2`) is a view of the
Level 2 - Server recommendations.

## Profile

`input.profile` selects the recommendations in scope; a Level 2 profile includes Level 1 of the same platform.

| `input.profile` | `total_controls` |
|---|---|
| `level1_server` (default; `level1` is accepted) | 257 |
| `level2_server` (`level2` is accepted) | 322 |
| `level1_workstation` | 252 |
| `level2_workstation` | 317 |

`standard_total` is always 322.

## Fail closed

Every Automated recommendation has two rules: `e_<id>` (its facts were collected) and `p_<id>` (the
requirement is met). Facts not collected give `<id>: evidence missing — <input path> not collected`, never a
pass. A Manual recommendation fails until its attestation is `true`. With no input at all the report is
`compliant: false`, `failed_controls == total_controls`, and carries a FAIL-CLOSED notice. A section that
received none of its input keys is listed in `sections_not_assessed`.

## Logging method

Section 6.2 covers journald or rsyslog, and only one of them is implemented. The method is decided from
collected facts: rsyslog when `rsyslog.service_active` is true, journald when rsyslog is collected inactive or
not installed. Under rsyslog, 6.2.1.1.4, 6.2.1.2.1 and 6.2.1.2.3 do not apply; under journald, 6.2.2.1-6.2.2.4
and 6.2.2.7 do not apply. Without rsyslog facts the method is undecided and each of these needs its own facts.

## Facts

The input contract of the RHEL 8 module (`benchmarks/cis/rhel_8/README.md`, "Facts"); nothing is specific to
Rocky. The optional second argument of the generator writes the input paths each recommendation reads, and a
passing input per section.

## Regenerating

```
python3 tools/cis_generators/gen_rocky_linux_8.py CIS_Rocky_Linux_8_Benchmark_v3.0.0.xlsx
opa fmt -w benchmarks/cis/rocky_linux_8
```

Needs openpyxl. The workbook is CIS-licensed and is not committed.

## Tests

`tests/` (generated): per recommendation a pass and a fail case, an evidence-missing case for every Automated
one, and a hollow-evidence case where blank strings or empty lists must not pass; per section, all
recommendations satisfied at once; regression tests for the logging method, the audit rule sources, keys and
architectures; profile counts against the workbook; empty input fails closed.

Co-authored with Claude (Anthropic).
