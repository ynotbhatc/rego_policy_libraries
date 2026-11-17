# CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_rhel_8.py` from the CIS workbook

All 322 recommendations: the 299 that CIS marks Automated are decided from collected facts, and the 23 it
marks Manual are operator attestations (`input.attest.<name>`). Ids, Automated/Manual status and profiles are
the workbook's; the wording of every message is ours.

This module replaces the earlier hand-written contents of this directory. Package names (`cis_rhel8.<section>`,
roll-up `cis_rhel8`, bridge `cis_rhel8.main`, Level 2 view `cis_rhel8.l2`) and section keys are kept, so callers
of the framework key `cis_rhel8` keep working. The earlier hand-written tests tested rules that no longer exist
and were removed with them.

Query: `POST /v1/data/cis_rhel8/main/compliance_report`

## Relation to the RHEL 9 module

The generator imports `gen_rhel_9.py`. A RHEL 9 v3.0.0 logic entry is reused only where the RHEL 8 audit
procedure checks the same thing (compared procedure by procedure). The checks written from the RHEL 8 audit
procedures because they differ are: crypto policy SHA1, MACs and CBC (1.6.2-1.6.4), Wayland disabled (1.8.7),
the GNOME environment group (2.1.21), the firewalld backend (4.1.2), sshd `CRYPTO_POLICY` and
`/etc/sysconfig/sshd` (5.1.1, 5.1.3), public host key group (5.1.5), the RHEL 8 weak-MAC list (5.1.17), PAM and
authselect versions and the profile templates (5.3.1.1, 5.3.1.2, 5.3.2.1), root and default umask (5.4.2.6,
5.4.3.3), the journald and journal-remote checks and the log-file classes (6.2), the kernel arguments of every
boot entry (6.3.1.2, 6.3.1.3), every audit rule (6.3.3.1-6.3.3.19) and the audit log group (6.3.4.4). The
generator aborts unless a digest of the workbook's ids, statuses, profiles and audit procedures equals the
one this table was written from.

## Sections

| Benchmark sections | Package `cis_rhel8.` | File | Recommendations |
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

`cis_rhel8_complete.rego` (package `cis_rhel8`) is the roll-up: the `controls` table, profile scoping, section
results. `cis_rhel8_main.rego` is the entrypoint. `l2_validation.rego` (`cis_rhel8.l2`) is a view of the
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

The shared Linux input contract of the RHEL 9 module. On RHEL 8, `ssh.sshd_config_raw` must be the output of
`sshd -T $OPTIONS $CRYPTO_POLICY` with `/etc/crypto-policies/back-ends/opensshserver.config` and
`/etc/sysconfig/sshd` sourced, the way the benchmark runs it. Audit rules are read from both
`auditd.rules` (on disk) and `auditd.active_rules` (`auditctl -l`). Fact paths this module adds:

| Path | Content | Recommendations |
|---|---|---|
| `ssh.sysconfig_sshd_raw` | text of `/etc/sysconfig/sshd`, comments included | 5.1.1 |
| `ssh.sysconfig_permissions` | `{mode, pw_name, gr_name}` of `/etc/sysconfig/sshd` | 5.1.3 |
| `pam.authselect_profile_files` | `{"system-auth": text, "password-auth": text}` of the active authselect profile | 5.3.2.1 |
| `pam.profile_d_raw` | text of `/etc/profile.d/*.sh` | 5.4.3.3 |
| `user_group.root_shell_init_raw`, `user_group.root_shell_init_exists` | text of `/root/.bash_profile` and `/root/.bashrc`; whether either exists | 5.4.2.6 |
| `journald.storage_mode`, `journald.compress_enabled` | effective `Storage=` and `Compress=` | 6.2.1.1.5, 6.2.1.1.6 |
| `log_file_permissions.analysis[].owner_has_login_shell` | whether the file owner's shell is listed in `/etc/shells` | 6.2.3.1 |

`boot_security.kernel_args` (arguments of every boot entry, from the RHEL 9 contract) is also read by 6.3.1.2
and 6.3.1.3.

The optional second argument of the generator writes the input paths each recommendation reads, and a passing
input per section.

## Regenerating

```
python3 tools/cis_generators/gen_rhel_8.py CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.xlsx
opa fmt -w benchmarks/cis/rhel_8
```

Needs openpyxl. The workbook is CIS-licensed and is not committed.

## Tests

`tests/` (generated): per recommendation a pass and a fail case, an evidence-missing case for every Automated
one, and a hollow-evidence case where blank strings or empty lists must not pass; per section, all
recommendations satisfied at once; regression tests for the logging method, the audit rule sources, keys and
architectures; profile counts against the workbook; empty input fails closed.

Co-authored with Claude (Anthropic).
