# CIS Debian Linux 12 Benchmark v2.0.1

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_debian_12.py` from the CIS workbook

All 331 recommendations: 316 Automated, decided from collected facts, and the 15 that CIS marks Manual,
reported as requiring operator attestation (`input.attest.<name>`). Ids, Automated/Manual status and profiles
are the workbook's; the wording is ours. Automated checks fail closed: a fact that was not collected yields
`<id>: evidence missing — <field> not collected`, never a pass.

Query: `POST /v1/data/cis_debian_12/main/compliance_report`

This is a new module. `benchmarks/cis/debian_11/` (a derived copy of another benchmark) is unchanged.

## Sections

| Section | Package | Recommendations |
|---|---|---|
| 1.1 Filesystem | `cis_debian_12.filesystem` | 37 (1 Manual) |
| 1.2 Package management (apt) | `cis_debian_12.package_management` | 10 (2 Manual) |
| 1.3 AppArmor | `cis_debian_12.apparmor` | 3 |
| 1.4 Bootloader | `cis_debian_12.bootloader` | 2 |
| 1.5 Process hardening | `cis_debian_12.process_hardening` | 11 |
| 1.6 Warning banners | `cis_debian_12.banners` | 10 |
| 1.7 GNOME Display Manager | `cis_debian_12.gdm` | 7 |
| 2.1-2.2 Server and client services | `cis_debian_12.services` | 29 (1 Manual) |
| 2.3 Time synchronization | `cis_debian_12.time_sync` | 6 |
| 2.4 Job schedulers | `cis_debian_12.job_schedulers` | 10 |
| 3 Network | `cis_debian_12.network` | 35 (1 Manual) |
| 4 Host firewall (ufw) | `cis_debian_12.firewall` | 5 |
| 5.1 SSH server | `cis_debian_12.ssh` | 24 |
| 5.2 Privilege escalation | `cis_debian_12.sudo` | 7 |
| 5.3 PAM | `cis_debian_12.pam` | 26 (1 Manual) |
| 5.4 User accounts and environment | `cis_debian_12.accounts` | 17 (1 Manual) |
| 6.1 Logging | `cis_debian_12.logging` | 18 (6 Manual) |
| 6.2 auditd | `cis_debian_12.auditd` | 48 (1 Manual) |
| 6.3 Integrity (AIDE) | `cis_debian_12.integrity` | 3 |
| 7.1 System files | `cis_debian_12.file_permissions` | 13 (1 Manual) |
| 7.2 Local users and groups | `cis_debian_12.user_group` | 10 |

`cis_debian_12` is the roll-up (controls table, profile selector, section coverage); `cis_debian_12.main`
is the bridge with the report.

## Profile

`input.profile` selects `level1_server` (default), `level2_server`, `level1_workstation` or
`level2_workstation`; a Level 2 profile includes the Level 1 recommendations of its platform. Levels differ by
platform, so each control carries its own server and workstation level. Eight recommendations have no
Workstation profile (1.2.1.3-1.2.1.5, 1.2.1.7-1.2.1.9, 2.1.23, 3.1.2).

| Profile | total_controls |
|---|---|
| level1_server | 257 |
| level2_server | 331 |
| level1_workstation | 246 |
| level2_workstation | 323 |

On empty input the report is `compliant: false` with `failed_controls == total_controls`.

## Input facts

The fact contract is the `ubuntu_26_04` module's, so one collector feeds both. Debian 12 reads five more facts:

| Path | Used by | Meaning |
|---|---|---|
| `initial_setup.motd_extra_files` | 1.6.1 | `[{path, content}]` for /run/motd, /usr/lib/motd, /etc/motd.d/\*, /run/motd.d/\*, /usr/lib/motd.d/\*, /etc/update-motd.d/\* (empty list when none) |
| `packages.sudo-ldap` | 5.2.1 | dpkg installed boolean |
| `sudo.default_timestamp_timeout` | 5.2.6 | compiled default in minutes from `sudo -V`, read only when sudoers sets no `timestamp_timeout` |
| `ssh.openssh_version` | 5.1.23 | OpenSSH server version, `9.2` or `OpenSSH_9.2p1` |
| `auditd.netplan_dir_exists` | 6.2.3.9 | whether /etc/netplan exists (absent directory passes) |

Where the Debian 12 audit differs from Ubuntu 26.04, the check follows Debian 12: syscall audit rules are
required for both `arch=b32` and `arch=b64`; the chcon, setfacl, chacl, usermod and kmod rules must be
`-a always,exit` rules carrying the `auid` filters; 4.1.5 accepts `disabled (routed)`; 1.3.1.2 reads only the
grub `linux` lines; 1.3.1.3 requires every loaded profile in enforce mode; 5.1.24 requires every effective
`ListenAddress` to be a private (RFC 1918, IPv6 ULA) or loopback address; 6.2.4.8-6.2.4.10 and 6.3.3 include
`autrace`, so `auditd.tools` must list all six tools (auditctl, aureport, ausearch, autrace, auditd, augenrules)
or the evidence is missing.

## Regenerate

```bash
/usr/bin/python3 tools/cis_generators/gen_debian_12.py <CIS_Debian_Linux_12_Benchmark_v2.0.1.xlsx> [fields.json]
```

The workbook is CIS-licensed and is not committed. The generator runs `opa fmt -w` on the files it writes.

Authored with Claude (Anthropic).
