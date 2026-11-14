# CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.1

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_ubuntu_24_04.py` from the CIS workbook

All 332 recommendations: the 317 that CIS marks Automated are decided from collected facts, and the 15 it
marks Manual are attestation booleans (`input.attest.<name>`), failed until attested. Ids, Automated/Manual
status and profiles come from the workbook; the wording of every message is ours.

This replaces the earlier contents of this directory, which were a copy of the Ubuntu 22.04 module and not
the 24.04 benchmark.

Query: `POST /v1/data/cis_ubuntu_2404/main/compliance_report` (framework key, `cis_ubuntu_2404_key_main.rego`)
or `POST /v1/data/cis_ubuntu_24_04/main/compliance_report`.

## Sections

| Section | Module | Recommendations |
|---|---|---|
| 1.1 Filesystem | `filesystem.rego` | 37 (1 Manual) |
| 1.2 Package Management (apt) | `package_management.rego` | 10 (2 Manual) |
| 1.3 Mandatory Access Control (AppArmor) | `apparmor.rego` | 4 |
| 1.4 Bootloader | `bootloader.rego` | 2 |
| 1.5 Additional Process Hardening | `process_hardening.rego` | 11 |
| 1.6 Command Line Warning Banners | `banners.rego` | 10 |
| 1.7 GNOME Display Manager | `gdm.rego` | 7 |
| 2.1-2.2 Server and Client Services | `services.rego` | 29 (1 Manual) |
| 2.3 Time Synchronization | `time_sync.rego` | 6 |
| 2.4 Job Schedulers | `job_schedulers.rego` | 10 |
| 3 Network | `network.rego` | 35 (1 Manual) |
| 4 Host Based Firewall (ufw) | `firewall.rego` | 5 |
| 5.1 SSH Server | `ssh.rego` | 24 |
| 5.2 Privilege Escalation | `sudo.rego` | 7 |
| 5.3 Pluggable Authentication Modules | `pam.rego` | 26 (1 Manual) |
| 5.4 User Accounts and Environment | `accounts.rego` | 17 (1 Manual) |
| 6.1 System Logging | `logging.rego` | 18 (6 Manual) |
| 6.2 System Auditing (auditd) | `auditd.rego` | 48 (1 Manual) |
| 6.3 Integrity Checking (AIDE) | `integrity.rego` | 3 |
| 7.1 System File and Directory Access | `file_permissions.rego` | 13 (1 Manual) |
| 7.2 Local User and Group Settings | `user_group.rego` | 10 |

Each section is its own package (`cis_ubuntu_24_04.<section>`); `cis_ubuntu_24_04.rego` rolls them up and
`cis_ubuntu_24_04_main.rego` is the report. Every recommendation has an evidence rule `e_<id>` and a pass rule
`p_<id>`: facts not collected give `<id>: evidence missing — <input path> not collected`, never a pass.

## Profile

`input.profile` selects `level1_server` (default), `level2_server`, `level1_workstation` or
`level2_workstation`; Level 2 includes Level 1 of the same platform.

| Profile | `total_controls` |
|---|---|
| `level1_server` | 258 |
| `level2_server` | 332 |
| `level1_workstation` | 247 |
| `level2_workstation` | 324 |

Levels are read per platform from the workbook's four profile sheets. Eight recommendations are on no
Workstation sheet (1.2.1.3, 1.2.1.4, 1.2.1.5, 1.2.1.7, 1.2.1.8, 1.2.1.9, 2.1.23, 3.1.2) and are out of
scope for the workstation profiles.

## Facts

The input contract is the Ubuntu 26.04 module's (`benchmarks/cis/ubuntu_26_04/`), so one collector feeds
both. Five paths are read here that 26.04 does not read:

| Input | Shape | Read by |
|---|---|---|
| `initial_setup.motd_extra_files` | `[{path, content}]` for `/run/motd`, `/usr/lib/motd`, `/etc/motd.d/*`, `/run/motd.d/*`, `/usr/lib/motd.d/*`, `/etc/update-motd.d/*`; `[]` when none exist | 1.6.1 |
| `ssh.openssh_version` | version string of `sshd -V`, such as `"9.6p1"` | 5.1.23 |
| `packages.sudo-ldap` | boolean | 5.2.1 |
| `sudo.default_timestamp_timeout` | number of minutes reported by `sudo -V` | 5.2.6 |
| `netplan.dir_exists` | boolean, whether `/etc/netplan` exists | 6.2.3.9 |

Two lists carry one more entry than on 26.04: `aide.audit_tool_options` and `auditd.tools` must include
`autrace`. 6.2.4.8 to 6.2.4.10 require an `auditd.tools` entry for each of the six tools (matched on the file
name), so a list without one is missing evidence, not a pass.
`ssh.sshd_config_raw` must be the output of `sshd -T` for 5.1.24, which reads every `listenaddress` line.

## Where 24.04 differs from 26.04

- 1.3.1.3 reads the counters the 24.04 audit names: profiles loaded, in enforce mode and in complain mode,
  and unconfined processes.
- Audit syscall rules (6.2.3.2, .4, .5, .17, .18, .19, .22, .28) are required for `arch=b64` and `arch=b32`.
- Command-use rules (6.2.3.24 to 6.2.3.27 and the `kmod` rule of 6.2.3.28) need `perm=x` with the
  `auid>=1000` and `auid!=unset` filters.
- 5.1.23 (post-quantum key exchange) is Automated: `sntrup761x25519-sha512` offered, plus
  `mlkem768x25519-sha256` from OpenSSH 9.9.
- 5.1.24 passes when at least one `listenaddress` is set and every one is a private (10/8, 172.16/12,
  192.168/16, fc00::/7) or loopback address; the wildcard, a public address or a host name fails.
- 5.2.3 needs a `Defaults logfile=` entry; 5.2.6 accepts the compiled-in default when sudoers sets no
  `timestamp_timeout`; 4.1.5 accepts `deny` or `disabled` for routed traffic; 6.1.2.6 looks for TCP reception.

## Regenerate

```bash
python3 tools/cis_generators/gen_ubuntu_24_04.py CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.1.xlsx
opa fmt -w benchmarks/cis/ubuntu_24_04
```

The workbook is CIS-licensed and is not committed. The generator writes only the files it generates;
`cis_ubuntu_2404_key_main.rego` and this README are kept by hand.
