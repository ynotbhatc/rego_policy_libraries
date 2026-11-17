# CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_ubuntu_22_04.py` from the CIS workbook

All 306 recommendations: the 290 that CIS marks Automated are decided from collected facts, and the 16 it
marks Manual are attestation booleans (`input.attest.<name>`), failed until attested. Ids, Automated/Manual
status and profiles come from the workbook; the wording of every message is ours.

This replaces the earlier hand-written contents of this directory, which followed an older release and were
not derived from the benchmark's audit procedures.

Query: `POST /v1/data/cis_ubuntu_2204/main/compliance_report` (framework key, `cis_ubuntu_2204_key_main.rego`)
or `POST /v1/data/cis_ubuntu_22_04/main/compliance_report`.

## Sections

| Section | Module | Recommendations |
|---|---|---|
| 1.1 Filesystem | `filesystem.rego` | 37 (1 Manual) |
| 1.2 Package Management (apt) | `package_management.rego` | 3 (3 Manual) |
| 1.3 Mandatory Access Control (AppArmor) | `apparmor.rego` | 4 |
| 1.4 Bootloader | `bootloader.rego` | 2 |
| 1.5 Additional Process Hardening | `process_hardening.rego` | 6 |
| 1.6 Command Line Warning Banners | `banners.rego` | 6 |
| 1.7 GNOME Display Manager | `gdm.rego` | 11 |
| 2.1-2.2 Server and Client Services | `services.rego` | 28 (1 Manual) |
| 2.3 Time Synchronization | `time_sync.rego` | 6 |
| 2.4 Job Schedulers | `job_schedulers.rego` | 10 |
| 3 Network | `network.rego` | 33 (1 Manual) |
| 4 Host Based Firewall (ufw) | `firewall.rego` | 5 |
| 5.1 SSH Server | `ssh.rego` | 22 |
| 5.2 Privilege Escalation | `sudo.rego` | 7 |
| 5.3 Pluggable Authentication Modules | `pam.rego` | 25 (1 Manual) |
| 5.4 User Accounts and Environment | `accounts.rego` | 17 (1 Manual) |
| 6.1 System Logging | `logging.rego` | 19 (6 Manual) |
| 6.2 System Auditing (auditd) | `auditd.rego` | 39 (1 Manual) |
| 6.3 Integrity Checking (AIDE) | `integrity.rego` | 3 |
| 7.1 System File and Directory Access | `file_permissions.rego` | 13 (1 Manual) |
| 7.2 Local User and Group Settings | `user_group.rego` | 10 |

Each section is its own package (`cis_ubuntu_22_04.<section>`); `cis_ubuntu_22_04.rego` rolls them up and
`cis_ubuntu_22_04_main.rego` is the report. Every recommendation has an evidence rule `e_<id>` and a pass rule
`p_<id>`: facts not collected give `<id>: evidence missing — <input path> not collected`, never a pass.

## Profile

`input.profile` selects `level1_server` (default), `level2_server`, `level1_workstation` or
`level2_workstation`; Level 2 includes Level 1 of the same platform.

| Profile | `total_controls` |
|---|---|
| `level1_server` | 246 |
| `level2_server` | 306 |
| `level1_workstation` | 240 |
| `level2_workstation` | 303 |

Three recommendations are on no Workstation sheet (1.7.1, 2.1.20, 3.1.2).

## Facts

The input contract is the Ubuntu 24.04 module's (`benchmarks/cis/ubuntu_24_04/`), so one collector feeds both.
Paths read here that 24.04 does not read:

| Input | Shape | Read by |
|---|---|---|
| `logging_method` | `"journald"` or `"rsyslog"`: the site's logging choice | 6.1.1.1.4, 6.1.1.2.1, 6.1.1.2.3, 6.1.2.1-6.1.2.4, 6.1.2.7 |
| `initial_setup.gdm_dconf_profile_exists` | boolean: a dconf profile with `user-db` and `system-db` entries exists | 1.7.2-1.7.4, 1.7.6, 1.7.8 |
| `initial_setup.gdm_lock_enabled` | boolean: `gsettings get org.gnome.desktop.screensaver lock-enabled` | 1.7.4 |
| `initial_setup.gdm_dconf_locks` | list of the active lines of `/etc/dconf/db/*/locks/*` | 1.7.5, 1.7.7, 1.7.9 |
| `packages.isc-dhcp-server` | boolean | 2.1.3 |
| `services["systemd-journal-upload.service"]`, `services["isc-dhcp-server.service"]`, `services["isc-dhcp-server6.service"]` | the usual unit entries | 6.1.1.2.3, 2.1.3 |
| `auditd.kmod_symlinks` | `{path: readlink -f path}` for `/usr/sbin/{lsmod,rmmod,insmod,modinfo,modprobe,depmod}` | 6.2.3.19 |
| `auditd.kmod_target` | `readlink -f /bin/kmod` | 6.2.3.19 |
| `aide.cron_raw` | text of `/etc/crontab`, `/etc/cron.*/*` and `/var/spool/cron/**` | 6.3.2 |
| `aide.aidecheck` | `{service_unit_file_state, timer_unit_file_state, timer_active_state}` of `aidecheck.service`/`.timer` | 6.3.2 |

Every 6.2.3 recommendation now also reads `auditd.rules` (the lines of `/etc/audit/rules.d/*.rules`) and, where
a rule filters on `auid>=`, `user_group.uid_min`.

## Where 22.04 differs from 24.04

- **Audit rules (6.2.3.1-6.2.3.19).** The 22.04 audits read the on-disk rules and the running rules and count
  only rules that carry a key, so each rule is required in `auditd.rules` and in `auditd.active_rules`, with
  `-k` or `key=`. `auid>=` must use the login.defs `UID_MIN`. Syscall rules are required for both `arch=b32`
  and `arch=b64`, except 6.2.3.19, whose expected output lists `arch=b64` only. 6.2.3.5 and 6.2.3.8 are one
  rule set each (network environment; user and group files). 6.2.3.13 has no `renameat2`. 6.2.3.19 also
  checks that the module tools are links to `kmod`.
- **Logging method.** 6.1.1.1.4 (ForwardToSyslog not `yes`) and 6.1.2.3 (ForwardToSyslog `yes`) cannot
  both hold. `logging_method` declares the site's choice, and the recommendations of the other method pass
  on that declaration (journald: 6.1.1.1.4, 6.1.1.2.1, 6.1.1.2.3; rsyslog: 6.1.2.1-6.1.2.4, 6.1.2.7).
  Without it, every one is evaluated.
- **GDM.** The settings and their locks are separate recommendations (1.7.2-1.7.9). A host without GDM
  passes them, as in 24.04. 1.7.1 requires GDM to be absent.
- **Other entries written from the 22.04 audits.** 1.3.1.3 (profiles in enforce or complain mode, no
  unconfined process); 1.6.1 (`/etc/motd` and `/etc/motd.d/*` only); 2.1.3 (`isc-dhcp-server`); 2.2.4
  (`telnet` only); 5.3.3.3.1-5.3.3.3.3 (the `pam_pwhistory` arguments only, with no `pwhistory.conf`
  alternative); 6.3.2 (an aide cron entry, or the `aidecheck` units); 7.1.8 (`/etc/gshadow-` must exist).
  1.2.1.1 and 1.2.1.2 are Manual in 22.04.

## Regenerate

```bash
python3 tools/cis_generators/gen_ubuntu_22_04.py CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.xlsx
```

The workbook is CIS-licensed and is not committed. The generator writes only the files it generates and
formats them with `opa fmt`. `cis_ubuntu_2204_key_main.rego` and this README are kept by hand.
