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

The full input contract is below: every input key the module reads, the paths under it and the
recommendations that read them. `python3 tools/cis_generators/gen_ubuntu_22_04.py <workbook> fields.json`
writes the same list per recommendation. Manual recommendations read `attest.<name>` booleans only.

| Input key | Paths read under it | Recommendations |
|---|---|---|
| `aide` | `aidecheck`, `audit_tool_options`, `collected`, `cron_raw` | 6.3.2, 6.3.3 |
| `ansible_facts` | `ansible_mounts` | 26 (1.1.2.1.1 to 1.1.2.7.4) |
| `apparmor` | `processes`, `profiles` | 1.3.1.3, 1.3.1.4 |
| `apport` | `default_raw` | 1.5.6 |
| `auditd` | `active_rules`, `config`, `config_files`, `kmod_symlinks`, `kmod_target`, `log_dir_permissions.mode`, `log_files`, `privileged_commands`, `rules`, `tools` | 34 (6.2.2.1 to 6.2.4.10) |
| `boot_security` | `grub_cfg_group`, `grub_cfg_linux_lines`, `grub_cfg_mode`, `grub_cfg_owner`, `grub_password_hashed`, `grub_password_set` | 1.3.1.2, 1.4.1, 1.4.2, 6.2.1.3, 6.2.1.4 |
| `chronyd` | `collected`, `pools_configured`, `process_users`, `servers_configured` | 2.3.3.1, 2.3.3.2 |
| `critical_files` | `analysis` | 10 (7.1.1 to 7.1.10) |
| `cron` | `at_allow_exists`, `at_allow_group`, `at_allow_mode`, `at_allow_owner`, `at_deny_exists`, `at_deny_group`, `at_deny_mode`, `at_deny_owner`, `cron_allow_exists`, `cron_allow_group`, `cron_allow_mode`, `cron_allow_owner`, `cron_d_group`, `cron_d_mode`, `cron_d_owner`, `cron_daily_group`, `cron_daily_mode`, `cron_daily_owner`, `cron_deny_exists`, `cron_deny_group`, `cron_deny_mode`, `cron_deny_owner`, `cron_hourly_group`, `cron_hourly_mode`, `cron_hourly_owner`, `cron_monthly_group`, `cron_monthly_mode`, `cron_monthly_owner`, `cron_weekly_group`, `cron_weekly_mode`, `cron_weekly_owner`, `cron_yearly_exists`, `cron_yearly_group`, `cron_yearly_mode`, `cron_yearly_owner`, `crontab_group`, `crontab_mode`, `crontab_owner` | 9 (2.4.1.2 to 2.4.2.1) |
| `disabled_filesystem_modules` | `modules` | 10 (1.1.1.1 to 1.1.1.11) |
| `disabled_network_modules` | `modules` | 3.2.1, 3.2.2, 3.2.3, 3.2.4 |
| `initial_setup` | `gdm_automount_disabled`, `gdm_automount_open_disabled`, `gdm_autorun_never_enabled`, `gdm_banner_configured`, `gdm_dconf_locks`, `gdm_dconf_profile_exists`, `gdm_disable_user_list`, `gdm_idle_delay`, `gdm_installed`, `gdm_lock_delay`, `gdm_lock_enabled`, `gdm_wayland_enabled`, `gdm_xdmcp_enabled`, `issue_content`, `issue_exists`, `issue_group`, `issue_mode`, `issue_net_content`, `issue_net_exists`, `issue_net_group`, `issue_net_mode`, `issue_net_owner`, `issue_owner`, `motd_content`, `motd_exists`, `motd_extra_files`, `motd_group`, `motd_mode`, `motd_owner` | 17 (1.6.1 to 1.7.11) |
| `ipv6` | `disabled` | 8 (3.3.2.1 to 3.3.2.8) |
| `journald` | `compress_enabled`, `forward_to_syslog`, `service_active`, `storage_mode` | 6.1.1.1.1, 6.1.1.1.4, 6.1.1.1.5, 6.1.1.1.6, 6.1.2.3 |
| `limits` | `limits_raw` | 1.5.4 |
| `log_file_permissions` | `analysis` | 6.1.3.1 |
| `logging_method` | (the value itself) | 8 (6.1.1.1.4 to 6.1.2.7) |
| `mta` | `inet_interfaces`, `non_loopback_listeners` | 2.1.21 |
| `packages` | `aide`, `aide-common`, `apache2`, `apparmor`, `apparmor-utils`, `apport`, `at`, `audispd-plugins`, `auditd`, `autofs`, `avahi-daemon`, `bind9`, `bluez`, `cron`, `cups`, `dnsmasq`, `dovecot-imapd`, `dovecot-pop3d`, `ftp`, `isc-dhcp-server`, `ldap-utils`, `libpam-modules`, `libpam-pwquality`, `libpam-runtime`, `nfs-kernel-server`, `nginx`, `nis`, `prelink`, `rpcbind`, `rsh-client`, `rsync`, `samba`, `slapd`, `snmpd`, `squid`, `sudo`, `sudo-ldap`, `systemd-journal-remote`, `talk`, `telnet`, `tftpd-hpa`, `tnftp`, `ufw`, `vsftpd`, `xinetd`, `xserver-common`, `ypserv` | 49 (1.3.1.1 to 6.3.1) |
| `pam` | `collected`, `common_account`, `common_auth`, `common_password`, `common_session`, `common_session_noninteractive`, `default_umask`, `encrypt_method`, `faillock_conf_raw`, `inactive_days`, `pass_max_days`, `pass_warn_age`, `profile_d_raw`, `pwquality_conf_raw`, `su`, `tmout`, `tmout_exported`, `tmout_readonly` | 28 (5.2.7 to 5.4.3.3) |
| `pending_updates` | (the value itself) | 5.3.1.1, 5.3.1.2, 5.3.1.3 |
| `rsyslog` | `config_raw`, `file_create_mode`, `installed`, `service_active`, `service_enabled` | 6.1.2.1, 6.1.2.2, 6.1.2.3, 6.1.2.4, 6.1.2.7 |
| `services` | `<unit>`: `{state, status}` per systemd unit (e.g. `chrony.service`, `tmp.mount`) | 33 (1.1.2.1.1 to 6.2.1.2) |
| `ssh` | `config_files`, `private_key_permissions`, `public_key_permissions`, `sshd_config_raw` | 22 (5.1.1 to 5.1.22) |
| `sticky_bit` | `world_writable_without_sticky` | 7.1.11 |
| `sudo` | `default_timestamp_timeout`, `sudoers_content` | 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 6.2.3.3 |
| `sysctl` | `fs.suid_dumpable`, `kernel.randomize_va_space`, `kernel.yama.ptrace_scope`, `net.ipv4.conf.all.accept_redirects`, `net.ipv4.conf.all.accept_source_route`, `net.ipv4.conf.all.forwarding`, `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.all.rp_filter`, `net.ipv4.conf.all.secure_redirects`, `net.ipv4.conf.all.send_redirects`, `net.ipv4.conf.default.accept_redirects`, `net.ipv4.conf.default.accept_source_route`, `net.ipv4.conf.default.forwarding`, `net.ipv4.conf.default.log_martians`, `net.ipv4.conf.default.rp_filter`, `net.ipv4.conf.default.secure_redirects`, `net.ipv4.conf.default.send_redirects`, `net.ipv4.icmp_echo_ignore_broadcasts`, `net.ipv4.icmp_ignore_bogus_error_responses`, `net.ipv4.ip_forward`, `net.ipv4.tcp_syncookies`, `net.ipv6.conf.all.accept_ra`, `net.ipv6.conf.all.accept_redirects`, `net.ipv6.conf.all.accept_source_route`, `net.ipv6.conf.all.forwarding`, `net.ipv6.conf.default.accept_ra`, `net.ipv6.conf.default.accept_redirects`, `net.ipv6.conf.default.accept_source_route`, `net.ipv6.conf.default.forwarding` | 29 (1.5.1 to 3.3.2.8) |
| `sysctl_persisted` | `fs.suid_dumpable`, `kernel.randomize_va_space`, `kernel.yama.ptrace_scope`, `net.ipv4.conf.all.accept_redirects`, `net.ipv4.conf.all.accept_source_route`, `net.ipv4.conf.all.forwarding`, `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.all.rp_filter`, `net.ipv4.conf.all.secure_redirects`, `net.ipv4.conf.all.send_redirects`, `net.ipv4.conf.default.accept_redirects`, `net.ipv4.conf.default.accept_source_route`, `net.ipv4.conf.default.forwarding`, `net.ipv4.conf.default.log_martians`, `net.ipv4.conf.default.rp_filter`, `net.ipv4.conf.default.secure_redirects`, `net.ipv4.conf.default.send_redirects`, `net.ipv4.icmp_echo_ignore_broadcasts`, `net.ipv4.icmp_ignore_bogus_error_responses`, `net.ipv4.ip_forward`, `net.ipv4.tcp_syncookies`, `net.ipv6.conf.all.accept_ra`, `net.ipv6.conf.all.accept_redirects`, `net.ipv6.conf.all.accept_source_route`, `net.ipv6.conf.all.forwarding`, `net.ipv6.conf.default.accept_ra`, `net.ipv6.conf.default.accept_redirects`, `net.ipv6.conf.default.accept_source_route`, `net.ipv6.conf.default.forwarding` | 29 (1.5.1 to 3.3.2.8) |
| `timesyncd` | `config_raw` | 2.3.2.1 |
| `ufw` | `status_verbose` | 4.1.2, 4.1.3, 4.1.4, 4.1.5 |
| `ungrouped_files` | `files` | 7.1.12 |
| `unowned_files` | `files` | 7.1.12 |
| `user_group` | `dotfiles`, `group_content`, `interactive_homes`, `passwd_content`, `root_password_status`, `root_path`, `root_path_entries`, `root_shell_init_exists`, `root_shell_init_raw`, `shadow_entries`, `shells_content`, `uid_min` | 33 (5.2.7 to 7.2.10) |
| `wireless_interfaces` | `has_wireless`, `modules` | 3.1.2 |
| `world_writable` | `files` | 7.1.11 |

### Collected markers

An empty string or list cannot tell "collected, nothing found" from "not collected", so by itself it is
evidence missing. Where an empty value is a real answer, the collector also sends `collected: true` on the
section, and the empty value is then judged by the requirement:

| Marker | With it | Read by |
|---|---|---|
| `chronyd.collected` | `chronyd.process_users: []` (no chronyd process) is not met | 2.3.3.2 |
| `pam.collected` | `pam.profile_d_raw: ""` (no umask line in `/etc/profile.d/*.sh`) is not met, and a missing `pam.default_umask` (no `UMASK` in login.defs) is not met | 5.4.3.3 |
| `aide.collected` | `aide.cron_raw: ""` (no cron file runs aide) is judged with `aide.aidecheck` | 6.3.2 |

Only `true` counts; a marker without the value itself (`process_users`, `profile_d_raw`, `cron_raw`) is
still evidence missing.

### Shapes worth noting

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
| `cron.cron_yearly_exists` | boolean: `/etc/cron.yearly` exists. `false` passes 2.4.1.7 (nothing to secure); `true` needs `cron_yearly_mode`/`_owner`/`_group` | 2.4.1.7 |
| `pam.profile_d_raw` | the active lines of `/etc/profile.d/*.sh` | 5.4.3.3 |
| `pam.default_umask` | the `UMASK` value of `/etc/login.defs` | 5.4.3.3 |

Every 6.2.3 recommendation now also reads `auditd.rules` (the lines of `/etc/audit/rules.d/*.rules`) and, where
a rule filters on `auid>=`, `user_group.uid_min`.

## Where 22.04 differs from 24.04

The logic of most recommendations is the 24.04 module's (`benchmarks/cis/ubuntu_24_04/`), carried by the
generator. These are written from the 22.04 audits instead:

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
  alternative); 6.3.2 (an aide cron entry, or the `aidecheck` units); 5.4.3.3 (a `umask` line in `/etc/profile.d/*.sh`
  is required, and login.defs `UMASK`); 7.1.8 (`/etc/gshadow-` must exist).
  2.4.1.7 passes on a collected `cron.cron_yearly_exists: false` (as in `rhel_9`), and 2.3.3.2 needs a
  running chronyd once `chronyd.collected` is sent.
  1.2.1.1 and 1.2.1.2 are Manual in 22.04.

## Regenerate

```bash
python3 tools/cis_generators/gen_ubuntu_22_04.py CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.xlsx
```

The workbook is CIS-licensed and is not committed. The generator writes only the files it generates and
formats them with `opa fmt`. `cis_ubuntu_2204_key_main.rego` and this README are kept by hand.
