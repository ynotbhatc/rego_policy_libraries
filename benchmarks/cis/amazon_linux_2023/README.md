# CIS Amazon Linux 2023 Benchmark v1.0.0

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_amazon_linux_2023.py` from the CIS workbook

All 243 recommendations (217 Automated, 26 Manual): every Automated one is decided from
collected facts and fails closed with `<id>: evidence missing — <field> not collected` when its facts are
absent; the 26 Manual ones need an operator attestation (`input.attest.<name>`). Ids, status and
profile are the workbook's; the messages are our own wording, not the benchmark text.

Query: `POST /v1/data/cis_amazon_linux_2023/main/compliance_report`

This module replaces the earlier hand-written sample of the benchmark. The deprecated package
`cis.amazon_linux_2023` (`violations`, `compliance_summary`) is now a view of the bridge for an existing caller.

## Sections

| Sections | Package (file) | Recommendations |
|---|---|---|
| Section 1.1: Filesystem Configuration | `filesystem` (`filesystem_validation.rego`) | 34 |
| Sections 1.2, 1.7-1.9: Software Updates, Banners, Patching, Crypto Policy | `initial_setup` (`initial_setup_validation.rego`) | 12 (4 Manual) |
| Sections 1.3-1.5: Integrity Checking (AIDE), Bootloader, Process Hardening | `boot_security` (`boot_security_validation.rego`) | 8 |
| Section 1.6: Mandatory Access Control (SELinux) | `selinux` (`selinux_validation.rego`) | 8 (1 Manual) |
| Section 2: Time Synchronization, Special Purpose Services, Service Clients | `services` (`service_validation.rego`) | 24 (1 Manual) |
| Section 3: Network Configuration, Host Based Firewall | `network` (`network_validation.rego`) | 25 (3 Manual) |
| Section 5.2: System Auditing (auditd) | `auditd` (`auditd_validation.rego`) | 38 (1 Manual) |
| Sections 5.1, 5.3: System Logging (rsyslog, journald), logrotate | `logging` (`logging_validation.rego`) | 19 (12 Manual) |
| Section 4.1: Job Schedulers | `cron` (`cron_validation.rego`) | 9 |
| Section 4.2: SSH Server | `ssh` (`ssh_validation.rego`) | 20 |
| Section 4.3: Privilege Escalation | `sudo` (`sudo_validation.rego`) | 6 |
| Sections 4.4-4.6: authselect, PAM, User Accounts and Environment | `pam` (`pam_validation.rego`) | 16 (2 Manual) |
| Section 6.1: System File Permissions | `file_permissions` (`file_permissions_validation.rego`) | 13 (2 Manual) |
| Section 6.2: Local User and Group Settings | `user_group` (`user_group_validation.rego`) | 11 |

The roll-up is package `cis_amazon_linux_2023` (`cis_amazon_linux_2023_complete.rego`); the bridge is `cis_amazon_linux_2023.main`.

## Profile

`input.profile`: `level1_server` (179 recommendations) or `level2_server` (all 243; Level 2
includes Level 1). `level1` and `level2` are accepted. `total_controls` is the number in scope for the profile;
`standard_total` is 243.
There is no default profile: an absent or unrecognised `profile` evaluates every recommendation, adds a
`PROFILE NOT SELECTED` violation and is never compliant.

## Facts

The shared Linux fact contract `cis_rhel9` reads (the AAC mapper `cis_linux_build_opa_input.yml`), so one
collector feeds both. Where a check is the same as a CIS RHEL 9 v3.0.0 check, the RHEL 9 logic is reused as is.
Facts this module reads beyond that contract:

| Input | Shape | Read by |
|---|---|---|
| `firewall.nft_ruleset_raw` | text of `nft list ruleset` ("" is an empty ruleset) | 3.4.2.2-3.4.2.4, 3.4.2.7 |
| `firewall.default_zone` | `firewall-cmd --get-default-zone` | 3.4.2.1 |
| `ssh.crypto_policy_override_raw` | text of `/etc/sysconfig/sshd` and `/etc/ssh/sshd_config.d/*.conf` ("" when absent) | 4.2.14 |
| `pam.su_config_raw` | text of `/etc/pam.d/su` | 4.3.6 |
| `user_group.group_members` | `{group: [member, ...]}` from `/etc/group` | 4.3.6 |
| `pam.libuser_conf_raw` | text of `/etc/libuser.conf` | 4.5.4 |
| `user_group.shadow_entries[].min_days` | field 4 of `/etc/shadow`, beside the existing aging fields | 4.6.1.2 |
| `user_group.home_dotfiles` | `[{user, primary_group, path, mode, owner, group}]`, every dot file in each interactive user's home | 6.2.11 |
| `cron.<cron|at>_allow_*`, `cron.<cron|at>_deny_exists` | allow file exists/mode/owner/group, deny file exists | 4.1.8, 4.1.9 |
| `services["<unit>.socket"]` | socket units (`rpcbind.socket`, `systemd-journal-remote.socket`); Ansible `service_facts` lists `.service` units only | 2.2.17, 5.1.2.1.4 |

`boot_security.kernel_args` (the arguments of every boot entry, `grubby --info=ALL`) decides 5.2.1.2 and
5.2.1.3, as the audit procedure reads them.

## Where the logic differs from the RHEL 9 module

- 1.5.2 accepts `kernel.yama.ptrace_scope = 1` only (the audit script compares for equality).
- 2.2.x: the package must be absent; only 2.2.12, 2.2.16-2.2.18 accept the unit alternative their titles name.
- 4.1.2-4.1.7: owner and group root, no permission for group or other (0700 at most, `/etc/crontab` included).
- 4.1.8 / 4.1.9: the deny file must not exist; the allow file must exist, 0600 at most, root:root.
- 4.2.3: public host keys must be group `root`. 4.6.1.4: 30 days. 5.2.4.3: groups `adm` or `root`.
- 5.1.1.4 / 5.1.1.7: Amazon Linux 2023 ships without rsyslog; a collected `rsyslog.installed == false` is
  evidence (5.1.1.7 passes, 5.1.1.4 is not met until rsyslog with a 0640 `$FileCreateMode` is in use).
- 5.1.3: this benchmark's own file table (no 0644 allowance for `cloud-init.log`, `localmessages`, `waagent.log`).
- 5.2.3.6: each privileged program needs a perm x rule on its path (the audit greps for the path only), not
  the RHEL 9 always,exit rule with both auid filters.
- 5.2.3.15-5.2.3.19: the `perm=x` rules must carry both auid filters on the same line.
- 6.2.11: a `.netrc` with correct access passes (the audit only warns); `.bash_history` must be 0600.
- 3.4.2.7: where nftables.service is enabled, the input and forward base chains must exist with policy drop.

## Attested (Manual)

1.2.1, 1.2.3, 1.2.4, 1.6.1.6, 1.8, 2.4, 3.1.1, 3.4.2.5, 3.4.2.6, 4.4.1, 4.6.6, 5.1.1.1, 5.1.1.2, 5.1.1.3, 5.1.1.5, 5.1.1.6, 5.1.2.1.1, 5.1.2.1.2, 5.1.2.1.3, 5.1.2.5, 5.1.2.6, 5.1.2.7, 5.2.3.21, 5.3, 6.1.10, 6.1.13

## Regenerate

```
/usr/bin/python3 tools/cis_generators/gen_amazon_linux_2023.py CIS_Amazon_Linux_2023_Benchmark_v1.0.0.xlsx
opa fmt -w benchmarks/cis/amazon_linux_2023
```

Authored with Claude (Anthropic).
