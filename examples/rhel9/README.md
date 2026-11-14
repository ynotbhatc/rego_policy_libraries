# A sample RHEL 9 server

`facts.json` is the input for one fictional server, `web01.example.com` (192.0.2.10), in the shape the CIS RHEL 9 benchmark in this library reads: mounts, kernel settings, packages, services, SSH, sudo, PAM, audit rules, file permissions and the sign-offs for the manual recommendations. Nothing in it comes from a real machine.

The host is mostly hardened and has the kind of gaps a real one has, so the result is mixed instead of all-pass or all-fail.

## Run it

From the repository root:

```bash
opa eval -d benchmarks/cis/rhel_9 -i examples/rhel9/facts.json -f pretty 'data.cis_rhel9.main.compliance_report'
```

## What the output means

- `compliant` is `false`: at least one control failed.
- `total_controls` is 352, every recommendation in CIS RHEL 9 v3.0.0, because the file sets `"profile": "level2_server"`. Remove that line and you get the default, Level 1 server (263 controls).
- `failed_controls` is 25 and `passed_controls` is 327.
- `violations` has one line per failing control, starting with the control id.
- `section_results` gives the same picture per section. `sections_not_assessed` is empty because every section received input. `missing_inputs` names older, alternative input keys; a section needs only one of its keys, so entries there are not findings.

To see only the failures:

```bash
opa eval -d benchmarks/cis/rhel_9 -i examples/rhel9/facts.json -f json 'data.cis_rhel9.main.compliance_report' \
  | jq -r '.result[0].expressions[0].value.violations[]'
```

## What is wrong with this host

- **1.1.2.2.4**: `/dev/shm` is mounted without `noexec`
- **1.4.1**: no bootloader password
- **1.5.7**: `kernel.yama.ptrace_scope` is 0
- **1.7.2**: `/etc/issue` shows the OS release
- **2.1.12**: `rpcbind` is enabled and nothing needs it
- **2.1.18**: nginx is running. It is a web server, so this one would be a documented exception, not a fix
- **2.4.1.2**: `/etc/crontab` is mode 0644
- **3.3.1.16, 3.3.1.17**: martian packets are not logged
- **4.1.10**: firewalld does not log denied packets
- **5.1.11**: SSH forwarding is allowed
- **5.1.17**: SSH `MaxAuthTries` is 6
- **5.1.21**: root may log in over SSH
- **5.2.5**: sudo has no log file
- **5.3.3.2.2**: minimum password length is 8
- **5.3.3.3.2**: password history is not enforced for root
- **5.4.1.1**: passwords never expire (`PASS_MAX_DAYS 99999`)
- **5.4.3.2**: no shell idle timeout
- **6.2.1.3**: `audit_backlog_limit` is not on the kernel command line
- **6.2.2.2**: audit logs rotate away instead of being kept
- **6.2.3.3**: follows from 5.2.5: with no sudo log file there is nothing for the audit rule to watch
- **6.2.3.21**: no audit rule for file system mounts
- **6.3.2**: AIDE is installed but never scheduled
- **7.1.11**: a world-writable file under the web root
- **7.2.8**: a home directory is mode 0755

Fix one in the file and run the command again: change `permitrootlogin yes` to `permitrootlogin no` in `ssh.sshd_config_raw` and `failed_controls` drops to 24. Delete a key, for example `world_writable`, and the control does not pass: it fails with an "evidence missing" violation, because a fact that was not collected is not a fact that passed.

## Where facts come from

This library evaluates facts; it does not collect them. The collectors that read a live host and produce this document are Ansible content in the companion product, [Ansible Automated Compliance](https://github.com/Ansible-Automated-Compliance/aac). Any tool that writes the same JSON works equally well. The fields each control reads are named in the module headers under [`benchmarks/cis/rhel_9/`](../../benchmarks/cis/rhel_9/) and in the "evidence missing" messages themselves.

## Keeping it true

`bash examples/rhel9/check.sh` evaluates the file and fails if the result is no longer the one described here (352 controls, these 25 failing, no evidence missing).
