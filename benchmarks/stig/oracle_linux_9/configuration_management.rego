# METADATA
# title: "DISA STIG for Oracle Linux 9 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle_linux]
#   coverage:
#     checks: 23
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_linux_9.configuration_management

# DISA STIG for Oracle Linux 9 - Configuration Management Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/configuration_management.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: System settings, kernel params, banners, SELinux, GRUB, CTL-ALT-DEL

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL09-00-002413 | V-271752 | CAT I
# Ctrl-Alt-Delete key sequence must be disabled
default ctrl_alt_del_disabled := false

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "masked"
}

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "inactive"
	input.kernel_params["kernel.ctrl-alt-del"] == "0"
}

status_ol09_00_002413 := "Not_a_Finding" if { ctrl_alt_del_disabled } else := "Open"

finding_ol09_00_002413 := {
	"vuln_id": "V-271752",
	"stig_id": "OL09-00-002413",
	"severity": "CAT I",
	"rule_title": "OL 9 must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled.",
	"status": status_ol09_00_002413,
	"fix_text": "Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target",
}

# OL09-00-000070 | V-271454 | CAT I
# FIPS mode must be enabled
default fips_mode_enabled := false

fips_mode_enabled if {
	input.fips_mode == true
}

status_ol09_00_000070 := "Not_a_Finding" if { fips_mode_enabled } else := "Open"

finding_ol09_00_000070 := {
	"vuln_id": "V-271454",
	"stig_id": "OL09-00-000070",
	"severity": "CAT I",
	"rule_title": "OL 9 must enable FIPS mode.",
	"status": status_ol09_00_000070,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable && reboot",
}

# OL09-00-000060 | V-271452 | CAT I
# System crypto policy must be FIPS
default crypto_policy_fips := false

crypto_policy_fips if {
	input.crypto_policy == "FIPS"
}

crypto_policy_fips if {
	input.crypto_policy == "FIPS:OSPP"
}

status_ol09_00_000060 := "Not_a_Finding" if { crypto_policy_fips } else := "Open"

finding_ol09_00_000060 := {
	"vuln_id": "V-271452",
	"stig_id": "OL09-00-000060",
	"severity": "CAT I",
	"rule_title": "OL 9 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_ol09_00_000060,
	"fix_text": "Set the crypto policy: update-crypto-policies --set FIPS",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-002107 | V-271677 | CAT II
# The Ctrl-Alt-Delete graphical key sequence must be disabled
default ctrl_alt_del_graphical_disabled := false

ctrl_alt_del_graphical_disabled if {
	input.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "''"
}

ctrl_alt_del_graphical_disabled if {
	not input.packages["gnome-desktop3"]
}

status_ol09_00_002107 := "Not_a_Finding" if { ctrl_alt_del_graphical_disabled } else := "Open"

finding_ol09_00_002107 := {
	"vuln_id": "V-271677",
	"stig_id": "OL09-00-002107",
	"severity": "CAT II",
	"rule_title": "OL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.",
	"status": status_ol09_00_002107,
	"fix_text": "Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
}

# OL09-00-000065 | V-271453 | CAT II
# SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if {
	input.selinux.policy == "targeted"
}

status_ol09_00_000065 := "Not_a_Finding" if { selinux_targeted } else := "Open"

finding_ol09_00_000065 := {
	"vuln_id": "V-271453",
	"stig_id": "OL09-00-000065",
	"severity": "CAT II",
	"rule_title": "OL 9 must enable the SELinux targeted policy.",
	"status": status_ol09_00_000065,
	"fix_text": "Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# OL09-00-001115 | V-271635 | CAT II
# GRUB bootloader must be password protected
default grub_password_set := false

grub_password_set if {
	input.grub_config.password_set == true
}

status_ol09_00_001115 := "Not_a_Finding" if { grub_password_set } else := "Open"

finding_ol09_00_001115 := {
	"vuln_id": "V-271635",
	"stig_id": "OL09-00-001115",
	"severity": "CAT II",
	"rule_title": "OL 9 must require authentication upon booting into single-user and maintenance modes.",
	"status": status_ol09_00_001115,
	"fix_text": "Configure a bootloader password: grub2-setpassword",
}

# OL09-00-000090 | V-271455 | CAT II
# Must display the Standard Mandatory DoD Notice on login banner
default login_banner_set := false

login_banner_set if {
	contains(input.login_banner.issue, "You are accessing a U.S. Government")
}

login_banner_set if {
	contains(input.login_banner.issue, "authorized users only")
}

status_ol09_00_000090 := "Not_a_Finding" if { login_banner_set } else := "Open"

finding_ol09_00_000090 := {
	"vuln_id": "V-271455",
	"stig_id": "OL09-00-000090",
	"severity": "CAT II",
	"rule_title": "OL 9 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon.",
	"status": status_ol09_00_000090,
	"fix_text": "Configure /etc/issue with the DoD warning banner text",
}

# OL09-00-000256 | V-271487 | CAT II
# SSH must display banner before granting access
default ssh_banner_set := false

ssh_banner_set if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_ol09_00_000256 := "Not_a_Finding" if { ssh_banner_set } else := "Open"

finding_ol09_00_000256 := {
	"vuln_id": "V-271487",
	"stig_id": "OL09-00-000256",
	"severity": "CAT II",
	"rule_title": "OL 9 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a SSH logon.",
	"status": status_ol09_00_000256,
	"fix_text": "Configure Banner in /etc/ssh/sshd_config to point to /etc/issue",
}

# OL09-00-002423 | V-271761 | CAT II
# kernel.randomize_va_space must be set to 2
default aslr_enabled := false

aslr_enabled if {
	input.kernel_params["kernel.randomize_va_space"] == "2"
}

status_ol09_00_002423 := "Not_a_Finding" if { aslr_enabled } else := "Open"

finding_ol09_00_002423 := {
	"vuln_id": "V-271761",
	"stig_id": "OL09-00-002423",
	"severity": "CAT II",
	"rule_title": "OL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_ol09_00_002423,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p",
}

# OL09-00-002406 | V-271745 | CAT II
# kernel.dmesg_restrict must be set to 1
default dmesg_restricted := false

dmesg_restricted if {
	input.kernel_params["kernel.dmesg_restrict"] == "1"
}

status_ol09_00_002406 := "Not_a_Finding" if { dmesg_restricted } else := "Open"

finding_ol09_00_002406 := {
	"vuln_id": "V-271745",
	"stig_id": "OL09-00-002406",
	"severity": "CAT II",
	"rule_title": "OL 9 must restrict access to the kernel message buffer.",
	"status": status_ol09_00_002406,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-002410 | V-271749 | CAT II
# kernel.perf_event_paranoid must be set to 2
default perf_event_restricted := false

perf_event_restricted if {
	to_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2
}

status_ol09_00_002410 := "Not_a_Finding" if { perf_event_restricted } else := "Open"

finding_ol09_00_002410 := {
	"vuln_id": "V-271749",
	"stig_id": "OL09-00-002410",
	"severity": "CAT II",
	"rule_title": "OL 9 must restrict usage of ptrace to descendant processes.",
	"status": status_ol09_00_002410,
	"fix_text": "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-002428 | V-271766 | CAT II
# kernel.unprivileged_bpf_disabled must be set to 1
default bpf_restricted := false

bpf_restricted if {
	input.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"
}

status_ol09_00_002428 := "Not_a_Finding" if { bpf_restricted } else := "Open"

finding_ol09_00_002428 := {
	"vuln_id": "V-271766",
	"stig_id": "OL09-00-002428",
	"severity": "CAT II",
	"rule_title": "OL 9 must prevent the loading of a new kernel for later execution.",
	"status": status_ol09_00_002428,
	"fix_text": "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-002430 | V-271768 | CAT II
# net.core.bpf_jit_harden must be set to 2
default bpf_jit_hardened := false

bpf_jit_hardened if {
	input.kernel_params["net.core.bpf_jit_harden"] == "2"
}

status_ol09_00_002430 := "Not_a_Finding" if { bpf_jit_hardened } else := "Open"

finding_ol09_00_002430 := {
	"vuln_id": "V-271768",
	"stig_id": "OL09-00-002430",
	"severity": "CAT II",
	"rule_title": "OL 9 must enable hardening for the Berkeley Packet Filter (BPF) just-in-time compiler.",
	"status": status_ol09_00_002430,
	"fix_text": "Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-000047 | V-271450 | CAT II
# USB storage kernel module must be disabled
default usb_storage_disabled := false

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].status == "disabled"
}

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].blacklisted == true
}

status_ol09_00_000047 := "Not_a_Finding" if { usb_storage_disabled } else := "Open"

finding_ol09_00_000047 := {
	"vuln_id": "V-271450",
	"stig_id": "OL09-00-000047",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured to disable USB mass storage.",
	"status": status_ol09_00_000047,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# OL09-00-000042 | V-271445 | CAT II
# Firewire kernel module must be disabled
default firewire_disabled := false

firewire_disabled if {
	input.kernel_modules["firewire-core"].status == "disabled"
}

firewire_disabled if {
	input.kernel_modules["firewire-core"].blacklisted == true
}

status_ol09_00_000042 := "Not_a_Finding" if { firewire_disabled } else := "Open"

finding_ol09_00_000042 := {
	"vuln_id": "V-271445",
	"stig_id": "OL09-00-000042",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured to disable the FireWire kernel module.",
	"status": status_ol09_00_000042,
	"fix_text": "Disable Firewire: echo 'install firewire-core /bin/false' >> /etc/modprobe.d/firewire.conf",
}

# OL09-00-000301 | V-271497 | CAT II
# AIDE integrity checking cron job must exist
default aide_cron_configured := false

aide_cron_configured if {
	input.aide_config.cron_job == true
}

status_ol09_00_000301 := "Not_a_Finding" if { aide_cron_configured } else := "Open"

finding_ol09_00_000301 := {
	"vuln_id": "V-271497",
	"stig_id": "OL09-00-000301",
	"severity": "CAT II",
	"rule_title": "OL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator (SA) when anomalies in the operation of any security functions are discovered.",
	"status": status_ol09_00_000301,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
}

# OL09-00-000302 | V-271498 | CAT II
# AIDE must be installed
default aide_installed := false

aide_installed if {
	input.packages.aide == true
}

status_ol09_00_000302 := "Not_a_Finding" if { aide_installed } else := "Open"

finding_ol09_00_000302 := {
	"vuln_id": "V-271498",
	"stig_id": "OL09-00-000302",
	"severity": "CAT II",
	"rule_title": "OL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.",
	"status": status_ol09_00_000302,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# OL09-00-000004 | V-271434 | CAT II
# /tmp must be on a separate partition
default tmp_separate_partition := false

tmp_separate_partition if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	mount.device != "tmpfs"
}

status_ol09_00_000004 := "Not_a_Finding" if { tmp_separate_partition } else := "Open"

finding_ol09_00_000004 := {
	"vuln_id": "V-271434",
	"stig_id": "OL09-00-000004",
	"severity": "CAT II",
	"rule_title": "OL 9 must use a separate file system for /tmp.",
	"status": status_ol09_00_000004,
	"fix_text": "Configure /tmp on a separate partition in /etc/fstab",
}

# OL09-00-002070 | V-271666 | CAT II
# /tmp must have nodev option
default tmp_nodev := false

tmp_nodev if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nodev" in mount.options
}

status_ol09_00_002070 := "Not_a_Finding" if { tmp_nodev } else := "Open"

finding_ol09_00_002070 := {
	"vuln_id": "V-271666",
	"stig_id": "OL09-00-002070",
	"severity": "CAT II",
	"rule_title": "OL 9 must prevent device files from being interpreted on file systems that contain user home directories.",
	"status": status_ol09_00_002070,
	"fix_text": "Add nodev option to /tmp in /etc/fstab",
}

# OL09-00-002071 | V-271667 | CAT II
# /tmp must have nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nosuid" in mount.options
}

status_ol09_00_002071 := "Not_a_Finding" if { tmp_nosuid } else := "Open"

finding_ol09_00_002071 := {
	"vuln_id": "V-271667",
	"stig_id": "OL09-00-002071",
	"severity": "CAT II",
	"rule_title": "OL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.",
	"status": status_ol09_00_002071,
	"fix_text": "Add nosuid option to /tmp in /etc/fstab",
}

# OL09-00-002072 | V-271668 | CAT II
# /tmp must have noexec option
default tmp_noexec := false

tmp_noexec if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"noexec" in mount.options
}

status_ol09_00_002072 := "Not_a_Finding" if { tmp_noexec } else := "Open"

finding_ol09_00_002072 := {
	"vuln_id": "V-271668",
	"stig_id": "OL09-00-002072",
	"severity": "CAT II",
	"rule_title": "OL 9 must prevent code from being executed on file systems that contain user home directories.",
	"status": status_ol09_00_002072,
	"fix_text": "Add noexec option to /tmp in /etc/fstab",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# OL09-00-000006 | V-271436 | CAT III
# /var/log must be a separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_ol09_00_000006 := "Not_a_Finding" if { var_log_separate } else := "Open"

finding_ol09_00_000006 := {
	"vuln_id": "V-271436",
	"stig_id": "OL09-00-000006",
	"severity": "CAT III",
	"rule_title": "OL 9 must use a separate file system for /var/log.",
	"status": status_ol09_00_000006,
	"fix_text": "Configure /var/log on a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol09_00_002413,
	finding_ol09_00_000070,
	finding_ol09_00_000060,
]

cat_ii_findings := [
	finding_ol09_00_002107,
	finding_ol09_00_000065,
	finding_ol09_00_001115,
	finding_ol09_00_000090,
	finding_ol09_00_000256,
	finding_ol09_00_002423,
	finding_ol09_00_002406,
	finding_ol09_00_002410,
	finding_ol09_00_002428,
	finding_ol09_00_002430,
	finding_ol09_00_000047,
	finding_ol09_00_000042,
	finding_ol09_00_000301,
	finding_ol09_00_000302,
	finding_ol09_00_000004,
	finding_ol09_00_002070,
	finding_ol09_00_002071,
	finding_ol09_00_002072,
]

cat_iii_findings := [
	finding_ol09_00_000006,
]

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "configuration_management",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
