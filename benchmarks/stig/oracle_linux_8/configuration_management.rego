# METADATA
# title: "DISA STIG for Oracle Linux 8 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 19
#     cited: 18
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_8.configuration_management

# DISA STIG for Oracle Linux 8 - Configuration Management Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/configuration_management.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: System settings, kernel params, banners, SELinux, GRUB, CTL-ALT-DEL

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL08-00-040170 | V-248869 | CAT I
# Ctrl-Alt-Delete key sequence must be disabled
default ctrl_alt_del_disabled := false

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "masked"
}

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "inactive"
	input.kernel_params["kernel.ctrl-alt-del"] == "0"
}

status_ol08_00_040170 := "Not_a_Finding" if { ctrl_alt_del_disabled } else := "Open"

finding_ol08_00_040170 := {
	"vuln_id": "V-248869",
	"stig_id": "OL08-00-040170",
	"severity": "CAT I",
	"rule_title": "The x86 Ctrl-Alt-Delete key sequence must be disabled on OL 8.",
	"status": status_ol08_00_040170,
	"fix_text": "Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target",
}

# OL08-00-040171 | V-248870 | CAT I
# The Ctrl-Alt-Delete graphical key sequence must be disabled
default ctrl_alt_del_graphical_disabled := false

ctrl_alt_del_graphical_disabled if {
	input.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "''"
}

ctrl_alt_del_graphical_disabled if {
	not input.packages["gnome-desktop3"]
}

status_ol08_00_040171 := "Not_a_Finding" if { ctrl_alt_del_graphical_disabled } else := "Open"

finding_ol08_00_040171 := {
	"vuln_id": "V-248870",
	"stig_id": "OL08-00-040171",
	"severity": "CAT I",
	"rule_title": "The x86 Ctrl-Alt-Delete key sequence in OL 8 must be disabled if a graphical user interface is installed.",
	"status": status_ol08_00_040171,
	"fix_text": "Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010170 | V-248548 | CAT II
# System crypto policy must be FIPS
default crypto_policy_fips := false

crypto_policy_fips if {
	input.crypto_policy == "FIPS"
}

crypto_policy_fips if {
	input.crypto_policy == "FIPS:OSPP"
}

status_ol08_00_010170 := "Not_a_Finding" if { crypto_policy_fips } else := "Open"

finding_ol08_00_010170 := {
	"vuln_id": "V-248548",
	"stig_id": "OL08-00-010170",
	"severity": "CAT II",
	"rule_title": "OL 8 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_ol08_00_010170,
	"fix_text": "Set the crypto policy: update-crypto-policies --set FIPS",
}

# OL08-00-010450 | V-248596 | CAT II
# SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if {
	input.selinux.policy == "targeted"
}

status_ol08_00_010450 := "Not_a_Finding" if { selinux_targeted } else := "Open"

finding_ol08_00_010450 := {
	"vuln_id": "V-248596",
	"stig_id": "OL08-00-010450",
	"severity": "CAT II",
	"rule_title": "OL 8 must enable the SELinux targeted policy.",
	"status": status_ol08_00_010450,
	"fix_text": "Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# OL08-00-010060 | V-248529 | CAT II
# Must display the Standard Mandatory DoD Notice on login banner
default login_banner_set := false

login_banner_set if {
	contains(input.login_banner.issue, "You are accessing a U.S. Government")
}

login_banner_set if {
	contains(input.login_banner.issue, "authorized users only")
}

status_ol08_00_010060 := "Not_a_Finding" if { login_banner_set } else := "Open"

finding_ol08_00_010060 := {
	"vuln_id": "V-248529",
	"stig_id": "OL08-00-010060",
	"severity": "CAT II",
	"rule_title": "OL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon.",
	"status": status_ol08_00_010060,
	"fix_text": "Configure /etc/issue with the DoD warning banner text",
}

# OL08-00-010040 | V-248526 | CAT II
# SSH must display banner before granting access
default ssh_banner_set := false

ssh_banner_set if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_ol08_00_010040 := "Not_a_Finding" if { ssh_banner_set } else := "Open"

finding_ol08_00_010040 := {
	"vuln_id": "V-248526",
	"stig_id": "OL08-00-010040",
	"severity": "CAT II",
	"rule_title": "OL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via an SSH logon.",
	"status": status_ol08_00_010040,
	"fix_text": "Configure Banner in /etc/ssh/sshd_config to point to /etc/issue",
}

# OL08-00-010430 | V-248594 | CAT II
# kernel.randomize_va_space must be set to 2
default aslr_enabled := false

aslr_enabled if {
	input.kernel_params["kernel.randomize_va_space"] == "2"
}

status_ol08_00_010430 := "Not_a_Finding" if { aslr_enabled } else := "Open"

finding_ol08_00_010430 := {
	"vuln_id": "V-248594",
	"stig_id": "OL08-00-010430",
	"severity": "CAT II",
	"rule_title": "OL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_ol08_00_010430,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p",
}

# OL08-00-040282 | V-248890 | CAT II
# kernel.perf_event_paranoid must be set to 2
default perf_event_restricted := false

perf_event_restricted if {
	to_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2
}

status_ol08_00_040282 := "Not_a_Finding" if { perf_event_restricted } else := "Open"

finding_ol08_00_040282 := {
	"vuln_id": "V-248890",
	"stig_id": "OL08-00-040282",
	"severity": "CAT II",
	"rule_title": "OL 8 must restrict the use of \"ptrace\" to descendant processes.",
	"status": status_ol08_00_040282,
	"fix_text": "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-010372 | V-248576 | CAT II
# kernel.unprivileged_bpf_disabled must be set to 1
default bpf_restricted := false

bpf_restricted if {
	input.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"
}

status_ol08_00_010372 := "Not_a_Finding" if { bpf_restricted } else := "Open"

finding_ol08_00_010372 := {
	"vuln_id": "V-248576",
	"stig_id": "OL08-00-010372",
	"severity": "CAT II",
	"rule_title": "OL 8 must prevent the loading of a new kernel for later execution.",
	"status": status_ol08_00_010372,
	"fix_text": "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040286 | V-248894 | CAT II
# net.core.bpf_jit_harden must be set to 2
default bpf_jit_hardened := false

bpf_jit_hardened if {
	input.kernel_params["net.core.bpf_jit_harden"] == "2"
}

status_ol08_00_040286 := "Not_a_Finding" if { bpf_jit_hardened } else := "Open"

finding_ol08_00_040286 := {
	"vuln_id": "V-248894",
	"stig_id": "OL08-00-040286",
	"severity": "CAT II",
	"rule_title": "OL 8 must enable hardening for the Berkeley Packet Filter Just-in-time compiler.",
	"status": status_ol08_00_040286,
	"fix_text": "Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040080 | V-248837 | CAT II
# USB storage kernel module must be disabled
default usb_storage_disabled := false

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].status == "disabled"
}

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].blacklisted == true
}

status_ol08_00_040080 := "Not_a_Finding" if { usb_storage_disabled } else := "Open"

finding_ol08_00_040080 := {
	"vuln_id": "V-248837",
	"stig_id": "OL08-00-040080",
	"severity": "CAT II",
	"rule_title": "OL 8 must be configured to disable the ability to use USB mass storage devices.",
	"status": status_ol08_00_040080,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# OL08-00-010360 | V-248573 | CAT II
# AIDE integrity checking cron job must exist
default aide_cron_configured := false

aide_cron_configured if {
	input.aide_config.cron_job == true
}

status_ol08_00_010360 := "Not_a_Finding" if { aide_cron_configured } else := "Open"

finding_ol08_00_010360 := {
	"vuln_id": "V-248573",
	"stig_id": "OL08-00-010360",
	"severity": "CAT II",
	"rule_title": "The OL 8 file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency.",
	"status": status_ol08_00_010360,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
}

# OL08-00-010543 | V-248611 | CAT II
# /tmp must be on a separate partition
default tmp_separate_partition := false

tmp_separate_partition if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	mount.device != "tmpfs"
}

status_ol08_00_010543 := "Not_a_Finding" if { tmp_separate_partition } else := "Open"

finding_ol08_00_010543 := {
	"vuln_id": "V-248611",
	"stig_id": "OL08-00-010543",
	"severity": "CAT II",
	"rule_title": "OL 8 must use a separate file system for \"/tmp\".",
	"status": status_ol08_00_010543,
	"fix_text": "Configure /tmp on a separate partition in /etc/fstab",
}

# OL08-00-010570 | V-248616 | CAT II
# /tmp must have nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nosuid" in mount.options
}

status_ol08_00_010570 := "Not_a_Finding" if { tmp_nosuid } else := "Open"

finding_ol08_00_010570 := {
	"vuln_id": "V-248616",
	"stig_id": "OL08-00-010570",
	"severity": "CAT II",
	"rule_title": "OL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.",
	"status": status_ol08_00_010570,
	"fix_text": "Add nosuid option to /tmp in /etc/fstab",
}

# OL08-00-010590 | V-248620 | CAT II
# /tmp must have noexec option
default tmp_noexec := false

tmp_noexec if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"noexec" in mount.options
}

status_ol08_00_010590 := "Not_a_Finding" if { tmp_noexec } else := "Open"

finding_ol08_00_010590 := {
	"vuln_id": "V-248620",
	"stig_id": "OL08-00-010590",
	"severity": "CAT II",
	"rule_title": "OL 8 file systems that contain user home directories must not execute binary files.",
	"status": status_ol08_00_010590,
	"fix_text": "Add noexec option to /tmp in /etc/fstab",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# OL08-00-010375 | V-248579 | CAT III
# kernel.dmesg_restrict must be set to 1
default dmesg_restricted := false

dmesg_restricted if {
	input.kernel_params["kernel.dmesg_restrict"] == "1"
}

status_ol08_00_010375 := "Not_a_Finding" if { dmesg_restricted } else := "Open"

finding_ol08_00_010375 := {
	"vuln_id": "V-248579",
	"stig_id": "OL08-00-010375",
	"severity": "CAT III",
	"rule_title": "OL 8 must restrict access to the kernel message buffer.",
	"status": status_ol08_00_010375,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040026 | V-248834 | CAT III
# Firewire kernel module must be disabled
default firewire_disabled := false

firewire_disabled if {
	input.kernel_modules["firewire-core"].status == "disabled"
}

firewire_disabled if {
	input.kernel_modules["firewire-core"].blacklisted == true
}

status_ol08_00_040026 := "Not_a_Finding" if { firewire_disabled } else := "Open"

finding_ol08_00_040026 := {
	"vuln_id": "V-248834",
	"stig_id": "OL08-00-040026",
	"severity": "CAT III",
	"rule_title": "OL 8 must disable IEEE 1394 (FireWire) Support.",
	"status": status_ol08_00_040026,
	"fix_text": "Disable Firewire: echo 'install firewire-core /bin/false' >> /etc/modprobe.d/firewire.conf",
}

# OL08-00-010541 | V-248609 | CAT III
# /var/log must be a separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_ol08_00_010541 := "Not_a_Finding" if { var_log_separate } else := "Open"

finding_ol08_00_010541 := {
	"vuln_id": "V-248609",
	"stig_id": "OL08-00-010541",
	"severity": "CAT III",
	"rule_title": "OL 8 must use a separate file system for \"/var/log\".",
	"status": status_ol08_00_010541,
	"fix_text": "Configure /var/log on a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol08_00_040170,
	finding_ol08_00_040171,
]

cat_ii_findings := [
	finding_ol08_00_010170,
	finding_ol08_00_010450,
	finding_ol08_00_010060,
	finding_ol08_00_010040,
	finding_ol08_00_010430,
	finding_ol08_00_040282,
	finding_ol08_00_010372,
	finding_ol08_00_040286,
	finding_ol08_00_040080,
	finding_ol08_00_010360,
	finding_ol08_00_010543,
	finding_ol08_00_010570,
	finding_ol08_00_010590,
]

cat_iii_findings := [
	finding_ol08_00_010375,
	finding_ol08_00_040026,
	finding_ol08_00_010541,
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

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "configuration_management",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
