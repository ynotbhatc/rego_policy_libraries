# METADATA
# title: "DISA STIG for RHEL 10 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 23
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.configuration_management

# DISA STIG for RHEL 10 - Configuration Management Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/configuration_management.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: System settings, kernel params, banners, SELinux, GRUB, CTL-ALT-DEL

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-700960 | V-281299 | CAT I
# Ctrl-Alt-Delete key sequence must be disabled
default ctrl_alt_del_disabled := false

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "masked"
}

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "inactive"
	input.kernel_params["kernel.ctrl-alt-del"] == "0"
}

status_rhel_10_700960 := "Not_a_Finding" if ctrl_alt_del_disabled

else := "Open"

finding_rhel_10_700960 := {
	"vuln_id": "V-281299",
	"stig_id": "RHEL-10-700960",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must disable the x86 Ctrl-Alt-Delete key sequence.",
	"status": status_rhel_10_700960,
	"fix_text": "Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target",
}

# RHEL-10-000500 | V-281009 | CAT I
# FIPS mode must be enabled
default fips_mode_enabled := false

fips_mode_enabled if {
	input.fips_mode == true
}

status_rhel_10_000500 := "Not_a_Finding" if fips_mode_enabled

else := "Open"

finding_rhel_10_000500 := {
	"vuln_id": "V-281009",
	"stig_id": "RHEL-10-000500",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must enable FIPS mode.",
	"status": status_rhel_10_000500,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable && reboot",
}

# RHEL-10-300010 | V-281008 | CAT I
# System crypto policy must be FIPS
default crypto_policy_fips := false

crypto_policy_fips if {
	input.crypto_policy == "FIPS"
}

crypto_policy_fips if {
	input.crypto_policy == "FIPS:OSPP"
}

status_rhel_10_300010 := "Not_a_Finding" if crypto_policy_fips

else := "Open"

finding_rhel_10_300010 := {
	"vuln_id": "V-281008",
	"stig_id": "RHEL-10-300010",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must implement a FIPS 140-3-compliant systemwide cryptographic policy.",
	"status": status_rhel_10_300010,
	"fix_text": "Set the crypto policy: update-crypto-policies --set FIPS",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-700420 | V-281251 | CAT II
# SELinux must be enabled in enforcing mode
default selinux_enforcing := false

selinux_enforcing if {
	input.selinux.status == "enforcing"
}

status_rhel_10_700420 := "Not_a_Finding" if selinux_enforcing

else := "Open"

finding_rhel_10_700420 := {
	"vuln_id": "V-281251",
	"stig_id": "RHEL-10-700420",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_rhel_10_700420,
	"fix_text": "Configure SELinux to be enabled: Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-10-700830 | V-281286 | CAT II
# The Ctrl-Alt-Delete graphical key sequence must be disabled
default ctrl_alt_del_graphical_disabled := false

ctrl_alt_del_graphical_disabled if {
	input.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "''"
}

ctrl_alt_del_graphical_disabled if {
	not input.packages["gnome-desktop3"]
}

status_rhel_10_700830 := "Not_a_Finding" if ctrl_alt_del_graphical_disabled

else := "Open"

finding_rhel_10_700830 := {
	"vuln_id": "V-281286",
	"stig_id": "RHEL-10-700830",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.",
	"status": status_rhel_10_700830,
	"fix_text": "Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
}

# RHEL-10-700400 | V-281249 | CAT II
# SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if {
	input.selinux.policy == "targeted"
}

status_rhel_10_700400 := "Not_a_Finding" if selinux_targeted

else := "Open"

finding_rhel_10_700400 := {
	"vuln_id": "V-281249",
	"stig_id": "RHEL-10-700400",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enable the SELinux targeted policy.",
	"status": status_rhel_10_700400,
	"fix_text": "Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-10-700040 | V-281227 | CAT II
# Must display the Standard Mandatory DoD Notice on login banner
default login_banner_set := false

login_banner_set if {
	contains(input.login_banner.issue, "You are accessing a U.S. Government")
}

login_banner_set if {
	contains(input.login_banner.issue, "authorized users only")
}

status_rhel_10_700040 := "Not_a_Finding" if login_banner_set

else := "Open"

finding_rhel_10_700040 := {
	"vuln_id": "V-281227",
	"stig_id": "RHEL-10-700040",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user login.",
	"status": status_rhel_10_700040,
	"fix_text": "Configure /etc/issue with the DoD warning banner text",
}

# RHEL-10-700010 | V-281224 | CAT II
# SSH must display banner before granting access
default ssh_banner_set := false

ssh_banner_set if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_rhel_10_700010 := "Not_a_Finding" if ssh_banner_set

else := "Open"

finding_rhel_10_700010 := {
	"vuln_id": "V-281224",
	"stig_id": "RHEL-10-700010",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a Secure Shell (SSH) login.",
	"status": status_rhel_10_700010,
	"fix_text": "Configure Banner in /etc/ssh/sshd_config to point to /etc/issue",
}

# RHEL-10-701130 | V-281315 | CAT II
# kernel.randomize_va_space must be set to 2
default aslr_enabled := false

aslr_enabled if {
	input.kernel_params["kernel.randomize_va_space"] == "2"
}

status_rhel_10_701130 := "Not_a_Finding" if aslr_enabled

else := "Open"

finding_rhel_10_701130 := {
	"vuln_id": "V-281315",
	"stig_id": "RHEL-10-701130",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_rhel_10_701130,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p",
}

# RHEL-10-701030 | V-281305 | CAT II
# kernel.dmesg_restrict must be set to 1
default dmesg_restricted := false

dmesg_restricted if {
	input.kernel_params["kernel.dmesg_restrict"] == "1"
}

status_rhel_10_701030 := "Not_a_Finding" if dmesg_restricted

else := "Open"

finding_rhel_10_701030 := {
	"vuln_id": "V-281305",
	"stig_id": "RHEL-10-701030",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must restrict access to the kernel message buffer.",
	"status": status_rhel_10_701030,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-701040 | V-281306 | CAT II
# kernel.perf_event_paranoid must be set to 2
default perf_event_restricted := false

perf_event_restricted if {
	to_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2
}

status_rhel_10_701040 := "Not_a_Finding" if perf_event_restricted

else := "Open"

finding_rhel_10_701040 := {
	"vuln_id": "V-281306",
	"stig_id": "RHEL-10-701040",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must prevent kernel profiling by nonprivileged users.",
	"status": status_rhel_10_701040,
	"fix_text": "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800030 | V-281335 | CAT II
# kernel.unprivileged_bpf_disabled must be set to 1
default bpf_restricted := false

bpf_restricted if {
	input.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"
}

status_rhel_10_800030 := "Not_a_Finding" if bpf_restricted

else := "Open"

finding_rhel_10_800030 := {
	"vuln_id": "V-281335",
	"stig_id": "RHEL-10-800030",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable access to the network bpf system call from nonprivileged processes.",
	"status": status_rhel_10_800030,
	"fix_text": "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800050 | V-281337 | CAT II
# net.core.bpf_jit_harden must be set to 2
default bpf_jit_hardened := false

bpf_jit_hardened if {
	input.kernel_params["net.core.bpf_jit_harden"] == "2"
}

status_rhel_10_800050 := "Not_a_Finding" if bpf_jit_hardened

else := "Open"

finding_rhel_10_800050 := {
	"vuln_id": "V-281337",
	"stig_id": "RHEL-10-800050",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enable hardening for the Berkeley Packet Filter (BPF) just-in-time compiler.",
	"status": status_rhel_10_800050,
	"fix_text": "Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-700850 | V-281288 | CAT II
# USB storage kernel module must be disabled
default usb_storage_disabled := false

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].status == "disabled"
}

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].blacklisted == true
}

status_rhel_10_700850 := "Not_a_Finding" if usb_storage_disabled

else := "Open"

finding_rhel_10_700850 := {
	"vuln_id": "V-281288",
	"stig_id": "RHEL-10-700850",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured to disable USB mass storage.",
	"status": status_rhel_10_700850,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-10-200633 | V-280980 | CAT II
# AIDE integrity checking cron job must exist
default aide_cron_configured := false

aide_cron_configured if {
	input.aide_config.cron_job == true
}

status_rhel_10_200633 := "Not_a_Finding" if aide_cron_configured

else := "Open"

finding_rhel_10_200633 := {
	"vuln_id": "V-280980",
	"stig_id": "RHEL-10-200633",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.",
	"status": status_rhel_10_200633,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
}

# RHEL-10-200630 | V-280977 | CAT II
# AIDE must be installed
default aide_installed := false

aide_installed if {
	input.packages.aide == true
}

status_rhel_10_200630 := "Not_a_Finding" if aide_installed

else := "Open"

finding_rhel_10_200630 := {
	"vuln_id": "V-280977",
	"stig_id": "RHEL-10-200630",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must have the Advanced Intrusion Detection Environment (AIDE) package installed.",
	"status": status_rhel_10_200630,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-10-000540 | V-280938 | CAT II
# /tmp must be on a separate partition
default tmp_separate_partition := false

tmp_separate_partition if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	mount.device != "tmpfs"
}

status_rhel_10_000540 := "Not_a_Finding" if tmp_separate_partition

else := "Open"

finding_rhel_10_000540 := {
	"vuln_id": "V-280938",
	"stig_id": "RHEL-10-000540",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must use a separate file system for \"/tmp\".",
	"status": status_rhel_10_000540,
	"fix_text": "Configure /tmp on a separate partition in /etc/fstab",
}

# RHEL-10-400355 | V-281088 | CAT II
# /tmp must have nodev option
default tmp_nodev := false

tmp_nodev if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nodev" in mount.options
}

status_rhel_10_400355 := "Not_a_Finding" if tmp_nodev

else := "Open"

finding_rhel_10_400355 := {
	"vuln_id": "V-281088",
	"stig_id": "RHEL-10-400355",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must prevent device files from being interpreted on file systems that contain user home directories.",
	"status": status_rhel_10_400355,
	"fix_text": "Add nodev option to /tmp in /etc/fstab",
}

# RHEL-10-400360 | V-281089 | CAT II
# /tmp must have nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nosuid" in mount.options
}

status_rhel_10_400360 := "Not_a_Finding" if tmp_nosuid

else := "Open"

finding_rhel_10_400360 := {
	"vuln_id": "V-281089",
	"stig_id": "RHEL-10-400360",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must prevent files with the \"setuid\" and \"setgid\" bit set from being executed on file systems that contain user home directories.",
	"status": status_rhel_10_400360,
	"fix_text": "Add nosuid option to /tmp in /etc/fstab",
}

# RHEL-10-400365 | V-281090 | CAT II
# /tmp must have noexec option
default tmp_noexec := false

tmp_noexec if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"noexec" in mount.options
}

status_rhel_10_400365 := "Not_a_Finding" if tmp_noexec

else := "Open"

finding_rhel_10_400365 := {
	"vuln_id": "V-281090",
	"stig_id": "RHEL-10-400365",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must prevent code from being executed on file systems that contain user home directories.",
	"status": status_rhel_10_400365,
	"fix_text": "Add noexec option to /tmp in /etc/fstab",
}

# RHEL-10-000560 | V-280940 | CAT II
# /var/log must be a separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_10_000560 := "Not_a_Finding" if var_log_separate

else := "Open"

finding_rhel_10_000560 := {
	"vuln_id": "V-280940",
	"stig_id": "RHEL-10-000560",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must use a separate file system for \"/var/log\".",
	"status": status_rhel_10_000560,
	"fix_text": "Configure /var/log on a separate partition",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# RHEL-10-000520 | V-280936 | CAT III
# /var/log/audit must be a separate partition
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_10_000520 := "Not_a_Finding" if var_log_audit_separate

else := "Open"

finding_rhel_10_000520 := {
	"vuln_id": "V-280936",
	"stig_id": "RHEL-10-000520",
	"severity": "CAT III",
	"rule_title": "RHEL 10 must use a separate file system for the system audit data path.",
	"status": status_rhel_10_000520,
	"fix_text": "Configure /var/log/audit on a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_10_700960,
	finding_rhel_10_000500,
	finding_rhel_10_300010,
]

cat_ii_findings := [
	finding_rhel_10_700420,
	finding_rhel_10_700830,
	finding_rhel_10_700400,
	finding_rhel_10_700040,
	finding_rhel_10_700010,
	finding_rhel_10_701130,
	finding_rhel_10_701030,
	finding_rhel_10_701040,
	finding_rhel_10_800030,
	finding_rhel_10_800050,
	finding_rhel_10_700850,
	finding_rhel_10_200633,
	finding_rhel_10_200630,
	finding_rhel_10_000540,
	finding_rhel_10_400355,
	finding_rhel_10_400360,
	finding_rhel_10_400365,
	finding_rhel_10_000560,
]

cat_iii_findings := [finding_rhel_10_000520]

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
