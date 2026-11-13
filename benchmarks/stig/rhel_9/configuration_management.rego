# METADATA
# title: "DISA STIG for RHEL 9 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 25
#     cited: 24
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.configuration_management

# DISA STIG for RHEL 9 - Configuration Management Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: System settings, kernel params, banners, SELinux, GRUB, CTL-ALT-DEL

import rego.v1

# =============================================================================
# HELPER DEFAULTS
# =============================================================================

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY FINDINGS
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-211050 | V-257785 | CAT I
# Ctrl-Alt-Delete key sequence must be disabled
default ctrl_alt_del_disabled := false

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "masked"
}

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "inactive"
	input.kernel_params["kernel.ctrl-alt-del"] == "0"
}

status_rhel_09_211050 := "Not_a_Finding" if ctrl_alt_del_disabled

else := "Open"

finding_rhel_09_211050 := {
	"vuln_id": "V-257785",
	"stig_id": "RHEL-09-211050",
	"severity": "CAT I",
	"rule_title": "The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 9.",
	"status": status_rhel_09_211050,
	"fix_text": "Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target",
}

# RHEL-09-431010 | V-258078 | CAT I
# SELinux must be enabled in enforcing mode
default selinux_enforcing := false

selinux_enforcing if {
	input.selinux.status == "enforcing"
}

status_rhel_09_431010 := "Not_a_Finding" if selinux_enforcing

else := "Open"

finding_rhel_09_431010 := {
	"vuln_id": "V-258078",
	"stig_id": "RHEL-09-431010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_rhel_09_431010,
	"fix_text": "Configure SELinux to be enabled: Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-09-671010 | V-258230 | CAT I
# FIPS mode must be enabled
default fips_mode_enabled := false

fips_mode_enabled if {
	input.fips_mode == true
}

status_rhel_09_671010 := "Not_a_Finding" if fips_mode_enabled

else := "Open"

finding_rhel_09_671010 := {
	"vuln_id": "V-258230",
	"stig_id": "RHEL-09-671010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must enable FIPS mode.",
	"status": status_rhel_09_671010,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable && reboot",
}

# RHEL-09-215105 | V-258241 | CAT I
# System crypto policy must be FIPS
default crypto_policy_fips := false

crypto_policy_fips if {
	input.crypto_policy == "FIPS"
}

crypto_policy_fips if {
	input.crypto_policy == "FIPS:OSPP"
}

status_rhel_09_215105 := "Not_a_Finding" if crypto_policy_fips

else := "Open"

finding_rhel_09_215105 := {
	"vuln_id": "V-258241",
	"stig_id": "RHEL-09-215105",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement a FIPS 140-3-compliant systemwide cryptographic policy.",
	"status": status_rhel_09_215105,
	"fix_text": "Set the crypto policy: update-crypto-policies --set FIPS",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-271105 | V-258031 | CAT II
# The Ctrl-Alt-Delete graphical key sequence must be disabled
default ctrl_alt_del_graphical_disabled := false

ctrl_alt_del_graphical_disabled if {
	input.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "''"
}

ctrl_alt_del_graphical_disabled if {
	is_object(input.packages)
	not input.packages["gnome-desktop3"]
}

status_rhel_09_271105 := "Not_a_Finding" if ctrl_alt_del_graphical_disabled

else := "Open"

finding_rhel_09_271105 := {
	"vuln_id": "V-258031",
	"stig_id": "RHEL-09-271105",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.",
	"status": status_rhel_09_271105,
	"fix_text": "Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
}

# RHEL-09-431015 | V-258079 | CAT II
# SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if {
	input.selinux.policy == "targeted"
}

status_rhel_09_431015 := "Not_a_Finding" if selinux_targeted

else := "Open"

finding_rhel_09_431015 := {
	"vuln_id": "V-258079",
	"stig_id": "RHEL-09-431015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable the SELinux targeted policy.",
	"status": status_rhel_09_431015,
	"fix_text": "Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-09-212010 | V-257787 | CAT II
# GRUB bootloader must be password protected
default grub_password_set := false

grub_password_set if {
	input.grub_config.password_set == true
}

status_rhel_09_212010 := "Not_a_Finding" if grub_password_set

else := "Open"

finding_rhel_09_212010 := {
	"vuln_id": "V-257787",
	"stig_id": "RHEL-09-212010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must require authentication upon booting into single-user and maintenance modes.",
	"status": status_rhel_09_212010,
	"fix_text": "Configure a bootloader password: grub2-setpassword",
}

# RHEL-09-211020 | V-257779 | CAT II
# Must display the Standard Mandatory DoD Notice on login banner
default login_banner_set := false

login_banner_set if {
	contains(input.login_banner.issue, "You are accessing a U.S. Government")
}

login_banner_set if {
	contains(input.login_banner.issue, "authorized users only")
}

status_rhel_09_211020 := "Not_a_Finding" if login_banner_set

else := "Open"

finding_rhel_09_211020 := {
	"vuln_id": "V-257779",
	"stig_id": "RHEL-09-211020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon.",
	"status": status_rhel_09_211020,
	"fix_text": "Configure /etc/issue with the DoD warning banner text",
}

# RHEL-09-255025 | V-257981 | CAT II
# SSH must display banner before granting access
default ssh_banner_set := false

ssh_banner_set if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_rhel_09_255025 := "Not_a_Finding" if ssh_banner_set

else := "Open"

finding_rhel_09_255025 := {
	"vuln_id": "V-257981",
	"stig_id": "RHEL-09-255025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a SSH logon.",
	"status": status_rhel_09_255025,
	"fix_text": "Configure Banner in /etc/ssh/sshd_config to point to /etc/issue",
}

# RHEL-09-213070 | V-257809 | CAT II
# kernel.randomize_va_space must be set to 2
default aslr_enabled := false

aslr_enabled if {
	input.kernel_params["kernel.randomize_va_space"] == "2"
}

status_rhel_09_213070 := "Not_a_Finding" if aslr_enabled

else := "Open"

finding_rhel_09_213070 := {
	"vuln_id": "V-257809",
	"stig_id": "RHEL-09-213070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_rhel_09_213070,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p",
}

# RHEL-09-213010 | V-257797 | CAT II
# kernel.dmesg_restrict must be set to 1
default dmesg_restricted := false

dmesg_restricted if {
	input.kernel_params["kernel.dmesg_restrict"] == "1"
}

status_rhel_09_213010 := "Not_a_Finding" if dmesg_restricted

else := "Open"

finding_rhel_09_213010 := {
	"vuln_id": "V-257797",
	"stig_id": "RHEL-09-213010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must restrict access to the kernel message buffer.",
	"status": status_rhel_09_213010,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-213015 | V-257798 | CAT II
# kernel.perf_event_paranoid must be set to 2
default perf_event_restricted := false

perf_event_restricted if {
	to_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2
}

status_rhel_09_213015 := "Not_a_Finding" if perf_event_restricted

else := "Open"

finding_rhel_09_213015 := {
	"vuln_id": "V-257798",
	"stig_id": "RHEL-09-213015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent kernel profiling by nonprivileged users.",
	"status": status_rhel_09_213015,
	"fix_text": "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-213075 | V-257810 | CAT II
# kernel.unprivileged_bpf_disabled must be set to 1
default bpf_restricted := false

bpf_restricted if {
	input.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"
}

status_rhel_09_213075 := "Not_a_Finding" if bpf_restricted

else := "Open"

finding_rhel_09_213075 := {
	"vuln_id": "V-257810",
	"stig_id": "RHEL-09-213075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable access to network bpf system call from nonprivileged processes.",
	"status": status_rhel_09_213075,
	"fix_text": "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251045 | V-257942 | CAT II
# net.core.bpf_jit_harden must be set to 2
default bpf_jit_hardened := false

bpf_jit_hardened if {
	input.kernel_params["net.core.bpf_jit_harden"] == "2"
}

status_rhel_09_251045 := "Not_a_Finding" if bpf_jit_hardened

else := "Open"

finding_rhel_09_251045 := {
	"vuln_id": "V-257942",
	"stig_id": "RHEL-09-251045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable hardening for the Berkeley Packet Filter just-in-time compiler.",
	"status": status_rhel_09_251045,
	"fix_text": "Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-291010 | V-258034 | CAT II
# USB storage kernel module must be disabled
default usb_storage_disabled := false

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].status == "disabled"
}

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].blacklisted == true
}

status_rhel_09_291010 := "Not_a_Finding" if usb_storage_disabled

else := "Open"

finding_rhel_09_291010 := {
	"vuln_id": "V-258034",
	"stig_id": "RHEL-09-291010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured to disable USB mass storage.",
	"status": status_rhel_09_291010,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-09-213055 | V-257806 | CAT II
# Firewire kernel module must be disabled
default firewire_disabled := false

firewire_disabled if {
	input.kernel_modules["firewire-core"].status == "disabled"
}

firewire_disabled if {
	input.kernel_modules["firewire-core"].blacklisted == true
}

status_rhel_09_213055 := "Not_a_Finding" if firewire_disabled

else := "Open"

finding_rhel_09_213055 := {
	"vuln_id": "V-257806",
	"stig_id": "RHEL-09-213055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured to disable the FireWire kernel module.",
	"status": status_rhel_09_213055,
	"fix_text": "Disable Firewire: echo 'install firewire-core /bin/false' >> /etc/modprobe.d/firewire.conf",
}

# RHEL-09-651015 | V-258135 | CAT II
# AIDE integrity checking cron job must exist
default aide_cron_configured := false

aide_cron_configured if {
	input.aide_config.cron_job == true
}

status_rhel_09_651015 := "Not_a_Finding" if aide_cron_configured

else := "Open"

finding_rhel_09_651015 := {
	"vuln_id": "V-258135",
	"stig_id": "RHEL-09-651015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.",
	"status": status_rhel_09_651015,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
}

# RHEL-09-651010 | V-258134 | CAT II
# AIDE must be installed
default aide_installed := false

aide_installed if {
	input.packages.aide == true
}

status_rhel_09_651010 := "Not_a_Finding" if aide_installed

else := "Open"

finding_rhel_09_651010 := {
	"vuln_id": "V-258134",
	"stig_id": "RHEL-09-651010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have the AIDE package installed.",
	"status": status_rhel_09_651010,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-09-231015 | V-257844 | CAT II
# /tmp must be on a separate partition
default tmp_separate_partition := false

tmp_separate_partition if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	mount.device != "tmpfs"
}

status_rhel_09_231015 := "Not_a_Finding" if tmp_separate_partition

else := "Open"

finding_rhel_09_231015 := {
	"vuln_id": "V-257844",
	"stig_id": "RHEL-09-231015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a separate file system for /tmp.",
	"status": status_rhel_09_231015,
	"fix_text": "Configure /tmp on a separate partition in /etc/fstab",
}

# RHEL-09-231045 | V-257850 | CAT II
# /tmp must have nodev option
default tmp_nodev := false

tmp_nodev if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nodev" in mount.options
}

status_rhel_09_231045 := "Not_a_Finding" if tmp_nodev

else := "Open"

finding_rhel_09_231045 := {
	"vuln_id": "V-257850",
	"stig_id": "RHEL-09-231045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent device files from being interpreted on file systems that contain user home directories.",
	"status": status_rhel_09_231045,
	"fix_text": "Add nodev option to /tmp in /etc/fstab",
}

# RHEL-09-231050 | V-257851 | CAT II
# /tmp must have nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nosuid" in mount.options
}

status_rhel_09_231050 := "Not_a_Finding" if tmp_nosuid

else := "Open"

finding_rhel_09_231050 := {
	"vuln_id": "V-257851",
	"stig_id": "RHEL-09-231050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.",
	"status": status_rhel_09_231050,
	"fix_text": "Add nosuid option to /tmp in /etc/fstab",
}

# RHEL-09-231055 | V-257852 | CAT II
# /tmp must have noexec option
default tmp_noexec := false

tmp_noexec if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"noexec" in mount.options
}

status_rhel_09_231055 := "Not_a_Finding" if tmp_noexec

else := "Open"

finding_rhel_09_231055 := {
	"vuln_id": "V-257852",
	"stig_id": "RHEL-09-231055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent code from being executed on file systems that contain user home directories.",
	"status": status_rhel_09_231055,
	"fix_text": "Add noexec option to /tmp in /etc/fstab",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# RHEL-09-231025 | V-257846 | CAT III
# /var/log must be a separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_09_231025 := "Not_a_Finding" if var_log_separate

else := "Open"

finding_rhel_09_231025 := {
	"vuln_id": "V-257846",
	"stig_id": "RHEL-09-231025",
	"severity": "CAT III",
	"rule_title": "RHEL 9 must use a separate file system for /var/log.",
	"status": status_rhel_09_231025,
	"fix_text": "Configure /var/log on a separate partition",
}

# RHEL-09-231030 | V-257847 | CAT III
# /var/log/audit must be a separate partition
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_09_231030 := "Not_a_Finding" if var_log_audit_separate

else := "Open"

finding_rhel_09_231030 := {
	"vuln_id": "V-257847",
	"stig_id": "RHEL-09-231030",
	"severity": "CAT III",
	"rule_title": "RHEL 9 must use a separate file system for the system audit data path.",
	"status": status_rhel_09_231030,
	"fix_text": "Configure /var/log/audit on a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_211050,
	finding_rhel_09_431010,
	finding_rhel_09_671010,
	finding_rhel_09_215105,
]

cat_ii_findings := [
	finding_rhel_09_271105,
	finding_rhel_09_431015,
	finding_rhel_09_212010,
	finding_rhel_09_211020,
	finding_rhel_09_255025,
	finding_rhel_09_213070,
	finding_rhel_09_213010,
	finding_rhel_09_213015,
	finding_rhel_09_213075,
	finding_rhel_09_251045,
	finding_rhel_09_291010,
	finding_rhel_09_213055,
	finding_rhel_09_651015,
	finding_rhel_09_651010,
	finding_rhel_09_231015,
	finding_rhel_09_231045,
	finding_rhel_09_231050,
	finding_rhel_09_231055,
]

cat_iii_findings := [
	finding_rhel_09_231025,
	finding_rhel_09_231030,
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
