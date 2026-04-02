package stig.rhel_9.configuration_management

# DISA STIG for RHEL 9 - Configuration Management Module
# STIG Version: V2R2 | Released: October 2024
# Covers: System settings, kernel params, banners, SELinux, GRUB, CTL-ALT-DEL

import rego.v1

# =============================================================================
# HELPER DEFAULTS
# =============================================================================

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY FINDINGS
# =============================================================================

# RHEL-09-211010 | V-257777 | CAT I
# Ctrl-Alt-Delete key sequence must be disabled
default ctrl_alt_del_disabled := false

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "masked"
}

ctrl_alt_del_disabled if {
	input.services["ctrl-alt-del.target"] == "inactive"
	input.kernel_params["kernel.ctrl-alt-del"] == "0"
}

status_rhel_09_211010 := "Not_a_Finding" if { ctrl_alt_del_disabled } else := "Open"

finding_rhel_09_211010 := {
	"vuln_id": "V-257777",
	"stig_id": "RHEL-09-211010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled",
	"status": status_rhel_09_211010,
	"fix_text": "Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target",
}

# RHEL-09-211015 | V-257778 | CAT I
# The Ctrl-Alt-Delete graphical key sequence must be disabled
default ctrl_alt_del_graphical_disabled := false

ctrl_alt_del_graphical_disabled if {
	input.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "''"
}

ctrl_alt_del_graphical_disabled if {
	not input.packages["gnome-desktop3"]
}

status_rhel_09_211015 := "Not_a_Finding" if { ctrl_alt_del_graphical_disabled } else := "Open"

finding_rhel_09_211015 := {
	"vuln_id": "V-257778",
	"stig_id": "RHEL-09-211015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must be configured so that the x86 Ctrl-Alt-Delete graphical key sequence is disabled",
	"status": status_rhel_09_211015,
	"fix_text": "Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
}

# RHEL-09-211020 | V-257779 | CAT I
# SELinux must be enabled in enforcing mode
default selinux_enforcing := false

selinux_enforcing if {
	input.selinux.status == "enforcing"
}

status_rhel_09_211020 := "Not_a_Finding" if { selinux_enforcing } else := "Open"

finding_rhel_09_211020 := {
	"vuln_id": "V-257779",
	"stig_id": "RHEL-09-211020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must enable SELinux",
	"status": status_rhel_09_211020,
	"fix_text": "Configure SELinux to be enabled: Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-09-211025 | V-257780 | CAT I
# SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if {
	input.selinux.policy == "targeted"
}

status_rhel_09_211025 := "Not_a_Finding" if { selinux_targeted } else := "Open"

finding_rhel_09_211025 := {
	"vuln_id": "V-257780",
	"stig_id": "RHEL-09-211025",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement the SELinux targeted policy",
	"status": status_rhel_09_211025,
	"fix_text": "Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-09-211030 | V-257781 | CAT I
# GRUB bootloader must be password protected
default grub_password_set := false

grub_password_set if {
	input.grub_config.password_set == true
}

status_rhel_09_211030 := "Not_a_Finding" if { grub_password_set } else := "Open"

finding_rhel_09_211030 := {
	"vuln_id": "V-257781",
	"stig_id": "RHEL-09-211030",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must require authentication upon booting into single-user and maintenance modes",
	"status": status_rhel_09_211030,
	"fix_text": "Configure a bootloader password: grub2-setpassword",
}

# RHEL-09-211040 | V-257783 | CAT I
# Must use DoD-approved DoD Root CA
default dod_root_ca_installed := false

dod_root_ca_installed if {
	input.certificates.dod_root_ca_installed == true
}

status_rhel_09_211040 := "Not_a_Finding" if { dod_root_ca_installed } else := "Open"

finding_rhel_09_211040 := {
	"vuln_id": "V-257783",
	"stig_id": "RHEL-09-211040",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have the DoD Root Certificate Authority (CA) installed as a trusted CA",
	"status": status_rhel_09_211040,
	"fix_text": "Install DoD Root CA certificates: trust anchor --store /path/to/DoD_PKE_CA_chain.pem",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY FINDINGS
# =============================================================================

# RHEL-09-211050 | V-257784 | CAT II
# FIPS mode must be enabled
default fips_mode_enabled := false

fips_mode_enabled if {
	input.fips_mode == true
}

status_rhel_09_211050 := "Not_a_Finding" if { fips_mode_enabled } else := "Open"

finding_rhel_09_211050 := {
	"vuln_id": "V-257784",
	"stig_id": "RHEL-09-211050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws",
	"status": status_rhel_09_211050,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable && reboot",
}

# RHEL-09-211060 | V-257785 | CAT II
# System crypto policy must be FIPS
default crypto_policy_fips := false

crypto_policy_fips if {
	input.crypto_policy == "FIPS"
}

crypto_policy_fips if {
	input.crypto_policy == "FIPS:OSPP"
}

status_rhel_09_211060 := "Not_a_Finding" if { crypto_policy_fips } else := "Open"

finding_rhel_09_211060 := {
	"vuln_id": "V-257785",
	"stig_id": "RHEL-09-211060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a Linux Security Module configured to enforce limits on system services",
	"status": status_rhel_09_211060,
	"fix_text": "Set the crypto policy: update-crypto-policies --set FIPS",
}

# RHEL-09-212010 | V-257795 | CAT II
# Must display the Standard Mandatory DoD Notice on login banner
default login_banner_set := false

login_banner_set if {
	contains(input.login_banner.issue, "You are accessing a U.S. Government")
}

login_banner_set if {
	contains(input.login_banner.issue, "authorized users only")
}

status_rhel_09_212010 := "Not_a_Finding" if { login_banner_set } else := "Open"

finding_rhel_09_212010 := {
	"vuln_id": "V-257795",
	"stig_id": "RHEL-09-212010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system",
	"status": status_rhel_09_212010,
	"fix_text": "Configure /etc/issue with the DoD warning banner text",
}

# RHEL-09-212020 | V-257796 | CAT II
# SSH must display banner before granting access
default ssh_banner_set := false

ssh_banner_set if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_rhel_09_212020 := "Not_a_Finding" if { ssh_banner_set } else := "Open"

finding_rhel_09_212020 := {
	"vuln_id": "V-257796",
	"stig_id": "RHEL-09-212020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must display the Standard Mandatory DoD Notice and Consent Banner before granting access via SSH",
	"status": status_rhel_09_212020,
	"fix_text": "Configure Banner in /etc/ssh/sshd_config to point to /etc/issue",
}

# RHEL-09-213010 | V-257800 | CAT II
# kernel.randomize_va_space must be set to 2
default aslr_enabled := false

aslr_enabled if {
	input.kernel_params["kernel.randomize_va_space"] == "2"
}

status_rhel_09_213010 := "Not_a_Finding" if { aslr_enabled } else := "Open"

finding_rhel_09_213010 := {
	"vuln_id": "V-257800",
	"stig_id": "RHEL-09-213010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must implement address space layout randomization (ASLR)",
	"status": status_rhel_09_213010,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p",
}

# RHEL-09-213020 | V-257801 | CAT II
# kernel.dmesg_restrict must be set to 1
default dmesg_restricted := false

dmesg_restricted if {
	input.kernel_params["kernel.dmesg_restrict"] == "1"
}

status_rhel_09_213020 := "Not_a_Finding" if { dmesg_restricted } else := "Open"

finding_rhel_09_213020 := {
	"vuln_id": "V-257801",
	"stig_id": "RHEL-09-213020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must restrict access to the kernel message buffer",
	"status": status_rhel_09_213020,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-213025 | V-257802 | CAT II
# kernel.perf_event_paranoid must be set to 2
default perf_event_restricted := false

perf_event_restricted if {
	to_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2
}

status_rhel_09_213025 := "Not_a_Finding" if { perf_event_restricted } else := "Open"

finding_rhel_09_213025 := {
	"vuln_id": "V-257802",
	"stig_id": "RHEL-09-213025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must restrict usage of ptrace to descendant processes",
	"status": status_rhel_09_213025,
	"fix_text": "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-213030 | V-257803 | CAT II
# kernel.unprivileged_bpf_disabled must be set to 1
default bpf_restricted := false

bpf_restricted if {
	input.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"
}

status_rhel_09_213030 := "Not_a_Finding" if { bpf_restricted } else := "Open"

finding_rhel_09_213030 := {
	"vuln_id": "V-257803",
	"stig_id": "RHEL-09-213030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent the loading of a new kernel for later execution",
	"status": status_rhel_09_213030,
	"fix_text": "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-213035 | V-257804 | CAT II
# net.core.bpf_jit_harden must be set to 2
default bpf_jit_hardened := false

bpf_jit_hardened if {
	input.kernel_params["net.core.bpf_jit_harden"] == "2"
}

status_rhel_09_213035 := "Not_a_Finding" if { bpf_jit_hardened } else := "Open"

finding_rhel_09_213035 := {
	"vuln_id": "V-257804",
	"stig_id": "RHEL-09-213035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable kernel harden for the BPF JIT compiler",
	"status": status_rhel_09_213035,
	"fix_text": "Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-214010 | V-257808 | CAT II
# USB storage kernel module must be disabled
default usb_storage_disabled := false

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].status == "disabled"
}

usb_storage_disabled if {
	input.kernel_modules["usb-storage"].blacklisted == true
}

status_rhel_09_214010 := "Not_a_Finding" if { usb_storage_disabled } else := "Open"

finding_rhel_09_214010 := {
	"vuln_id": "V-257808",
	"stig_id": "RHEL-09-214010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the usbguard service unless USB is required",
	"status": status_rhel_09_214010,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-09-214015 | V-257809 | CAT II
# Firewire kernel module must be disabled
default firewire_disabled := false

firewire_disabled if {
	input.kernel_modules["firewire-core"].status == "disabled"
}

firewire_disabled if {
	input.kernel_modules["firewire-core"].blacklisted == true
}

status_rhel_09_214015 := "Not_a_Finding" if { firewire_disabled } else := "Open"

finding_rhel_09_214015 := {
	"vuln_id": "V-257809",
	"stig_id": "RHEL-09-214015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the IEEE 1394 (Firewire) kernel module",
	"status": status_rhel_09_214015,
	"fix_text": "Disable Firewire: echo 'install firewire-core /bin/false' >> /etc/modprobe.d/firewire.conf",
}

# RHEL-09-215010 | V-257815 | CAT II
# AIDE integrity checking cron job must exist
default aide_cron_configured := false

aide_cron_configured if {
	input.aide_config.cron_job == true
}

status_rhel_09_215010 := "Not_a_Finding" if { aide_cron_configured } else := "Open"

finding_rhel_09_215010 := {
	"vuln_id": "V-257815",
	"stig_id": "RHEL-09-215010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered",
	"status": status_rhel_09_215010,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
}

# RHEL-09-215015 | V-257816 | CAT II
# AIDE must be installed
default aide_installed := false

aide_installed if {
	input.packages.aide == true
}

status_rhel_09_215015 := "Not_a_Finding" if { aide_installed } else := "Open"

finding_rhel_09_215015 := {
	"vuln_id": "V-257816",
	"stig_id": "RHEL-09-215015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories",
	"status": status_rhel_09_215015,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-09-231010 | V-257825 | CAT II
# /tmp must be on a separate partition
default tmp_separate_partition := false

tmp_separate_partition if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	mount.device != "tmpfs"
}

status_rhel_09_231010 := "Not_a_Finding" if { tmp_separate_partition } else := "Open"

finding_rhel_09_231010 := {
	"vuln_id": "V-257825",
	"stig_id": "RHEL-09-231010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a separate file system for /tmp",
	"status": status_rhel_09_231010,
	"fix_text": "Configure /tmp on a separate partition in /etc/fstab",
}

# RHEL-09-231015 | V-257826 | CAT II
# /tmp must have nodev option
default tmp_nodev := false

tmp_nodev if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nodev" in mount.options
}

status_rhel_09_231015 := "Not_a_Finding" if { tmp_nodev } else := "Open"

finding_rhel_09_231015 := {
	"vuln_id": "V-257826",
	"stig_id": "RHEL-09-231015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent device files from being interpreted on file systems that contain user home directories",
	"status": status_rhel_09_231015,
	"fix_text": "Add nodev option to /tmp in /etc/fstab",
}

# RHEL-09-231020 | V-257827 | CAT II
# /tmp must have nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"nosuid" in mount.options
}

status_rhel_09_231020 := "Not_a_Finding" if { tmp_nosuid } else := "Open"

finding_rhel_09_231020 := {
	"vuln_id": "V-257827",
	"stig_id": "RHEL-09-231020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories",
	"status": status_rhel_09_231020,
	"fix_text": "Add nosuid option to /tmp in /etc/fstab",
}

# RHEL-09-231025 | V-257828 | CAT II
# /tmp must have noexec option
default tmp_noexec := false

tmp_noexec if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
	"noexec" in mount.options
}

status_rhel_09_231025 := "Not_a_Finding" if { tmp_noexec } else := "Open"

finding_rhel_09_231025 := {
	"vuln_id": "V-257828",
	"stig_id": "RHEL-09-231025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent code from being executed on file system that contains user home directories",
	"status": status_rhel_09_231025,
	"fix_text": "Add noexec option to /tmp in /etc/fstab",
}

# RHEL-09-231180 | V-257865 | CAT II
# /var/log must be a separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_09_231180 := "Not_a_Finding" if { var_log_separate } else := "Open"

finding_rhel_09_231180 := {
	"vuln_id": "V-257865",
	"stig_id": "RHEL-09-231180",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a separate file system for /var/log",
	"status": status_rhel_09_231180,
	"fix_text": "Configure /var/log on a separate partition",
}

# RHEL-09-231190 | V-257866 | CAT II
# /var/log/audit must be a separate partition
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_09_231190 := "Not_a_Finding" if { var_log_audit_separate } else := "Open"

finding_rhel_09_231190 := {
	"vuln_id": "V-257866",
	"stig_id": "RHEL-09-231190",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a separate file system for /var/log/audit",
	"status": status_rhel_09_231190,
	"fix_text": "Configure /var/log/audit on a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_211010,
	finding_rhel_09_211015,
	finding_rhel_09_211020,
	finding_rhel_09_211025,
	finding_rhel_09_211030,
	finding_rhel_09_211040,
]

cat_ii_findings := [
	finding_rhel_09_211050,
	finding_rhel_09_211060,
	finding_rhel_09_212010,
	finding_rhel_09_212020,
	finding_rhel_09_213010,
	finding_rhel_09_213020,
	finding_rhel_09_213025,
	finding_rhel_09_213030,
	finding_rhel_09_213035,
	finding_rhel_09_214010,
	finding_rhel_09_214015,
	finding_rhel_09_215010,
	finding_rhel_09_215015,
	finding_rhel_09_231010,
	finding_rhel_09_231015,
	finding_rhel_09_231020,
	finding_rhel_09_231025,
	finding_rhel_09_231180,
	finding_rhel_09_231190,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

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
