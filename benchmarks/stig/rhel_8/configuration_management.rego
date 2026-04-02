package stig.rhel_8.configuration_management

# DISA STIG for RHEL 8 - Configuration Management Module
# STIG Version: V1R13 | Released: July 2024
# Covers: System settings, kernel params, banners, SELinux, GRUB

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-08-010000 | V-230221 | CAT I - SELinux must be enforcing
default selinux_enforcing := false

selinux_enforcing if { input.selinux.status == "enforcing" }

status_rhel_08_010000 := "Not_a_Finding" if { selinux_enforcing } else := "Open"

finding_rhel_08_010000 := {
	"vuln_id": "V-230221",
	"stig_id": "RHEL-08-010000",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must enable SELinux in enforcing mode",
	"status": status_rhel_08_010000,
	"fix_text": "Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-08-010010 | V-230222 | CAT I - SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if { input.selinux.policy == "targeted" }

status_rhel_08_010010 := "Not_a_Finding" if { selinux_targeted } else := "Open"

finding_rhel_08_010010 := {
	"vuln_id": "V-230222",
	"stig_id": "RHEL-08-010010",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement the SELinux targeted policy",
	"status": status_rhel_08_010010,
	"fix_text": "Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-08-010020 | V-230223 | CAT I - FIPS must be enabled
default fips_mode := false

fips_mode if { input.fips_mode == true }

status_rhel_08_010020 := "Not_a_Finding" if { fips_mode } else := "Open"

finding_rhel_08_010020 := {
	"vuln_id": "V-230223",
	"stig_id": "RHEL-08-010020",
	"severity": "CAT I",
	"rule_title": "All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure",
	"status": status_rhel_08_010020,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable",
}

# RHEL-08-010030 | V-230224 | CAT I - GRUB password required
default grub_password := false

grub_password if { input.grub_config.password_set == true }

status_rhel_08_010030 := "Not_a_Finding" if { grub_password } else := "Open"

finding_rhel_08_010030 := {
	"vuln_id": "V-230224",
	"stig_id": "RHEL-08-010030",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must require authentication upon booting into single-user and maintenance modes",
	"status": status_rhel_08_010030,
	"fix_text": "Configure bootloader password: grub2-setpassword",
}

# RHEL-08-010040 | V-230225 | CAT I - Ctrl-Alt-Delete must be disabled
default ctrl_alt_del := false

ctrl_alt_del if { input.services["ctrl-alt-del.target"] == "masked" }

status_rhel_08_010040 := "Not_a_Finding" if { ctrl_alt_del } else := "Open"

finding_rhel_08_010040 := {
	"vuln_id": "V-230225",
	"stig_id": "RHEL-08-010040",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must disable the x86 Ctrl-Alt-Delete key sequence",
	"status": status_rhel_08_010040,
	"fix_text": "Disable Ctrl-Alt-Del: systemctl mask ctrl-alt-del.target",
}

# RHEL-08-010050 | V-230226 | CAT I - DoD Root CA must be installed
default dod_root_ca := false

dod_root_ca if { input.certificates.dod_root_ca_installed == true }

status_rhel_08_010050 := "Not_a_Finding" if { dod_root_ca } else := "Open"

finding_rhel_08_010050 := {
	"vuln_id": "V-230226",
	"stig_id": "RHEL-08-010050",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must have the DoD Root CA certificates installed as a trusted CA",
	"status": status_rhel_08_010050,
	"fix_text": "Install DoD Root CAs: trust anchor --store DoD_PKE_CA_chain.pem",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-010060 | V-230227 | CAT II - Crypto policy must not be LEGACY
default no_legacy_crypto := false

no_legacy_crypto if { input.crypto_policy != "LEGACY" }
no_legacy_crypto if { not input.crypto_policy }

status_rhel_08_010060 := "Not_a_Finding" if { no_legacy_crypto } else := "Open"

finding_rhel_08_010060 := {
	"vuln_id": "V-230227",
	"stig_id": "RHEL-08-010060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must ensure system-wide crypto policy is not set to legacy",
	"status": status_rhel_08_010060,
	"fix_text": "Set crypto policy: update-crypto-policies --set FIPS",
}

# RHEL-08-010070 | V-230228 | CAT II - Login banner required
default login_banner := false

login_banner if { contains(input.login_banner.issue, "U.S. Government") }
login_banner if { contains(input.login_banner.issue, "authorized users") }

status_rhel_08_010070 := "Not_a_Finding" if { login_banner } else := "Open"

finding_rhel_08_010070 := {
	"vuln_id": "V-230228",
	"stig_id": "RHEL-08-010070",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting access",
	"status": status_rhel_08_010070,
	"fix_text": "Configure DoD banner in /etc/issue",
}

# RHEL-08-010080 | V-230229 | CAT II - ASLR must be enabled
default aslr_enabled := false

aslr_enabled if { input.kernel_params["kernel.randomize_va_space"] == "2" }

status_rhel_08_010080 := "Not_a_Finding" if { aslr_enabled } else := "Open"

finding_rhel_08_010080 := {
	"vuln_id": "V-230229",
	"stig_id": "RHEL-08-010080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must implement address space layout randomization (ASLR)",
	"status": status_rhel_08_010080,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-010090 | V-230230 | CAT II - dmesg restrict must be 1
default dmesg_restrict := false

dmesg_restrict if { input.kernel_params["kernel.dmesg_restrict"] == "1" }

status_rhel_08_010090 := "Not_a_Finding" if { dmesg_restrict } else := "Open"

finding_rhel_08_010090 := {
	"vuln_id": "V-230230",
	"stig_id": "RHEL-08-010090",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must restrict access to the kernel message buffer",
	"status": status_rhel_08_010090,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-010100 | V-230231 | CAT II - USB storage must be disabled
default usb_storage_disabled := false

usb_storage_disabled if { input.kernel_modules["usb-storage"].blacklisted == true }
usb_storage_disabled if { input.kernel_modules["usb-storage"].status == "disabled" }

status_rhel_08_010100 := "Not_a_Finding" if { usb_storage_disabled } else := "Open"

finding_rhel_08_010100 := {
	"vuln_id": "V-230231",
	"stig_id": "RHEL-08-010100",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable the USB mass storage kernel module",
	"status": status_rhel_08_010100,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-08-010110 | V-230232 | CAT II - AIDE must be installed
default aide_installed := false

aide_installed if { input.packages.aide == true }

status_rhel_08_010110 := "Not_a_Finding" if { aide_installed } else := "Open"

finding_rhel_08_010110 := {
	"vuln_id": "V-230232",
	"stig_id": "RHEL-08-010110",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a file integrity tool",
	"status": status_rhel_08_010110,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-08-010120 | V-230233 | CAT II - AIDE cron job must exist
default aide_cron := false

aide_cron if { input.aide_config.cron_job == true }

status_rhel_08_010120 := "Not_a_Finding" if { aide_cron } else := "Open"

finding_rhel_08_010120 := {
	"vuln_id": "V-230233",
	"stig_id": "RHEL-08-010120",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must routinely check the baseline configuration for unauthorized changes",
	"status": status_rhel_08_010120,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * root /usr/sbin/aide --check' > /etc/cron.d/aide",
}

# RHEL-08-010130 | V-230234 | CAT II - /tmp must be separate partition
default tmp_separate := false

tmp_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
}

status_rhel_08_010130 := "Not_a_Finding" if { tmp_separate } else := "Open"

finding_rhel_08_010130 := {
	"vuln_id": "V-230234",
	"stig_id": "RHEL-08-010130",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a separate file system for /tmp",
	"status": status_rhel_08_010130,
	"fix_text": "Configure /tmp as a separate partition",
}

# RHEL-08-010140 | V-230235 | CAT II - /var/log must be separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_08_010140 := "Not_a_Finding" if { var_log_separate } else := "Open"

finding_rhel_08_010140 := {
	"vuln_id": "V-230235",
	"stig_id": "RHEL-08-010140",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a separate file system for /var/log",
	"status": status_rhel_08_010140,
	"fix_text": "Configure /var/log as a separate partition",
}

# RHEL-08-010150 | V-230236 | CAT II - /var/log/audit must be separate
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_08_010150 := "Not_a_Finding" if { var_log_audit_separate } else := "Open"

finding_rhel_08_010150 := {
	"vuln_id": "V-230236",
	"stig_id": "RHEL-08-010150",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a separate file system for /var/log/audit",
	"status": status_rhel_08_010150,
	"fix_text": "Configure /var/log/audit as a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_010000,
	finding_rhel_08_010010,
	finding_rhel_08_010020,
	finding_rhel_08_010030,
	finding_rhel_08_010040,
	finding_rhel_08_010050,
]

cat_ii_findings := [
	finding_rhel_08_010060,
	finding_rhel_08_010070,
	finding_rhel_08_010080,
	finding_rhel_08_010090,
	finding_rhel_08_010100,
	finding_rhel_08_010110,
	finding_rhel_08_010120,
	finding_rhel_08_010130,
	finding_rhel_08_010140,
	finding_rhel_08_010150,
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

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "configuration_management",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
