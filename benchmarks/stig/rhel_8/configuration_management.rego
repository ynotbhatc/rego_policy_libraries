# METADATA
# title: "DISA STIG for RHEL 8 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 16
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.configuration_management

# DISA STIG for RHEL 8 - Configuration Management Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: System settings, kernel params, banners, SELinux, GRUB

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-08-010020 | V-230223 | CAT I - FIPS must be enabled
default fips_mode := false

fips_mode if input.fips_mode == true

status_rhel_08_010020 := "Not_a_Finding" if fips_mode

else := "Open"

finding_rhel_08_010020 := {
	"vuln_id": "V-230223",
	"stig_id": "RHEL-08-010020",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement a FIPS 140-3-compliant systemwide cryptographic policy.",
	"status": status_rhel_08_010020,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable",
}

# RHEL-08-010150 | V-230235 | CAT I - GRUB password required
default grub_password := false

grub_password if input.grub_config.password_set == true

status_rhel_08_010150 := "Not_a_Finding" if grub_password

else := "Open"

finding_rhel_08_010150 := {
	"vuln_id": "V-230235",
	"stig_id": "RHEL-08-010150",
	"severity": "CAT I",
	"rule_title": "RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.",
	"status": status_rhel_08_010150,
	"fix_text": "Configure bootloader password: grub2-setpassword",
}

# RHEL-08-040170 | V-230529 | CAT I - Ctrl-Alt-Delete must be disabled
default ctrl_alt_del := false

ctrl_alt_del if input.services["ctrl-alt-del.target"] == "masked"

status_rhel_08_040170 := "Not_a_Finding" if ctrl_alt_del

else := "Open"

finding_rhel_08_040170 := {
	"vuln_id": "V-230529",
	"stig_id": "RHEL-08-040170",
	"severity": "CAT I",
	"rule_title": "The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 8.",
	"status": status_rhel_08_040170,
	"fix_text": "Disable Ctrl-Alt-Del: systemctl mask ctrl-alt-del.target",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-010170 | V-230240 | CAT II - SELinux must be enforcing
default selinux_enforcing := false

selinux_enforcing if input.selinux.status == "enforcing"

status_rhel_08_010170 := "Not_a_Finding" if selinux_enforcing

else := "Open"

finding_rhel_08_010170 := {
	"vuln_id": "V-230240",
	"stig_id": "RHEL-08-010170",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_rhel_08_010170,
	"fix_text": "Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-08-010450 | V-230282 | CAT II - SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if input.selinux.policy == "targeted"

status_rhel_08_010450 := "Not_a_Finding" if selinux_targeted

else := "Open"

finding_rhel_08_010450 := {
	"vuln_id": "V-230282",
	"stig_id": "RHEL-08-010450",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must enable the SELinux targeted policy.",
	"status": status_rhel_08_010450,
	"fix_text": "Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-08-010090 | V-230229 | CAT II - DoD Root CA must be installed
default dod_root_ca := false

dod_root_ca if input.certificates.dod_root_ca_installed == true

status_rhel_08_010090 := "Not_a_Finding" if dod_root_ca

else := "Open"

finding_rhel_08_010090 := {
	"vuln_id": "V-230229",
	"stig_id": "RHEL-08-010090",
	"severity": "CAT II",
	"rule_title": "RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.",
	"status": status_rhel_08_010090,
	"fix_text": "Install DoD Root CAs: trust anchor --store DoD_PKE_CA_chain.pem",
}

# RHEL-08-010040 | V-230225 | CAT II - Login banner required
default login_banner := false

login_banner if contains(input.login_banner.issue, "U.S. Government")
login_banner if contains(input.login_banner.issue, "authorized users")

status_rhel_08_010040 := "Not_a_Finding" if login_banner

else := "Open"

finding_rhel_08_010040 := {
	"vuln_id": "V-230225",
	"stig_id": "RHEL-08-010040",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a ssh logon.",
	"status": status_rhel_08_010040,
	"fix_text": "Configure DoD banner in /etc/issue",
}

# RHEL-08-010430 | V-230280 | CAT II - ASLR must be enabled
default aslr_enabled := false

aslr_enabled if input.kernel_params["kernel.randomize_va_space"] == "2"

status_rhel_08_010430 := "Not_a_Finding" if aslr_enabled

else := "Open"

finding_rhel_08_010430 := {
	"vuln_id": "V-230280",
	"stig_id": "RHEL-08-010430",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_rhel_08_010430,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-040080 | V-230503 | CAT II - USB storage must be disabled
default usb_storage_disabled := false

usb_storage_disabled if input.kernel_modules["usb-storage"].blacklisted == true
usb_storage_disabled if input.kernel_modules["usb-storage"].status == "disabled"

status_rhel_08_040080 := "Not_a_Finding" if usb_storage_disabled

else := "Open"

finding_rhel_08_040080 := {
	"vuln_id": "V-230503",
	"stig_id": "RHEL-08-040080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must be configured to disable USB mass storage.",
	"status": status_rhel_08_040080,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-08-010359 | V-251710 | CAT II - AIDE must be installed
default aide_installed := false

aide_installed if input.packages.aide == true

status_rhel_08_010359 := "Not_a_Finding" if aide_installed

else := "Open"

finding_rhel_08_010359 := {
	"vuln_id": "V-251710",
	"stig_id": "RHEL-08-010359",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.",
	"status": status_rhel_08_010359,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-08-010360 | V-230263 | CAT II - AIDE cron job must exist
default aide_cron := false

aide_cron if input.aide_config.cron_job == true

status_rhel_08_010360 := "Not_a_Finding" if aide_cron

else := "Open"

finding_rhel_08_010360 := {
	"vuln_id": "V-230263",
	"stig_id": "RHEL-08-010360",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency.",
	"status": status_rhel_08_010360,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * root /usr/sbin/aide --check' > /etc/cron.d/aide",
}

# RHEL-08-010543 | V-230295 | CAT II - /tmp must be separate partition
default tmp_separate := false

tmp_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
}

status_rhel_08_010543 := "Not_a_Finding" if tmp_separate

else := "Open"

finding_rhel_08_010543 := {
	"vuln_id": "V-230295",
	"stig_id": "RHEL-08-010543",
	"severity": "CAT II",
	"rule_title": "A separate RHEL 8 filesystem must be used for the /tmp directory.",
	"status": status_rhel_08_010543,
	"fix_text": "Configure /tmp as a separate partition",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# RHEL-08-010375 | V-230269 | CAT III - dmesg restrict must be 1
default dmesg_restrict := false

dmesg_restrict if input.kernel_params["kernel.dmesg_restrict"] == "1"

status_rhel_08_010375 := "Not_a_Finding" if dmesg_restrict

else := "Open"

finding_rhel_08_010375 := {
	"vuln_id": "V-230269",
	"stig_id": "RHEL-08-010375",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must restrict access to the kernel message buffer.",
	"status": status_rhel_08_010375,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-010541 | V-230293 | CAT III - /var/log must be separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_08_010541 := "Not_a_Finding" if var_log_separate

else := "Open"

finding_rhel_08_010541 := {
	"vuln_id": "V-230293",
	"stig_id": "RHEL-08-010541",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must use a separate file system for /var/log.",
	"status": status_rhel_08_010541,
	"fix_text": "Configure /var/log as a separate partition",
}

# RHEL-08-010542 | V-230294 | CAT III - /var/log/audit must be separate
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_08_010542 := "Not_a_Finding" if var_log_audit_separate

else := "Open"

finding_rhel_08_010542 := {
	"vuln_id": "V-230294",
	"stig_id": "RHEL-08-010542",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must use a separate file system for the system audit data path.",
	"status": status_rhel_08_010542,
	"fix_text": "Configure /var/log/audit as a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_010020,
	finding_rhel_08_010150,
	finding_rhel_08_040170,
]

cat_ii_findings := [
	finding_rhel_08_010170,
	finding_rhel_08_010450,
	finding_rhel_08_010090,
	finding_rhel_08_010040,
	finding_rhel_08_010430,
	finding_rhel_08_040080,
	finding_rhel_08_010359,
	finding_rhel_08_010360,
	finding_rhel_08_010543,
]

cat_iii_findings := [
	finding_rhel_08_010375,
	finding_rhel_08_010541,
	finding_rhel_08_010542,
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
