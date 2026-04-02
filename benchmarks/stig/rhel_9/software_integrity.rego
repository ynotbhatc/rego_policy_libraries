package stig.rhel_9.software_integrity

# DISA STIG for RHEL 9 - Software Integrity Module
# STIG Version: V2R2 | Released: October 2024
# Covers: GPG signing, package verification, AIDE, kernel module restrictions

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-214010 | V-257808 | CAT I
# GPG check must be globally activated for repository packages
default gpgcheck_global := false

gpgcheck_global if {
	input.dnf_config.gpgcheck == true
}

gpgcheck_global if {
	input.yum_config.gpgcheck == true
}

status_rhel_09_251010 := "Not_a_Finding" if { gpgcheck_global } else := "Open"

finding_rhel_09_251010 := {
	"vuln_id": "V-257849",
	"stig_id": "RHEL-09-251010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must ensure the system-wide crypto policy is not set to LEGACY",
	"status": status_rhel_09_251010,
	"fix_text": "Enable GPG check globally: Set gpgcheck=1 in /etc/dnf/dnf.conf",
}

# RHEL-09-251015 | V-257850 | CAT I
# GPG must be enabled for all repo files
default all_repos_gpgcheck := false

all_repos_gpgcheck if {
	count([r | some r in input.yum_repos; r.gpgcheck != true]) == 0
	count(input.yum_repos) > 0
}

all_repos_gpgcheck if {
	count(input.yum_repos) == 0
}

status_rhel_09_251015 := "Not_a_Finding" if { all_repos_gpgcheck } else := "Open"

finding_rhel_09_251015 := {
	"vuln_id": "V-257850",
	"stig_id": "RHEL-09-251015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have GPG signature checking enabled for all package repositories",
	"status": status_rhel_09_251015,
	"fix_text": "Enable gpgcheck=1 in all .repo files under /etc/yum.repos.d/",
}

# RHEL-09-251020 | V-257851 | CAT I
# Packages must not be installed from unsigned repos
default no_unsigned_packages := false

no_unsigned_packages if {
	count(input.unsigned_packages) == 0
}

no_unsigned_packages if {
	not input.unsigned_packages
}

status_rhel_09_251020 := "Not_a_Finding" if { no_unsigned_packages } else := "Open"

finding_rhel_09_251020 := {
	"vuln_id": "V-257851",
	"stig_id": "RHEL-09-251020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have any unverified or unsigned packages installed",
	"status": status_rhel_09_251020,
	"fix_text": "Remove unsigned packages: rpm -qa --qf '%{NAME} %{SIGPGP:pgpsig}\\n' | grep 'Key ID'",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-251025 | V-257852 | CAT II
# AIDE must be configured to use FIPS 140-3 approved hashes
default aide_fips_hashes := false

aide_fips_hashes if {
	input.aide_config.hash_algorithms
	algorithms := input.aide_config.hash_algorithms
	"sha512" in algorithms
}

aide_fips_hashes if {
	input.aide_config.hash_algorithms
	algorithms := input.aide_config.hash_algorithms
	"sha256" in algorithms
}

status_rhel_09_251025 := "Not_a_Finding" if { aide_fips_hashes } else := "Open"

finding_rhel_09_251025 := {
	"vuln_id": "V-257852",
	"stig_id": "RHEL-09-251025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes",
	"status": status_rhel_09_251025,
	"fix_text": "Configure AIDE to use SHA-512: Set NORMAL = sha512+rmd160+sha1+haval+tiger+crc32 in /etc/aide.conf",
}

# RHEL-09-251030 | V-257853 | CAT II
# AIDE database must exist
default aide_db_exists := false

aide_db_exists if {
	input.aide_config.db_path != ""
	input.aide_config.db_exists == true
}

status_rhel_09_251030 := "Not_a_Finding" if { aide_db_exists } else := "Open"

finding_rhel_09_251030 := {
	"vuln_id": "V-257853",
	"stig_id": "RHEL-09-251030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured so that the AIDE notification mechanism sends audit failure advisories",
	"status": status_rhel_09_251030,
	"fix_text": "Initialize AIDE database: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
}

# RHEL-09-251035 | V-257854 | CAT II
# AIDE notify on check must be configured
default aide_notify_configured := false

aide_notify_configured if {
	input.aide_config.acl_enabled == true
}

aide_notify_configured if {
	input.aide_config.notify_email != ""
}

status_rhel_09_251035 := "Not_a_Finding" if { aide_notify_configured } else := "Open"

finding_rhel_09_251035 := {
	"vuln_id": "V-257854",
	"stig_id": "RHEL-09-251035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must notify designated personnel if baseline configurations are changed in an unauthorized manner",
	"status": status_rhel_09_251035,
	"fix_text": "Configure AIDE email notification in /etc/aide.conf",
}

# RHEL-09-252010 | V-257855 | CAT II
# kernel module loading via sysctl must be disabled (kexec)
default kexec_disabled := false

kexec_disabled if {
	input.kernel_params["kernel.kexec_load_disabled"] == "1"
}

status_rhel_09_252010 := "Not_a_Finding" if { kexec_disabled } else := "Open"

finding_rhel_09_252010 := {
	"vuln_id": "V-257855",
	"stig_id": "RHEL-09-252010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent kernel profiling by unprivileged users",
	"status": status_rhel_09_252010,
	"fix_text": "Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-252015 | V-257856 | CAT II
# System must not allow loading of dynamic kernel modules without approval
default module_signing_enforced := false

module_signing_enforced if {
	input.kernel_params["kernel.modules_disabled"] == "1"
}

module_signing_enforced if {
	input.kernel_config.module_sig_enforce == true
}

status_rhel_09_252015 := "Not_a_Finding" if { module_signing_enforced } else := "Open"

finding_rhel_09_252015 := {
	"vuln_id": "V-257856",
	"stig_id": "RHEL-09-252015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must require that new packages are cryptographically signed",
	"status": status_rhel_09_252015,
	"fix_text": "Enable module signing enforcement in kernel boot parameters",
}

# RHEL-09-252020 | V-257857 | CAT II
# Kernel must not load unverified modules
default localpkg_gpgcheck := false

localpkg_gpgcheck if {
	input.dnf_config.localpkg_gpgcheck == true
}

status_rhel_09_252020 := "Not_a_Finding" if { localpkg_gpgcheck } else := "Open"

finding_rhel_09_252020 := {
	"vuln_id": "V-257857",
	"stig_id": "RHEL-09-252020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have the gpg-pubkey package installed",
	"status": status_rhel_09_252020,
	"fix_text": "Enable local package GPG check: Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
}

# RHEL-09-252025 | V-257858 | CAT II
# Crypto policy must not be LEGACY
default crypto_not_legacy := false

crypto_not_legacy if {
	input.crypto_policy != "LEGACY"
}

crypto_not_legacy if {
	not input.crypto_policy
}

status_rhel_09_252025 := "Not_a_Finding" if { crypto_not_legacy } else := "Open"

finding_rhel_09_252025 := {
	"vuln_id": "V-257858",
	"stig_id": "RHEL-09-252025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use the FIPS or a FIPS-compatible crypto policy",
	"status": status_rhel_09_252025,
	"fix_text": "Set crypto policy: update-crypto-policies --set FIPS",
}

# RHEL-09-252030 | V-257859 | CAT II
# rsyslog must be installed
default rsyslog_installed := false

rsyslog_installed if {
	input.packages.rsyslog == true
}

status_rhel_09_252030 := "Not_a_Finding" if { rsyslog_installed } else := "Open"

finding_rhel_09_252030 := {
	"vuln_id": "V-257859",
	"stig_id": "RHEL-09-252030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have the rsyslog package installed",
	"status": status_rhel_09_252030,
	"fix_text": "Install rsyslog: dnf install rsyslog -y",
}

# RHEL-09-252035 | V-257860 | CAT II
# rsyslog service must be active
default rsyslog_active := false

rsyslog_active if {
	input.services.rsyslog == "active"
}

status_rhel_09_252035 := "Not_a_Finding" if { rsyslog_active } else := "Open"

finding_rhel_09_252035 := {
	"vuln_id": "V-257860",
	"stig_id": "RHEL-09-252035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have the rsyslog service active",
	"status": status_rhel_09_252035,
	"fix_text": "Enable and start rsyslog: systemctl enable --now rsyslog",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_251010,
	finding_rhel_09_251015,
	finding_rhel_09_251020,
]

cat_ii_findings := [
	finding_rhel_09_251025,
	finding_rhel_09_251030,
	finding_rhel_09_251035,
	finding_rhel_09_252010,
	finding_rhel_09_252015,
	finding_rhel_09_252020,
	finding_rhel_09_252025,
	finding_rhel_09_252030,
	finding_rhel_09_252035,
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
	"module": "software_integrity",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
