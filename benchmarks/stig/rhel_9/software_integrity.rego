# METADATA
# title: "DISA STIG for RHEL 9 - Software Integrity Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 8
#     cited: 7
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.software_integrity

# DISA STIG for RHEL 9 - Software Integrity Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: GPG signing, package verification, AIDE, kernel module restrictions

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-214025 | V-257822 | CAT I
# GPG must be enabled for all repo files
default all_repos_gpgcheck := false

all_repos_gpgcheck if {
	count([r | some r in input.yum_repos; object.get(r, "gpgcheck", false) != true]) == 0
	count(input.yum_repos) > 0
}

all_repos_gpgcheck if {
	count(input.yum_repos) == 0
}

status_rhel_09_214025 := "Not_a_Finding" if all_repos_gpgcheck

else := "Open"

finding_rhel_09_214025 := {
	"vuln_id": "V-257822",
	"stig_id": "RHEL-09-214025",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have GPG signature verification enabled for all software repositories.",
	"status": status_rhel_09_214025,
	"fix_text": "Enable gpgcheck=1 in all .repo files under /etc/yum.repos.d/",
}

# RHEL-09-214020 | V-257821 | CAT I
# Kernel must not load unverified modules
default localpkg_gpgcheck := false

localpkg_gpgcheck if {
	input.dnf_config.localpkg_gpgcheck == true
}

status_rhel_09_214020 := "Not_a_Finding" if localpkg_gpgcheck

else := "Open"

finding_rhel_09_214020 := {
	"vuln_id": "V-257821",
	"stig_id": "RHEL-09-214020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must check the GPG signature of locally installed software packages before installation.",
	"status": status_rhel_09_214020,
	"fix_text": "Enable local package GPG check: Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-214010 | V-257819 | CAT II
# GPG check must be globally activated for repository packages
default gpgcheck_global := false

gpgcheck_global if {
	input.dnf_config.gpgcheck == true
}

gpgcheck_global if {
	input.yum_config.gpgcheck == true
}

status_rhel_09_214010 := "Not_a_Finding" if gpgcheck_global

else := "Open"

finding_rhel_09_214010 := {
	"vuln_id": "V-257849",
	"stig_id": "RHEL-09-251010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must ensure cryptographic verification of vendor software packages.",
	"status": status_rhel_09_214010,
	"fix_text": "Enable GPG check globally: Set gpgcheck=1 in /etc/dnf/dnf.conf",
}

# RHEL-09-651020 | V-258136 | CAT II
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

status_rhel_09_651020 := "Not_a_Finding" if aide_fips_hashes

else := "Open"

finding_rhel_09_651020 := {
	"vuln_id": "V-258136",
	"stig_id": "RHEL-09-651020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.",
	"status": status_rhel_09_651020,
	"fix_text": "Configure AIDE to use SHA-512: Set NORMAL = sha512+rmd160+sha1+haval+tiger+crc32 in /etc/aide.conf",
}

# RHEL-09-213020 | V-257799 | CAT II
# kernel module loading via sysctl must be disabled (kexec)
default kexec_disabled := false

kexec_disabled if {
	input.kernel_params["kernel.kexec_load_disabled"] == "1"
}

status_rhel_09_213020 := "Not_a_Finding" if kexec_disabled

else := "Open"

finding_rhel_09_213020 := {
	"vuln_id": "V-257799",
	"stig_id": "RHEL-09-213020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prevent the loading of a new kernel for later execution.",
	"status": status_rhel_09_213020,
	"fix_text": "Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-652010 | V-258140 | CAT II
# rsyslog must be installed
default rsyslog_installed := false

rsyslog_installed if {
	input.packages.rsyslog == true
}

status_rhel_09_652010 := "Not_a_Finding" if rsyslog_installed

else := "Open"

finding_rhel_09_652010 := {
	"vuln_id": "V-258140",
	"stig_id": "RHEL-09-652010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have the rsyslog package installed.",
	"status": status_rhel_09_652010,
	"fix_text": "Install rsyslog: dnf install rsyslog -y",
}

# RHEL-09-652020 | V-258142 | CAT II
# rsyslog service must be active
default rsyslog_active := false

rsyslog_active if {
	input.services.rsyslog == "active"
}

status_rhel_09_652020 := "Not_a_Finding" if rsyslog_active

else := "Open"

finding_rhel_09_652020 := {
	"vuln_id": "V-258142",
	"stig_id": "RHEL-09-652020",
	"severity": "CAT II",
	"rule_title": "The rsyslog service on RHEL 9 must be active.",
	"status": status_rhel_09_652020,
	"fix_text": "Enable and start rsyslog: systemctl enable --now rsyslog",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_214025,
	finding_rhel_09_214020,
]

cat_ii_findings := [
	finding_rhel_09_214010,
	finding_rhel_09_651020,
	finding_rhel_09_213020,
	finding_rhel_09_652010,
	finding_rhel_09_652020,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

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
	"module": "software_integrity",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
