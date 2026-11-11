# METADATA
# title: "DISA STIG for RHEL 10 - Software Integrity Module"
# custom:
#   class: security
#   framework: stig_rhel_10
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
package stig.rhel_10.software_integrity

# DISA STIG for RHEL 10 - Software Integrity Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/software_integrity.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: GPG signing, package verification, AIDE, kernel module restrictions

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-001050 | V-280934 | CAT I
# GPG must be enabled for all repo files
default all_repos_gpgcheck := false

all_repos_gpgcheck if {
	count([r | some r in input.yum_repos; r.gpgcheck != true]) == 0
	count(input.yum_repos) > 0
}

all_repos_gpgcheck if {
	count(input.yum_repos) == 0
}

status_rhel_10_001050 := "Not_a_Finding" if all_repos_gpgcheck

else := "Open"

finding_rhel_10_001050 := {
	"vuln_id": "V-280934",
	"stig_id": "RHEL-10-001050",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must have GNU Privacy Guard (GPG) signature verification enabled for all software repositories.",
	"status": status_rhel_10_001050,
	"fix_text": "Enable gpgcheck=1 in all .repo files under /etc/yum.repos.d/",
}

# RHEL-10-001040 | V-280933 | CAT I
# Kernel must not load unverified modules
default localpkg_gpgcheck := false

localpkg_gpgcheck if {
	input.dnf_config.localpkg_gpgcheck == true
}

status_rhel_10_001040 := "Not_a_Finding" if localpkg_gpgcheck

else := "Open"

finding_rhel_10_001040 := {
	"vuln_id": "V-280933",
	"stig_id": "RHEL-10-001040",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must check the GNU Privacy Guard (GPG) signature of locally installed software packages before installation.",
	"status": status_rhel_10_001040,
	"fix_text": "Enable local package GPG check: Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
}

# RHEL-10-701050 | V-281307 | CAT I
# kernel module loading via sysctl must be disabled (kexec)
default kexec_disabled := false

kexec_disabled if {
	input.kernel_params["kernel.kexec_load_disabled"] == "1"
}

status_rhel_10_701050 := "Not_a_Finding" if kexec_disabled

else := "Open"

finding_rhel_10_701050 := {
	"vuln_id": "V-281307",
	"stig_id": "RHEL-10-701050",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must prevent the loading of a new kernel for later execution.",
	"status": status_rhel_10_701050,
	"fix_text": "Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-001020 | V-280931 | CAT II
# GPG check must be globally activated for repository packages
default gpgcheck_global := false

gpgcheck_global if {
	input.dnf_config.gpgcheck == true
}

gpgcheck_global if {
	input.yum_config.gpgcheck == true
}

status_rhel_10_001020 := "Not_a_Finding" if gpgcheck_global

else := "Open"

finding_rhel_10_001020 := {
	"vuln_id": "V-257849",
	"stig_id": "RHEL-09-251010",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must ensure cryptographic verification of vendor software packages.",
	"status": status_rhel_10_001020,
	"fix_text": "Enable GPG check globally: Set gpgcheck=1 in /etc/dnf/dnf.conf",
}

# RHEL-10-200632 | V-280979 | CAT II
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

status_rhel_10_200632 := "Not_a_Finding" if aide_fips_hashes

else := "Open"

finding_rhel_10_200632 := {
	"vuln_id": "V-280979",
	"stig_id": "RHEL-10-200632",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.",
	"status": status_rhel_10_200632,
	"fix_text": "Configure AIDE to use SHA-512: Set NORMAL = sha512+rmd160+sha1+haval+tiger+crc32 in /etc/aide.conf",
}

# RHEL-10-200640 | V-280983 | CAT II
# rsyslog must be installed
default rsyslog_installed := false

rsyslog_installed if {
	input.packages.rsyslog == true
}

status_rhel_10_200640 := "Not_a_Finding" if rsyslog_installed

else := "Open"

finding_rhel_10_200640 := {
	"vuln_id": "V-280983",
	"stig_id": "RHEL-10-200640",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must have the \"rsyslog\" package installed.",
	"status": status_rhel_10_200640,
	"fix_text": "Install rsyslog: dnf install rsyslog -y",
}

# RHEL-10-200641 | V-280984 | CAT II
# rsyslog service must be active
default rsyslog_active := false

rsyslog_active if {
	input.services.rsyslog == "active"
}

status_rhel_10_200641 := "Not_a_Finding" if rsyslog_active

else := "Open"

finding_rhel_10_200641 := {
	"vuln_id": "V-280984",
	"stig_id": "RHEL-10-200641",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must have the rsyslog service set to active.",
	"status": status_rhel_10_200641,
	"fix_text": "Enable and start rsyslog: systemctl enable --now rsyslog",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_10_001050,
	finding_rhel_10_001040,
	finding_rhel_10_701050,
]

cat_ii_findings := [
	finding_rhel_10_001020,
	finding_rhel_10_200632,
	finding_rhel_10_200640,
	finding_rhel_10_200641,
]

cat_iii_findings := []

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
	"module": "software_integrity",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
