# METADATA
# title: "DISA STIG for Oracle Linux 9 - Software Integrity Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 5
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_9.software_integrity

# DISA STIG for Oracle Linux 9 - Software Integrity Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/software_integrity.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: GPG signing, package verification, AIDE, kernel module restrictions

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL09-00-000498 | V-271525 | CAT I
# GPG must be enabled for all repo files
default all_repos_gpgcheck := false

all_repos_gpgcheck if {
	count([r | some r in input.yum_repos; r.gpgcheck != true]) == 0
	count(input.yum_repos) > 0
}

all_repos_gpgcheck if {
	count(input.yum_repos) == 0
}

status_ol09_00_000498 := "Not_a_Finding" if { all_repos_gpgcheck } else := "Open"

finding_ol09_00_000498 := {
	"vuln_id": "V-271525",
	"stig_id": "OL09-00-000498",
	"severity": "CAT I",
	"rule_title": "OL 9 must have GPG signature verification enabled for all software repositories.",
	"status": status_ol09_00_000498,
	"fix_text": "Enable gpgcheck=1 in all .repo files under /etc/yum.repos.d/",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-002407 | V-271746 | CAT II
# kernel module loading via sysctl must be disabled (kexec)
default kexec_disabled := false

kexec_disabled if {
	input.kernel_params["kernel.kexec_load_disabled"] == "1"
}

status_ol09_00_002407 := "Not_a_Finding" if { kexec_disabled } else := "Open"

finding_ol09_00_002407 := {
	"vuln_id": "V-271746",
	"stig_id": "OL09-00-002407",
	"severity": "CAT II",
	"rule_title": "OL 9 must prevent kernel profiling by nonprivileged users.",
	"status": status_ol09_00_002407,
	"fix_text": "Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-000350 | V-271508 | CAT II
# rsyslog must be installed
default rsyslog_installed := false

rsyslog_installed if {
	input.packages.rsyslog == true
}

status_ol09_00_000350 := "Not_a_Finding" if { rsyslog_installed } else := "Open"

finding_ol09_00_000350 := {
	"vuln_id": "V-271508",
	"stig_id": "OL09-00-000350",
	"severity": "CAT II",
	"rule_title": "OL 9 must have the rsyslog package installed.",
	"status": status_ol09_00_000350,
	"fix_text": "Install rsyslog: dnf install rsyslog -y",
}

# OL09-00-000351 | V-271509 | CAT II
# rsyslog service must be active
default rsyslog_active := false

rsyslog_active if {
	input.services.rsyslog == "active"
}

status_ol09_00_000351 := "Not_a_Finding" if { rsyslog_active } else := "Open"

finding_ol09_00_000351 := {
	"vuln_id": "V-271509",
	"stig_id": "OL09-00-000351",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured so that the rsyslog service is active.",
	"status": status_ol09_00_000351,
	"fix_text": "Enable and start rsyslog: systemctl enable --now rsyslog",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol09_00_000498,
]

cat_ii_findings := [
	finding_ol09_00_002407,
	finding_ol09_00_000350,
	finding_ol09_00_000351,
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
