# METADATA
# title: "DISA STIG for Oracle Linux 8 - Software Integrity Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 3
#     cited: 2
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_8.software_integrity

# DISA STIG for Oracle Linux 8 - Software Integrity Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/software_integrity.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: GPG signing, package verification, AIDE, kernel module restrictions

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010561 | V-248615 | CAT II
# rsyslog service must be active
default rsyslog_active := false

rsyslog_active if {
	input.services.rsyslog == "active"
}

status_ol08_00_010561 := "Not_a_Finding" if { rsyslog_active } else := "Open"

finding_ol08_00_010561 := {
	"vuln_id": "V-248615",
	"stig_id": "OL08-00-010561",
	"severity": "CAT II",
	"rule_title": "OL 8 must have the rsyslog service enabled and active.",
	"status": status_ol08_00_010561,
	"fix_text": "Enable and start rsyslog: systemctl enable --now rsyslog",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# OL08-00-010376 | V-248580 | CAT III
# kernel module loading via sysctl must be disabled (kexec)
default kexec_disabled := false

kexec_disabled if {
	input.kernel_params["kernel.kexec_load_disabled"] == "1"
}

status_ol08_00_010376 := "Not_a_Finding" if { kexec_disabled } else := "Open"

finding_ol08_00_010376 := {
	"vuln_id": "V-248580",
	"stig_id": "OL08-00-010376",
	"severity": "CAT III",
	"rule_title": "OL 8 must prevent kernel profiling by nonprivileged users.",
	"status": status_ol08_00_010376,
	"fix_text": "Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol08_00_010561,
]

cat_iii_findings := [
	finding_ol08_00_010376,
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

# Evidence gate: a module with none of its facts collected is unevaluated, not compliant.
evidence_present if {
	some key in {"services", "kernel_params"}
	object.get(input, key, null) != null
}

# NOTE: `compliant` is scoped to CAT I findings only (module convention), and this module carries
# no CAT I findings. Whether CAT II/III should also gate it is an open scope decision, see the
# validation 2026-10-17 report.
compliant if {
	evidence_present
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
