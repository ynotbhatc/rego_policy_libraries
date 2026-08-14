# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 3 -- Microsoft Purview
#
# Input contract (from the aac.m365 collection):
#   input.purview.audit_log_accessible - bool; a directoryAudits probe
#                                        returned at least one record
#
# NOT EVALUATED: 3.2.x (DLP), 3.3.x (labels), Insider Risk Management and
# Communication Compliance. The Purview collector returns Secure Score plus
# an audit-log reachability probe and an eDiscovery case count; none of
# those establish the remaining section 3 controls. See COVERAGE.md.

package cis_m365_v7.purview

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	is_boolean(input.purview.audit_log_accessible)
}

# CIS 3.1.1 -- unified audit log search must be enabled. If the audit log
# cannot be searched, there is no record for an investigator to read.
violation contains msg if {
	facts_present
	not input.purview.audit_log_accessible
	msg := "CIS 3.1.1: unified audit log search returned no records -- audit logging is not enabled, so tenant activity is not retained for investigation"
}

violation contains msg if {
	not facts_present
	msg := "CIS 3.1.1: audit log facts not collected -- control could not be evaluated (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "3",
	"name": "Microsoft Purview",
	"section_total_controls": 5,
	"controls_evaluated": 1,
	"controls": ["3.1.1"],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
