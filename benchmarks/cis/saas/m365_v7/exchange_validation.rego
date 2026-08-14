# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 6 -- Exchange admin center
#
# Input contract (from the aac.m365 collection):
#   input.exchange.mailbox_audit_summary - {sampled, audit_enabled,
#                                           audit_disabled, evaluable}
#
# COLLECTION LIMIT -- read this before trusting 6.1.1. Graph v1.0 does not
# expose the tenant-wide 'AuditDisabled' organization flag. The collector
# samples per-user mailboxSettings instead, so this is a PROXY: it can show
# that auditing is off for sampled mailboxes, but it cannot prove the
# organization-level flag is False. A clean result here is weaker evidence
# than a clean result from Exchange Online PowerShell, which is what the
# benchmark's own audit procedure uses. Surfaced in compliance_report as
# evidence_strength so a reader cannot miss it.

package cis_m365_v7.exchange

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	input.exchange.mailbox_audit_summary.evaluable == true
}

# CIS 6.1.1 -- mailbox auditing must not be disabled organizationally.
violation contains msg if {
	facts_present
	input.exchange.mailbox_audit_summary.audit_disabled > 0
	msg := sprintf("CIS 6.1.1: AuditDisabled is effectively true for %d of %d sampled mailboxes -- organizationally this flag must be False or mailbox actions are not recorded", [input.exchange.mailbox_audit_summary.audit_disabled, input.exchange.mailbox_audit_summary.sampled])
}

violation contains msg if {
	not facts_present
	msg := "CIS 6.1.1: mailbox facts not collected -- could not establish that AuditDisabled is organizationally False (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "6",
	"name": "Exchange admin center",
	"section_total_controls": 13,
	"controls_evaluated": 1,
	"controls": ["6.1.1"],
	"facts_present": facts_present,
	"evidence_strength": {
		"6.1.1": "proxy -- per-user mailboxSettings sample; Graph v1.0 does not expose the tenant-wide AuditDisabled flag",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
