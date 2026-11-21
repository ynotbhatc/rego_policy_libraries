package cis_m365.exchange_test

import rego.v1

test_not_compliant_without_facts if {
	r := data.cis_m365.exchange.compliance_report with input as {}
	not r.compliant == true
	r.violation_count > 0
}

# Semantic review 2026-11-13 regressions: each control needs its own facts.
test_empty_secure_score_only_flags_every_missing_fact if {
	v := data.cis_m365.exchange.violations with input as {"secure_score_controls": []}
	ids := ["CIS 4.1.1:", "CIS 4.5.1:", "CIS 4.6.1:", "CIS 4.7.1:", "CIS 4.8.1:", "CIS 4.11.1:"]
	every id in ids {
		count({m | some m in v; startswith(m, id)}) >= 1
	}
	not data.cis_m365.exchange.compliant with input as {"secure_score_controls": []}
}

test_all_facts_present_has_no_evidence_missing if {
	inp := {
		"mailbox_audit_summary": {"sampled": 5, "audit_enabled": 5, "audit_disabled": 0, "evaluable": true},
		"verified_domains": [{"id": "example.com", "spf_present": true, "dkim_present": true, "dmarc_present": true}],
		"secure_score_controls": [
			{"id": "ExternalSenderTagging", "implementation_status": "Implemented"},
			{"id": "SMTPAuthDisabled", "implementation_status": "Implemented"},
		],
	}
	data.cis_m365.exchange.compliant with input as inp
}

# #300 type traps: a non-number audit_disabled is evidence missing; real numbers keep their behaviour.
test_audit_disabled_number_type_traps if {
	"CIS 4.1.1: evidence missing — mailbox_audit_summary.audit_disabled is not a number" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": "1"}}
	"CIS 4.1.1: evidence missing — mailbox_audit_summary.audit_disabled is not a number" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": null}}
	"CIS 4.1.1: evidence missing — mailbox_audit_summary.audit_disabled is not a number" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": "not-a-number"}}
	not "CIS 4.1.1: evidence missing — mailbox_audit_summary.audit_disabled is not a number" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": 0}}
	not "CIS 4.1.1: 2 of 10 sampled mailboxes have audit disabled; enable tenant-wide mailbox audit" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": 0}}
	"CIS 4.1.1: 2 of 10 sampled mailboxes have audit disabled; enable tenant-wide mailbox audit" in data.cis_m365.exchange.violation_4_1_1 with input as {"mailbox_audit_summary": {"evaluable": true, "sampled": 10, "audit_disabled": 2}}
}
