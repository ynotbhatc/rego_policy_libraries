package glba.main_test

import rego.v1

import data.glba.main

# ── Contract smoke: report never collapses to {} ─────────────────────────────

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

# ── Fully compliant institution ──────────────────────────────────────────────

compliant_input := {
	"entity_name": "Example Lending LLC",
	"entity_type": "non-bank lender",
	"assessment_date": "2026-09-02",
	"qualified_individual": {"designated": true},
	"risk_assessment": {
		"written": true,
		"criteria_documented": true,
		"periodic_reassessment": true,
	},
	"access_control": {
		"authenticate_users": true,
		"least_privilege": true,
		"periodic_review": true,
	},
	"inventory": {
		"data_identified": true,
		"systems_inventoried": true,
	},
	"encryption": {"customer_info": {
		"in_transit": true,
		"at_rest": true,
	}},
	"secure_development": {
		"inhouse_practices": true,
		"external_apps_assessed": true,
	},
	"mfa": {"all_information_systems": true},
	"disposal": {
		"within_two_years": true,
		"retention_policy_reviewed": true,
	},
	"change_management": {"procedures_adopted": true},
	"monitoring": {
		"authorized_user_activity": true,
		"unauthorized_access_detection": true,
	},
	"testing": {"continuous_monitoring": true},
	"training": {"security_awareness": true},
	"personnel": {
		"qualified_infosec_staff": true,
		"knowledge_current": true,
	},
	"service_providers": {
		"capability_assessed": true,
		"contracts_require_safeguards": true,
		"periodic_assessment": true,
	},
	"program": {"adjusted_from_findings": true},
	"incident_response": {"plan": {
		"written": true,
		"roles_defined": true,
		"post_event_revision": true,
	}},
	"board_report": {
		"annual_written": true,
		"covers_program_status": true,
	},
	"breach_notification": {"ftc_process_within_30_days": true},
}

test_fully_compliant if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

# ── Alternative-control paths ────────────────────────────────────────────────

test_mfa_equivalent_approved_satisfies if {
	inp := object.union(compliant_input, {"mfa": {
		"all_information_systems": false,
		"equivalent_approved_in_writing": true,
	}})
	report := main.compliance_report with input as inp
	report.compliant == true
}

test_missing_mfa_without_equivalent_violates if {
	inp := object.union(compliant_input, {"mfa": {"all_information_systems": false}})
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "314.4(c)(5)")
}

test_pentest_plus_vuln_scans_satisfy_testing if {
	inp := object.union(compliant_input, {"testing": {
		"continuous_monitoring": false,
		"penetration_test": {"annual": true},
		"vulnerability_assessment": {"semi_annual": true},
	}})
	report := main.compliance_report with input as inp
	report.compliant == true
}

test_no_monitoring_and_no_pentest_violates if {
	inp := object.union(compliant_input, {"testing": {"continuous_monitoring": false}})
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "314.4(d)(2)(i)")
}

test_unencrypted_without_compensating_violates if {
	inp := object.union(compliant_input, {"encryption": {"customer_info": {
		"in_transit": false,
		"at_rest": true,
	}}})
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "314.4(c)(3)")
}

test_compensating_controls_satisfy_encryption if {
	inp := object.union(compliant_input, {"encryption": {
		"customer_info": {"in_transit": false, "at_rest": false},
		"compensating_controls_approved": true,
	}})
	report := main.compliance_report with input as inp
	report.compliant == true
}

# ── Small-institution exemption (<5,000 consumers) ───────────────────────────

test_small_institution_exemption_suppresses_exempt_elements if {
	stripped := json.remove(compliant_input, [
		"risk_assessment",
		"incident_response",
		"board_report",
		"testing",
	])
	inp := object.union(stripped, {"small_institution_exemption": true})
	report := main.compliance_report with input as inp
	report.compliant == true
	report.small_institution_exemption == true
}

test_small_exemption_does_not_suppress_core_safeguards if {
	stripped := json.remove(compliant_input, ["mfa"])
	inp := object.union(stripped, {"small_institution_exemption": true})
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "314.4(c)(5)")
}

# ── Breach notification (2024 amendment) ─────────────────────────────────────

test_missing_ftc_notification_process_violates if {
	inp := json.remove(compliant_input, ["breach_notification"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "314.5")
}
