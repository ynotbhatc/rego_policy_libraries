package ferpa.main_test

import data.ferpa.main
import rego.v1

# ── Contract smoke: report never collapses to {} ─────────────────────────────

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

# ── Fail-closed: absent facts fire every control ─────────────────────────────

test_empty_input_fails_all_controls if {
	report := main.compliance_report with input as {}
	report.violation_count == report.total_controls
}

# ── Fully compliant institution ──────────────────────────────────────────────

compliant_input := {
	"entity_name": "Example School District",
	"assessment_date": "2026-09-16",
	"ferpa": {
		"notification": {
			"published": true,
			"includes_right_to_inspect": true,
			"includes_right_to_amend": true,
			"includes_disclosure_conditions": true,
			"includes_complaint_right": true,
		},
		"access": {
			"process_documented": true,
			"response_deadline_enforced": true,
			"amendment_procedure_documented": true,
			"hearing_available": true,
			"statement_right_provided": true,
		},
		"consent": {
			"written_before_disclosure": true,
			"specifies_scope": true,
			"records_retained": true,
		},
		"school_officials": {
			"criteria_in_notification": true,
			"access_controls_enforced": true,
			"contractors_under_direct_control": true,
		},
		"exceptions": {
			"transfer_conditions_met": true,
			"audit_written_agreements": true,
			"audit_data_destroyed": true,
			"studies_written_agreement": true,
			"subpoena_notify_effort": true,
			"health_safety_threat_recorded": true,
		},
		"directory": {
			"public_notice": true,
			"opt_out_offered": true,
			"opt_out_honored": true,
		},
		"records_of_disclosure": {
			"log_maintained": true,
			"log_retained_with_records": true,
			"redisclosure_recorded": true,
		},
		"redisclosure": {
			"limits_communicated": true,
			"violation_process": true,
		},
		"program": {
			"eligible_student_rights_transfer": true,
			"leu_records_separated": true,
		},
	},
}

test_fully_compliant_institution if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
	report.entity_name == "Example School District"
}

# ── Targeted single-control failures ─────────────────────────────────────────

test_missing_disclosure_log_flagged if {
	bad := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/ferpa/records_of_disclosure/log_maintained",
		"value": false,
	}])
	report := main.compliance_report with input as bad
	report.compliant == false
	report.violation_count == 1
	some v in report.violations
	contains(v, "§99.32(a)(1)")
}

test_no_access_controls_flagged if {
	bad := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/ferpa/school_officials/access_controls_enforced",
		"value": false,
	}])
	report := main.compliance_report with input as bad
	report.compliant == false
	some v in report.violations
	contains(v, "§99.31(a)(1)(ii)")
}

# ── Area rollup buckets partition the violation set ──────────────────────────

test_area_summary_sums_to_violation_count_on_empty if {
	report := main.compliance_report with input as {}
	total := sum([n | some _, n in report.area_summary])
	total == report.violation_count
}
