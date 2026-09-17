package coppa.main_test

import data.coppa.main
import rego.v1

# ── Contract smoke + fail-closed ─────────────────────────────────────────────

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	report.compliant == false
	report.violation_count > 0
}

test_empty_input_fails_all_controls if {
	report := main.compliance_report with input as {}
	report.violation_count == report.total_controls
}

# ── Fully compliant operator (safe-harbor non-participant) ───────────────────

compliant_input := {
	"entity_name": "Example Kids App LLC",
	"assessment_date": "2026-09-16",
	"coppa": {
		"notice": {
			"online_notice_posted": true,
			"direct_notice_to_parents": true,
			"notice_content_complete": true,
		},
		"consent": {
			"verifiable_consent_before_collection": true,
			"approved_method_used": true,
			"separate_consent_third_party_disclosure": true,
			"consent_records_retained": true,
		},
		"parental_rights": {
			"review_mechanism": true,
			"deletion_mechanism": true,
			"refusal_mechanism": true,
		},
		"collection": {"not_conditioned_on_excess_data": true},
		"security": {
			"written_program": true,
			"safeguards_risk_based": true,
			"third_party_capability_assurances": true,
			"program_reviewed": true,
		},
		"retention": {
			"limited_to_necessary": true,
			"written_policy_public": true,
			"no_indefinite_retention": true,
		},
		"scope": {
			"pi_inventory_includes_new_categories": true,
			"audience_determination_documented": true,
		},
		"safe_harbor": {"participates": false},
	},
}

test_fully_compliant_operator if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

# ── Safe-harbor conditional behavior ─────────────────────────────────────────

test_safe_harbor_participant_meeting_requirements_passes if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/coppa/safe_harbor",
		"value": {"participates": true, "program_requirements_met": true},
	}])
	report := main.compliance_report with input as modified
	report.compliant == true
}

test_safe_harbor_participant_failing_requirements_flagged if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/coppa/safe_harbor",
		"value": {"participates": true, "program_requirements_met": false},
	}])
	report := main.compliance_report with input as modified
	report.compliant == false
	some v in report.violations
	contains(v, "§312.11")
}

# ── 2025 amendment controls ──────────────────────────────────────────────────

test_missing_separate_third_party_consent_flagged if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/coppa/consent/separate_consent_third_party_disclosure",
		"value": false,
	}])
	report := main.compliance_report with input as modified
	report.compliant == false
	report.violation_count == 1
	some v in report.violations
	contains(v, "[2025]")
	contains(v, "targeted advertising")
}

test_indefinite_retention_flagged if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/coppa/retention/no_indefinite_retention",
		"value": false,
	}])
	report := main.compliance_report with input as modified
	report.compliant == false
	some v in report.violations
	contains(v, "§312.10")
}

# ── Rollup partition ─────────────────────────────────────────────────────────

test_area_summary_sums_to_violation_count_on_empty if {
	report := main.compliance_report with input as {}
	total := sum([n | some _, n in report.area_summary])
	total == report.violation_count
}
