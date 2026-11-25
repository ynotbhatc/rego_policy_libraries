package fedramp.main_test

import data.fedramp.main
import rego.v1

# The two agency selectors, stated: "does not apply" is an explicit false.
_stated := {"data_residency": {"us_only_required": false}, "personnel_requirements": {"us_persons_required_for_admin": false}}

test_compliance_report_defined_on_empty_input if {
	r := main.compliance_report with input as {}
	r.framework == "FedRAMP"
	is_number(r.total_controls)
	is_array(r.violations)
}

test_non_compliant_on_empty_input if {
	not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
	count(main.violations) > 0 with input as {}
}

test_unknown_impact_level_reports_no_baseline_size if {
	r := main.compliance_report with input as _stated
	r.impact_level == "unknown"
	r.baseline_size == null
	r.total_controls == 12 # every check, Moderate/High ones included, until the level is declared
}

# Rev 5 baseline sizes (FedRAMP OSCAL profiles): 156 / 323 / 410 — reported as baseline_size, never as
# total_controls, which is the number of checks this module evaluates.
test_low_reports_rev5_baseline_size_and_evaluated_count if {
	r := main.compliance_report with input as object.union(_stated, {"impact_level": "low"})
	r.impact_level == "low"
	r.baseline_size == 156
	r.total_controls == 10
}

test_moderate_reports_rev5_baseline_size_and_evaluated_count if {
	r := main.compliance_report with input as object.union(_stated, {"impact_level": "moderate"})
	r.baseline_size == 323
	r.total_controls == 11
}

test_high_reports_rev5_baseline_size_and_evaluated_count if {
	r := main.compliance_report with input as object.union(_stated, {"impact_level": "high"})
	r.baseline_size == 410
	r.total_controls == 12
}

test_baseline_sizes_table if {
	r := main.compliance_report with input as {}
	r.baseline_sizes == {"low": 156, "moderate": 323, "high": 410, "li_saas": 156}
}

test_failed_controls_counts_ids_not_findings if {
	# three admins without background checks are three PS-3 findings but one failed control
	inp := object.union(low_good_input, {
		"impact_level": "low",
		"personnel": [
			{"name": "a", "admin_access": true},
			{"name": "b", "admin_access": true},
			{"name": "c", "admin_access": true},
		],
	})
	r := main.compliance_report with input as inp
	r.violation_count == 3
	r.failed_controls == 1
	r.failed_control_ids == ["PS-3"]
	r.failed_controls <= r.total_controls
}

low_good_input := {
	"data_residency": {"us_only_required": false},
	"personnel_requirements": {"us_persons_required_for_admin": false},
	"authorization": {"fedramp_authorized": true, "authorization_type": "ATO", "ato_expiry_days": 300, "assessed_by_3pao": true, "last_3pao_assessment_days": 100},
	"cryptography": {"fips_140_validated": true, "algorithms_in_use": ["AES-256"]},
	"continuous_monitoring": {
		"program_documented": true, "monthly_vulnerability_scans": true, "last_vulnerability_scan_days": 5,
		"monthly_os_scan": true, "web_app_scan_enabled": true, "database_scan_enabled": true,
		"monthly_ato_report_submitted": true, "high_vulnerabilities_open_days": 0, "critical_vulnerabilities_open_days": 0, "moderate_vulnerabilities_open_days": 45, "low_vulnerabilities_open_days": 100,
	},
	"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true},
	"supply_chain": {"risk_management_plan": true},
	"personnel": [{"name": "admin1", "admin_access": true, "background_check_completed": true}],
}

test_missing_impact_level_is_finding_and_strict_checks_run if {
	r := main.compliance_report with input as low_good_input
	not r.compliant
	some v in r.violations
	contains(v, "impact_level")
	some w in r.violations
	contains(w, "CP-7")
}

test_mixed_case_impact_level_not_skipped if {
	r := main.compliance_report with input as object.union(low_good_input, {"impact_level": "Moderate"})
	some w in r.violations
	contains(w, "CP-7")
	count([x | some x in r.violations; contains(x, "must be one of")]) == 0
}

test_low_impact_good_input_compliant if {
	r := main.compliance_report with input as object.union(low_good_input, {"impact_level": "low"})
	r.compliant
	r.failed_controls == 0
}

test_high_only_failures_reflected_in_area_summary if {
	inp := object.union(low_good_input, {
		"impact_level": "high",
		"cloud_service": {"redundant_processing": true},
	})
	r := main.compliance_report with input as inp
	not r.compliant
	r.area_summary.data_residency.compliant == false
	r.failed_control_ids == ["SA-9(5)"]
}

# An agency selector that was not sent is missing evidence, and the check it selects is applied.
test_unstated_selectors_apply_their_checks_and_are_reported if {
	r := main.compliance_report with input as {"impact_level": "moderate"}
	r.total_controls == 13
	"SA-9(5)" in r.failed_control_ids
	"PS-3(3)" in r.failed_control_ids
	some v in r.violations
	contains(v, "input.data_residency.us_only_required not stated")
	some w in r.violations
	contains(w, "input.personnel_requirements.us_persons_required_for_admin not stated")
	low := main.compliance_report with input as {"impact_level": "low"}
	low.total_controls == 11
	not "PS-3(3)" in low.failed_control_ids
}
