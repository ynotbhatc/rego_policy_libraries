package fedramp.main_test

import data.fedramp.main
import rego.v1

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

test_default_impact_level_is_moderate if {
	r := main.compliance_report with input as {}
	r.impact_level == "unknown"
	r.total_controls == 325
}

test_low_impact_drops_total_controls if {
	r := main.compliance_report with input as {"impact_level": "low"}
	r.impact_level == "low"
	r.total_controls == 125
}

test_high_impact_raises_total_controls if {
	r := main.compliance_report with input as {"impact_level": "high"}
	r.impact_level == "high"
	r.total_controls == 421
}

low_good_input := {
	"authorization": {"fedramp_authorized": true, "authorization_type": "ATO", "ato_expiry_days": 300, "assessed_by_3pao": true, "last_3pao_assessment_days": 100},
	"cryptography": {"fips_140_validated": true, "fips_validation_level": 2, "algorithms_in_use": ["AES-256"]},
	"continuous_monitoring": {
		"program_documented": true, "monthly_vulnerability_scans": true, "last_vulnerability_scan_days": 5,
		"monthly_os_scan": true, "web_app_scan_enabled": true, "database_scan_enabled": true,
		"monthly_ato_report_submitted": true,
	},
}

test_missing_impact_level_is_finding_and_strict_checks_run if {
	r := main.compliance_report with input as low_good_input
	not r.compliant
	some v in r.violations
	contains(v, "impact_level")
	some w in r.violations
	contains(w, "CA-8")
}

test_mixed_case_impact_level_not_skipped if {
	r := main.compliance_report with input as object.union(low_good_input, {"impact_level": "Moderate"})
	some w in r.violations
	contains(w, "CA-8")
	count([x | some x in r.violations; contains(x, "must be one of")]) == 0
}

test_low_impact_good_input_compliant if {
	r := main.compliance_report with input as object.union(low_good_input, {"impact_level": "low"})
	r.compliant
}

test_high_only_failures_reflected_in_area_summary if {
	inp := object.union(low_good_input, {
		"impact_level": "high",
		"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true},
		"supply_chain": {"risk_management_plan": true},
	})
	r := main.compliance_report with input as inp
	not r.compliant
	r.area_summary.high.compliant == false
}
