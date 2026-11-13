package nis2.main_test

import data.nis2.main
import rego.v1

test_compliance_report_defined_on_empty_input if {
	r := main.compliance_report with input as {}
	r.framework == "EU Network and Information Security Directive 2 (NIS2)"
	is_number(r.total_controls)
	count(r.violations) >= 0
}

test_non_compliant_on_empty_input if {
	not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
	count(main.violations) > 20 with input as {}
}

test_defaults_for_metadata if {
	r := main.compliance_report with input as {}
	r.entity_name == "unknown"
	r.sector == "unknown"
	r.assessed_at == "unknown"
}

test_metadata_picked_up_from_input if {
	r := main.compliance_report with input as {
		"entity_name": "Big Bank Plc",
		"entity_type": "credit_institution",
		"sector": "banking",
		"entity_category": "essential",
		"assessment_date": "2026-06-26",
	}
	r.entity_name == "Big Bank Plc"
	r.sector == "banking"
	r.assessed_at == "2026-06-26"
}

# Semantic review 2026-11-13: total_controls must cover every violation rule.
test_empty_input_failed_controls_equal_violation_count if {
	r := data.nis2.main.compliance_report with input as {}
	r.total_controls == 35
	r.failed_controls == r.violation_count
	r.failed_controls <= r.total_controls
}
