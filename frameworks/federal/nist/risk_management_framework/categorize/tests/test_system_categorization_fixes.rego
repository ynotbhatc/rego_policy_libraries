package nist.rmf.categorize_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_rmf_categorize_report_defined_on_empty_input if {
	r := data.nist.rmf.categorize.rmf_categorization_compliance with input as {}
	r.overall_compliant == false
	r.confidentiality_properly_categorized == false
	r.system_impact_level == null
}

test_rmf_categorize_report_defined_on_failing_input if {
	i := {"system_categorization": {
		"overall_impact_level": "moderate",
		"confidentiality": {"impact_level": "moderate", "rationale": "", "loss_scenario_documented": true},
	}}
	r := data.nist.rmf.categorize.rmf_categorization_compliance with input as i
	r.confidentiality_properly_categorized == false
	r.system_impact_level == "moderate"
	r.overall_compliant == false
}

test_rmf_categorize_compliant_false_on_failing_input if {
	c := data.nist.rmf.categorize.rmf_categorization_compliant with input as {"system_categorization": {}}
	c == false
}
