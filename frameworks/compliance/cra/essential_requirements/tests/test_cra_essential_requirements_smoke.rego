package cra.essential_requirements_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/essential_requirements/cra_essential_requirements.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_essential_requirements_loads_on_empty_input if {
	m := data.cra.essential_requirements with input as {}
	is_object(m)
}

test_cra_essential_requirements_report_wellformed_on_empty_input if {
	report := data.cra.essential_requirements.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cra_essential_requirements_fail_closed_on_empty_input if {
	report := data.cra.essential_requirements.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
