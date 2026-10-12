package nist_800_171.main_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_171/nist_800_171_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_800_171_main_loads_on_empty_input if {
	m := data.nist_800_171.main with input as {}
	is_object(m)
}

test_nist_800_171_main_report_wellformed_on_empty_input if {
	report := data.nist_800_171.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_800_171_main_fail_closed_on_empty_input if {
	report := data.nist_800_171.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
