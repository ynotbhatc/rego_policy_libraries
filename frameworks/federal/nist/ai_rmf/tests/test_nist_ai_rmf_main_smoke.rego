package nist.ai_rmf.main_test

import rego.v1

# Smoke test in the scripts/gen_tests.py format (written by hand with the module) for frameworks/federal/nist/ai_rmf/nist_ai_rmf_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_ai_rmf_main_loads_on_empty_input if {
	m := data.nist.ai_rmf.main with input as {}
	is_object(m)
}

test_nist_ai_rmf_main_report_wellformed_on_empty_input if {
	report := data.nist.ai_rmf.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_ai_rmf_main_fail_closed_on_empty_input if {
	report := data.nist.ai_rmf.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nist_ai_rmf_main_violations_on_empty_input if {
	v := data.nist.ai_rmf.main.violations with input as {}
	count(v) > 0
}
