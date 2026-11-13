package nist_800_82.main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nist_800_82/nist_800_82_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_800_82_main_loads_on_empty_input if {
	m := data.nist_800_82.main with input as {}
	is_object(m)
}

test_nist_800_82_main_report_wellformed_on_empty_input if {
	report := data.nist_800_82.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_800_82_main_fail_closed_on_empty_input if {
	report := data.nist_800_82.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nist_800_82_main_violations_on_empty_input if {
	v := data.nist_800_82.main.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: total_controls covers all 35 control violation rules.
test_empty_input_failed_controls_cover_every_control if {
	r := data.nist_800_82.main.compliance_report with input as {}
	r.total_controls == 35
	r.failed_controls == 35
	r.failed_controls <= r.total_controls
}
