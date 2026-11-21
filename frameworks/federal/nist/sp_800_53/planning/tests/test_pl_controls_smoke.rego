package nist.sp800_53.planning_test

import rego.v1

# Smoke test for frameworks/federal/nist/sp_800_53/planning/pl_controls.rego, written in the shape scripts/gen_tests.py generates: each rule states one thing the
# module does on empty input (loads, returns a well-formed report, fails closed).

test_pl_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.planning with input as {}
	is_object(m)
}

test_pl_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.planning.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_pl_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.planning.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
