package stig.postgresql_16.main_test

import rego.v1

# Generated smoke test for benchmarks/stig/postgresql_16/stig_postgresql_16_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_postgresql_16_main_loads_on_empty_input if {
	m := data.stig.postgresql_16.main with input as {}
	is_object(m)
}

test_stig_postgresql_16_main_report_wellformed_on_empty_input if {
	report := data.stig.postgresql_16.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_stig_postgresql_16_main_fail_closed_on_empty_input if {
	report := data.stig.postgresql_16.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_stig_postgresql_16_main_violations_on_empty_input if {
	v := data.stig.postgresql_16.main.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: the no-facts condition is reported once, not once by the .main
# report and again by the key bridge.
test_bridge_does_not_double_count_no_facts if {
	r := data.stig_postgresql_16.main.compliance_report with input as {}
	fc := [v | some v in r.violations; _is_fail_closed(v)]
	count(fc) == 1
	r.violation_count == count(r.violations)
}

_is_fail_closed(v) if startswith(object.get(v, "rule_title", ""), "FAIL-CLOSED")

_is_fail_closed(v) if object.get(v, "control", "") == "FAIL-CLOSED"
