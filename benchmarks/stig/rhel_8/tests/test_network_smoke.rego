package stig.rhel_8.network_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_8/network.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_network_loads_on_empty_input if {
	m := data.stig.rhel_8.network with input as {}
	is_object(m)
}

test_network_report_wellformed_on_empty_input if {
	report := data.stig.rhel_8.network.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_network_fail_closed_on_empty_input if {
	report := data.stig.rhel_8.network.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_network_violations_on_empty_input if {
	v := data.stig.rhel_8.network.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_missing_evidence_open_status_rhel_08_040110 if {
	data.stig.rhel_8.network.status_rhel_08_040110 == "Open" with input as {"x": 1}
}
