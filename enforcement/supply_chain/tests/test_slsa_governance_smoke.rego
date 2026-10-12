package supply_chain.slsa_test

import rego.v1

# Generated smoke test for enforcement/supply_chain/slsa_governance.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_slsa_governance_loads_on_empty_input if {
	m := data.supply_chain.slsa with input as {}
	is_object(m)
}

test_slsa_governance_report_wellformed_on_empty_input if {
	report := data.supply_chain.slsa.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_slsa_governance_fail_closed_on_empty_input if {
	report := data.supply_chain.slsa.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_slsa_governance_violations_on_empty_input if {
	v := data.supply_chain.slsa.violations with input as {}
	count(v) > 0
}
