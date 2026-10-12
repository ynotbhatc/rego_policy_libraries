package iec_62443.fr5_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/fr5_restricted_data_flow.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_fr5_restricted_data_flow_loads_on_empty_input if {
	m := data.iec_62443.fr5 with input as {}
	is_object(m)
}

test_fr5_restricted_data_flow_report_wellformed_on_empty_input if {
	report := data.iec_62443.fr5.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_fr5_restricted_data_flow_fail_closed_on_empty_input if {
	report := data.iec_62443.fr5.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_fr5_restricted_data_flow_violations_on_empty_input if {
	v := data.iec_62443.fr5.violations with input as {}
	count(v) > 0
}
