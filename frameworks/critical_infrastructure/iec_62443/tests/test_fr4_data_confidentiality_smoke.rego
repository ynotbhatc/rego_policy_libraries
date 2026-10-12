package iec_62443.fr4_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/fr4_data_confidentiality.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_fr4_data_confidentiality_loads_on_empty_input if {
	m := data.iec_62443.fr4 with input as {}
	is_object(m)
}

test_fr4_data_confidentiality_report_wellformed_on_empty_input if {
	report := data.iec_62443.fr4.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

