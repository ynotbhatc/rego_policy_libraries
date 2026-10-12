package iec_62443.fr3_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/fr3_system_integrity.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_fr3_system_integrity_loads_on_empty_input if {
	m := data.iec_62443.fr3 with input as {}
	is_object(m)
}

test_fr3_system_integrity_report_wellformed_on_empty_input if {
	report := data.iec_62443.fr3.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_fr3_system_integrity_fail_closed_on_empty_input if {
	report := data.iec_62443.fr3.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_fr3_system_integrity_violations_on_empty_input if {
	v := data.iec_62443.fr3.violations with input as {}
	count(v) > 0
}
