package ami.nist_ir7628.config_management_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/ami/nist_ir_7628/nist_ir7628_config_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_ir7628_config_management_loads_on_empty_input if {
	m := data.ami.nist_ir7628.config_management with input as {}
	is_object(m)
}

test_nist_ir7628_config_management_report_wellformed_on_empty_input if {
	report := data.ami.nist_ir7628.config_management.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_ir7628_config_management_fail_closed_on_empty_input if {
	report := data.ami.nist_ir7628.config_management.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nist_ir7628_config_management_violations_on_empty_input if {
	v := data.ami.nist_ir7628.config_management.violations with input as {}
	count(v) > 0
}
