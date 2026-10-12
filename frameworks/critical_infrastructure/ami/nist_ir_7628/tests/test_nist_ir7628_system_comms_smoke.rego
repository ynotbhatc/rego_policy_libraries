package ami.nist_ir7628.system_comms_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/ami/nist_ir_7628/nist_ir7628_system_comms.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_ir7628_system_comms_loads_on_empty_input if {
	m := data.ami.nist_ir7628.system_comms with input as {}
	is_object(m)
}

test_nist_ir7628_system_comms_report_wellformed_on_empty_input if {
	report := data.ami.nist_ir7628.system_comms.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_ir7628_system_comms_fail_closed_on_empty_input if {
	report := data.ami.nist_ir7628.system_comms.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nist_ir7628_system_comms_violations_on_empty_input if {
	v := data.ami.nist_ir7628.system_comms.violations with input as {}
	count(v) > 0
}
