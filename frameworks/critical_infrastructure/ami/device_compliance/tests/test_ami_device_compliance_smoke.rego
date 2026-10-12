package ami.device.compliance_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/ami/device_compliance/ami_device_compliance.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ami_device_compliance_loads_on_empty_input if {
	m := data.ami.device.compliance with input as {}
	is_object(m)
}

test_ami_device_compliance_report_wellformed_on_empty_input if {
	report := data.ami.device.compliance.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ami_device_compliance_fail_closed_on_empty_input if {
	report := data.ami.device.compliance.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
