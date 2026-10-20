package cis_opnsense_test

import rego.v1

# Empty-input smoke tests for benchmarks/cis/network_devices/opnsense/cis_opnsense.rego,
# in the same form as the generated smoke tests of the sibling packages.

test_cis_opnsense_loads_on_empty_input if {
	m := data.cis_opnsense with input as {}
	is_object(m)
}

test_cis_opnsense_violations_on_empty_input if {
	v := data.cis_opnsense.violations with input as {}
	count(v) > 0
}

test_cis_opnsense_assessment_populated_on_empty_input if {
	a := data.cis_opnsense.compliance_assessment with input as {}
	a.compliant == false
	a.summary.total_controls == 29
	a.summary.failing_controls == 29
	a.summary.overall_compliance == "FAIL"
}
