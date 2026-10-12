package governance.geisa.lee_test

import rego.v1

# Generated smoke test for governance/geisa/geisa_lee.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_geisa_lee_loads_on_empty_input if {
	m := data.governance.geisa.lee with input as {}
	is_object(m)
}

test_geisa_lee_report_wellformed_on_empty_input if {
	report := data.governance.geisa.lee.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

