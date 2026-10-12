package governance.geisa.adm_test

import rego.v1

# Generated smoke test for governance/geisa/geisa_adm.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_geisa_adm_loads_on_empty_input if {
	m := data.governance.geisa.adm with input as {}
	is_object(m)
}

test_geisa_adm_report_wellformed_on_empty_input if {
	report := data.governance.geisa.adm.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_geisa_adm_fail_closed_on_empty_input if {
	report := data.governance.geisa.adm.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_geisa_adm_violations_on_empty_input if {
	v := data.governance.geisa.adm.violations with input as {}
	count(v) > 0
}
