package governance.geisa.vee_test

import rego.v1

import data.governance.geisa.vee

# Generated smoke test for governance/geisa/geisa_vee.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_geisa_vee_loads_on_empty_input if {
	m := data.governance.geisa.vee with input as {}
	is_object(m)
}

test_geisa_vee_report_wellformed_on_empty_input if {
	report := data.governance.geisa.vee.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_geisa_vee_fail_closed_on_empty_input if {
	report := data.governance.geisa.vee.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_geisa_vee_violations_on_empty_input if {
	v := data.governance.geisa.vee.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: VEE required + container without runtime must not pass.
test_vee_required_container_without_runtime_fails if {
	inp := {"discovery_response": {"pillars": {"vee": true}}, "container": {"isolated": true}}
	not vee.compliant with input as inp
	vee.violations["VEE: discovery_response.pillars.vee is true but evidence missing — container.runtime not collected"] with input as inp
}
