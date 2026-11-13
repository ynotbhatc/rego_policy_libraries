package cis_m365_v7.fabric_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/fabric_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_fabric_validation_loads_on_empty_input if {
	m := data.cis_m365_v7.fabric with input as {}
	is_object(m)
}

test_fabric_validation_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.fabric.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_fabric_validation_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.fabric.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13 regressions.
test_collected_but_settings_absent_is_not_a_pass if {
	v := data.cis_m365_v7.fabric.violation with input as {"fabric": {"collected": true, "settings": {}}}
	count(v) >= 12
	not data.cis_m365_v7.fabric.compliant with input as {"fabric": {"collected": true, "settings": {}}}
}

test_absent_setting_reported_once_when_also_unavailable if {
	v := data.cis_m365_v7.fabric.violation with input as {"fabric": {"collected": true, "settings": {}, "unavailable": {"PublishToWeb": "no permission"}}}
	count({m | some m in v; contains(m, "'PublishToWeb' not collected")}) == 0
}
