package digital_sovereignty.geopolitical_sovereignty_test

import rego.v1

# Generated smoke test for frameworks/sovereignty/digital_sovereignty/geopolitical_sovereignty.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_geopolitical_sovereignty_loads_on_empty_input if {
	m := data.digital_sovereignty.geopolitical_sovereignty with input as {}
	is_object(m)
}

test_geopolitical_sovereignty_report_wellformed_on_empty_input if {
	report := data.digital_sovereignty.geopolitical_sovereignty.report with input as {}
	is_object(report)
	count(report) > 0
}

test_geopolitical_sovereignty_fail_closed_on_empty_input if {
	report := data.digital_sovereignty.geopolitical_sovereignty.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_geopolitical_sovereignty_violations_on_empty_input if {
	v := data.digital_sovereignty.geopolitical_sovereignty.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: report stays defined when GT-002/GT-003 fail; GT-003 gap has a finding.
test_report_defined_when_trigger_procedure_missing if {
	inp := {"geopolitical_risk": {"geopolitical_event_triggers": [{"trigger_id": "t1", "event_type": "sanctions", "response_procedure_documented": false, "activation_criteria_defined": true}]}}
	r := data.digital_sovereignty.geopolitical_sovereignty.report with input as inp
	r.controls["GT-002_event_triggers_documented"] == false
	r.violation_count > 0
}

test_missing_withdrawal_plan_raises_gt003 if {
	inp := {"geopolitical_risk": {"country_exit_procedures": [{"country": "DE", "data_egress_procedure_documented": true, "infrastructure_withdrawal_plan": false}]}}
	v := data.digital_sovereignty.geopolitical_sovereignty.violations with input as inp
	some x in v
	x.control == "GT-003"
}
