package digital_sovereignty.dora_sovereignty_fixes_test

import rego.v1

d := data.digital_sovereignty.dora_sovereignty

has_control(vs, c) if {
	some v in vs
	v.control == c
}

dora(x) := {"dora": x}

provs(list) := dora({"critical_ict_providers": list, "concentration_risk_threshold_pct": 60})

ok_provider := {"provider_name": "P", "exit_strategy_documented": true, "contractual_requirements_met": true, "pct_critical_functions": 30}

test_null_initial_notification_fails if not d.initial_notification_compliant with input as dora({"initial_notification_timeline_hours": null})

test_null_intermediate_fails if not d.intermediate_report_compliant with input as dora({"intermediate_report_timeline_hours": null})

test_initial_4h_ok if d.initial_notification_compliant with input as dora({"initial_notification_timeline_hours": 4})

test_intermediate_72h_ok if d.intermediate_report_compliant with input as dora({"intermediate_report_timeline_hours": 72})

test_null_initial_reports_dora006 if has_control(d.violations, "DORA-006") with input as dora({"initial_notification_timeline_hours": null})

test_missing_initial_reports_dora006 if has_control(d.violations, "DORA-006") with input as dora({})

test_missing_intermediate_reports_dora007 if has_control(d.violations, "DORA-007") with input as dora({})

test_fractional_hours_not_truncated_in_description if {
	some v in d.violations with input as dora({"initial_notification_timeline_hours": 4.5})
	v.control == "DORA-006"
	contains(v.description, "4.5")
}

test_null_pct_fails_concentration_and_reports if {
	inp := provs([object.union(ok_provider, {"pct_critical_functions": null})])
	not d.concentration_risk_acceptable with input as inp
	has_control(d.violations, "DORA-013") with input as inp
}

test_pct_over_threshold_reports if {
	inp := provs([object.union(ok_provider, {"pct_critical_functions": 75.5})])
	not d.concentration_risk_acceptable with input as inp
	some v in d.violations with input as inp
	v.control == "DORA-013"
	contains(v.description, "75.5")
}

test_pct_within_threshold_ok if d.concentration_risk_acceptable with input as provs([ok_provider])

test_absent_provider_list_fails_all_three if {
	not d.all_providers_have_exit_strategy with input as dora({})
	not d.all_providers_meet_contractual_requirements with input as dora({})
	not d.concentration_risk_acceptable with input as dora({})
	has_control(d.violations, "DORA-011") with input as dora({})
}

test_empty_provider_list_ok if {
	inp := provs([])
	d.all_providers_have_exit_strategy with input as inp
	d.all_providers_meet_contractual_requirements with input as inp
	d.concentration_risk_acceptable with input as inp
}

test_provider_missing_exit_field_fails if {
	inp := provs([json.remove(ok_provider, ["/exit_strategy_documented"])])
	not d.all_providers_have_exit_strategy with input as inp
	has_control(d.violations, "DORA-011") with input as inp
}

test_provider_missing_contract_field_fails if {
	inp := provs([json.remove(ok_provider, ["/contractual_requirements_met"])])
	not d.all_providers_meet_contractual_requirements with input as inp
	has_control(d.violations, "DORA-012") with input as inp
}

test_provider_without_name_still_reported if {
	inp := provs([{"exit_strategy_documented": false, "contractual_requirements_met": true, "pct_critical_functions": 10}])
	has_control(d.violations, "DORA-011") with input as inp
}

# Undefined-in-literal trap: the report must exist while provider controls fail.
test_report_defined_when_provider_controls_fail if {
	r := d.report with input as provs([json.remove(ok_provider, ["/exit_strategy_documented"])])
	r.compliant == false
	r.controls["DORA-011_exit_strategies"] == false
	r.violation_count > 0
}
