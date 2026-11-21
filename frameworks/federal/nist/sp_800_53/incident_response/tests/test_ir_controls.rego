package nist.sp800_53.incident_response_logic_test

# IR-2 / IR-3 frequencies are organization-defined; IR-5 is "track and document incidents"; the Moderate-baseline
# enhancements each have their own finding. Every test binds its own input (no `with` inside helpers: a
# `f(x) := ... with input as ...` helper breaks `opa build -t wasm`).

import data.nist.sp800_53.incident_response as ir
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

# Control ids that have a finding ("NIST IR-6(1): ..." -> "IR-6(1)").
_failing(r) := {id |
	some v in r.violations
	id := substring(v, 5, indexof(v, ":") - 5)
}

_att := {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}

_pass_base := {"ir_controls": {
	"policy": {"documented": true},
	"training": {
		"days_since_last": 100, "odp": {"frequency_days": 365},
		"simulated_events": {"included_in_last_training": true},
		"automated_environment": {"mechanisms_in_use": ["cyber range", "SOAR sandbox"], "odp": {"mechanisms": ["cyber range"]}},
	},
	"testing": {"days_since_last": 90, "odp": {"frequency_days": 365}, "coordinated_with_related_plans": true},
	"handling": {
		"process_defined": true,
		"automated_support": {"enabled": true},
		"dynamic_reconfiguration": {
			"supported_reconfiguration_types": ["firewall rule change", "host isolation", "traffic reroute"],
			"odp": {"reconfiguration_types": ["firewall rule change", "host isolation"]},
		},
		"correlation": {"enabled": true, "incidents_not_correlated": 0},
		"insider_threat": {"playbook_in_place": true},
		"integrated_team": {"established": true, "deployment_hours": 12, "odp": {"deployment_hours": 24}},
	},
	"incident_tracking": {"tracked_and_documented": true, "automated": {"enabled": true, "incidents_tracked_manually_only": 0}},
	"reporting": {
		"timely": true,
		"automated": {"enabled": true, "incidents_reported_manually_only": 0},
		"supply_chain": {"incidents_not_shared": 0},
	},
	"assistance": {"available": true, "automated_support": {"enabled": true}},
	"plan": {"documented": true},
	"information_spillage": {
		"process_defined": true,
		"training": {"days_since_last": 200, "odp": {"frequency_days": 365}},
		"post_spill_operations": {"attestation": _att},
		"exposure": {"exposures_without_controls": 0},
	},
}}

test_all_pass_fixture_is_compliant if {
	r := ir.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_catalog if {
	ir.evaluated_controls == {
		"IR-1", "IR-2", "IR-2(1)", "IR-2(2)", "IR-3", "IR-3(2)", "IR-4", "IR-4(1)", "IR-4(2)", "IR-4(4)", "IR-4(6)",
		"IR-4(11)", "IR-5", "IR-5(1)", "IR-6", "IR-6(1)", "IR-6(3)", "IR-7", "IR-7(1)", "IR-8", "IR-9", "IR-9(2)",
		"IR-9(3)", "IR-9(4)", "IR-2(3)", "IR-8(1)",
	}
	count(ir.evaluated_controls) == 26
}

test_ir_one_finding_per_id_on_empty_input if {
	r := ir.compliance_report with input as {}
	count(r.violations) == count(ir.evaluated_controls)
	_failing(r) == ir.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- IR-2 / IR-3 -----------------------------------------------------------------------------------------------

test_ir2_within_org_frequency_passes if {
	r := ir.compliance_report with input as {"ir_controls": {"training": {"days_since_last": 500, "odp": {"frequency_days": 730}}}}
	count(_finding(r, "IR-2")) == 0
}

test_ir2_beyond_org_frequency_fails if {
	r := ir.compliance_report with input as {"ir_controls": {"training": {"days_since_last": 200, "odp": {"frequency_days": 180}}}}
	f := _finding(r, "IR-2")
	count(f) == 1
	contains(f[0], "180")
}

test_ir2_missing_odp_is_missing_evidence if {
	r := ir.compliance_report with input as {"ir_controls": {"training": {"days_since_last": 10}}}
	f := _finding(r, "IR-2")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "frequency_days")
}

test_ir2_old_within_year_boolean_not_evidence if {
	r := ir.compliance_report with input as {"ir_controls": {"training": {"completed_within_year": true}}}
	f := _finding(r, "IR-2")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ir3_within_org_frequency_passes if {
	r := ir.compliance_report with input as {"ir_controls": {"testing": {"days_since_last": 90, "odp": {"frequency_days": 365}}}}
	count(_finding(r, "IR-3")) == 0
}

test_ir3_beyond_org_frequency_fails if {
	r := ir.compliance_report with input as {"ir_controls": {"testing": {"days_since_last": 400, "odp": {"frequency_days": 365}}}}
	count(_finding(r, "IR-3")) == 1
}

test_ir3_missing_observation_is_missing_evidence if {
	r := ir.compliance_report with input as {"ir_controls": {"testing": {"odp": {"frequency_days": 365}}}}
	f := _finding(r, "IR-3")
	count(f) == 1
	contains(f[0], "days_since_last")
}

test_ir3_days_as_string_is_missing_evidence if {
	inp := object.union(_pass, {"ir_controls": {"testing": {"days_since_last": "1"}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-3"}
	contains(concat("", r.violations), "evidence missing")
}

# --- IR-5 ------------------------------------------------------------------------------------------------------

test_ir5_tracking_passes if {
	r := ir.compliance_report with input as {"ir_controls": {"incident_tracking": {"tracked_and_documented": true}}}
	count(_finding(r, "IR-5")) == 0
}

test_ir5_continuous_monitoring_is_not_ir5_evidence if {
	r := ir.compliance_report with input as {"ir_controls": {"monitoring": {"continuous": true}}}
	count(_finding(r, "IR-5")) == 1
}

test_ir5_not_tracked_fails if {
	r := ir.compliance_report with input as {"ir_controls": {"incident_tracking": {"tracked_and_documented": false}}}
	f := _finding(r, "IR-5")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_ir5_boolean_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"incident_tracking": {"tracked_and_documented": "true"}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-5: evidence missing — input.ir_controls.incident_tracking.tracked_and_documented not collected"}
}

# --- original single-fact rules: absent is evidence missing, false keeps the original message -------------------

test_ir1_false_keeps_original_message if {
	inp := object.union(_pass, {"ir_controls": {"policy": {"documented": false}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-1: Incident response policy and procedures not documented"}
}

test_ir4_absent_is_evidence_missing_and_ir4_1_unaffected if {
	inp := json.remove(_pass, ["ir_controls/handling/process_defined"])
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-4: evidence missing — input.ir_controls.handling.process_defined not collected"}
}

# --- enhancements: one flip, one evidence-missing case ------------------------------------------------------------

test_ir3_2_not_coordinated_flips_only_ir3_2 if {
	inp := object.union(_pass, {"ir_controls": {"testing": {"coordinated_with_related_plans": false}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-3(2)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_ir3_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"testing": {"coordinated_with_related_plans": null}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-3(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_1_not_automated_flips_only_ir4_1 if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"automated_support": {"enabled": false}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(1)"}
}

test_ir4_1_boolean_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"automated_support": {"enabled": "true"}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir6_1_manual_reports_flip_only_ir6_1 if {
	inp := object.union(_pass, {"ir_controls": {"reporting": {"automated": {"incidents_reported_manually_only": 2}}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-6(1): 2 incidents not reported through the automated mechanism"}
}

test_ir6_1_count_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"reporting": {"automated": {"incidents_reported_manually_only": null}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-6(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir6_3_unshared_incidents_flip_only_ir6_3 if {
	inp := object.union(_pass, {"ir_controls": {"reporting": {"supply_chain": {"incidents_not_shared": 1}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-6(3)"}
}

test_ir6_3_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"reporting": {"supply_chain": {"incidents_not_shared": "0"}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-6(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir7_1_not_automated_flips_only_ir7_1 if {
	inp := object.union(_pass, {"ir_controls": {"assistance": {"automated_support": {"enabled": false}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-7(1)"}
}

test_ir7_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"assistance": {"automated_support": null}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-7(1)"}
	contains(concat("", r.violations), "evidence missing")
}

# --- strict booleans on the original single-fact rules: only true passes ----------------------------------------

test_ir1_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"policy": {"documented": "true"}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-1: evidence missing — input.ir_controls.policy.documented not collected"}
}

test_ir6_number_one_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"reporting": {"timely": 1}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-6: evidence missing — input.ir_controls.reporting.timely not collected"}
}

test_ir8_null_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"plan": {"documented": null}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-8: evidence missing — input.ir_controls.plan.documented not collected"}
}

test_ir9_string_false_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"information_spillage": {"process_defined": "false"}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-9: evidence missing — input.ir_controls.information_spillage.process_defined not collected"}
}

test_ir7_object_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"assistance": {"available": {"yes": true}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-7"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_false_keeps_original_message if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"process_defined": false}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4"}
	not contains(concat("", r.violations), "evidence missing")
}

# --- High-baseline enhancements: one flip, one evidence-missing case ----------------------------------------------

test_ir2_1_no_simulation_flips_only_ir2_1 if {
	inp := object.union(_pass, {"ir_controls": {"training": {"simulated_events": {"included_in_last_training": false}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-2(1)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_ir2_1_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"training": {"simulated_events": {"included_in_last_training": "true"}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-2(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir2_2_mechanism_absent_flips_only_ir2_2 if {
	inp := object.union(_pass, {"ir_controls": {"training": {"automated_environment": {"mechanisms_in_use": ["SOAR sandbox"]}}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-2(2): incident response training environment does not provide automated mechanism cyber range"}
}

test_ir2_2_missing_odp_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/training/automated_environment/odp"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-2(2)"}
	contains(concat("", r.violations), "evidence missing")
	contains(concat("", r.violations), "odp.mechanisms")
}

test_ir4_2_type_unsupported_flips_only_ir4_2 if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"dynamic_reconfiguration": {"supported_reconfiguration_types": ["host isolation"]}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(2)"}
	contains(concat("", r.violations), "firewall rule change")
}

test_ir4_2_missing_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/handling/dynamic_reconfiguration/supported_reconfiguration_types"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_4_uncorrelated_flips_only_ir4_4 if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"correlation": {"incidents_not_correlated": 3}}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-4(4): 3 incidents not correlated with the organization-wide incident view"}
}

test_ir4_4_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"correlation": {"incidents_not_correlated": "1"}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_6_no_playbook_flips_only_ir4_6 if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"insider_threat": {"playbook_in_place": false}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(6)"}
}

test_ir4_6_missing_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/handling/insider_threat"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(6)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_11_slow_deployment_flips_only_ir4_11 if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"integrated_team": {"deployment_hours": 36}}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-4(11): integrated incident response team deploys in 36 hours; the organization-defined period is 24 hours"}
}

test_ir4_11_hours_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"integrated_team": {"deployment_hours": null}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(11)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir4_11_odp_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"handling": {"integrated_team": {"odp": {"deployment_hours": "48"}}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-4(11)"}
	contains(concat("", r.violations), "odp.deployment_hours")
}

test_ir5_1_manual_tracking_flips_only_ir5_1 if {
	inp := object.union(_pass, {"ir_controls": {"incident_tracking": {"automated": {"incidents_tracked_manually_only": 2}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-5(1)"}
}

test_ir5_1_missing_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/incident_tracking/automated"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-5(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir9_2_overdue_training_flips_only_ir9_2 if {
	inp := object.union(_pass, {"ir_controls": {"information_spillage": {"training": {"days_since_last": 400}}}})
	r := ir.compliance_report with input as inp
	r.violations == {"NIST IR-9(2): information spillage response training last provided 400 days ago; the organization-defined frequency is 365 days"}
}

test_ir9_2_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ir_controls": {"information_spillage": {"training": {"days_since_last": "1"}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-9(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ir9_3_incomplete_attestation_flips_only_ir9_3 if {
	inp := object.union(_pass, {"ir_controls": {"information_spillage": {"post_spill_operations": {"attestation": {"by": ""}}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-9(3)"}
	contains(concat("", r.violations), "not attested")
	not contains(concat("", r.violations), "evidence missing")
}

test_ir9_3_missing_attestation_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/information_spillage/post_spill_operations"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-9(3)"}
	contains(concat("", r.violations), "evidence missing")
	contains(concat("", r.violations), "not attested")
}

test_ir9_4_exposure_without_controls_flips_only_ir9_4 if {
	inp := object.union(_pass, {"ir_controls": {"information_spillage": {"exposure": {"exposures_without_controls": 1}}}})
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-9(4)"}
}

test_ir9_4_missing_is_evidence_missing if {
	inp := json.remove(_pass, ["ir_controls/information_spillage/exposure"])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-9(4)"}
	contains(concat("", r.violations), "evidence missing")
}

# A base control never fails for an enhancement: removing every High-baseline enhancement fact flips only those ids.
test_base_controls_ignore_high_enhancement_facts if {
	inp := json.remove(_pass, [
		"ir_controls/training/simulated_events", "ir_controls/training/automated_environment",
		"ir_controls/handling/dynamic_reconfiguration", "ir_controls/handling/correlation",
		"ir_controls/handling/insider_threat", "ir_controls/handling/integrated_team",
		"ir_controls/incident_tracking/automated", "ir_controls/information_spillage/training",
		"ir_controls/information_spillage/post_spill_operations", "ir_controls/information_spillage/exposure",
	])
	r := ir.compliance_report with input as inp
	_failing(r) == {"IR-2(1)", "IR-2(2)", "IR-4(2)", "IR-4(4)", "IR-4(6)", "IR-4(11)", "IR-5(1)", "IR-9(2)", "IR-9(3)", "IR-9(4)"}
}

# The all-pass fixture with the facts of the Privacy-baseline enhancements.
_pass := object.union(_pass_base, {"ir_controls": {"training": {"breach": {"covers_identification": true, "covers_response": true, "covers_reporting_process": true}}, "plan": {"breaches": {"notification_determination_process": true, "harm_assessment_process": true, "privacy_requirements_identified": true}}}})

# --- Privacy-baseline enhancements and count type traps: each case flips exactly one id ---

test_privacy_ir2_3_fails_1 if {
	v := data.nist.sp800_53.incident_response.violation with input as object.union(_pass, {"ir_controls": {"training": {"breach": {"covers_reporting_process": false}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"IR-2(3)"}
	some x in v
	contains(x, "reporting a breach")
}

test_privacy_ir2_3_evidence_missing_2 if {
	v := data.nist.sp800_53.incident_response.violation with input as object.union(_pass, {"ir_controls": {"training": {"breach": {"covers_identification": 1}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"IR-2(3)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_ir8_1_fails_1 if {
	v := data.nist.sp800_53.incident_response.violation with input as object.union(_pass, {"ir_controls": {"plan": {"breaches": {"harm_assessment_process": false}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"IR-8(1)"}
	some x in v
	contains(x, "assess the harm")
}

test_privacy_ir8_1_evidence_missing_2 if {
	v := data.nist.sp800_53.incident_response.violation with input as object.union(_pass, {"ir_controls": {"plan": {"breaches": {"privacy_requirements_identified": null}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"IR-8(1)"}
	some x in v
	contains(x, "evidence missing")
}
