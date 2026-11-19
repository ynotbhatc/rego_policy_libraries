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

_pass := {"ir_controls": {
	"policy": {"documented": true},
	"training": {"days_since_last": 100, "odp": {"frequency_days": 365}},
	"testing": {"days_since_last": 90, "odp": {"frequency_days": 365}, "coordinated_with_related_plans": true},
	"handling": {"process_defined": true, "automated_support": {"enabled": true}},
	"incident_tracking": {"tracked_and_documented": true},
	"reporting": {
		"timely": true,
		"automated": {"enabled": true, "incidents_reported_manually_only": 0},
		"supply_chain": {"incidents_not_shared": 0},
	},
	"assistance": {"available": true, "automated_support": {"enabled": true}},
	"plan": {"documented": true},
	"information_spillage": {"process_defined": true},
}}

test_all_pass_fixture_is_compliant if {
	r := ir.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_catalog if {
	ir.evaluated_controls == {
		"IR-1", "IR-2", "IR-3", "IR-3(2)", "IR-4", "IR-4(1)", "IR-5", "IR-6", "IR-6(1)", "IR-6(3)", "IR-7", "IR-7(1)",
		"IR-8", "IR-9",
	}
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
