package govramp.main_test

import data.govramp.main
import data.nist.sp800_53.index
import data.nist.sp800_53.main_test.fully_compliant_input
import rego.v1

# Most tests below stand in for the NIST SP 800-53 module (every control passing, or the rows a test names): that
# module is tested in its own directory and one evaluation of it costs more than a second. The tests that evaluate it
# for real are the ones named test_real_*.
_pass_row(id) := {"id": id, "status": "pass", "basis": "evidence", "baselines": [], "findings": []}

_all_pass_rows := [_pass_row(id) | some id in index.order]

_stub_ids := {id | some id in index.order}

_report_rows(inp, rows) := r if {
	r := main.compliance_report with input as inp
		with data.nist.sp800_53.main.control_results as rows
		with data.nist.sp800_53.main.violations as []
		with data.nist.sp800_53.main.evaluated_controls as _stub_ids
}

# the 800-53 module passing every control
_report(inp) := _report_rows(inp, _all_pass_rows)

# ... and failing every control, each with a finding in its own prefix
_all_fail_rows := [_failing_row(id) | some id in index.order]

# the 800-53 module failing no control but with one control carrying a finding
_failing_row(id) := {"id": id, "status": "fail", "basis": "evidence", "baselines": [], "findings": [sprintf("NIST %s: a stand-in finding", [id])]}

_rows_with_failure(id) := [row | some i in index.order; row := _row_or_failure(i, id)]

_row_or_failure(i, id) := _failing_row(i) if i == id

_row_or_failure(i, id) := _pass_row(i) if i != id

# The all-pass fixtures: the 800-53 module's all-pass input (every control GovRAMP selects is one that module
# evaluates) plus the programme facts of the declared level and status.
_facts(level, status, extra) := object.union(fully_compliant_input, object.union({
	"impact_level": level,
	"verification_status": status,
	"verification": {"status_valid_days_remaining": 200},
	"continuous_monitoring": {"reports_submitted_on_schedule": true},
}, extra))

_third_party := {"verification": {"third_party_assessment_completed": true, "status_valid_days_remaining": 200}}

_third_party_sponsor := {"verification": {"third_party_assessment_completed": true, "sponsoring_body_approved": true, "status_valid_days_remaining": 200}}

_pmo := {"verification": {"pmo_assessment_completed": true, "status_valid_days_remaining": 200}}

good_moderate_authorized := _facts("moderate", "authorized", _third_party_sponsor)

good_low_ready := _facts("low", "ready", _third_party)

good_moderate_core := _facts("moderate", "core", _pmo)

good_high_authorized := _facts("high", "authorized", _third_party_sponsor)

# object.union merges deeply, so it cannot take a key out: this replaces the whole value of one key.
_with(inp, key, val) := object.union(object.remove(inp, [key]), {key: val})

_empty_scope(r) if {
	r.passed_controls + r.failed_controls + r.not_applicable_controls == r.total_controls
}

# --- empty input and the selectors ---------------------------------------------------------------------------------

test_real_empty_input_fails_closed_on_the_high_baseline if {
	r := main.compliance_report with input as {}
	r.framework == "GovRAMP"
	r.formerly == "StateRAMP"
	r.compliant == false
	r.total_controls == 406
	r.failed_controls == 406
	r.passed_controls == 0
	r.scope == {"impact_level": "high", "status": "authorized", "map": "govramp_high"}
	_empty_scope(r)
	count(r.violations) == 409 # 406 controls and three programme findings
}

test_real_empty_input_names_the_missing_selectors if {
	r := _report({})
	r.impact_level == "unknown"
	r.verification_status == "unknown"
	some v in r.violations
	startswith(v, "GovRAMP IMPACT: evidence missing or invalid")
	some w in r.violations
	startswith(w, "GovRAMP STATUS: evidence missing or invalid")
}

test_unknown_level_values_are_findings_never_compliant if {
	every bad in ["", "medium", "Moderate-Plus", 2, true, null, ["moderate"], {"level": "moderate"}] {
		r := _report(object.union(good_moderate_authorized, {"impact_level": bad}))
		r.impact_level == "unknown"
		r.compliant == false
		r.scope.impact_level == "high"
	}
}

test_level_is_trimmed_and_case_folded_like_fedramp if {
	r := _report(object.union(good_moderate_authorized, {"impact_level": " Moderate "}))
	r.impact_level == "moderate"
	r.compliant
}

test_unknown_status_values_are_findings_never_compliant if {
	every bad in ["", "snapshot", "progressing", 1, false, null, ["core"]] {
		r := _report(object.union(good_moderate_authorized, {"verification_status": bad}))
		r.verification_status == "unknown"
		r.compliant == false
		r.scope.status == "authorized"
	}
}

test_core_exists_at_moderate_only if {
	r := _report(object.union(good_low_ready, {"verification_status": "core"}))
	r.compliant == false
	r.scope == {"impact_level": "low", "status": "authorized", "map": "govramp_low"}
	r.total_controls == 153
	some v in r.violations
	startswith(v, "GovRAMP STATUS: Core exists at the Moderate impact level only")
}

# --- every level and status ---------------------------------------------------------------------------------------

test_real_low_ready_all_pass if {
	r := main.compliance_report with input as good_low_ready
	r.compliant
	r.violations == []
	r.total_controls == 29
	r.passed_controls == 29
	r.failed_controls == 0
	r.scope.map == "govramp_low_ready"
	r.baseline_size == 153
}

test_real_moderate_core_all_pass if {
	r := main.compliance_report with input as good_moderate_core
	r.compliant
	r.total_controls == 60
	r.passed_controls == 60
	r.scope.map == "govramp_moderate_core"
	r.baseline_size == 319
}

test_real_moderate_authorized_all_pass if {
	r := main.compliance_report with input as good_moderate_authorized
	r.compliant
	r.violations == []
	r.total_controls == 319
	r.passed_controls == 319
	r.failed_control_ids == []
	r.not_applicable_controls == 0
	r.control_result_counts == {"pass": 319, "fail": 0, "evidence_missing": 0, "not_attested": 0, "not_evaluated": 0}
	count(r.control_results) == 319
}

test_real_high_authorized_all_pass if {
	r := main.compliance_report with input as good_high_authorized
	r.compliant
	r.total_controls == 406
	r.passed_controls == 406
	r.baseline_size == 406
}

test_provisionally_authorized_shares_the_authorized_scope if {
	r := _report(object.union(good_high_authorized, {"verification_status": "provisionally_authorized"}))
	r.compliant
	r.total_controls == 406
	r.scope == {"impact_level": "high", "status": "provisionally_authorized", "map": "govramp_high"}
}

test_ready_and_authorized_totals_differ_at_one_level if {
	ready := _report(object.union(good_moderate_authorized, {"verification_status": "ready"}))
	auth := _report(good_moderate_authorized)
	ready.total_controls == 80
	auth.total_controls == 319
	ready.compliant
}

# --- programme facts: only the boolean true (or a number) passes ---------------------------------------------------

_finding_names(r, needle) if {
	some v in r.violations
	contains(v, needle)
}

test_authorized_third_party_assessment_must_be_true if {
	every bad in [false, "true", "false", "yes", 1, 0, null] {
		inp := object.union(good_moderate_authorized, {"verification": object.union(good_moderate_authorized.verification, {"third_party_assessment_completed": bad})})
		r := _report(inp)
		r.compliant == false
		_finding_names(r, "input.verification.third_party_assessment_completed is not true")
	}
}

test_authorized_third_party_assessment_missing_is_evidence_missing if {
	inp := _with(good_moderate_authorized, "verification", {"sponsoring_body_approved": true, "status_valid_days_remaining": 200})
	r := _report(inp)
	r.compliant == false
	_finding_names(r, "[evidence missing: input.verification.third_party_assessment_completed not collected]")
}

test_string_is_named_as_not_a_boolean if {
	inp := object.union(good_moderate_authorized, {"verification": object.union(good_moderate_authorized.verification, {"sponsoring_body_approved": "true"})})
	r := _report(inp)
	r.compliant == false
	_finding_names(r, "[evidence invalid: input.verification.sponsoring_body_approved is not a boolean (got string)]")
}

test_core_needs_the_pmo_assessment_and_no_3pao if {
	missing := _report(_with(good_moderate_core, "verification", {"status_valid_days_remaining": 200}))
	missing.compliant == false
	_finding_names(missing, "input.verification.pmo_assessment_completed is not true")
	# a 3PAO fact on a Core status is not asked for
	r := _report(good_moderate_core)
	not _finding_names(r, "3PAO")
}

test_sponsor_is_asked_for_authorized_and_not_for_ready if {
	ready := _report(_with(_with(good_moderate_authorized, "verification_status", "ready"), "verification", _third_party.verification))
	ready.compliant
	auth := _report(_with(good_moderate_authorized, "verification", _third_party.verification))
	auth.compliant == false
	_finding_names(auth, "input.verification.sponsoring_body_approved is not true")
}

test_status_validity_is_a_number_and_not_expired if {
	every bad in ["200", "30", true, null, [], {}] {
		r := _report(object.union(good_moderate_authorized, {"verification": object.union(good_moderate_authorized.verification, {"status_valid_days_remaining": bad})}))
		r.compliant == false
		_finding_names(r, "status_valid_days_remaining")
	}
	expired := _report(object.union(good_moderate_authorized, {"verification": object.union(good_moderate_authorized.verification, {"status_valid_days_remaining": -3})}))
	expired.compliant == false
	_finding_names(expired, "the verified status expired 3 days ago")
	today := _report(object.union(good_moderate_authorized, {"verification": object.union(good_moderate_authorized.verification, {"status_valid_days_remaining": 0})}))
	today.compliant
}

test_continuous_monitoring_cadence_follows_the_status if {
	core := _report(object.union(good_moderate_core, {"continuous_monitoring": {"reports_submitted_on_schedule": false}}))
	core.compliant == false
	_finding_names(core, "due quarterly for core")
	auth := _report(object.union(good_moderate_authorized, {"continuous_monitoring": {"reports_submitted_on_schedule": "true"}}))
	auth.compliant == false
	_finding_names(auth, "due monthly for authorized")
	_finding_names(auth, "[evidence invalid: input.continuous_monitoring.reports_submitted_on_schedule is not a boolean (got string)]")
}

test_missing_or_null_sections_are_findings if {
	every key in ["verification", "continuous_monitoring"] {
		gone := _report(object.remove(good_moderate_authorized, [key]))
		gone.compliant == false
		nulled := _report(object.union(good_moderate_authorized, {key: null}))
		nulled.compliant == false
		stringy := _report(object.union(good_moderate_authorized, {key: "ok"}))
		stringy.compliant == false
	}
}

# --- the control results ------------------------------------------------------------------------------------------

test_real_a_failing_control_is_counted_and_not_clamped if {
	# one 800-53 control with a finding (and the rest passing) is one failed control; the counts add up
	inp := object.union(good_moderate_authorized, {"sc_controls": object.union(good_moderate_authorized.sc_controls, {"secure_dns": {"dnssec_enforced": false}})})
	r := main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls == count(r.failed_control_ids)
	r.failed_controls >= 1
	r.failed_controls <= r.total_controls
	_empty_scope(r)
	every id in r.failed_control_ids {
		some row in r.control_results
		row.id == id
		row.status != "pass"
	}
}

test_findings_carry_the_framework_name if {
	r := _report_rows({}, _all_fail_rows)
	every v in r.violations {
		startswith(v, "GovRAMP ")
	}
	every row in r.control_results {
		every f in row.findings {
			startswith(f, concat("", ["GovRAMP ", row.id, ":"]))
		}
	}
}

test_control_rows_are_in_natural_order_and_one_per_control if {
	r := _report({})
	ids := [row.id | some row in r.control_results]
	count(ids) == 406
	count({id | some id in ids}) == 406
	ids[0] == "AC-1"
	index_of(ids, "AC-2") < index_of(ids, "AC-2(1)")
	index_of(ids, "AC-2(1)") < index_of(ids, "AC-3")
}

index_of(arr, x) := i if {
	some i, v in arr
	v == x
}

test_overlay_differences_are_flagged_on_the_rows if {
	r := _report(good_moderate_authorized)
	flagged := {row.id | some row in r.control_results; row.federal_overlay_differs_from_fedramp}
	flagged == {"AU-11", "CA-6", "CP-9(8)", "IA-2(6)", "MP-5", "SC-8(1)", "SC-13"}
	low := _report(good_low_ready)
	every id in {row.id | some row in low.control_results; row.federal_overlay_differs_from_fedramp} {
		id in {"AU-11", "CA-6"}
	}
}

test_not_selected_from_fedramp_is_reported if {
	mod := _report({"impact_level": "moderate", "verification_status": "authorized"})
	mod.not_selected_from_fedramp_rev5 == ["CA-8(2)", "IA-2(12)", "IA-8(1)", "SA-4(10)"]
	low := _report({"impact_level": "low", "verification_status": "authorized"})
	low.not_selected_from_fedramp_rev5 == ["IA-2(12)", "IA-8(1)", "SA-4(10)"]
	low.baseline_sizes == {"low": 153, "moderate": 319, "high": 406}
	low.fedramp_rev5_baseline_sizes == {"low": 156, "moderate": 323, "high": 410}
}

# --- fail closed when the maps or the 800-53 module are not loaded ----------------------------------------------

test_missing_control_index_fails_closed if {
	r := main.compliance_report with input as good_moderate_authorized
		with data.govramp.index.scopes as {}
		with data.nist.sp800_53.main.control_results as _all_pass_rows
		with data.nist.sp800_53.main.violations as []
		with data.nist.sp800_53.main.evaluated_controls as _stub_ids
	r.compliant == false
	r.total_controls == 319
	r.failed_controls == 319
	r.passed_controls == 0
	r.control_results == []
	_empty_scope(r)
	some v in r.violations
	startswith(v, "FAIL-CLOSED: the GovRAMP control index")
}

# --- benchmark results through the 800-53 module ------------------------------------------------------------------

_ev(st, rules, open) := {"status": st, "rules": rules, "open_rules": open, "not_reviewed_rules": []}

_bench_input := object.union(good_moderate_authorized, {"findings": [{"stig_id": "R-1", "status": "Open"}]})

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

test_benchmark_gap_in_scope_fails_the_control if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as {"rules_supplied": 1, "rules_unmapped": 0}
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	r.compliant == false
	_row(r, "AC-7").status == "fail"
	_row(r, "AC-7").benchmark.open_rules == ["R-1"]
	r.failed_control_ids == ["AC-7"]
	r.failed_controls == 1
	r.passed_controls == 318
	_empty_scope(r)
	r.benchmark_evidence.gap == ["AC-7"]
	r.benchmark_gaps_outside_scope == []
}

test_benchmark_gap_outside_scope_is_not_a_finding if {
	# CA-8(2) is in the FedRAMP Moderate baseline and not in the GovRAMP one
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as {"rules_supplied": 1, "rules_unmapped": 0}
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"CA-8(2)": _ev("gap", ["R-1"], ["R-1"])}
	r.compliant
	r.failed_controls == 0
	r.benchmark_gaps_outside_scope == ["CA-8(2)"]
}

test_benchmark_results_without_the_spine_fail_closed if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
	r.compliant == false
	some v in r.violations
	startswith(v, "FAIL-CLOSED: benchmark results were supplied")
}

test_no_benchmark_input_has_no_benchmark_block if {
	r := _report(good_low_ready)
	not r.benchmark_evidence
	every row in r.control_results {
		not row.benchmark
	}
}
