package txramp.main_test

import data.nist.sp800_53.index
import data.nist.sp800_53.main_test.fully_compliant_input
import data.txramp.main
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
_failing_row(id) := {"id": id, "status": "fail", "basis": "evidence", "baselines": [], "findings": [sprintf("NIST %s: a stand-in finding", [id])]}

_all_fail_rows := [_failing_row(id) | some id in index.order]

# ... one control with a benchmark gap (as the 800-53 module reports it), the rest passing
_gap_row(id) := {
	"id": id,
	"status": "fail",
	"basis": "evidence",
	"baselines": [],
	"findings": [sprintf("NIST %s: benchmark results show a gap: 1 mapped STIG rule(s) Open (R-1); the control fails regardless", [id])],
	"benchmark": {"status": "gap", "rules": ["R-1"], "open_rules": ["R-1"], "not_reviewed_rules": []},
}

_rows_with_gap(id) := [row | some i in index.order; row := _row_or_gap(i, id)]

_row_or_gap(i, id) := _gap_row(i) if i == id

_row_or_gap(i, id) := _pass_row(i) if i != id

# The programme facts of an assessment: both levels, the same facts.
_programme := {
	"certification": {
		"acknowledgment_inventory_approved": true,
		"assessment_questionnaire_approved": true,
		"security_plan_workbook_submitted": true,
		"poam_current": true,
		"valid_days_remaining": 800,
	},
	"continuous_monitoring": {
		"vulnerability_reports_on_schedule": true,
		"breach_notices_within_48_hours": true,
		"significant_changes_reported_within_30_days": true,
	},
}

# The all-pass fixtures: the 800-53 module's all-pass input (every control Level 1 selects is one that module evaluates)
# plus the programme facts. Level 2 has none: AC-17(9) and SA-10(1) are not evaluated by that module, so a Level 2
# assessment cannot report compliant (test_real_level_2_*).
# The all-pass fixtures: the 800-53 module's all-pass input (every control either level selects is one that module
# evaluates) plus the programme facts.
good_level_1 := object.union(fully_compliant_input, object.union({"certification_level": "level_1"}, _programme))

good_level_2 := object.union(fully_compliant_input, object.union({"certification_level": "level_2"}, _programme))

# An accepted equivalence stands in for the assessment: only the equivalence and the facts of every certification.
good_equivalence_level_2 := {
	"certification_level": "level_2",
	"equivalence": {
		"program": "fedramp",
		"status": "authorized",
		"impact_level": "moderate",
		"status_current": true,
		"reciprocal_certification_granted": true,
	},
	"certification": {"acknowledgment_inventory_approved": true},
	"continuous_monitoring": {
		"breach_notices_within_48_hours": true,
		"significant_changes_reported_within_30_days": true,
	},
}

# object.union merges deeply, so it cannot take a key out: this replaces the whole value of one key.
_with(inp, key, val) := object.union(object.remove(inp, [key]), {key: val})

_with_eq(inp, fields) := _with(inp, "equivalence", object.union(inp.equivalence, fields))

_arith(r) if {
	(r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls
}

_names(r, needle) if {
	some v in r.violations
	contains(v, needle)
}

# --- empty input and the selector ----------------------------------------------------------------------------------

test_real_empty_input_fails_closed_on_level_2 if {
	r := main.compliance_report with input as {}
	r.framework == "TX-RAMP"
	r.compliant == false
	r.total_controls == 223
	r.failed_controls == 223
	r.passed_controls == 0
	r.certification_basis == "assessment"
	r.scope == {"certification_level": "level_2", "map": "txramp_level_2", "basis": "assessment"}
	_arith(r)
	r.not_evaluated_control_ids == []
	r.control_result_counts.not_evaluated == 0
	_names(r, "TX-RAMP LEVEL: evidence missing or invalid")
}

test_unknown_level_values_are_findings_never_compliant if {
	every bad in ["", "level_3", "Level 2 Plus", 2, true, null, ["level_2"], {"level": 2}, "moderate"] {
		r := _report(object.union(good_level_1, {"certification_level": bad}))
		r.certification_level == "unknown"
		r.compliant == false
		r.scope.certification_level == "level_2"
		r.total_controls == 223
	}
}

test_level_is_trimmed_and_case_folded if {
	r := _report(object.union(good_level_1, {"certification_level": " Level_1 "}))
	r.certification_level == "level_1"
	r.compliant
}

test_provisional_is_a_finding_with_no_zero_control_scope if {
	r := _report(object.union(good_level_1, {"certification_level": "provisional"}))
	r.compliant == false
	r.certification_level == "provisional"
	r.total_controls == 223
	_names(r, "Provisional certification does not indicate compliance")
}

test_missing_level_is_a_finding if {
	r := _report(object.remove(good_level_1, ["certification_level"]))
	r.compliant == false
	_names(r, "input.certification_level must be one of level_1, level_2")
}

# --- every level ---------------------------------------------------------------------------------------------------

test_real_level_1_all_pass if {
	r := main.compliance_report with input as good_level_1
	r.compliant
	r.violations == []
	r.total_controls == 117
	r.passed_controls == 117
	r.failed_controls == 0
	r.not_applicable_controls == 0
	r.not_evaluated_control_ids == []
	r.scope == {"certification_level": "level_1", "map": "txramp_level_1", "basis": "assessment"}
	r.control_result_counts == {"pass": 117, "fail": 0, "evidence_missing": 0, "not_attested": 0, "not_evaluated": 0}
	count(r.control_results) == 117
	r.baseline_sizes == {"level_1": 117, "level_2": 223}
}

test_real_level_2_all_pass if {
	r := main.compliance_report with input as good_level_2
	r.compliant
	r.violations == []
	r.total_controls == 223
	r.passed_controls == 223
	r.failed_controls == 0
	r.failed_control_ids == []
	r.not_evaluated_control_ids == []
	r.control_result_counts == {"pass": 223, "fail": 0, "evidence_missing": 0, "not_attested": 0, "not_evaluated": 0}
	r.scope == {"certification_level": "level_2", "map": "txramp_level_2", "basis": "assessment"}
	_arith(r)

	# the two controls added to the 800-53 module for this framework are checked like any other
	some row in r.control_results
	row.id == "AC-17(9)"
	row.status == "pass"
	row.basis == "evidence"
}

test_real_level_2_fails_when_ac_17_9_or_sa_10_1_evidence_is_not_true if {
	inp := object.union(good_level_2, {
		"ac_controls": object.union(good_level_2.ac_controls, {"remote_access": object.union(good_level_2.ac_controls.remote_access, {"disconnect": {"capability_provided": "true"}})}),
		"sa_controls": object.union(good_level_2.sa_controls, {"developer_cm": object.union(good_level_2.sa_controls.developer_cm, {"integrity_verification": {"enabled": false}})}),
	})
	r := main.compliance_report with input as inp
	r.compliant == false
	r.failed_control_ids == ["AC-17(9)", "SA-10(1)"]
	r.passed_controls == 221
	_arith(r)
}

test_level_1_and_level_2_totals_differ_with_the_level if {
	l1 := _report(good_level_1)
	l2 := _report(good_level_2)
	l1.total_controls == 117
	l2.total_controls == 223
	l1.compliant
	l2.compliant
}

# --- programme facts: only the boolean true (or a number) passes ---------------------------------------------------

_bool_facts := [
	["certification", "acknowledgment_inventory_approved"],
	["certification", "assessment_questionnaire_approved"],
	["certification", "security_plan_workbook_submitted"],
	["certification", "poam_current"],
	["continuous_monitoring", "vulnerability_reports_on_schedule"],
	["continuous_monitoring", "breach_notices_within_48_hours"],
	["continuous_monitoring", "significant_changes_reported_within_30_days"],
]

_set_fact(inp, section, field, val) := _with(inp, section, object.union(inp[section], {field: val}))

_must_be_true(pair) if {
	every bad in [false, "true", "false", "yes", 1, 0, null] {
		r := _report(_set_fact(good_level_1, pair[0], pair[1], bad))
		r.compliant == false
		_names(r, sprintf("input.%s.%s is not true", [pair[0], pair[1]]))
	}
}

test_each_certification_attestation_must_be_the_boolean_true_a if {
	_must_be_true(_bool_facts[0])
	_must_be_true(_bool_facts[1])
}

test_each_certification_attestation_must_be_the_boolean_true_b if {
	_must_be_true(_bool_facts[2])
	_must_be_true(_bool_facts[3])
}

test_each_monitoring_attestation_must_be_the_boolean_true if {
	_must_be_true(_bool_facts[4])
	_must_be_true(_bool_facts[5])
	_must_be_true(_bool_facts[6])
}

test_each_attestation_removed_is_evidence_missing if {
	every pair in _bool_facts {
		inp := _with(good_level_1, pair[0], object.remove(good_level_1[pair[0]], [pair[1]]))
		r := _report(inp)
		r.compliant == false
		_names(r, sprintf("[evidence missing: input.%s.%s not collected]", [pair[0], pair[1]]))
	}
}

test_a_string_is_named_as_not_a_boolean if {
	r := _report(_set_fact(good_level_1, "certification", "poam_current", "true"))
	r.compliant == false
	_names(r, "[evidence invalid: input.certification.poam_current is not a boolean (got string)]")
}

test_validity_is_a_number_and_not_expired if {
	every bad in ["800", "30", true, null, [], {}] {
		r := _report(_set_fact(good_level_1, "certification", "valid_days_remaining", bad))
		r.compliant == false
		_names(r, "valid_days_remaining")
	}
	gone := _report(_with(good_level_1, "certification", object.remove(good_level_1.certification, ["valid_days_remaining"])))
	gone.compliant == false
	expired := _report(_set_fact(good_level_1, "certification", "valid_days_remaining", -3))
	expired.compliant == false
	_names(expired, "the certification expired 3 days ago")
	today := _report(_set_fact(good_level_1, "certification", "valid_days_remaining", 0))
	today.compliant
}

test_vulnerability_report_cadence_follows_the_level if {
	l1 := _report(_set_fact(good_level_1, "continuous_monitoring", "vulnerability_reports_on_schedule", false))
	_names(l1, "due annual for level_1")
	l2 := _report(_set_fact(good_level_2, "continuous_monitoring", "vulnerability_reports_on_schedule", false))
	_names(l2, "due quarterly for level_2")
}

test_missing_null_or_string_sections_are_findings if {
	every key in ["certification", "continuous_monitoring"] {
		gone := _report(object.remove(good_level_1, [key]))
		gone.compliant == false
		nulled := _report(_with(good_level_1, key, null))
		nulled.compliant == false
		stringy := _report(_with(good_level_1, key, "ok"))
		stringy.compliant == false
		listy := _report(_with(good_level_1, key, [true]))
		listy.compliant == false
	}
}

# --- the control results -------------------------------------------------------------------------------------------

test_real_a_failing_control_is_counted_and_not_clamped if {
	inp := object.union(good_level_1, {"sc_controls": object.union(good_level_1.sc_controls, {"secure_dns": {"dnssec_enforced": false}})})
	r := main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls == count(r.failed_control_ids)
	r.failed_controls >= 1
	r.failed_controls <= r.total_controls
	_arith(r)
	every id in r.failed_control_ids {
		some row in r.control_results
		row.id == id
		row.status != "pass"
	}
}

test_arithmetic_identity_with_every_control_failing if {
	r := _report_rows(good_level_1, _all_fail_rows)
	r.passed_controls == 0
	r.failed_controls == 117
	_arith(r)
	count(r.failed_control_ids) == 117
}

test_findings_carry_the_framework_name if {
	r := _report_rows({}, _all_fail_rows)
	every v in r.violations {
		startswith(v, "TX-RAMP ")
	}
	every row in r.control_results {
		every f in row.findings {
			startswith(f, concat("", ["TX-RAMP ", row.id, ":"]))
		}
	}
}

test_control_rows_are_in_natural_order_and_one_per_control if {
	r := _report({})
	ids := [row.id | some row in r.control_results]
	count(ids) == 223
	count({id | some id in ids}) == 223
	ids[0] == "AC-1"
	_index_of(ids, "AC-2") < _index_of(ids, "AC-2(3)")
	_index_of(ids, "AC-2(3)") < _index_of(ids, "AC-3")
}

_index_of(arr, x) := i if {
	some i, v in arr
	v == x
}

# A control the 800-53 module has no row for (a synthetic gap: the module's rows without AC-3) is not evaluated, counts
# failed and is listed; nothing can pass it.
_rows_without(id) := [_pass_row(i) | some i in index.order; i != id]

test_a_control_without_an_800_53_row_is_not_evaluated_and_counted_failed if {
	r := _report_rows(good_level_2, _rows_without("AC-3"))
	r.compliant == false
	r.not_evaluated_control_ids == ["AC-3"]
	r.failed_control_ids == ["AC-3"]
	r.passed_controls == 222
	r.failed_controls == 1
	r.control_result_counts.not_evaluated == 1
	_arith(r)
	_names(r, "TX-RAMP AC-3: not evaluated")
	some row in r.control_results
	row.id == "AC-3"
	row.status == "not_evaluated"
	row.basis == "none"
}

test_a_control_without_an_800_53_row_is_accepted_on_an_equivalence_and_still_listed if {
	r := _report_rows(good_equivalence_level_2, _rows_without("AC-3"))
	r.compliant
	r.passed_controls == 223
	r.not_evaluated_control_ids == ["AC-3"]
	some row in r.control_results
	row.id == "AC-3"
	row.status == "pass"
	row.basis == "equivalence"
	row.evidence_status == "not_evaluated"
}

# --- equivalence ---------------------------------------------------------------------------------------------------

test_accepted_equivalence_is_visible_and_needs_no_control_facts if {
	r := _report_rows(good_equivalence_level_2, _all_fail_rows)
	r.compliant
	r.violations == []
	r.certification_basis == "equivalence"
	r.scope == {"certification_level": "level_2", "map": "txramp_level_2", "basis": "equivalence"}
	r.equivalence == {"claimed": true, "accepted": true, "earned_level": "level_2", "problems": []}
	r.total_controls == 223
	r.passed_controls == 223
	r.failed_controls == 0
	_arith(r)
	every row in r.control_results {
		row.status == "pass"
		row.basis == "equivalence"
		row.findings == []
	}

	# the 800-53 verdict is kept beside the pass, never hidden
	some row in r.control_results
	row.id == "AC-2"
	row.evidence_status == "fail"

	r.not_evaluated_control_ids == []
}

test_real_accepted_equivalence_passes_223_with_basis_equivalence if {
	r := main.compliance_report with input as good_equivalence_level_2
	r.compliant
	r.passed_controls == 223
	r.control_result_counts.pass == 223
	r.certification_basis == "equivalence"
}

test_equivalence_does_not_ask_for_the_assessment_facts if {
	r := _report(good_equivalence_level_2)
	not _names(r, "assessment_questionnaire_approved")
	not _names(r, "security_plan_workbook_submitted")
	not _names(r, "poam_current")
	not _names(r, "valid_days_remaining")
	not _names(r, "vulnerability_reports_on_schedule")
}

test_equivalence_still_asks_for_the_facts_of_every_certification if {
	every pair in [
		["certification", "acknowledgment_inventory_approved"],
		["continuous_monitoring", "breach_notices_within_48_hours"],
		["continuous_monitoring", "significant_changes_reported_within_30_days"],
	] {
		every bad in [false, "true", null] {
			r := _report(_set_fact(good_equivalence_level_2, pair[0], pair[1], bad))
			r.compliant == false
			_names(r, sprintf("input.%s.%s is not true", [pair[0], pair[1]]))
		}
	}
}

test_fedramp_authorized_earns_the_matching_level if {
	low1 := _report(_with_eq(_with(good_equivalence_level_2, "certification_level", "level_1"), {"impact_level": "low"}))
	low1.certification_basis == "equivalence"
	low1.total_controls == 117
	low1.compliant
	every impact in ["moderate", "high"] {
		r := _report(_with_eq(good_equivalence_level_2, {"impact_level": impact}))
		r.certification_basis == "equivalence"
		r.equivalence.earned_level == "level_2"
		r.compliant
	}
}

test_fedramp_low_does_not_earn_level_2 if {
	r := _report(_with_eq(good_equivalence_level_2, {"impact_level": "low"}))
	r.certification_basis == "assessment"
	r.compliant == false
	r.equivalence.accepted == false
	_names(r, "the external status earns level_1, below the declared level_2")

	# the assessment path then applies in full
	_names(r, "input.certification.assessment_questionnaire_approved is not true")
}

test_fedramp_moderate_satisfies_level_1 if {
	inp := _with_eq(_with(good_equivalence_level_2, "certification_level", "level_1"), {"impact_level": "moderate"})
	r := _report(inp)
	r.certification_basis == "equivalence"
	r.equivalence.earned_level == "level_2"
	r.compliant
}

test_fedramp_low_impact_saas_has_no_equivalent if {
	r := _report(_with_eq(good_equivalence_level_2, {"impact_level": "li_saas"}))
	r.compliant == false
	r.certification_basis == "assessment"
	_names(r, "Low-impact SaaS authorization does not inherit a TX-RAMP certification")
}

test_fedramp_in_process_and_ready_earn_provisional_only if {
	every st in ["in_process", "ready"] {
		r := _report(_with_eq(good_equivalence_level_2, {"status": st}))
		r.compliant == false
		r.certification_basis == "assessment"
		r.equivalence.earned_level == "provisional"
		_names(r, "earns TX-RAMP Provisional certification only")
	}
}

test_govramp_statuses_earn_level_2 if {
	every st in ["core", "ready", "provisionally_authorized", "authorized"] {
		r := _report(_with_eq(good_equivalence_level_2, {"program": "govramp", "status": st}))
		r.compliant
		r.certification_basis == "equivalence"
		r.equivalence.earned_level == "level_2"
	}
	alias := _report(_with_eq(good_equivalence_level_2, {"program": "StateRAMP", "status": "authorized"}))
	alias.certification_basis == "equivalence"
}

test_govramp_snapshot_earns_provisional_only if {
	every st in ["snapshot", "progressing_snapshot"] {
		r := _report(_with_eq(good_equivalence_level_2, {"program": "govramp", "status": st}))
		r.compliant == false
		r.certification_basis == "assessment"
		_names(r, "earns TX-RAMP Provisional certification only")
	}
}

test_equivalence_needs_the_boolean_true_status_and_grant if {
	every field in ["status_current", "reciprocal_certification_granted"] {
		every bad in [false, "true", "false", "yes", 1, 0, null] {
			r := _report(_with_eq(good_equivalence_level_2, {field: bad}))
			r.compliant == false
			r.certification_basis == "assessment"
			r.equivalence.accepted == false
			_names(r, sprintf("input.equivalence.%s is not true", [field]))
		}
		gone := _report(_with(good_equivalence_level_2, "equivalence", object.remove(good_equivalence_level_2.equivalence, [field])))
		gone.compliant == false
		gone.certification_basis == "assessment"
		_names(gone, sprintf("[evidence missing: input.equivalence.%s not collected]", [field]))
	}
}

test_loss_of_the_external_status_ends_the_equivalence if {
	r := _report(_with_eq(good_equivalence_level_2, {"status_current": false}))
	r.compliant == false
	_names(r, "a reciprocal certification stays valid only while the external status is maintained")
}

test_unknown_program_status_or_impact_is_not_accepted if {
	every fields in [
		{"program": "other"}, {"program": 7}, {"program": null}, {"status": "approved"}, {"status": 3}, {"status": null},
		{"impact_level": "medium"}, {"impact_level": null}, {"impact_level": 1},
	] {
		r := _report(_with_eq(good_equivalence_level_2, fields))
		r.compliant == false
		r.certification_basis == "assessment"
		r.equivalence.accepted == false
		count(r.equivalence.problems) >= 1
	}
}

test_a_claimed_equivalence_that_is_not_an_object_is_a_finding if {
	every bad in [null, "fedramp", true, 1, ["fedramp"]] {
		r := _report(_with(good_equivalence_level_2, "equivalence", bad))
		r.compliant == false
		r.certification_basis == "assessment"
		r.equivalence.claimed
		_names(r, "input.equivalence is not an object")
	}
}

test_no_equivalence_key_is_not_a_claim if {
	r := _report(good_level_1)
	r.equivalence == {"claimed": false, "accepted": false, "earned_level": "none", "problems": []}
	r.certification_basis == "assessment"
}

test_an_equivalence_cannot_rescue_an_unusable_level if {
	every bad in [null, "provisional", "level_9"] {
		r := _report(_with(good_equivalence_level_2, "certification_level", bad))
		r.compliant == false
		r.certification_basis == "assessment"
	}
}

test_an_equivalence_with_a_failed_assessment_still_reports_the_assessment_path if {
	# not accepted: the control facts count again
	r := _report_rows(_with_eq(good_equivalence_level_2, {"status_current": null}), _all_fail_rows)
	r.passed_controls == 0
	r.failed_controls == 223
}

test_benchmark_gap_still_fails_a_control_accepted_by_equivalence if {
	r := _report_rows(good_equivalence_level_2, _rows_with_gap("AC-7"))
	r.compliant == false
	r.certification_basis == "equivalence"
	r.failed_control_ids == ["AC-7"]
	r.passed_controls == 222
	_arith(r)
	some row in r.control_results
	row.id == "AC-7"
	row.status == "fail"
	row.benchmark.status == "gap"
	count(row.findings) == 1
	startswith(row.findings[0], "TX-RAMP AC-7: benchmark results show a gap")
}

# --- fail closed when the index or the 800-53 module is not loaded -------------------------------------------------

test_missing_control_index_fails_closed if {
	r := main.compliance_report with input as good_level_1
		with data.txramp.index.scopes as {}
		with data.nist.sp800_53.main.control_results as _all_pass_rows
		with data.nist.sp800_53.main.violations as []
		with data.nist.sp800_53.main.evaluated_controls as _stub_ids
	r.compliant == false
	r.total_controls == 117
	r.failed_controls == 117
	r.passed_controls == 0
	r.control_results == []
	_arith(r)
	some v in r.violations
	startswith(v, "FAIL-CLOSED: the TX-RAMP control index")
}

test_missing_control_index_fails_closed_also_under_equivalence if {
	r := main.compliance_report with input as good_equivalence_level_2
		with data.txramp.index.scopes as {}
		with data.nist.sp800_53.main.control_results as _all_pass_rows
		with data.nist.sp800_53.main.violations as []
		with data.nist.sp800_53.main.evaluated_controls as _stub_ids
	r.compliant == false
	r.passed_controls == 0
	r.failed_controls == 223
}

test_missing_800_53_module_fails_closed if {
	r := main.compliance_report with input as good_level_1
		with data.nist.sp800_53.main.control_results as []
		with data.nist.sp800_53.main.violations as []
		with data.nist.sp800_53.main.evaluated_controls as set()
	r.compliant == false
	r.passed_controls == 0
	r.failed_controls == 117
}

# --- benchmark results through the 800-53 module -------------------------------------------------------------------

_ev(st, rules, open) := {"status": st, "rules": rules, "open_rules": open, "not_reviewed_rules": []}

_bench_input := object.union(good_level_1, {"findings": [{"stig_id": "R-1", "status": "Open"}]})

_row_of(r, id) := x if {
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
	_row_of(r, "AC-7").status == "fail"
	_row_of(r, "AC-7").benchmark.open_rules == ["R-1"]
	r.failed_control_ids == ["AC-7"]
	r.failed_controls == 1
	r.passed_controls == 116
	_arith(r)
	r.benchmark_evidence.gap == ["AC-7"]
	r.benchmark_gaps_outside_scope == []
}

test_benchmark_gap_outside_scope_is_not_a_finding if {
	# AC-4 is selected at Level 2 and not at Level 1: a gap there is listed and is not a TX-RAMP finding at Level 1
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as {"rules_supplied": 1, "rules_unmapped": 0}
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"AC-4": _ev("gap", ["R-1"], ["R-1"])}
	r.compliant
	r.failed_controls == 0
	r.benchmark_gaps_outside_scope == ["AC-4"]
}

test_benchmark_results_without_the_spine_fail_closed if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
	r.compliant == false
	some v in r.violations
	startswith(v, "FAIL-CLOSED: benchmark results were supplied")
}

test_no_benchmark_input_has_no_benchmark_block if {
	r := _report(good_level_1)
	not r.benchmark_evidence
	every row in r.control_results {
		not row.benchmark
	}
}
