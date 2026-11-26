# Tests for owasp_asvs.main (OWASP ASVS 5.0.0). The id, level and chapter figures below are the standard's own
# (release v5.0.0_release): 345 requirements, 70 at L1, 183 more at L2, 92 more at L3, 17 chapters, 80 sections.

package owasp_asvs.main_test

import data.owasp_asvs.index
import data.owasp_asvs.main
import rego.v1

_level(id) := to_number(n) if {
	some n, ids in index.levels
	id in ids
}

_ids(n) := [id | some id in index.order; _level(id) <= n]

_all_true(n) := {id: true | some id in _ids(n)}

_inp(n, results) := {"owasp_asvs": {"level": n, "requirements": results}}

# the all-pass fixtures, one per level
good_level_1 := _inp(1, _all_true(1))

good_level_2 := _inp(2, _all_true(2))

good_level_3 := _inp(3, _all_true(3))

# Level 3 with one requirement explicitly not applicable (a reason, and no result for it)
good_level_3_with_not_applicable := {"owasp_asvs": {
	"level": 3,
	"requirements": object.remove(_all_true(3), ["V17.1.1"]),
	"not_applicable": {"V17.1.1": "no WebRTC components in this application"},
}}

_r(inp) := r if {
	r := main.compliance_report with input as inp
}

_identity(r) if (r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls

_mentions(r, id) if {
	some m in r.violations
	startswith(m, concat("", ["OWASP ASVS ", id, ":"]))
}

# ── the index is the standard's ──────────────────────────────────────────────

test_index_counts_are_the_standards if {
	count(index.order) == 345
	main.requirements_total == 345
	count({id | some id in index.order}) == 345
	count(index.levels["1"]) == 70
	count(index.levels["2"]) == 183
	count(index.levels["3"]) == 92
	count(((index.levels["1"] | index.levels["2"]) | index.levels["3"])) == 345
	count(index.levels["1"] & index.levels["2"]) == 0
	count(index.levels["2"] & index.levels["3"]) == 0
	count(index.levels["1"] & index.levels["3"]) == 0
	{id | some id in index.order} == (index.levels["1"] | index.levels["2"]) | index.levels["3"]
	count(index.chapters) == 17
	count({concat(".", [split(id, ".")[0], split(id, ".")[1]]) | some id in index.order}) == 80
	index.in_scope_totals == {"1": 70, "2": 253, "3": 345}
	count(index.CONTROL_INDEX) == 345
}

test_index_by_chapter_matches_the_ids if {
	every ch, members in index.by_chapter {
		every id in members {
			split(id, ".")[0] == ch
		}
	}
	count(index.by_chapter) == 17
	sum([count(m) | some _, m in index.by_chapter]) == 345
	{id | some _, m in index.by_chapter; some id in m} == {id | some id in index.order}
}

# ── empty and bad level ──────────────────────────────────────────────────────

test_empty_input_fails_closed_at_level_3 if {
	r := _r({})
	r.compliant == false
	r.assessed_level == 3
	r.declared_level == null
	r.total_controls == 345
	r.passed_controls == 0
	r.failed_controls == 345
	r.not_applicable_controls == 0
	_identity(r)
	r.violation_count == 347 # 345 requirements, the missing level, the missing container
	count(r.control_results) == 345
}

test_no_input_document_fails_closed if {
	r := main.compliance_report with input as null
	r.compliant == false
	r.total_controls == 345
	r.failed_controls == 345
}

test_unknown_level_values_assess_level_3 if {
	some bad in [0, 4, -1, 2.5, "2", "L2", "2 ", null, true, false, [2], {"n": 2}]
	r := _r({"owasp_asvs": {"level": bad, "requirements": _all_true(3)}})
	r.compliant == false
	r.assessed_level == 3
	r.total_controls == 345
	r.passed_controls == 345 # the results are fine; the declaration is not
	some m in r.violations
	contains(m, "input.owasp_asvs.level is missing or is not the number 1, 2 or 3")
}

test_missing_level_assesses_level_3_and_is_a_finding if {
	r := _r({"owasp_asvs": {"requirements": _all_true(3)}})
	r.compliant == false
	r.assessed_level == 3
	r.violation_count == 1
}

test_level_1_results_with_missing_level_fail_at_level_3 if {
	r := _r({"owasp_asvs": {"requirements": _all_true(1)}})
	r.compliant == false
	r.total_controls == 345
	r.failed_controls == 275
}

# ── each level ───────────────────────────────────────────────────────────────

test_level_1_all_pass if {
	r := _r(good_level_1)
	r.compliant
	r.total_controls == 70
	r.passed_controls == 70
	r.failed_controls == 0
	r.not_applicable_controls == 0
	r.violation_count == 0
	r.assessed_level == 1
	_identity(r)
}

test_level_2_all_pass if {
	r := _r(good_level_2)
	r.compliant
	r.total_controls == 253
	r.passed_controls == 253
	r.violation_count == 0
	_identity(r)
}

test_level_3_all_pass if {
	r := _r(good_level_3)
	r.compliant
	r.total_controls == 345
	r.passed_controls == 345
	r.violation_count == 0
	r.results_above_level == []
	_identity(r)
}

test_level_1_results_do_not_satisfy_level_2 if {
	r := _r(_inp(2, _all_true(1)))
	r.compliant == false
	r.total_controls == 253
	r.passed_controls == 70
	r.failed_controls == 183
	_identity(r)
}

test_level_2_results_do_not_satisfy_level_3 if {
	r := _r(_inp(3, _all_true(2)))
	r.compliant == false
	r.total_controls == 345
	r.failed_controls == 92
}

test_results_above_the_level_are_ignored_and_listed if {
	r := _r(_inp(1, _all_true(3)))
	r.compliant
	r.total_controls == 70
	r.passed_controls == 70
	count(r.results_above_level) == 275
	r.violation_count == 0
}

test_a_false_result_above_the_level_does_not_fail_the_level if {
	r := _r(_inp(1, object.union(_all_true(1), {"V1.2.10": false})))
	r.compliant
}

test_all_false_fails_every_requirement if {
	some n in [1, 2, 3]
	r := _r(_inp(n, {id: false | some id in _ids(n)}))
	r.compliant == false
	r.failed_controls == r.total_controls
	r.passed_controls == 0
	_identity(r)
}

# ── evidence rule: one value, one requirement ────────────────────────────────

test_bad_values_are_findings_naming_the_id if {
	some bad in ["true", "false", "yes", "no", 1, 0, null, [], {}, "V1.2.3"]
	r := _r(_inp(3, object.union(_all_true(3), {"V1.2.3": bad})))
	r.compliant == false
	r.passed_controls == 344
	r.failed_controls == 1
	r.failed_control_ids == ["V1.2.3"]
	_mentions(r, "V1.2.3")
	_identity(r)
}

test_a_false_result_is_a_failed_requirement if {
	r := _r(_inp(3, object.union(_all_true(3), {"V6.2.1": false})))
	r.compliant == false
	r.failed_controls == 1
	some m in r.violations
	startswith(m, "OWASP ASVS V6.2.1:")
	contains(m, "is false")
}

test_string_is_named_as_not_a_boolean if {
	r := _r(_inp(3, object.union(_all_true(3), {"V1.2.3": "true"})))
	some m in r.violations
	contains(m, "is not a boolean (got string)")
}

test_null_and_missing_are_evidence_missing if {
	r := _r(_inp(3, object.union(object.remove(_all_true(3), ["V1.2.4"]), {"V1.2.3": null})))
	r.control_result_counts.evidence_missing == 2
	some m in r.violations
	contains(m, "requirements[\"V1.2.3\"] is null")
	some m2 in r.violations
	contains(m2, "requirements[\"V1.2.4\"] not collected")
}

test_requirements_container_wrong_type if {
	some bad in [null, "true", true, [true], 1]
	r := _r({"owasp_asvs": {"level": 3, "requirements": bad}})
	r.compliant == false
	r.failed_controls == 345
	some m in r.violations
	contains(m, "input.owasp_asvs.requirements is missing or not an object")
}

test_whole_section_wrong_type if {
	some bad in [null, "true", [], 7]
	r := _r({"owasp_asvs": bad})
	r.compliant == false
	r.failed_controls == 345
	some m in r.violations
	contains(m, "input.owasp_asvs is missing or not an object")
}

# ── not applicable ───────────────────────────────────────────────────────────

test_not_applicable_with_a_reason if {
	r := _r(good_level_3_with_not_applicable)
	r.compliant
	r.total_controls == 345
	r.passed_controls == 344
	r.not_applicable_controls == 1
	r.failed_controls == 0
	r.not_applicable_ids == ["V17.1.1"]
	_identity(r)
}

test_not_applicable_does_not_change_the_total if {
	some n in [1, 2, 3]
	na := {"V1.1.1": "reason"} # an L2 id: in scope at levels 2 and 3 only
	n >= 2
	r := _r({"owasp_asvs": {"level": n, "requirements": object.remove(_all_true(n), ["V1.1.1"]), "not_applicable": na}})
	r.total_controls == index.in_scope_totals[sprintf("%d", [n])]
	r.not_applicable_controls == 1
	_identity(r)
}

test_not_applicable_without_a_usable_reason_is_a_finding if {
	some bad in ["", " ", "\t\n", null, true, false, 1, [], {}, ["a reason"]]
	r := _r({"owasp_asvs": {"level": 3, "requirements": object.remove(_all_true(3), ["V17.1.1"]), "not_applicable": {"V17.1.1": bad}}})
	r.compliant == false
	r.not_applicable_controls == 0
	r.failed_controls == 1
	r.failed_control_ids == ["V17.1.1"]
	_mentions(r, "V17.1.1")
	_identity(r)
}

test_not_applicable_beside_a_result_is_a_conflict if {
	some result in [true, false, null, "true"]
	r := _r({"owasp_asvs": {"level": 3, "requirements": object.union(_all_true(3), {"V17.1.1": result}), "not_applicable": {"V17.1.1": "no WebRTC"}}})
	r.compliant == false
	r.not_applicable_controls == 0
	r.failed_controls == 1
	some m in r.violations
	contains(m, "a requirement has a result or is not applicable, not both")
}

test_not_applicable_for_an_id_above_the_level_is_a_finding if {
	r := _r({"owasp_asvs": {"level": 1, "requirements": _all_true(1), "not_applicable": {"V1.2.10": "reason", "V1.1.1": "reason"}}})
	r.compliant == false
	r.total_controls == 70
	r.not_applicable_controls == 0
	r.failed_controls == 0 # the finding is about the input, not about a requirement in scope
	r.violation_count == 2
	some m in r.violations
	contains(m, "not_applicable[\"V1.2.10\"] is a Level 3 requirement and is outside the Level 1 scope")
	some m2 in r.violations
	contains(m2, "not_applicable[\"V1.1.1\"] is a Level 2 requirement and is outside the Level 1 scope")
}

test_not_applicable_for_an_unknown_id_is_a_finding if {
	r := _r({"owasp_asvs": {"level": 3, "requirements": _all_true(3), "not_applicable": {"V99.1.1": "reason"}}})
	r.compliant == false
	some m in r.violations
	contains(m, "not_applicable[\"V99.1.1\"] is not a requirement id of ASVS 5.0.0")
}

test_a_missing_result_is_never_not_applicable if {
	r := _r(_inp(3, object.remove(_all_true(3), ["V17.1.1"])))
	r.compliant == false
	r.not_applicable_controls == 0
	r.control_result_counts.evidence_missing == 1
}

test_not_applicable_container_wrong_type if {
	some bad in [["V17.1.1"], "V17.1.1", true, 5]
	r := _r({"owasp_asvs": {"level": 3, "requirements": object.remove(_all_true(3), ["V17.1.1"]), "not_applicable": bad}})
	r.compliant == false
	r.not_applicable_controls == 0
	some m in r.violations
	contains(m, "not_applicable is not an object")
}

test_everything_not_applicable_is_not_a_pass if {
	r := _r({"owasp_asvs": {"level": 1, "requirements": {}, "not_applicable": {id: "reason" | some id in _ids(1)}}})
	r.not_applicable_controls == 70
	r.passed_controls == 0
	r.compliant == false
}

# ── unknown ids ──────────────────────────────────────────────────────────────

test_unknown_requirement_ids_are_reported if {
	some bad in ["V99.1.1", "v1.1.1", "1.1.1", "V1.1", "V1.1.1 ", "v5.0.0-1.1.1", "V1.1.1.1", "V0.0.0"]
	r := _r(_inp(3, object.union(_all_true(3), {bad: true})))
	r.compliant == false
	r.failed_controls == 0 # every real requirement passed; the input is what is wrong
	r.passed_controls == 345
	some m in r.violations
	contains(m, "is not a requirement id of ASVS 5.0.0")
	contains(m, bad)
}

# ── arithmetic and shape ─────────────────────────────────────────────────────

_mixed(n) := object.union(object.remove({id: true | some id in _ids(n)}, ["V1.2.1", "V1.2.3", "V1.2.4", "V1.2.5", "V6.1.1"]), {"V1.2.3": false, "V1.2.4": "true", "V1.2.5": null})

test_identity_at_each_level_with_mixed_results if {
	some n in [1, 2, 3]
	r := _r({"owasp_asvs": {"level": n, "requirements": _mixed(n), "not_applicable": {"V1.2.1": "reason"}}})
	_identity(r)
	r.total_controls == index.in_scope_totals[sprintf("%d", [n])]
	r.not_applicable_controls == 1
	r.failed_controls >= 3
	count(r.failed_control_ids) == r.failed_controls
}

test_failed_is_counted_not_clamped_when_requirements_have_many_findings if {
	r := _r({"owasp_asvs": {"level": 3, "requirements": {}, "not_applicable": {"V1.2.1": "reason", "V99.9.9": "reason", "V5.1.1": ""}}})
	r.total_controls == 345
	r.not_applicable_controls == 1
	r.passed_controls == 0
	r.failed_controls == 344
	_identity(r)
}

test_control_results_follow_the_standards_order_and_carry_the_level if {
	r := _r(good_level_2)
	ids := [c.id | some c in r.control_results]
	ids == _ids(2)
	every c in r.control_results {
		c.status == "pass"
		c.findings == []
		c.level == _level(c.id)
		c.chapter == split(c.id, ".")[0]
		c.section == concat(".", [split(c.id, ".")[0], split(c.id, ".")[1]])
	}
}

test_chapter_results_add_up if {
	some n in [1, 2, 3]
	r := _r(_inp(n, object.union(_all_true(n), {"V6.1.1": false})))
	sum([c.total | some c in r.chapter_results]) == r.total_controls
	sum([c.passed | some c in r.chapter_results]) == r.passed_controls
	sum([c.failed | some c in r.chapter_results]) == r.failed_controls
	r.chapter_results.V6.failed == 1
	count(r.chapter_results) == 17
}

test_control_results_row_for_a_failure_has_its_finding if {
	r := _r(_inp(1, object.union(_all_true(1), {"V1.2.1": false})))
	some c in r.control_results
	c.id == "V1.2.1"
	c.status == "fail"
	count(c.findings) == 1
}

test_report_carries_the_version_and_attribution if {
	r := _r({})
	r.standard_version == "5.0.0"
	r.release_tag == "v5.0.0_release"
	r.requirements_total == 345
	contains(r.attribution, "CC BY-SA 4.0")
	contains(r.approval, "Not approved by OWASP")
}

test_findings_are_prefixed_with_the_catalogue_label if {
	r := _r({})
	every m in r.violations {
		startswith(m, "OWASP ASVS ")
	}
}

# ── each requirement removed, in slices of 20 ids in the standard's order (a cover test checks the slices) ──
# Each slice removes one requirement at a time from the all-pass Level 3 input; exactly that requirement must fail.
# Only failed_control_ids is evaluated, so a slice stays well under a second even on the oldest supported OPA.

_slice(n) := [id | some i, id in index.order; i >= n * 20; i < (n * 20) + 20]

_removed_one_at_a_time(n) if {
	every id in _slice(n) {
		failed := main.failed_control_ids with input as _inp(3, object.remove(_all_true(3), [id]))
		failed == [id]
	}
}

test_removal_slices_cover_every_requirement if {
	{id | some n in numbers.range(0, 17); some id in _slice(n)} == {id | some id in index.order}
	count(_slice(17)) > 0
	count(_slice(18)) == 0 # test_removal_slice_00 to test_removal_slice_17 are the slices that exist
}

test_removal_slice_00 if _removed_one_at_a_time(0)

test_removal_slice_01 if _removed_one_at_a_time(1)

test_removal_slice_02 if _removed_one_at_a_time(2)

test_removal_slice_03 if _removed_one_at_a_time(3)

test_removal_slice_04 if _removed_one_at_a_time(4)

test_removal_slice_05 if _removed_one_at_a_time(5)

test_removal_slice_06 if _removed_one_at_a_time(6)

test_removal_slice_07 if _removed_one_at_a_time(7)

test_removal_slice_08 if _removed_one_at_a_time(8)

test_removal_slice_09 if _removed_one_at_a_time(9)

test_removal_slice_10 if _removed_one_at_a_time(10)

test_removal_slice_11 if _removed_one_at_a_time(11)

test_removal_slice_12 if _removed_one_at_a_time(12)

test_removal_slice_13 if _removed_one_at_a_time(13)

test_removal_slice_14 if _removed_one_at_a_time(14)

test_removal_slice_15 if _removed_one_at_a_time(15)

test_removal_slice_16 if _removed_one_at_a_time(16)

test_removal_slice_17 if _removed_one_at_a_time(17)

# ── every requirement at once: removed, null, "true", "false", false, 1, 0: none passes and each is named ──

_named(r) := {split(m, ":")[0] | some m in r.violations}

test_every_requirement_removed_is_named_and_fails if {
	r := _r(_inp(3, {}))
	r.failed_controls == 345
	every id in index.order {
		concat("", ["OWASP ASVS ", id]) in _named(r)
	}
}

test_every_requirement_null_is_named_and_fails if {
	r := _r(_inp(3, {id: null | some id in index.order}))
	r.failed_controls == 345
	r.control_result_counts.evidence_missing == 345
	every id in index.order {
		concat("", ["OWASP ASVS ", id]) in _named(r)
	}
}

test_every_requirement_as_string_true_fails if {
	r := _r(_inp(3, {id: "true" | some id in index.order}))
	r.compliant == false
	r.failed_controls == 345
	r.control_result_counts.evidence_invalid == 345
	every id in index.order {
		concat("", ["OWASP ASVS ", id]) in _named(r)
	}
}

test_every_requirement_as_string_false_fails if {
	r := _r(_inp(3, {id: "false" | some id in index.order}))
	r.compliant == false
	r.control_result_counts.evidence_invalid == 345
}

test_every_requirement_as_number_fails if {
	some bad in [0, 1]
	r := _r(_inp(3, {id: bad | some id in index.order}))
	r.compliant == false
	r.passed_controls == 0
}

test_every_requirement_false_is_a_failed_requirement if {
	r := _r(_inp(3, {id: false | some id in index.order}))
	r.control_result_counts.fail == 345
	every id in index.order {
		concat("", ["OWASP ASVS ", id]) in _named(r)
	}
}
