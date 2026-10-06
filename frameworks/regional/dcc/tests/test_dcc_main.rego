# Tests for dcc.main — DEF STAN 05-138 Issue 4 / DCC
#
# The table itself is test-anchored to the standard: per-level applicable
# counts must equal the declared 3 / 101 / 139 / 144. Behavior tests cover
# fail-closed attestation (== true), the non-cumulative supersession pairs,
# target-level defaulting and the unknown-id/unknown-level guards.

package dcc.main_test

import rego.v1

import data.dcc.main

# ── Table integrity (anchored to the standard's declared counts) ─────────────

test_table_has_148_controls if {
	count(main.controls) == 148
}

test_level_counts_match_standard if {
	count({id | some id, m in main.controls; 0 in m.levels}) == 3
	count({id | some id, m in main.controls; 1 in m.levels}) == 101
	count({id | some id, m in main.controls; 2 in m.levels}) == 139
	count({id | some id, m in main.controls; 3 in m.levels}) == 144
}

test_l0_controls_are_the_three if {
	{id | some id, m in main.controls; 0 in m.levels} == {"0001", "2314", "2500"}
}

# ── Level 0 compliance ───────────────────────────────────────────────────────

l0_compliant := {"dcc": {
	"target_level": 0,
	"controls": {"0001": true, "2314": true, "2500": true},
}}

test_l0_compliant if {
	main.compliant with input as l0_compliant
	r := main.compliance_report with input as l0_compliant
	r.controls_evaluated == 3
	r.controls_attested == 3
	r.level_name == "Basic"
}

test_l0_missing_one_fails if {
	inp := {"dcc": {"target_level": 0, "controls": {"0001": true, "2314": true}}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "2500")
	contains(msg, "Resilient networks")
}

# ── Fail-closed attestation ──────────────────────────────────────────────────

test_string_true_fails_closed if {
	inp := {"dcc": {"target_level": 0, "controls": {"0001": "true", "2314": true, "2500": true}}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "0001")
}

test_unknown_control_id_flagged if {
	inp := {"dcc": {"target_level": 0, "controls": {
		"0001": true, "2314": true, "2500": true,
		"9999": true,
	}}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown control id")
}

# ── Target-level handling ────────────────────────────────────────────────────

test_absent_target_level_evaluates_l3 if {
	r := main.compliance_report with input as {"dcc": {"controls": {}}}
	r.target_level == 3
	r.controls_evaluated == 144
	not main.compliant with input as {"dcc": {"controls": {}}}
}

test_unrecognized_target_level_flagged_and_strict if {
	inp := {"dcc": {"target_level": "two", "controls": {}}}
	r := main.compliance_report with input as inp
	r.target_level == 3

	# 144 unattested controls + 1 input-contract violation
	r.violation_count == 145
	some msg in main.violations with input as inp
	contains(msg, "unrecognized target_level")
}

test_level_counts_via_applicable if {
	r1 := main.compliance_report with input as {"dcc": {"target_level": 1, "controls": {}}}
	r1.controls_evaluated == 101
	r2 := main.compliance_report with input as {"dcc": {"target_level": 2, "controls": {}}}
	r2.controls_evaluated == 139
}

# ── Non-cumulative supersession pairs ────────────────────────────────────────

test_superseded_controls_by_level if {
	l1 := main.applicable with input as {"dcc": {"target_level": 1}}
	"2504" in l1
	not "2505" in l1
	"3101" in l1
	not "3102" in l1
	"2300" in l1

	l3 := main.applicable with input as {"dcc": {"target_level": 3}}
	not "2504" in l3
	"2505" in l3
	not "3101" in l3
	"3102" in l3
	not "2300" in l3
	not "2502" in l3
	"2503" in l3
}

# ── Empty input ──────────────────────────────────────────────────────────────

test_empty_input_fails_closed if {
	not main.compliant with input as {}
	r := main.compliance_report with input as {}
	r.target_level == 3
	r.violation_count == 144
	r.controls_attested == 0
	r.compliant == false
}

test_report_objectives_populated if {
	r := main.compliance_report with input as {}
	r.objectives.B.title == "Protecting against cyber attack"
	r.objectives.B.open_violations > 0

	# L3 applicable CE controls: 0001 Cyber Essentials + 0002 CE Plus
	r.objectives.CE.open_violations == 2
}

# ── Message content (auditor-facing) ─────────────────────────────────────────

test_vulnerability_management_message if {
	inp := {"dcc": {"target_level": 1, "controls": {}}}
	some msg in main.violations with input as inp
	contains(msg, "DCC 2402")
	contains(msg, "Vulnerability management")
	contains(msg, "CVSS v3")
}

# F1/F2 regression: a non-object controls container gets an explicit
# input-contract violation, and array indices are never reported as ids.
test_array_controls_flagged_as_shape_error if {
	inp := {"dcc": {"target_level": 0, "controls": ["0001", "2314", "2500"]}}
	v := main.violations with input as inp

	# 3 unattested applicable controls + 1 shape violation, no index noise
	count(v) == 4
	some msg in v
	contains(msg, "must be an object")
	every m in v {
		not contains(m, "unknown control id")
	}
}

test_string_controls_flagged_as_shape_error if {
	inp := {"dcc": {"target_level": 0, "controls": "all attested"}}
	v := main.violations with input as inp
	count(v) == 4
	some msg in v
	contains(msg, "must be an object")
}

# Reviewer-suggested coverage (2026-10-06 round)

# An objective with zero applicable controls at the level reports 0, not
# undefined (protects the report against a refactor that collapses it).
test_empty_objective_reports_zero if {
	r := main.compliance_report with input as {"dcc": {"target_level": 0, "controls": {}}}
	r.objectives.A.open_violations == 0
	r.objectives.C.open_violations == 0
	r.objectives.D.open_violations == 0
}

# false attestation value fails closed (likeliest real-world non-true value).
test_false_attestation_fails if {
	inp := {"dcc": {"target_level": 0, "controls": {"0001": false, "2314": true, "2500": true}}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "0001")
}

# Pinned by design: attesting a known control outside the target level's
# profile is accepted without violation (over-attestation is harmless).
test_known_but_inapplicable_attestation_accepted if {
	inp := {"dcc": {"target_level": 0, "controls": {
		"0001": true, "2314": true, "2500": true,
		"2402": true,
	}}}
	main.compliant with input as inp
}

# Full positive compliance at Level 3 — also regression-tests that every
# table id agrees with its own levels set at evaluation time.
test_l3_full_attestation_compliant if {
	all3 := {id: true | some id, m in main.controls; 3 in m.levels}
	inp := {"dcc": {"target_level": 3, "controls": all3}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.controls_attested == 144
}

# Unrecognized level: assert the L3 evaluation explicitly, not just the count.
test_unrecognized_level_evaluates_all_l3_controls if {
	r := main.compliance_report with input as {"dcc": {"target_level": "two", "controls": {}}}
	r.controls_evaluated == 144
}

# Every control's level set is a contiguous range — the "L1-L3" display
# convention depends on it; a future table edit introducing {1,3} must fail.
test_all_level_sets_contiguous if {
	every _, m in main.controls {
		lv := sort([x | some x in m.levels])
		count(lv) == (lv[count(lv) - 1] - lv[0]) + 1
	}
}
