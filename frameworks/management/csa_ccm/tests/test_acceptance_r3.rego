# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# csa_ccm.main: count arithmetic of the compliance report (round 3 task list item 6; audit 2026-11-24, "counts must
# satisfy passed + failed + not_applicable = total, and violations must not exceed what the report declares").
#  - total_controls is a property of the standard, not of the input: the same number on empty input, on the
#    all-pass fixture and on every other input tried here.
#  - 0 <= failed_controls <= total_controls, and the verdict agrees with the counts: a compliant report has no
#    failed control and no violation; a report with a failed control is not compliant.
#  - where the report has the fields, passed + failed + not applicable / not checked == total.
#  - where the report lists the failed control ids, failed_controls is the number of DISTINCT ids (so the
#    inequality holds by counting, not by clamping a finding count with min()/max()).
# Not asserted here because it cannot be observed from outside: that a report WITHOUT a list of failed control
# ids counts distinct controls rather than findings (see audit-reports/r3-tests.md).

package csa_ccm_acceptance_r3

import rego.v1

rep(inp) := r if {
	r := data.csa_ccm.main.compliance_report with input as inp
}

fx := data.csa_ccm.evidence_test.all_pass

# one record of a list, made to fail and made distinct: every true becomes false, every string gets a suffix
failing_record(o, i) := {k: nv |
	some k, v in o
	nv := failing_value({"v": v}, i)
}

failing_value(w, _) := false if w.v == true

failing_value(w, i) := sprintf("%v-%d", [w.v, i]) if is_string(w.v)

failing_value(w, _) := w.v if {
	not is_string(w.v)
	w.v != true
}

# the fixture with every list of records replaced by 80 failing records: many findings under few controls, so a
# total or a failed count that follows the number of findings shows up
many_failing_records := json.patch(fx, [{"op": "replace", "path": p, "value": [failing_record(v[0], i) | some i in numbers.range(1, 80)]} |
	walk(fx, [p, v])
	is_array(v)
	count(v) > 0
	is_object(v[0])
])

# empty input, the all-pass fixture, the fixture with 80 failing records in every list of records, the fixture with each top-level section removed in turn (all of them, no
# sampling) and the fixture with every true set to false
inputs := object.union(
	{
		"(empty)": {},
		"(fixture)": fx,
		"(every true set to false)": json.patch(fx, [{"op": "replace", "path": p, "value": false} | walk(fx, [p, v]); v == true]),
		"(every list of records repeated 80 times, failing)": many_failing_records,
	},
	{sprintf("without %v", [s]): json.remove(fx, [[s]]) | some s, _ in fx},
)

base_total := rep({}).total_controls

verdict_agrees(r) if {
	r.compliant == true
	r.failed_controls == 0
	r.violation_count == 0
}

verdict_agrees(r) if {
	r.compliant == false
	r.violation_count >= 1
}

consistent(r) if {
	is_boolean(r.compliant)
	r.total_controls == base_total
	r.failed_controls >= 0
	r.failed_controls <= r.total_controls
	verdict_agrees(r)
	(r.failed_controls + r.passed_controls) + r.controls_not_checked == r.total_controls
	r.passed_controls >= 0
	r.controls_not_checked >= 0
	r.failed_controls == count({id | some id in r.failed_control_ids})
	count(r.failed_control_ids) == count({id | some id in r.failed_control_ids})
	r.controls_checked + r.controls_not_checked == r.total_controls
}

# Requirement: the all-pass fixture is compliant with nothing failed (regression guard).
test_all_pass_fixture_passes if {
	r := rep(fx)
	r.compliant == true
	r.failed_controls == 0
	r.violation_count == 0
}

# Requirement: total_controls is the same number on empty input and on the all-pass fixture.
test_total_controls_is_the_same_on_empty_input_and_on_the_fixture if {
	is_number(base_total)
	base_total > 0
	rep(fx).total_controls == base_total
}

# Requirement: empty input is not compliant and every control fails or is otherwise accounted for.
test_empty_input_is_not_compliant if {
	r := rep({})
	r.compliant == false
	r.failed_controls >= 1
	is_number(base_total)
	base_total > 0
}

# Requirement: on every input the total is that same number, 0 <= failed <= total, the verdict agrees with the
# counts, and the report's own count fields add up (see the header for the list).
test_counts_are_consistent_on_every_input if {
	count(inputs) >= 3
	every _, inp in inputs {
		consistent(rep(inp))
	}
}
