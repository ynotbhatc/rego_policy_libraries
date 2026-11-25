# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# ncsc_caf.main: count arithmetic of the compliance report (round 3 task list item 6; audit 2026-11-24, "counts must
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

package ncsc_caf_acceptance_r3

import rego.v1

rep(inp) := r if {
	r := data.ncsc_caf.main.compliance_report with input as inp
}

# No all-pass fixture exists for this entrypoint in the tree (none is referenced by its tests), so the inputs
# are empty input and three small inputs that supply facts without satisfying anything.
inputs := {
	"(empty)": {},
	"(unrelated fact)": {"r3_unrelated_fact": true},
	"(one low impact system)": {"bes_cyber_systems": [{"system_id": "L1", "impact_level": "low"}]},
	"(sections present but empty)": {"assets": {}, "identity": {}, "monitoring": {}, "personnel": [], "bes_cyber_systems": []},
}

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
	r.failed_controls + r.achievement_summary.achieved == r.total_controls
	r.achievement_summary.achieved >= 0
	r.failed_controls == count({co | some co in r.not_achieved_cos} | {co | some co in r.partially_achieved_cos})
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
