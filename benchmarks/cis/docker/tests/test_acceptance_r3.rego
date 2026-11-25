# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# cis_docker.main: the CIS level is selected by input.cis_profile.level, the number 1 or 2.
# Requirement (round 3 task list item 7; evidence rule in AGENT_BRIEF.md, "'Does not apply' must be an explicit
# statement in the input, never inferred from a missing field"): a level that is absent, null, of the wrong
# type or not 1 or 2 is never compliant and the report carries a finding that the level was not selected.
# Today an absent level (or an absent cis_profile) is read as Level 2 and the green fixture stays compliant
# with nothing said; that default is documented in cis_docker_benchmark.rego ("absent => 2") and pinned by
# tests/test_cis_docker_bad_evidence.rego ("absent selects Level 2, the stricter profile"), which this
# requirement supersedes.
#
# Fixture: data.cis_docker_test.green (cis_profile.level 2), by reference.

package cis_docker_acceptance_r3

import rego.v1

green := data.cis_docker_test.green

rep(inp) := r if {
	r := data.cis_docker.main.compliance_report with input as inp
}

texts(r) := {sprintf("%v", [v]) | some v in r.violations}

# not compliant, with a finding (not present on the green fixture) that names cis_profile
not_selected(r) if {
	r.compliant == false
	r.violation_count >= 1
	some t in (texts(r) - texts(rep(green)))
	contains(t, "cis_profile")
}

# Requirement: each valid level on the fixture evaluates as before - compliant, nothing failed, Level 1 scoped
# smaller than Level 2, and no finding about the profile (regression guard).
test_each_valid_level_still_evaluates_as_before if {
	l2 := rep(green)
	l2.compliant == true
	l2.failed_controls == 0
	l2.violation_count == 0
	l1 := rep(json.patch(green, [{"op": "replace", "path": "/cis_profile/level", "value": 1}]))
	l1.compliant == true
	l1.failed_controls == 0
	l1.violation_count == 0
	l1.total_controls < l2.total_controls
}

# Requirement: an ABSENT level - cis_profile without level, or no cis_profile at all - is not compliant and
# carries the finding.
test_absent_level_is_not_compliant_and_says_so if {
	not_selected(rep(json.remove(green, ["cis_profile/level"])))
	not_selected(rep(json.remove(green, ["cis_profile"])))
}

# Requirement: null, a value of the wrong type and an unknown level are not compliant and carry the finding.
test_level_that_selects_nothing_is_not_compliant_and_says_so if {
	every bad in [null, "1", "2", "level2", 0, 3, 1.5, true, [2], {"level": 2}] {
		not_selected(rep(json.patch(green, [{"op": "replace", "path": "/cis_profile/level", "value": bad}])))
	}
}

# Requirement: a cis_profile that is not an object selects nothing either.
test_cis_profile_of_the_wrong_type_is_not_compliant_and_says_so if {
	every bad in [null, "level2", 2, true, [{"level": 2}]] {
		not_selected(rep(json.patch(green, [{"op": "replace", "path": "/cis_profile", "value": bad}])))
	}
}
