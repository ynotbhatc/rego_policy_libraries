# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# cis_amazon_linux_2023.main: the CIS profile is selected by input.profile (level1_server or level2_server; "level1" / "level2" are documented aliases).
# Requirement (round 3 task list item 7; evidence rule in AGENT_BRIEF.md, "'Does not apply' must be an explicit
# statement in the input, never inferred from a missing field"): a profile that is absent, null, of the wrong
# type or not one of the benchmark's profiles is never compliant and the report carries a finding that the
# profile was not selected. Today such an input is silently scoped at level1_server, which drops every Level 2
# recommendation. This supersedes `test_unknown_profile_defaults_to_level1_server` in this tree's main test.
#
# This tree has no all-pass fixture (its tests evaluate small inputs), so the facts used here are empty input
# and one small fact set; "never compliant" is therefore asserted on inputs that fail for other reasons too, and
# the finding is what the tests can pin. An all-pass fixture per profile would let the verdict be pinned as well
# (reported in audit-reports/r3-tests.md).

package cis_amazon_linux_2023.acceptance_r3

import rego.v1

valid_profiles := ["level1_server", "level2_server"]

# values that select nothing
not_a_selection := {
	"null": null,
	"unknown name": "bogus",
	"empty string": "",
	"wrong case": "LEVEL2_SERVER",
	"number": 2,
	"boolean": true,
	"array": ["level2_server"],
	"object": {"level": 2},
}

fact_sets := [{}, {"ssh": {"sshd_config_raw": "permitrootlogin no"}}]

rep(inp) := r if {
	r := data.cis_amazon_linux_2023.main.compliance_report with input as inp
}

texts(r) := {sprintf("%v", [v]) | some v in r.violations}

# every violation text any validly selected profile produces on these facts
known_texts(facts) := {t |
	some p in valid_profiles
	some t in texts(rep(object.union(facts, {"profile": p})))
}

# a finding that is not produced under any valid selection and that names the profile
# `known` is known_texts(facts), computed once by the caller (one report evaluation per valid profile)
has_profile_finding(r, known) if {
	some t in (texts(r) - known)
	contains(lower(t), "profile")
}

# Requirement: every valid profile still selects itself and scopes the report (regression guard): the report
# names the profile, Level 2 has more recommendations in scope than Level 1, and no profile finding appears.
test_each_valid_profile_still_selects_itself_set_0 if {
	every facts in fact_set_shard(0) {
		every p in valid_profiles {
			r := rep(object.union(facts, {"profile": p}))
			r.profile == p
			r.total_controls > 0
			every t in texts(r) {
				not contains(lower(t), "input.profile")
			}
		}
		rep(object.union(facts, {"profile": "level1_server"})).total_controls < rep(object.union(facts, {"profile": "level2_server"})).total_controls
	}
}

test_each_valid_profile_still_selects_itself_set_1 if {
	every facts in fact_set_shard(1) {
		every p in valid_profiles {
			r := rep(object.union(facts, {"profile": p}))
			r.profile == p
			r.total_controls > 0
			every t in texts(r) {
				not contains(lower(t), "input.profile")
			}
		}
		rep(object.union(facts, {"profile": "level1_server"})).total_controls < rep(object.union(facts, {"profile": "level2_server"})).total_controls
	}
}

# Requirement: the documented aliases "level1" / "level2" keep selecting level1_server / level2_server.
test_documented_aliases_still_select if {
	rep({"profile": "level1"}).profile == "level1_server"
	rep({"profile": "level2"}).profile == "level2_server"
	rep({"profile": "level1"}).total_controls == rep({"profile": "level1_server"}).total_controls
	rep({"profile": "level2"}).total_controls == rep({"profile": "level2_server"}).total_controls
}

# Requirement: an ABSENT profile is not compliant and carries a finding that the profile was not selected.
test_absent_profile_is_not_compliant_and_says_so_set_0 if {
	every facts in fact_set_shard(0) {
		r := rep(facts)
		r.compliant == false
		has_profile_finding(r, known_texts(facts))
	}
}

test_absent_profile_is_not_compliant_and_says_so_set_1 if {
	every facts in fact_set_shard(1) {
		r := rep(facts)
		r.compliant == false
		has_profile_finding(r, known_texts(facts))
	}
}

# Requirement: null, a value of the wrong type and an unknown name are not compliant and carry the finding.
# The sweep below runs one fact set and one of 2 parts of the values at a time (value index modulo 2, in sorted key
# order), so that no test runs long enough to meet the suite's per-test timeout on the oldest supported OPA;
# known_texts is computed once per test. Every (fact set, value) pair is in exactly one test.
fact_set_shard(i) := [f | some j, f in fact_sets; j == i]

bad_part(q) := {k: not_a_selection[k] | some j, k in sort([x | some x, _ in not_a_selection]); j % 2 == q}

test_the_selection_shards_cover_every_fact_set_and_value if {
	count(fact_sets) == 2
	sum([count(bad_part(q)) | some q in numbers.range(0, 1)]) == count(not_a_selection)
	every k, _ in not_a_selection {
		count([q | some q in numbers.range(0, 1); k in object.keys(bad_part(q))]) == 1
	}
	every facts in fact_sets {
		count([i | some i in [0, 1]; facts in fact_set_shard(i)]) == 1
	}
}

test_value_that_selects_nothing_is_not_compliant_and_says_so_set_0_part_0 if {
	every facts in fact_set_shard(0) {
		known := known_texts(facts)
		every _, bad in bad_part(0) {
			r := rep(object.union(facts, {"profile": bad}))
			r.compliant == false
			has_profile_finding(r, known)
		}
	}
}

test_value_that_selects_nothing_is_not_compliant_and_says_so_set_0_part_1 if {
	every facts in fact_set_shard(0) {
		known := known_texts(facts)
		every _, bad in bad_part(1) {
			r := rep(object.union(facts, {"profile": bad}))
			r.compliant == false
			has_profile_finding(r, known)
		}
	}
}

test_value_that_selects_nothing_is_not_compliant_and_says_so_set_1_part_0 if {
	every facts in fact_set_shard(1) {
		known := known_texts(facts)
		every _, bad in bad_part(0) {
			r := rep(object.union(facts, {"profile": bad}))
			r.compliant == false
			has_profile_finding(r, known)
		}
	}
}

test_value_that_selects_nothing_is_not_compliant_and_says_so_set_1_part_1 if {
	every facts in fact_set_shard(1) {
		known := known_texts(facts)
		every _, bad in bad_part(1) {
			r := rep(object.union(facts, {"profile": bad}))
			r.compliant == false
			has_profile_finding(r, known)
		}
	}
}
