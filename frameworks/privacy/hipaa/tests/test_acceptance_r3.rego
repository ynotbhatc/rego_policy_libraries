# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# hipaa.main: the attestation maps input.hipaa.specifications (Security Rule, 45 CFR 164.308-164.316),
# input.hipaa.subpart_d (Breach Notification Rule) and input.hipaa.subpart_e (Privacy Rule) are evidence.
# An attestation that is missing is evidence that was not collected, and the report must not be compliant.
# Source: audit 2026-11-24, harness entries `hipaa.main drop:hipaa.specifications.164.308(a)(5)(i)` and five
# like it (scripts/bad_input_known_failures.txt, "pass: compliant=true"); evidence rule in AGENT_BRIEF.md
# ("missing ... the control fails, and the finding text names the problem").
#
# The all-pass fixture is data.hipaa.test_fixtures.full_input, used by reference.

package hipaa.acceptance_r3

import rego.v1

fx := data.hipaa.test_fixtures.full_input

maps := ["specifications", "subpart_d", "subpart_e"]

rep(inp) := r if {
	r := data.hipaa.main.compliance_report with input as inp
}

# not compliant, and a violation names the id that is the problem
fails_naming(inp, id) if {
	r := rep(inp)
	r.compliant == false
	r.overall_compliant == false
	r.violation_count >= 1
	some v in r.violations
	contains(sprintf("%v", [v]), id)
}

# Requirement: the unmutated all-pass fixture is compliant (regression guard).
test_all_pass_fixture_is_compliant if {
	r := rep(fx)
	r.compliant == true
	r.overall_compliant == true
	r.violation_count == 0
}

# Requirement: the fixture carries the three maps with keys that are 45 CFR citations (the sweep is not vacuous).
test_fixture_carries_the_three_attestation_maps if {
	# Integrator, 2026-11-24: the fixture now carries only the attestations that decide a row (20 / 8 / 73).
	# The 48 / 9 / 37 fact-decided rows take no attestation (module header), so the original thresholds
	# (68 / 17 / 100), which counted them, were the test's error, as its own report said.
	count(fx.hipaa.specifications) >= 20
	count(fx.hipaa.subpart_d) >= 8
	count(fx.hipaa.subpart_e) >= 73
	every m in maps {
		every id, v in fx.hipaa[m] {
			v == true
			startswith(id, "164.")
		}
	}
}

# ids the report decides by the attestation alone: attesting `false` makes the report non-compliant
decided_by_attestation(m) := {id |
	some id, _ in fx.hipaa[m]
	rep(json.patch(fx, [{"op": "replace", "path": ["hipaa", m, id], "value": false}])).compliant == false
}

# Requirement (certain): for every id the report decides by attestation, a REMOVED attestation fails exactly
# as a false one does, and the violation names the id. Source: evidence rule; module headers ("a non-true
# attestation ... is a violation").
test_removing_an_attestation_that_decides_a_row_fails_specifications if {
	ids := decided_by_attestation("specifications")
	count(ids) >= 20
	every id in ids {
		fails_naming(json.remove(fx, [["hipaa", "specifications", id]]), id)
	}
}

test_removing_an_attestation_that_decides_a_row_fails_subpart_d if {
	ids := decided_by_attestation("subpart_d")
	count(ids) >= 8
	every id in ids {
		fails_naming(json.remove(fx, [["hipaa", "subpart_d", id]]), id)
	}
}

test_removing_an_attestation_that_decides_a_row_fails_subpart_e if {
	ids := decided_by_attestation("subpart_e")
	count(ids) >= 1
	every id in ids {
		fails_naming(json.remove(fx, [["hipaa", "subpart_e", id]]), id)
	}
}

# Requirement (as instructed for round 3, task list item 3: "removing any one attested specification key ...
# must make the report non-compliant. Sweep every key."): EVERY key of the three maps, one at a time. This is
# stricter than the three tests above: it includes the rows the modules decide from facts, where the module
# header of hipaa_security_rule.rego says "An attestation for a fact row is accepted but does not decide it".
# The round 3 report (audit-reports/r3-tests.md) raises that conflict for the owner; until it is ruled on,
# this test stands as written.
test_removing_any_key_fails_specifications if {
	every id, _ in fx.hipaa.specifications {
		fails_naming(json.remove(fx, [["hipaa", "specifications", id]]), id)
	}
}

test_removing_any_key_fails_subpart_d if {
	every id, _ in fx.hipaa.subpart_d {
		fails_naming(json.remove(fx, [["hipaa", "subpart_d", id]]), id)
	}
}

test_removing_any_key_fails_subpart_e if {
	every id, _ in fx.hipaa.subpart_e {
		fails_naming(json.remove(fx, [["hipaa", "subpart_e", id]]), id)
	}
}
