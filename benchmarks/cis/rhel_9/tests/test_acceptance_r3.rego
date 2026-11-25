# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# cis_rhel9.main: the numbers of one report must agree with each other and with its verdict.
# Source: audit 2026-11-24 (spot checks) - with the `auditd` section removed from the Level 1 fixture the
# report said compliant == false with compliance_percentage 100 and failed_controls 0. Every auditd
# recommendation of this benchmark is Level 2, so at Level 1 nothing that is in scope lost its evidence.
#
# Report fields used (read from the module): compliant, compliance_percentage, total_controls (recommendations
# in scope of the selected profile), passed_controls, failed_controls, standard_total (recommendations in the
# benchmark), control_results[] and control_result_counts {pass, fail, evidence_missing, not_attested,
# not_applicable}.
#
# Fixtures, by reference: data.cis_rhel9.control_results_test.fixture_compliant (Level 2) and
# fixture_compliant_level1_server (Level 1). Each is evaluated as it is, as {} and with each of its top-level
# sections removed in turn (every section, no sampling).

package cis_rhel9.acceptance_r3

import rego.v1

l2 := data.cis_rhel9.control_results_test.fixture_compliant

l1 := data.cis_rhel9.control_results_test.fixture_compliant_level1_server

rep(inp) := r if {
	r := data.cis_rhel9.main.compliance_report with input as inp
}

# ── the invariants ────────────────────────────────────────────────────────────────────────────────────────

# never "not compliant" with a perfect score and nothing failed
verdict_has_a_reason(r) if r.compliant == true

verdict_has_a_reason(r) if {
	r.compliant == false
	r.failed_controls >= 1
}

verdict_has_a_reason(r) if {
	r.compliant == false
	r.compliance_percentage != 100
}

# never "compliant" with a failed control or a score below 100
compliant_means_nothing_failed(r) if r.compliant == false

compliant_means_nothing_failed(r) if {
	r.compliant == true
	r.failed_controls == 0
	r.compliance_percentage == 100
	r.control_result_counts.fail == 0
	r.control_result_counts.evidence_missing == 0
	r.control_result_counts.not_attested == 0
}

# passed + failed + not applicable == total, in the report's own fields
counts_add_up(r) if {
	c := r.control_result_counts
	r.passed_controls + r.failed_controls == r.total_controls
	r.total_controls + c.not_applicable == r.standard_total
	r.passed_controls == c.pass
	r.failed_controls == (c.fail + c.evidence_missing) + c.not_attested
	sum([n | some _, n in c]) == r.standard_total
	count(r.control_results) == r.standard_total
	r.failed_controls <= r.total_controls
	r.passed_controls >= 0
}

consistent(r) if {
	is_boolean(r.compliant)
	verdict_has_a_reason(r)
	compliant_means_nothing_failed(r)
	counts_add_up(r)
}

# ── tests ─────────────────────────────────────────────────────────────────────────────────────────────────

# Requirement: both fixtures are compliant, at the level they declare (regression guard).
test_fixtures_pass_at_their_level if {
	r1 := rep(l1)
	r1.compliant == true
	r1.failed_controls == 0
	r1.profile == "level1_server"
	r2 := rep(l2)
	r2.compliant == true
	r2.failed_controls == 0
	r2.profile == "level2_server"
	r1.total_controls < r2.total_controls
}

# Requirement: the report is self-consistent on each fixture and on empty input.
test_report_is_consistent_on_the_fixtures_and_on_empty_input if {
	consistent(rep(l1))
	consistent(rep(l2))
	e := rep({})
	consistent(e)
	e.compliant == false
}

# The section sweeps run in slices of the sorted top-level sections (section index modulo the slice count: 6 at Level 1,
# 33 at Level 2 (one section each), whose reports are much larger), so that no test runs long enough to meet the suite's per-test
# timeout on the oldest supported OPA. Every section is in exactly one slice.
section_shard(l, i, n) := [s | some j, s in sort([k | some k, _ in l]); j % n == i]

test_the_section_shards_cover_every_section if {
	sum([count(section_shard(l1, i, 6)) | some i in numbers.range(0, 5)]) == count(l1)
	sum([count(section_shard(l2, i, 33)) | some i in numbers.range(0, 32)]) == count(l2)
	every s, _ in l1 {
		some i in numbers.range(0, 5)
		s in section_shard(l1, i, 6)
	}
	every s, _ in l2 {
		some i in numbers.range(0, 32)
		s in section_shard(l2, i, 33)
	}
}

# Requirement: the report stays self-consistent with any one top-level section of the Level 1 fixture removed.
test_report_is_consistent_with_any_section_removed_level_1_shard_0 if {
	count(l1) >= 25
	every s in section_shard(l1, 0, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_1_shard_1 if {
	count(l1) >= 25
	every s in section_shard(l1, 1, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_1_shard_2 if {
	count(l1) >= 25
	every s in section_shard(l1, 2, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_1_shard_3 if {
	count(l1) >= 25
	every s in section_shard(l1, 3, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_1_shard_4 if {
	count(l1) >= 25
	every s in section_shard(l1, 4, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_1_shard_5 if {
	count(l1) >= 25
	every s in section_shard(l1, 5, 6) {
		consistent(rep(json.remove(l1, [[s]])))
	}
}

# Requirement: the same on the Level 2 fixture.
test_report_is_consistent_with_any_section_removed_level_2_shard_0 if {
	count(l2) >= 25
	every s in section_shard(l2, 0, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_1 if {
	count(l2) >= 25
	every s in section_shard(l2, 1, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_2 if {
	count(l2) >= 25
	every s in section_shard(l2, 2, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_3 if {
	count(l2) >= 25
	every s in section_shard(l2, 3, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_4 if {
	count(l2) >= 25
	every s in section_shard(l2, 4, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_5 if {
	count(l2) >= 25
	every s in section_shard(l2, 5, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_6 if {
	count(l2) >= 25
	every s in section_shard(l2, 6, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_7 if {
	count(l2) >= 25
	every s in section_shard(l2, 7, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_8 if {
	count(l2) >= 25
	every s in section_shard(l2, 8, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_9 if {
	count(l2) >= 25
	every s in section_shard(l2, 9, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_10 if {
	count(l2) >= 25
	every s in section_shard(l2, 10, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_11 if {
	count(l2) >= 25
	every s in section_shard(l2, 11, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_12 if {
	count(l2) >= 25
	every s in section_shard(l2, 12, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_13 if {
	count(l2) >= 25
	every s in section_shard(l2, 13, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_14 if {
	count(l2) >= 25
	every s in section_shard(l2, 14, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_15 if {
	count(l2) >= 25
	every s in section_shard(l2, 15, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_16 if {
	count(l2) >= 25
	every s in section_shard(l2, 16, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_17 if {
	count(l2) >= 25
	every s in section_shard(l2, 17, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_18 if {
	count(l2) >= 25
	every s in section_shard(l2, 18, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_19 if {
	count(l2) >= 25
	every s in section_shard(l2, 19, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_20 if {
	count(l2) >= 25
	every s in section_shard(l2, 20, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_21 if {
	count(l2) >= 25
	every s in section_shard(l2, 21, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_22 if {
	count(l2) >= 25
	every s in section_shard(l2, 22, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_23 if {
	count(l2) >= 25
	every s in section_shard(l2, 23, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_24 if {
	count(l2) >= 25
	every s in section_shard(l2, 24, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_25 if {
	count(l2) >= 25
	every s in section_shard(l2, 25, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_26 if {
	count(l2) >= 25
	every s in section_shard(l2, 26, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_27 if {
	count(l2) >= 25
	every s in section_shard(l2, 27, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_28 if {
	count(l2) >= 25
	every s in section_shard(l2, 28, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_29 if {
	count(l2) >= 25
	every s in section_shard(l2, 29, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_30 if {
	count(l2) >= 25
	every s in section_shard(l2, 30, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_31 if {
	count(l2) >= 25
	every s in section_shard(l2, 31, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

test_report_is_consistent_with_any_section_removed_level_2_shard_32 if {
	count(l2) >= 25
	every s in section_shard(l2, 32, 33) {
		consistent(rep(json.remove(l2, [[s]])))
	}
}

# Requirement: removing `auditd` from the Level 1 fixture leaves the Level 1 verdict unchanged - compliant,
# nothing failed, the same counts - because no auditd recommendation is in scope at Level 1.
# Source: round 3 task list item 5; CIS profile applicability of the auditd section (Level 2).
test_auditd_removed_at_level_1_leaves_the_verdict_unchanged if {
	base := rep(l1)
	r := rep(json.remove(l1, [["auditd"]]))
	r.compliant == true
	r.compliant == base.compliant
	r.failed_controls == 0
	r.passed_controls == base.passed_controls
	r.total_controls == base.total_controls
	r.compliance_percentage == 100
	r.control_result_counts == base.control_result_counts
}

# Requirement: removing `auditd` from the Level 2 fixture makes the report non-compliant with auditd
# recommendations failed for missing evidence.
test_auditd_removed_at_level_2_fails if {
	r := rep(json.remove(l2, [["auditd"]]))
	r.compliant == false
	r.failed_controls >= 1
	r.compliance_percentage < 100
	r.control_result_counts.evidence_missing >= 1
}
