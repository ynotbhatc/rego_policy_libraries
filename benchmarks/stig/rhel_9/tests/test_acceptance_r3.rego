# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# Requirement (owner ruling, audit 2026-11-24 round 3): "Fix the STIG, do it right" - a STIG module takes a
# number as a JSON number only. A decimal string ("900"), a whitespace-padded decimal string (" 900 ") and a
# fraction (900.5) are not the number the check text asks for: the rule that reads the fact is Open and the
# report is not compliant. This supersedes the "number or decimal string" reading of `_num` in
# benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md and tests that assert it (tests/test_num_contract.rego,
# test_decimal_string_passes_as_documented).
#
# The numeric facts are derived from the tree's own green fixture (every leaf that is a JSON number), so the
# test cannot drift from the fixture. The rule that reads a fact is not hard-coded either: it is whichever
# rule opens when the fact is removed from the fixture.

package stig.rhel_9.acceptance_r3

import rego.v1

fx := data.stig.rhel_9.green_test.green_fixture

# Numeric leaves that are NOT part of the sweep, each with the reason. Locked: additions go through the
# integrator, with the reason.
#  - yum_repos[].gpgcheck: a configuration-file token (1 / true / yes as written in the .repo file), which the
#    collector contract types as number/string; it is a switch, not a quantity.
#  - interactive_users[].uid: a record identifier; no rule compares it (the collector selects UID >= 1000).
excluded_leaf(p) if p[count(p) - 1] in {"gpgcheck", "uid"}

# [JSON pointer, fixture value, key name, true when the leaf sits directly under a top-level fact object]
num_leaves := [[ptr, v, sprintf("%v", [p[count(p) - 1]]), count(p) == 2] |
	walk(fx, [p, v])
	is_number(v)
	not excluded_leaf(p)
	ptr := sprintf("/%s", [concat("/", [sprintf("%v", [s]) | some s in p])])
]

open_of(inp) := fs if {
	r := data.stig.rhel_9.main.compliance_report with input as inp
	fs := r.open_findings
}

# The sweeps run in `shards` slices of num_leaves (leaf index modulo `shards`), so that no test runs long enough
# to meet the suite's per-test timeout on the oldest supported OPA. Every leaf is in exactly one slice; the
# slices are checked to cover num_leaves in test_the_shards_cover_every_numeric_fact.
shards := 4

shard(i) := [l | some j, l in num_leaves; j % shards == i]

# the rule(s) that read each leaf: those Open once the leaf is removed (for the leaves given)
readers_of(leaves) := {l[0]: ids |
	some l in leaves
	ids := {f.stig_id | some f in open_of(json.patch(fx, [{"op": "remove", "path": l[0]}]))}
}

# `rd` is `readers_of` the shard, bound once per test (it is expensive). The mutated input fails every reader rule; `named` additionally requires a finding of a reader rule to name
# the fact (evidence rule: the finding names the field that is the problem)
rejected(l, rd, inp, named) if {
	r := data.stig.rhel_9.main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls >= 1
	fs := r.open_findings
	every id in rd[l[0]] {
		some f in fs
		f.stig_id == id
	}
	names_fact(l, rd, fs, named)
}

names_fact(_, _, _, false)

names_fact(l, _, _, true) if l[3] == false

names_fact(l, rd, fs, true) if {
	l[3] == true
	some f in fs
	f.stig_id in rd[l[0]]
	contains(json.marshal(f), l[2])
}

# Requirement: the unmutated green fixture is compliant with no open finding (regression guard).
test_green_fixture_passes if {
	r := data.stig.rhel_9.main.compliance_report with input as fx
	r.compliant == true
	r.failed_controls == 0
	count(r.open_findings) == 0
}

# The shards partition num_leaves: each leaf is in exactly one, and together they are all of it.
test_the_shards_cover_every_numeric_fact if {
	count(num_leaves) >= 24
	every j, l in num_leaves {
		l in shard(j % shards)
	}
	sum([count(shard(i)) | some i in numbers.range(0, shards - 1)]) == count(num_leaves)
}

# Requirement: the sweep is not vacuous - the fixture has numeric facts and each is read by at least one rule
# (removing it opens a finding). Source: evidence rule, "a missing number must not default to a passing value".
test_every_numeric_fact_is_read_by_a_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		count(rd[l[0]]) >= 1
	}
}

test_every_numeric_fact_is_read_by_a_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		count(rd[l[0]]) >= 1
	}
}

test_every_numeric_fact_is_read_by_a_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		count(rd[l[0]]) >= 1
	}
}

test_every_numeric_fact_is_read_by_a_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		count(rd[l[0]]) >= 1
	}
}

# Requirement: a decimal string is not a number (owner ruling "numbers are JSON numbers only"); the finding of
# the reading rule names the fact.
test_decimal_string_fails_the_reading_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf("%d", [l[1]])}]), true)
	}
}

test_decimal_string_fails_the_reading_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf("%d", [l[1]])}]), true)
	}
}

test_decimal_string_fails_the_reading_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf("%d", [l[1]])}]), true)
	}
}

test_decimal_string_fails_the_reading_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf("%d", [l[1]])}]), true)
	}
}

# Requirement: a whitespace-padded decimal string is not a number (same ruling).
test_padded_decimal_string_fails_the_reading_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf(" %d ", [l[1]])}]), true)
	}
}

test_padded_decimal_string_fails_the_reading_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf(" %d ", [l[1]])}]), true)
	}
}

test_padded_decimal_string_fails_the_reading_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf(" %d ", [l[1]])}]), true)
	}
}

test_padded_decimal_string_fails_the_reading_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": sprintf(" %d ", [l[1]])}]), true)
	}
}

# Requirement: a fraction is not a valid value of a whole-number setting (every numeric fact of this STIG is a
# count, a size, a number of days/seconds or an id). Source: LINUX_COLLECTOR_CONTRACT.md `_num` "a whole number".
test_fraction_fails_the_reading_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": l[1] + 0.5}]), false)
	}
}

test_fraction_fails_the_reading_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": l[1] + 0.5}]), false)
	}
}

test_fraction_fails_the_reading_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": l[1] + 0.5}]), false)
	}
}

test_fraction_fails_the_reading_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		rejected(l, rd, json.patch(fx, [{"op": "replace", "path": l[0], "value": l[1] + 0.5}]), false)
	}
}
