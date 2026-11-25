package cmmc_evidence_rule_test

import data.cmmc_level_2_pass_test.level_2_facts
import rego.v1

# Evidence rule, data-driven over the all-pass Level 2 fixture: only the boolean
# true (or, for a "does this apply" fact, a stated boolean) is evidence. Every
# boolean leaf is replaced by "false", "true", null, 0 and 1 and removed; every
# number leaf is replaced by its string form and null and removed. None of the
# mutated inputs may be reported compliant.

_bool_leaves := [p | walk(level_2_facts, [p, v]); is_boolean(v)]

# Two numbers in the fixture are read by no rule: 3.5.9 and 3.14.4 name no period, so the
# hours are not compared (test_cmmc_org_defined_parameters asserts that).
_unread := {["identity", "temp_password_expiry_hours"], ["integrity", "signature_update_frequency_hours"]}

_number_leaves := [p | walk(level_2_facts, [p, v]); is_number(v); not p in _unread]

_bad_booleans := ["false", "true", "no", null, 0, 1]

_label(p) := concat(".", [sprintf("%v", [s]) | some s in p])

# Each case is a name and a JSON patch; the mutated input is built only when the case is evaluated.
_cases contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "patch": [{"op": "replace", "path": p, "value": bad}]} if {
	some p in _bool_leaves
	some bad in _bad_booleans
}

_cases contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "patch": [{"op": "replace", "path": p, "value": bad}]} if {
	some p in _number_leaves
	some bad in [sprintf("%v", [object.get(level_2_facts, p, null)]), null]
}

_cases contains {"case": sprintf("%s removed", [_label(p)]), "patch": [{"op": "remove", "path": p}]} if {
	some p in array.concat(_bool_leaves, _number_leaves)
}

# Every top-level section removed, null, a string and an empty array.
_cases contains {"case": sprintf("%s := %s", [key, json.marshal(bad)]), "patch": [{"op": "replace", "path": [key], "value": bad}]} if {
	some key, _ in level_2_facts
	some bad in [null, "true", []]
}

_cases contains {"case": sprintf("%s removed", [key]), "patch": [{"op": "remove", "path": [key]}]} if {
	some key, _ in level_2_facts
}

# The cases are evaluated in 16 shards (first hex digit of the md5 of the case name) so that no single test
# runs long enough to meet the suite's 30 s per-test timeout.
_shards := ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

# The mutated inputs of one shard that still pass (empty when the evidence rule holds). Only the shard asked
# for is evaluated, and each mutated input is built when its case is reached.
escapes_in(shard) := {c.case |

	# The shard is selected first and as its own list: written as a filter on `_cases` next to the `with`
	# below, OPA 1.10 evaluates the report for every case before it applies the filter (16 times the work).
	some c in [x | some x in _cases; substring(crypto.md5(x.case), 0, 1) == shard]

	inp := json.patch(level_2_facts, c.patch)
	_domains_all_pass(inp)
}

# A mutated input "still passes" when every one of the 14 domain modules reports compliant. The domain verdicts
# are what the yes/no facts decide; scoring them into practices (data.cmmc.main) costs about thirty times as
# much per input, so the full set runs against the domains and a fixed sample against the scored report below.
_domains_all_pass(inp) if {
	results := data.cmmc.domain_results with input as inp
	count(results) == 14
	not false in results
}

# About one case in 32 (md5 of the case name starts 00..07), each also evaluated through the scored report.
_sample := {c | some c in _cases; substring(crypto.md5(c.case), 0, 2) in {"00", "01", "02", "03", "04", "05", "06", "07"}}

test_sampled_mutations_fail_the_scored_report_too if {
	count(_sample) > 20
	every c in _sample {
		inp := json.patch(level_2_facts, c.patch)
		r := data.cmmc.main.compliance_report with input as inp
		r.compliant == false
		r.failed_controls > 0
	}
}

test_fixture_passes_every_domain if _domains_all_pass(level_2_facts)

# Every escape, for debugging: opa eval 'data.<this package>.escapes'
escapes := {x | some shard in _shards; some x in escapes_in(shard)}

_clean(shard) if count(escapes_in(shard)) == 0

test_fixture_passes if {
	r := data.cmmc.main.compliance_report with input as level_2_facts
	r.compliant == true
	count(r.violations) == 0
}

test_empty_input_fails if {
	r := data.cmmc.main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_the_cases_are_many_and_every_one_is_in_a_shard if {
	count(_cases) > 1000
	every c in _cases {
		substring(crypto.md5(c.case), 0, 1) in _shards
	}
}

test_no_bad_evidence_passes_shard_0 if _clean("0")

test_no_bad_evidence_passes_shard_1 if _clean("1")

test_no_bad_evidence_passes_shard_2 if _clean("2")

test_no_bad_evidence_passes_shard_3 if _clean("3")

test_no_bad_evidence_passes_shard_4 if _clean("4")

test_no_bad_evidence_passes_shard_5 if _clean("5")

test_no_bad_evidence_passes_shard_6 if _clean("6")

test_no_bad_evidence_passes_shard_7 if _clean("7")

test_no_bad_evidence_passes_shard_8 if _clean("8")

test_no_bad_evidence_passes_shard_9 if _clean("9")

test_no_bad_evidence_passes_shard_a if _clean("a")

test_no_bad_evidence_passes_shard_b if _clean("b")

test_no_bad_evidence_passes_shard_c if _clean("c")

test_no_bad_evidence_passes_shard_d if _clean("d")

test_no_bad_evidence_passes_shard_e if _clean("e")

test_no_bad_evidence_passes_shard_f if _clean("f")
