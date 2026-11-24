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

_mutations contains {"case": sprintf("%s := %s", [concat(".", [sprintf("%v", [s]) | some s in p]), json.marshal(bad)]), "input": inp} if {
	some p in _bool_leaves
	some bad in _bad_booleans
	inp := json.patch(level_2_facts, [{"op": "replace", "path": p, "value": bad}])
}

_mutations contains {"case": sprintf("%s := %s", [concat(".", [sprintf("%v", [s]) | some s in p]), json.marshal(bad)]), "input": inp} if {
	some p in _number_leaves
	some bad in [sprintf("%v", [object.get(level_2_facts, p, null)]), null]
	inp := json.patch(level_2_facts, [{"op": "replace", "path": p, "value": bad}])
}

_mutations contains {"case": sprintf("%s removed", [concat(".", [sprintf("%v", [s]) | some s in p])]), "input": inp} if {
	some p in array.concat(_bool_leaves, _number_leaves)
	inp := json.patch(level_2_facts, [{"op": "remove", "path": p}])
}

# The mutated inputs that still pass (empty when the evidence rule holds).
escapes contains m.case if {
	some m in _mutations
	data.cmmc.main.compliance_report.compliant == true with input as m.input
}

test_fixture_passes if {
	r := data.cmmc.main.compliance_report with input as level_2_facts
	r.compliant == true
	count(r.violations) == 0
}

test_fixture_is_large_enough_to_mean_something if {
	count(_bool_leaves) > 150
	count(_mutations) > 1000
}

test_empty_input_fails if {
	r := data.cmmc.main.compliance_report with input as {}
	r.compliant == false
}

test_no_bad_evidence_passes if {
	count(escapes) == 0
}
