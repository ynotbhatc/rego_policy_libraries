# Hand-written (the generator leaves hand-written tests in tests/ alone).
#
# A value of the wrong type is never a pass. Rego orders values of different types, so an unguarded bound
# (`x >= 6`, `x <= 10`) holds for a string or for null, and to_number() reads null as 0. Every registry value the
# generated rules read is taken from the all-pass fixture and replaced, one at a time, by the same digits in a
# string (or, for a number held as REG_SZ, by the number), by null and by a boolean: each replacement
# must open at least one of the generated registry rules.
package stig.windows_server_2016_bad_input_test

import data.stig.windows_server_2016
import data.stig.windows_server_2016_test.device_guard_rule_ids
import data.stig.windows_server_2016_test.green_fixture
import data.stig.windows_server_2016_test.registry_rule_ids
import rego.v1

open_rules(facts) := {f.stig_id |
	some f in windows_server_2016.stig_assessment.findings with input as facts
	f.status == "Open"
	registry_rule_ids[f.stig_id]
}

# [key path, value name, value] for every scalar the fixture holds
leaves := [[path, name, v] |
	some path, values in green_fixture.registry
	some name, v in values
	not is_array(v)
]

with_leaf(path, name, v) := object.union(green_fixture, {"registry": {path: {name: v}}})

# the same digits in the other JSON type: 90 -> "90", "4" -> 4; text has no other representation
swapped(v) := sprintf("%v", [v]) if is_number(v)

swapped(v) := to_number(v) if {
	is_string(v)
	regex.match(`^-?[0-9]+$`, v)
}

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_leaves_3 if {
	sum([count(_slice(leaves, i, 3)) | some i in numbers.range(0, 2)]) == count(leaves)
	every i in numbers.range(0, 2) {
		every k, x in _slice(leaves, i, 3) {
			x == leaves[i + (k * 3)]
		}
	}
}

test_the_fixture_opens_no_generated_rule if {
	count(open_rules(green_fixture)) == 0
	count(leaves) > 50
}

test_a_number_held_as_the_wrong_type_opens_a_rule if {
	typed := [l | some l in leaves; swapped(l[2])]
	count(typed) > 50
	every l in typed {
		count(open_rules(with_leaf(l[0], l[1], swapped(l[2])))) > 0
	}
}

test_null_and_booleans_open_a_rule_slice_0 if {
	every l in _slice(leaves, 0, 3) {
		every bad in [null, true, false] {
			count(open_rules(with_leaf(l[0], l[1], bad))) > 0
		}
	}
}

test_null_and_booleans_open_a_rule_slice_1 if {
	every l in _slice(leaves, 1, 3) {
		every bad in [null, true, false] {
			count(open_rules(with_leaf(l[0], l[1], bad))) > 0
		}
	}
}

test_null_and_booleans_open_a_rule_slice_2 if {
	every l in _slice(leaves, 2, 3) {
		every bad in [null, true, false] {
			count(open_rules(with_leaf(l[0], l[1], bad))) > 0
		}
	}
}

# A value DISA's check text accepts as absent ("does not exist, or is 0") may be removed without a finding, so
# removal is not tested leaf by leaf (tests/test_stig_*_check_text.rego holds those rules); a registry that was
# not collected at all opens every generated rule that reads it. The Win32_DeviceGuard rules read
# input.device_guard instead, as their check text states.
registry_reading_rule_ids := {id | registry_rule_ids[id]} - device_guard_rule_ids

test_an_uncollected_registry_opens_every_rule_that_reads_it if {
	count(registry_reading_rule_ids) > 50
	open_rules(json.remove(green_fixture, ["registry"])) == registry_reading_rule_ids
	every bad in [{}, null, "collected", []] {
		facts := json.patch(green_fixture, [{"op": "replace", "path": "/registry", "value": bad}])
		open_rules(facts) == registry_reading_rule_ids
	}
}

test_empty_input_is_not_compliant if {
	r := data.stig.windows_server_2016.main.compliance_report with input as {}
	r.compliant == false
}
