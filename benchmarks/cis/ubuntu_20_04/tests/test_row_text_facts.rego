# Text facts (a file's mode or owner, a sysctl parameter's value, a service's state ...) are read with
# `row.field == "x"` / `!= "x"` or inside `not f(row.field)`: all undefined when the field is missing, so a row
# or section without it used to drop out of the check. Every text leaf of the all-pass host, removed or sent as
# null, must now leave the host non-compliant. The names listed are labels a message prints; no rule selects on
# them.
package cis_ubuntu_20_04.row_text_facts_test

import rego.v1

_fx := data.cis_ubuntu_20_04.all_pass_fixture_test.fixture_compliant

# su_allowed_group: `su` need not be restricted to a named group where pam_wheel is not used (CIS 5.3.7 only checks a group when one is set)
_labels := {"name", "path", "file", "package", "module", "cis_id", "mount_point", "su_allowed_group"}

# every string leaf that is a keyed field (not a list member), in a row or in a section: [path]
_leaves := [path |
	walk(_fx, [path, v])
	is_string(v)
	count(path) >= 2
	not is_number(path[count(path) - 1])
	not path[count(path) - 1] in _labels
]

_compliant(inp) := c if {
	r := data.cis_ubuntu_20_04.main.compliance_report with input as inp
	c := r.compliant
}

_without(path) := json.patch(_fx, [{"op": "remove", "path": concat("/", array.concat([""], [sprintf("%v", [s]) | some s in path]))}])

_nulled(path) := json.patch(_fx, [{"op": "replace", "path": concat("/", array.concat([""], [sprintf("%v", [s]) | some s in path])), "value": null}])

test_the_fixture_still_passes if _compliant(_fx) == true

test_the_walk_covers_the_row_text_facts if count(_leaves) > 5

test_a_row_text_fact_removed_is_not_compliant if {
	every path in _leaves {
		_compliant(_without(path)) == false
	}
}

test_a_row_text_fact_sent_as_null_is_not_compliant if {
	every path in _leaves {
		_compliant(_nulled(path)) == false
	}
}
