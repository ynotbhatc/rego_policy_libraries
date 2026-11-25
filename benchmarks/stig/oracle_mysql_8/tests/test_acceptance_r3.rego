# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# Requirement (owner ruling, audit 2026-11-24 round 3): "Fix the STIG, do it right" - a STIG module takes a
# number as a JSON number only. A numeric limit sent as a decimal string ("3") or a whitespace-padded decimal
# string (" 3 ") is not a pass: the rule that reads it is Open and the report is not compliant. This
# supersedes tests/test_bad_input_types.rego `test_number_and_decimal_string_pass` and the "number or decimal
# string" comment on `_num` in core.rego.
#
# The tree's green fixture is used by reference. It holds these limits as decimal strings today, so the
# passing baseline of this test is that fixture with every numeric limit converted to the JSON number it
# spells (`base`): the test holds whether or not the fixture is converted by the fix.
#
# Not part of the sweep (the DBMS legitimately reports text here):
#  - system variables that are words (validate_password.policy STRONG, require_secure_transport ON,
#    ssl_fips_mode ON).

package stig.oracle_mysql_8.acceptance_r3

import rego.v1

fx := data.stig.oracle_mysql_8_test.green_fixture

# JSON pointers of the numeric limits a rule compares. Locked.
numeric_paths := [
	"/mysql/variables/max_user_connections",
	"/mysql/variables/validate_password.length",
	"/mysql/variables/audit_log_rotate_on_size",
]

# numeric limits that are whole numbers by definition (a count, a length, a size, minutes): a fraction fails
whole_number_paths := [
	"/mysql/variables/max_user_connections",
	"/mysql/variables/validate_password.length",
	"/mysql/variables/audit_log_rotate_on_size",
]

ptr_segments(ptr) := [replace(replace(s, "~1", "/"), "~0", "~") | some s in array.slice(split(ptr, "/"), 1, 1000)]

fixture_value(ptr) := object.get(fx, ptr_segments(ptr), null)

as_number(v) := v if is_number(v)

as_number(v) := to_number(trim_space(v)) if is_string(v)

# [pointer, expected word] - text the DBMS reports that must keep passing as text
word_values := [["/mysql/variables/validate_password.policy", "STRONG"], ["/mysql/variables/require_secure_transport", "ON"], ["/mysql/variables/ssl_fips_mode", "ON"]]

# [pointer, the JSON number the fixture spells, key name]
num_facts := [[ptr, as_number(fixture_value(ptr)), segs[count(segs) - 1]] |
	some ptr in numeric_paths
	segs := ptr_segments(ptr)
]

base := json.patch(fx, [{"op": "replace", "path": f[0], "value": f[1]} | some f in num_facts])

open_of(inp) := fs if {
	r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
	fs := r.open_findings
}

not_compliant(inp) if {
	r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls >= 1
}

# the rule(s) that read each limit: those Open once it is removed from the baseline
readers := {f[0]: ids |
	some f in num_facts
	ids := {o.stig_id | some o in open_of(json.patch(base, [{"op": "remove", "path": f[0]}]))}
}

# `rd` is `readers`, bound once per test. The mutated input fails every reader rule.
rejected(f, rd, inp) if {
	not_compliant(inp)
	fs := open_of(inp)
	every id in rd[f[0]] {
		some o in fs
		o.stig_id == id
	}
}

# Requirement: every listed limit is present in the green fixture and spells a number (the sweep is not
# vacuous), and removing it opens at least one rule (evidence rule: a missing number never passes).
test_every_numeric_limit_is_in_the_fixture_and_read if {
	count(num_facts) == count(numeric_paths)
	rd := readers
	every f in num_facts {
		is_number(f[1])
		count(rd[f[0]]) >= 1
	}
}

# Requirement: the green fixture with its numeric limits as JSON numbers is compliant with no open finding.
test_fixture_with_json_numbers_passes if {
	r := data.stig.oracle_mysql_8.main.compliance_report with input as base
	r.compliant == true
	r.failed_controls == 0
	count(r.open_findings) == 0
}

# Requirement: a decimal string is not a number (owner ruling "numbers are JSON numbers only").
test_decimal_string_fails_the_reading_rule if {
	rd := readers
	every f in num_facts {
		rejected(f, rd, json.patch(base, [{"op": "replace", "path": f[0], "value": sprintf("%d", [f[1]])}]))
	}
}

# Requirement: a whitespace-padded decimal string is not a number (same ruling).
test_padded_decimal_string_fails_the_reading_rule if {
	rd := readers
	every f in num_facts {
		rejected(f, rd, json.patch(base, [{"op": "replace", "path": f[0], "value": sprintf(" %d ", [f[1]])}]))
	}
}

# Requirement: a fraction is not a valid value of a whole-number limit (task list item 1, "sent as a fraction
# must fail"), restricted to the limits that cannot be fractional.
test_fraction_fails_a_whole_number_limit if {
	rd := readers
	count([g | some g in num_facts; g[0] in whole_number_paths]) == count(whole_number_paths)
	count(whole_number_paths) >= 1
	every f in [g | some g in num_facts; g[0] in whole_number_paths] {
		rejected(f, rd, json.patch(base, [{"op": "replace", "path": f[0], "value": f[1] + 0.5}]))
	}
}

# Requirement: the words the DBMS reports in a numeric column are still read as words, not swept as bad
# numbers - a baseline that keeps them stays compliant (guards against a fix that rejects every string).
test_word_values_are_untouched if {
	every w in word_values {
		object.get(base, ptr_segments(w[0]), null) == w[1]
	}
	r := data.stig.oracle_mysql_8.main.compliance_report with input as base
	r.compliant == true
}
