package cis_ubuntu_20_04_bad_input_types_test

# (top-level package name on purpose: the smoke test evaluates everything under data.cis_ubuntu_20_04, and these
# cases are too many to ride along with it)

# The evidence rule, proved leaf by leaf on the all-pass fixture (tests/test_all_pass_fixture.rego).
# A yes/no fact is answered only by a JSON boolean and a number only by a JSON number. For EVERY boolean
# leaf of the fixture, the string of its own value ("true" for true), the string of the opposite value,
# "no", 0/1, null and a missing key must each make the report fail, with a finding that names the leaf
# and the problem ("<leaf> is not a boolean (got string)" / "<leaf> not collected"). For every number
# leaf the same holds for its string form, a boolean and null. The leaves are found by walking the
# fixture, so a fact added to the fixture is covered without editing this file. Sharded by leaf index
# so each test stays well inside the 30 s timeout. The audit-rule comparison (39 required rules against
# every active rule, two regex passes each) is 80% of one evaluation and reads no boolean or number, so
# the mutation cases replace its result with the empty set it has on the fixture; the fixture test and
# the mixed-input test below evaluate it for real.
#
# This file replaces the round-1 version, which required a wrong-typed fact to produce the same finding
# as the boolean false ("AppArmor is not installed"); the finding now names the evidence problem instead.

import data.cis_ubuntu_20_04.all_pass_fixture_test.fixture_compliant as fx
import rego.v1

bool_leaves := [p | walk(fx, [p, v]); is_boolean(v)]

number_leaves := [p | walk(fx, [p, v]); is_number(v)]

shards := 2

passes(r) if r.compliant == true

passes(r) if r.compliance_percentage >= 100

passes(r) if count(r.violations) == 0

passes(r) if r.failed_controls == 0

# counts stay consistent whatever the input: passed + failed = total (this report has no not-applicable bucket)
consistent(r) if {
	r.passed_controls + r.failed_controls == r.total_controls
	r.failed_controls >= 1
	r.failed_controls <= r.total_controls
}

leaf_name(p) := p[count(p) - 1]

names(r, p, problem) if {
	some v in r.violations
	contains(v, "evidence missing")
	contains(v, concat("", [leaf_name(p), " ", problem]))
}

replaced(p, v) := json.patch(fx, [{"op": "replace", "path": p, "value": v}])

removed(p) := json.patch(fx, [{"op": "remove", "path": p}])

opposite(p) := "false" if object.get(fx, p, null) == true

opposite(p) := "true" if object.get(fx, p, null) == false

as_number(p) := 1 if object.get(fx, p, null) == true

as_number(p) := 0 if object.get(fx, p, null) == false

test_fixture_has_the_leaves if {
	count(bool_leaves) >= 100
	count(number_leaves) >= 20
}

# a wrong-typed boolean fails the report and is named
bool_wrong_type_fails(main, s, kind) if {
	every i, p in bool_leaves {
		bool_case_ok(main, i, p, s, kind)
	}
}

bool_case_ok(_, i, _, s, _) if i % shards != s

bool_case_ok(main, i, p, s, kind) if {
	i % shards == s
	bad := bad_value(p, kind)
	r := data[main].main.compliance_report with input as replaced(p, bad)
		with data.cis_ubuntu_20_04.auditd.rules_violations as set()
	not passes(r)
	consistent(r)
	names(r, p, sprintf("is not a boolean (got %s)", [type_name(bad)]))
}

bad_value(p, "own string") := sprintf("%v", [object.get(fx, p, null)])

bad_value(p, "opposite string") := opposite(p)

bad_value(_, "no") := "no"

bad_value(p, "number") := as_number(p)

# a boolean that is null or missing fails the report and is named
bool_absent_fails(main, s) if {
	every i, p in bool_leaves {
		bool_absent_ok(main, i, p, s)
	}
}

bool_absent_ok(_, i, _, s) if i % shards != s

bool_absent_ok(main, i, p, s) if {
	i % shards == s
	r1 := data[main].main.compliance_report with input as replaced(p, null)
		with data.cis_ubuntu_20_04.auditd.rules_violations as set()
	not passes(r1)
	consistent(r1)
	names(r1, p, "not collected")
	r2 := data[main].main.compliance_report with input as removed(p)
		with data.cis_ubuntu_20_04.auditd.rules_violations as set()
	not passes(r2)
	consistent(r2)
	names(r2, p, "not collected")
}

# a number sent as a string, a boolean or null fails the report
number_wrong_type_fails(main) if {
	every p in number_leaves {
		every bad in [sprintf("%v", [object.get(fx, p, null)]), true, null] {
			r := data[main].main.compliance_report with input as replaced(p, bad)
				with data.cis_ubuntu_20_04.auditd.rules_violations as set()
				with data.cis_ubuntu_20_04.auditd.rules_violations as set()
			not passes(r)
			consistent(r)
			some v in r.violations
			contains(v, "evidence missing")
			contains(v, leaf_name(p))
		}
	}
}

test_numbers_wrong_type_fail_cis_ubuntu_20_04 if number_wrong_type_fails("cis_ubuntu_20_04")

test_bool_own_string_fails_cis_ubuntu_20_04_shard_0 if bool_wrong_type_fails("cis_ubuntu_20_04", 0, "own string")

test_bool_opposite_string_fails_cis_ubuntu_20_04_shard_0 if bool_wrong_type_fails("cis_ubuntu_20_04", 0, "opposite string")

test_bool_no_fails_cis_ubuntu_20_04_shard_0 if bool_wrong_type_fails("cis_ubuntu_20_04", 0, "no")

test_bool_number_fails_cis_ubuntu_20_04_shard_0 if bool_wrong_type_fails("cis_ubuntu_20_04", 0, "number")

test_bool_null_or_missing_fails_cis_ubuntu_20_04_shard_0 if bool_absent_fails("cis_ubuntu_20_04", 0)

test_bool_own_string_fails_cis_ubuntu_20_04_shard_1 if bool_wrong_type_fails("cis_ubuntu_20_04", 1, "own string")

test_bool_opposite_string_fails_cis_ubuntu_20_04_shard_1 if bool_wrong_type_fails("cis_ubuntu_20_04", 1, "opposite string")

test_bool_no_fails_cis_ubuntu_20_04_shard_1 if bool_wrong_type_fails("cis_ubuntu_20_04", 1, "no")

test_bool_number_fails_cis_ubuntu_20_04_shard_1 if bool_wrong_type_fails("cis_ubuntu_20_04", 1, "number")

test_bool_null_or_missing_fails_cis_ubuntu_20_04_shard_1 if bool_absent_fails("cis_ubuntu_20_04", 1)

test_numbers_wrong_type_fail_cis_ubuntu_2004 if number_wrong_type_fails("cis_ubuntu_2004")

test_bool_own_string_fails_cis_ubuntu_2004_shard_0 if bool_wrong_type_fails("cis_ubuntu_2004", 0, "own string")

test_bool_opposite_string_fails_cis_ubuntu_2004_shard_0 if bool_wrong_type_fails("cis_ubuntu_2004", 0, "opposite string")

test_bool_no_fails_cis_ubuntu_2004_shard_0 if bool_wrong_type_fails("cis_ubuntu_2004", 0, "no")

test_bool_number_fails_cis_ubuntu_2004_shard_0 if bool_wrong_type_fails("cis_ubuntu_2004", 0, "number")

test_bool_null_or_missing_fails_cis_ubuntu_2004_shard_0 if bool_absent_fails("cis_ubuntu_2004", 0)

test_bool_own_string_fails_cis_ubuntu_2004_shard_1 if bool_wrong_type_fails("cis_ubuntu_2004", 1, "own string")

test_bool_opposite_string_fails_cis_ubuntu_2004_shard_1 if bool_wrong_type_fails("cis_ubuntu_2004", 1, "opposite string")

test_bool_no_fails_cis_ubuntu_2004_shard_1 if bool_wrong_type_fails("cis_ubuntu_2004", 1, "no")

test_bool_number_fails_cis_ubuntu_2004_shard_1 if bool_wrong_type_fails("cis_ubuntu_2004", 1, "number")

test_bool_null_or_missing_fails_cis_ubuntu_2004_shard_1 if bool_absent_fails("cis_ubuntu_2004", 1)

# sections reported per module stay consistent with the roll-up on a mixed input (some facts wrong, most right)
mixed := json.patch(fx, [
	{"op": "replace", "path": ["sudo", "use_pty"], "value": false},
	{"op": "replace", "path": ["cron", "crond_enabled"], "value": "true"},
	{"op": "remove", "path": ["initial_setup", "gdm_installed"]},
	{"op": "replace", "path": ["pam", "pass_max_days"], "value": "365"},
])

test_mixed_input_counts_are_consistent if {
	r := data.cis_ubuntu_20_04.main.compliance_report with input as mixed
	r.compliant == false
	r.failed_controls == 4
	r.passed_controls == r.total_controls - 4
	count(r.violations) == 4
	"CIS 5.3.2: sudo is not configured to use pty (Defaults use_pty not found)" in r.violations
	"CIS 5.1.1: evidence missing — cron.crond_enabled is not a boolean (got string)" in r.violations
	"CIS 1.8.1: evidence missing — initial_setup.gdm_installed not collected" in r.violations
	"CIS 5.5.2: evidence missing — pam.pass_max_days is not a number" in r.violations
}

# "does not apply" is an explicit boolean false on the gate fact: the gated facts are then not required
test_explicit_not_applicable_passes if {
	inp := json.patch(fx, [
		{"op": "replace", "path": ["initial_setup", "gdm_installed"], "value": false},
		{"op": "remove", "path": ["initial_setup", "server_environment"]},
		{"op": "remove", "path": ["initial_setup", "gui_required"]},
		{"op": "remove", "path": ["initial_setup", "gdm_banner_configured"]},
		{"op": "remove", "path": ["initial_setup", "gdm_screen_lock_enabled"]},
		{"op": "remove", "path": ["initial_setup", "gdm_idle_delay"]},
		{"op": "replace", "path": ["require_remote_logging"], "value": false},
		{"op": "remove", "path": ["rsyslog", "remote_logging_configured"]},
		{"op": "replace", "path": ["autofs"], "value": {"installed": false}},
	])
	r := data.cis_ubuntu_20_04.main.compliance_report with input as inp
	r.compliant == true
	count(r.violations) == 0
}

# the same gates inferred from a missing or wrong-typed fact do not pass
test_gate_inferred_from_missing_fact_fails if {
	every p in [["initial_setup", "gdm_installed"], ["require_remote_logging"], ["require_ipv6_disabled"], ["autofs", "installed"], ["ipv6", "disabled"]] {
		every bad in ["false", "no", 0, null] {
			r := data.cis_ubuntu_20_04.main.compliance_report with input as replaced(p, bad)
			not passes(r)
		}
		r2 := data.cis_ubuntu_20_04.main.compliance_report with input as removed(p)
		not passes(r2)
	}
}
