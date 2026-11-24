# Copied into benchmarks/cis/windows_server_2025_modular/tests/test_lib.rego by
# tools/cis_generators/gen_windows_server_2025.py -- edit the copy under tools/.
#
# The evaluator's edge cases, on hand-built rows. The generated tests prove every recommendation passes on a
# compliant host and fails when its own facts are broken; these pin the comparisons those tests cannot see.
package cis_windows_server_2025_tests.lib_test

import rego.v1

# a one-row table in place of section 1's, read back through lib.results
status(row) := s if {
	s := data.cis_windows_server_2025.lib.results.T with data.cis_windows_server_2025.account_policies.controls as {"T": row}
}

ms := {"role": "member_server", "level": 2}

reg(op, value) := {"kind": "reg", "profiles": ["L1_DC", "L1_MS"], "path": "HKLM\\X", "name": "V", "op": op, "value": value}

with_value(v) := {"cis_profile": ms, "registry": {"HKLM\\X": {"V": v}}}

# the findings of the one-row table
findings(row) := v if {
	v := data.cis_windows_server_2025.lib.section_reports.account_policies.violations with data.cis_windows_server_2025.account_policies.controls as {"T": row}
}

sz(op, value) := object.union(reg(op, value), {"vtype": "sz"})

anytype(op, value) := object.union(reg(op, value), {"vtype": "any"})

# A REG_DWORD arrives as a number: the same digits as a string, a boolean or a list are a collector fault, never
# a pass, and the finding names the type.
test_a_dword_row_rejects_a_number_held_as_a_string if {
	status(reg("eq", 1)) == "pass" with input as with_value(1)
	every bad in ["1", " 1 ", true, [1], {"v": 1}] {
		status(reg("eq", 1)) == "fail" with input as with_value(bad)
	}
	every op in ["ge", "le", "le_not0", "ge_or_forever"] {
		status(reg(op, 15)) == "pass" with input as with_value(15)
		status(reg(op, 15)) == "fail" with input as with_value("15")
	}
	status(reg("in", [1, 2])) == "fail" with input as with_value("2")
	status(reg("range", [5, 14])) == "fail" with input as with_value("7")
	status(reg("eq_or_absent", 4)) == "fail" with input as with_value("4")
}

test_a_dword_type_problem_is_named_in_the_finding if {
	msgs := findings(object.union(reg("eq", 1), {"msg": "CIS T"})) with input as with_value("1")
	msgs == ["CIS T -- found: 1 -- evidence: registry.HKLM\\X.V is not a number (got string)"]
	plain := findings(object.union(reg("eq", 1), {"msg": "CIS T"})) with input as with_value(0)
	plain == ["CIS T -- found: 0"]
}

# A REG_SZ holding a number (the row's vtype) arrives as a string: that passes, and a JSON number does not.
test_an_sz_row_reads_the_string_and_rejects_a_number if {
	status(sz("le", 4)) == "pass" with input as with_value("4")
	status(sz("le", 4)) == "pass" with input as with_value(" 0 ")
	status(sz("le", 4)) == "fail" with input as with_value("5")
	status(sz("le", 4)) == "fail" with input as with_value(4)
	status(sz("le", 4)) == "fail" with input as with_value("four")
	status(sz("in", [1, 2, 3])) == "pass" with input as with_value("2")
	status(sz("in", [1, 2, 3])) == "fail" with input as with_value(2)
	msgs := findings(object.union(sz("eq", 0), {"msg": "CIS T"})) with input as with_value(0)
	msgs == ["CIS T -- found: 0 -- evidence: registry.HKLM\\X.V is not a string holding a number (got number)"]
}

# The audit procedure states no type (or both): either representation is read, text is still not a number.
test_an_untyped_row_accepts_either_representation if {
	status(anytype("eq", 1)) == "pass" with input as with_value(1)
	status(anytype("eq", 1)) == "pass" with input as with_value("1")
	status(anytype("eq", 1)) == "fail" with input as with_value("one")
	status(anytype("eq", 1)) == "fail" with input as with_value(true)
}

test_a_reg_all_item_carries_its_own_type if {
	row := {"kind": "reg_all", "profiles": ["L1_DC", "L1_MS"], "items": [["HKLM\\X", "V", "eq", 1], ["HKLM\\X", "W", "eq", 1, "sz"]]}
	status(row) == "pass" with input as {"cis_profile": ms, "registry": {"HKLM\\X": {"V": 1, "W": "1"}}}
	status(row) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\X": {"V": "1", "W": "1"}}}
	status(row) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\X": {"V": 1, "W": 1}}}
}

test_secedit_and_auditpol_numbers_are_numbers if {
	pol := {"kind": "secedit", "profiles": ["L1_DC", "L1_MS"], "key": "MinimumPasswordAge", "op": "ge", "value": 1}
	status(pol) == "pass" with input as {"cis_profile": ms, "secedit": {"system_access": {"MinimumPasswordAge": 1}}}
	status(pol) == "fail" with input as {"cis_profile": ms, "secedit": {"system_access": {"MinimumPasswordAge": "1"}}}
	aud := {"kind": "auditpol", "profiles": ["L1_DC", "L1_MS"], "guid": "{0cce923f-69ae-11d9-bed3-505054503031}", "bits": 3}
	status(aud) == "pass" with input as {"cis_profile": ms, "audit_policy": {"{0cce923f-69ae-11d9-bed3-505054503031}": 3}}
	status(aud) == "fail" with input as {"cis_profile": ms, "audit_policy": {"{0cce923f-69ae-11d9-bed3-505054503031}": "3"}}
}

# A right that is present must be a list of SID strings: text or null in its place is not "nobody holds it".
test_a_right_that_is_not_a_list_never_passes if {
	none := {"kind": "rights", "profiles": ["L1_DC", "L1_MS"], "privilege": "SeX", "mode": "none", "sids": []}
	only := object.union(none, {"mode": "only", "sids": ["S-1-5-32-544"]})
	status(none) == "pass" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeOther": ["S-1-1-0"]}}}
	every bad in ["S-1-1-0", null, 0, [1], {"a": "S-1-1-0"}] {
		status(none) == "fail" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeOther": [], "SeX": bad}}}
		status(only) == "fail" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeOther": [], "SeX": bad}}}
	}
}

test_eq_compares_strings_without_case if {
	status(reg("eq", "Block")) == "pass" with input as with_value("block")
}

test_le_not0_rejects_zero_and_negative if {
	status(reg("le_not0", 365)) == "fail" with input as with_value(0)
	status(reg("le_not0", 365)) == "fail" with input as with_value(-1)
	status(reg("le_not0", 365)) == "pass" with input as with_value(30)
	status(reg("le_not0", 365)) == "pass" with input as with_value(365)
	status(reg("le_not0", 365)) == "fail" with input as with_value(366)
}

test_in_accepts_every_listed_value if {
	status(reg("in", [1, 2])) == "pass" with input as with_value(1)
	status(reg("in", [1, 2])) == "pass" with input as with_value(2)
	status(reg("in", [1, 2])) == "fail" with input as with_value(0)
}

test_range_bounds_are_inclusive if {
	status(reg("range", [5, 14])) == "fail" with input as with_value(4)
	status(reg("range", [5, 14])) == "pass" with input as with_value(5)
	status(reg("range", [5, 14])) == "pass" with input as with_value(14)
	status(reg("range", [5, 14])) == "fail" with input as with_value(15)
}

test_rename_sees_through_secedit_quotes if {
	row := {"kind": "secedit", "profiles": ["L1_MS"], "key": "NewAdministratorName", "op": "ne", "value": "Administrator"}
	status(row) == "fail" with input as {"cis_profile": ms, "secedit": {"system_access": {"NewAdministratorName": "\"Administrator\""}}}
	status(row) == "pass" with input as {"cis_profile": ms, "secedit": {"system_access": {"NewAdministratorName": "\"ops-admin\""}}}
}

test_rights_without_privilege_rights_are_not_assessed if {
	row := {"kind": "rights", "profiles": ["L1_MS"], "privilege": "SeTcbPrivilege", "mode": "none", "sids": []}
	status(row) == "not_assessed" with input as {"cis_profile": ms, "secedit": {"system_access": {"PasswordHistorySize": 24}}}
}

test_service_hives_alone_are_not_assessed if {
	row := {"kind": "ureg", "profiles": ["L1_MS"], "path": "Software\\P", "name": "V", "op": "eq", "value": 1}
	hives := {".DEFAULT": {}, "S-1-5-18": {}, "S-1-5-19": {}, "S-1-5-21-1-2-3-1001_Classes": {}}
	status(row) == "not_assessed" with input as {"cis_profile": ms, "registry_users": hives}
}

test_service_hives_are_ignored_beside_a_user_hive if {
	row := {"kind": "ureg", "profiles": ["L1_MS"], "path": "Software\\P", "name": "V", "op": "eq", "value": 1}
	hives := {"S-1-5-18": {}, "S-1-5-21-1-2-3-1001": {"Software\\P": {"V": 1}}}
	status(row) == "pass" with input as {"cis_profile": ms, "registry_users": hives}
}

test_ge_or_forever_accepts_zero_and_minus_one if {
	row := {"kind": "secedit", "profiles": ["L1_MS"], "key": "LockoutDuration", "op": "ge_or_forever", "value": 15}
	status(row) == "pass" with input as {"cis_profile": ms, "secedit": {"system_access": {"LockoutDuration": -1}}}
	status(row) == "pass" with input as {"cis_profile": ms, "secedit": {"system_access": {"LockoutDuration": 0}}}
	status(row) == "fail" with input as {"cis_profile": ms, "secedit": {"system_access": {"LockoutDuration": 10}}}
}

test_a_missing_value_fails if {
	status(reg("eq", 1)) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\Other": {"V": 1}}}
}

# a service that is not installed has no key: compliant for an "or Not Installed" row, never for a plain one
test_eq_or_absent_accepts_the_value_or_no_value if {
	status(reg("eq_or_absent", 4)) == "pass" with input as with_value(4)
	status(reg("eq_or_absent", 4)) == "pass" with input as {"cis_profile": ms, "registry": {"HKLM\\Other": {"V": 1}}}
	status(reg("eq_or_absent", 4)) == "fail" with input as with_value(2)
	status(reg("eq_or_absent", 4)) == "not_assessed" with input as {"cis_profile": ms, "secedit": {"system_access": {"A": 1}}}
}

test_registry_not_collected_is_not_assessed if {
	status(reg("eq", 1)) == "not_assessed" with input as {"cis_profile": ms, "secedit": {"system_access": {"A": 1}}}
}

test_absent_accepts_missing_or_empty if {
	row := {"kind": "reg_absent", "profiles": ["L1_MS"], "path": "HKLM\\X", "name": "V"}
	status(row) == "pass" with input as {"cis_profile": ms, "registry": {"HKLM\\Y": {}}}
	status(row) == "pass" with input as with_value([])
	status(row) == "fail" with input as with_value(0)
}

test_rights_only_allows_a_narrower_assignment if {
	row := {"kind": "rights", "profiles": ["L1_MS"], "privilege": "SeX", "mode": "only", "sids": ["S-1-5-32-544", "S-1-5-83-0"]}
	status(row) == "pass" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeX": ["*S-1-5-32-544"]}}}
	status(row) == "fail" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeX": ["*S-1-5-32-544", "*S-1-5-32-551"]}}}
}

test_rights_include_needs_every_named_principal if {
	row := {"kind": "rights", "profiles": ["L1_MS"], "privilege": "SeDeny", "mode": "include", "sids": ["S-1-5-32-546"]}
	status(row) == "pass" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeDeny": ["*S-1-5-32-546", "*S-1-5-113"]}}}
	status(row) == "fail" with input as {"cis_profile": ms, "secedit": {"privilege_rights": {"SeOther": ["*S-1-5-32-546"]}}}
}

test_auditpol_setting_is_a_minimum if {
	row := {"kind": "auditpol", "profiles": ["L1_MS"], "guid": "{0cce923f-69ae-11d9-bed3-505054503030}", "bits": 1}
	status(row) == "pass" with input as {"cis_profile": ms, "audit_policy": {"{0cce923f-69ae-11d9-bed3-505054503030}": 3}}
	status(row) == "fail" with input as {"cis_profile": ms, "audit_policy": {"{0cce923f-69ae-11d9-bed3-505054503030}": 2}}
}

test_every_user_hive_must_comply if {
	row := {"kind": "ureg", "profiles": ["L1_MS"], "path": "Software\\P", "name": "V", "op": "eq", "value": 1}
	users := {"S-1-5-21-1": {"Software\\P": {"V": 1}}, "S-1-5-21-2": {"Software\\P": {"V": 0}}}
	status(row) == "fail" with input as {"cis_profile": ms, "registry_users": users}
}

test_role_specific_row_is_not_assessed_without_a_role if {
	row := {"kind": "reg", "profiles": ["L1_MS"], "path": "HKLM\\X", "name": "V", "op": "eq", "value": 1}
	status(row) == "not_assessed" with input as {"registry": {"HKLM\\X": {"V": 1}}}
}

test_row_for_both_roles_is_assessed_without_a_role if {
	status(reg("eq", 1)) == "pass" with input as {"registry": {"HKLM\\X": {"V": 1}}}
}

test_level_2_row_is_out_of_scope_at_level_1 if {
	row := {"kind": "reg", "profiles": ["L2_MS"], "path": "HKLM\\X", "name": "V", "op": "eq", "value": 1}
	status(row) == "not_applicable" with input as {"cis_profile": {"role": "member_server", "level": 1}, "registry": {"HKLM\\X": {"V": 1}}}
}

# Only `true` opts a tier in and only `false` (or no selector) leaves it out. A selector of another type decides
# nothing: the tier's rows are in scope and not assessed, so a mistyped selector cannot shrink the assessment.
test_a_mistyped_tier_selector_is_not_assessed if {
	row := {"kind": "reg", "profiles": ["NG_MS"], "path": "HKLM\\X", "name": "V", "op": "eq", "value": 1, "msg": "CIS T"}
	reg1 := {"HKLM\\X": {"V": 1}}
	status(row) == "not_applicable" with input as {"cis_profile": ms, "registry": reg1}
	status(row) == "not_applicable" with input as {"cis_profile": object.union(ms, {"next_generation": false}), "registry": reg1}
	status(row) == "pass" with input as {"cis_profile": object.union(ms, {"next_generation": true}), "registry": reg1}
	every bad in ["true", "false", "yes", 1, 0, null, [true]] {
		status(row) == "not_assessed" with input as {"cis_profile": object.union(ms, {"next_generation": bad}), "registry": reg1}
	}
	status(row) == "not_assessed" with input as {"cis_profile": "level 2", "registry": reg1}
	msgs := findings(row) with input as {"cis_profile": object.union(ms, {"next_generation": "true"}), "registry": reg1}
	count(msgs) == 1
	startswith(msgs[0], "CIS T -- ")
	contains(msgs[0], "input.cis_profile.next_generation is not a boolean (got string), so the profile cannot place this recommendation")
	contains(msgs[0], "counted as failed")
}

# ---------------------------------------------------------------------------------------------------------------
# Data-driven, on the all-pass fixture and the benchmark's own rows: every number the rows compare is sent as the
# other JSON type (90 -> "90"; a number held as REG_SZ, "4" -> 4), then as null. Every row that reads a number must
# fail; none may pass. The exceptions are stated by the rows themselves: a row whose audit procedure accepts either
# registry type ("vtype": "any"), and, for null, a service row that is compliant when the value does not exist.
# ---------------------------------------------------------------------------------------------------------------

all_pass := data.cis_windows_server_2025_tests.fixtures_test.fixture_ms

retyped(v) := sprintf("%v", [v]) if is_number(v)

retyped(v) := to_number(v) if {
	is_string(v)
	regex.match(`^-?[0-9]+$`, v)
}

retyped(v) := v if {
	not is_number(v)
	not regex.match(`^-?[0-9]+$`, sprintf("%v", [v]))
}

nulled(v) := null if retyped(v) != v

nulled(v) := v if retyped(v) == v

# the fixture with every scalar fact passed through f ("retyped" or "nulled"); lists (user rights, MULTI_SZ) stay
facts_with(f) := object.union(all_pass, {
	"registry": {path: {name: changed(f, v) | some name, v in values} | some path, values in all_pass.registry},
	"registry_users": {sid: {path: {name: changed(f, v) | some name, v in values} | some path, values in hive} | some sid, hive in all_pass.registry_users},
	"audit_policy": {guid: changed(f, v) | some guid, v in all_pass.audit_policy},
	"secedit": {"system_access": {key: changed(f, v) | some key, v in all_pass.secedit.system_access}},
})

changed("retyped", v) := retyped(v)

changed("nulled", v) := nulled(v)

numeric_op(op, _) if op in {"ge", "ge_or_forever", "le", "le_not0", "range", "in"}

numeric_op(op, want) if {
	op in {"eq", "eq_or_absent", "ne"}
	is_number(want)
}

# rows that compare a number of a stated type, by id -> the comparisons they make
typed_rows[cid] := ops if {
	some t in data.cis_windows_server_2025.lib._tables
	some cid, c in t
	c.kind in {"reg", "ureg", "secedit"}
	numeric_op(c.op, c.value)
	object.get(c, "vtype", "dword") != "any"
	ops := {c.op}
}

typed_rows[cid] := {"bits"} if {
	some t in data.cis_windows_server_2025.lib._tables
	some cid, c in t
	c.kind == "auditpol"
}

typed_rows[cid] := ops if {
	some t in data.cis_windows_server_2025.lib._tables
	some cid, c in t
	c.kind == "reg_all"
	ops := {i[2] | some i in c.items; numeric_op(i[2], i[3]); array.slice(i, 4, 5) != ["any"]}
	count(ops) > 0
}

test_fixture_every_number_of_the_wrong_type_fails_its_row if {
	before := data.cis_windows_server_2025.lib.results with input as all_pass
	after := data.cis_windows_server_2025.lib.results with input as facts_with("retyped")
	checked := {cid | some cid, _ in typed_rows; before[cid] == "pass"}
	count(checked) > 150
	every cid in checked {
		after[cid] == "fail"
	}
	r := data.cis_windows_server_2025.main.compliance_report with input as facts_with("retyped")
	r.compliant == false
	r.failed_controls >= count(checked)
}

test_fixture_every_number_sent_as_null_fails_its_row if {
	before := data.cis_windows_server_2025.lib.results with input as all_pass
	after := data.cis_windows_server_2025.lib.results with input as facts_with("nulled")
	checked := {cid | some cid, ops in typed_rows; before[cid] == "pass"; not "eq_or_absent" in ops}
	count(checked) > 150
	every cid in checked {
		after[cid] == "fail"
	}
}

test_fixture_passes_and_empty_input_fails if {
	ok := data.cis_windows_server_2025.main.compliance_report with input as all_pass
	ok.compliant == true
	empty := data.cis_windows_server_2025.main.compliance_report with input as {}
	empty.compliant == false
}
