# Copied into benchmarks/cis/windows_server_2022_modular/tests/test_lib.rego by
# tools/cis_generators/gen_windows_server_2022.py -- edit the copy under tools/.
#
# The evaluator's edge cases, on hand-built rows. The generated tests prove every recommendation passes on a
# compliant host and fails when its own facts are broken; these pin the comparisons those tests cannot see.
package cis_windows_server_2022.lib_test

import rego.v1

# a one-row table in place of section 1's, read back through lib.results
status(row) := s if {
	s := data.cis_windows_server_2022.lib.results.T with data.cis_windows_server_2022.account_policies.controls as {"T": row}
}

ms := {"role": "member_server", "level": 2}

reg(op, value) := {"kind": "reg", "profiles": ["L1_DC", "L1_MS"], "path": "HKLM\\X", "name": "V", "op": op, "value": value}

with_value(v) := {"cis_profile": ms, "registry": {"HKLM\\X": {"V": v}}}

test_eq_accepts_a_number_held_as_a_string if {
	status(reg("eq", 1)) == "pass" with input as with_value("1")
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
	row := {"kind": "auditpol", "profiles": ["L1_MS"], "guid": "{g}", "bits": 1}
	status(row) == "pass" with input as {"cis_profile": ms, "audit_policy": {"{g}": 3}}
	status(row) == "fail" with input as {"cis_profile": ms, "audit_policy": {"{g}": 2}}
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
