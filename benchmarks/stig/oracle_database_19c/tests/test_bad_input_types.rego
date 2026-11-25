package stig.oracle_database_19c.bad_input_types_test

# Wrong-typed facts never pass (audit 2026-11-24). Oracle reports limits and parameters as text ("3",
# "UNLIMITED"); the collector converts a number to a JSON number and leaves a word (UNLIMITED, DEFAULT) as the
# word. Numeric limits are JSON numbers only (owner ruling 2026-11-24): "3" and " 3 " are not numbers, nor are
# null, booleans, lists or other text. to_number(null) is 0 and to_number(true) is 1, which used to satisfy
# "<= 3" and ">= 0".
# count() of a string is its length, which used to satisfy "three control files" and "no rows returned".

import rego.v1

green := data.stig.oracle_database_19c_test.green_fixture

compliant(inp) := c if {
	r := data.stig.oracle_database_19c.main.compliance_report with input as inp
	c := r.compliant
}

set(path, v) := json.patch(green, [{"op": "add", "path": path, "value": v}])

test_green_fixture_is_compliant if compliant(green) == true

numeric_text := [
	"/oracle/profiles/ORA_STIG_PROFILE/SESSIONS_PER_USER",
	"/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS",
	"/oracle/profiles/ORA_STIG_PROFILE/INACTIVE_ACCOUNT_TIME",
	"/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME",
	"/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME",
	"/oracle/parameters/max_idle_time",
]

test_numeric_value_of_the_wrong_type_does_not_pass if {
	every p in numeric_text {
		every bad in [null, true, false, "UNLIMITED", "DEFAULT", "abc", "", "3", " 3 ", "3\n", "0", ["3"], {"value": 3}] {
			compliant(set(p, bad)) == false
		}
	}
}

test_numeric_value_removed_does_not_pass if {
	every p in numeric_text {
		compliant(json.patch(green, [{"op": "remove", "path": p}])) == false
	}
}

# a JSON number is read, and the comparison is still made; the same value as text is not a number
test_number_passes_and_the_comparison_is_made if {
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 3)) == true
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 2)) == true
	compliant(set("/oracle/parameters/max_idle_time", 15)) == true
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 4)) == false
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", "3")) == false
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", "UNLIMITED")) == false
}

test_profile_limit_null_is_not_set if {
	every bad in [null, true, "DEFAULT", "NULL", "", " ", 7, 0, ["ORA12C_STIG_VERIFY_FUNCTION"]] {
		compliant(set("/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_VERIFY_FUNCTION", bad)) == false
	}
}

# O19C-00-008600: the instance name must not contain the version number. `not contains(null, "19")` is true
# (the call is undefined), so a null, numeric or empty instance name used to read as "does not contain it".
test_instance_name_and_version_must_be_text if {
	every bad in [null, true, 7, "", " ", ["PRODDB"], "ORCL19"] {
		"O19C-00-008600" in open_ids(set("/oracle/instance_name", bad))
	}
	every bad in [null, true, 19, "", "nineteen", ["19.0.0.0.0"]] {
		"O19C-00-008600" in open_ids(set("/oracle/version", bad))
	}
	"O19C-00-008600" in open_ids(json.patch(green, [{"op": "remove", "path": "/oracle/instance_name"}]))
	"O19C-00-008600" in open_ids(json.patch(green, [{"op": "remove", "path": "/oracle/version"}]))
	compliant(set("/oracle/instance_name", "PRODDB")) == true
}

test_control_files_must_be_a_list_of_names if {
	every bad in ["abc", "/u01/a.ctl,/u02/b.ctl,/u03/c.ctl", [null, null, null], ["", "", ""], [1, 2, 3], {"a": 1, "b": 2, "c": 3}, null] {
		compliant(set("/oracle/control_files", bad)) == false
	}
}

test_redo_log_groups_must_be_lists_of_member_names if {
	every bad in ["abc", null, [{"members": "ab"}, {"members": "ab"}, {"members": "ab"}], [{"members": [null, null]}, {"members": [null, null]}, {"members": [null, null]}]] {
		compliant(set("/oracle/redo_log_groups", bad)) == false
	}
}

# with standard auditing off, only a real list of enabled unified audit policies counts
test_audit_enabled_needs_a_real_policy_list if {
	off := set("/oracle/parameters/audit_trail", "NONE")
	every bad in ["ORA_SECURECONFIG", [null], [""], [7], {"ORA_SECURECONFIG": true}, null] {
		compliant(json.patch(off, [{"op": "add", "path": "/oracle/unified_audit_policies_enabled", "value": bad}])) == false
	}
	every bad in ["", " ", null, 7, true] {
		no_unified := json.patch(green, [{"op": "remove", "path": "/oracle/unified_audit_policies_enabled"}, {"op": "add", "path": "/oracle/parameters/audit_trail", "value": bad}])
		compliant(no_unified) == false
	}
}

# "the query returns no rows" is an empty array; an empty string or object is not that evidence
test_empty_query_result_must_be_an_array if {
	every p in empty_query_results {
		every bad in ["", {}, null, 0, false, "none"] {
			compliant(set(p, bad)) == false
		}
	}
}

# every "no rows returned" fact of the module (all 15), not a sample: O19C-00-014800 was left without the
# array test in the first pass
empty_query_results := [
	"/oracle/unauthorized_object_owners",
	"/oracle/direct_admin_privilege_grantees",
	"/oracle/unauthorized_db_links",
	"/oracle/grantable_privileges_non_dba",
	"/oracle/unauthorized_admin_option_system_privileges",
	"/oracle/public_system_privileges",
	"/oracle/unauthorized_admin_option_roles",
	"/oracle/unauthorized_public_object_privileges",
	"/oracle/public_granted_roles",
	"/oracle/unauthorized_default_admin_roles",
	"/oracle/users_with_default_password",
	"/oracle/sample_schemas_present",
	"/oracle/unused_components_installed",
	"/oracle/unused_integrated_options_enabled",
	"/oracle/users_with_10g_password_verifier",
]

test_empty_query_result_removed_or_with_rows_does_not_pass if {
	every p in empty_query_results {
		compliant(json.patch(green, [{"op": "remove", "path": p}])) == false
		compliant(set(p, ["ROW"])) == false
	}
}

test_every_empty_query_result_is_in_the_fixture if {
	every p in empty_query_results {
		green.oracle[trim_prefix(p, "/oracle/")] == []
	}
	count(empty_query_results) == count([k | some k, v in green.oracle; v == []])
}

# O19C-00-001800 / O19C-00-002000 accept either auditing mode: standard auditing (audit_trail other than NONE)
# or unified auditing (at least one enabled policy). With standard auditing on, the unified list may be absent
# or null; with neither, both rules are Open.
open_ids(inp) := {f.stig_id |
	r := data.stig.oracle_database_19c.main.compliance_report with input as inp
	some f in r.open_findings
}

test_standard_auditing_alone_satisfies_the_audit_rules if {
	compliant(json.patch(green, [{"op": "remove", "path": "/oracle/unified_audit_policies_enabled"}])) == true
	compliant(set("/oracle/unified_audit_policies_enabled", null)) == true
}

test_unified_auditing_alone_satisfies_the_audit_rules if {
	compliant(set("/oracle/parameters/audit_trail", "NONE")) == true
	compliant(json.patch(green, [{"op": "remove", "path": "/oracle/parameters/audit_trail"}])) == true
}

test_neither_auditing_mode_opens_both_audit_rules if {
	every trail in ["NONE", "none", "", null] {
		every unified in [null, [], "ORA_SECURECONFIG", [null], [""], true, 1] {
			inp := json.patch(green, [
				{"op": "add", "path": "/oracle/parameters/audit_trail", "value": trail},
				{"op": "add", "path": "/oracle/unified_audit_policies_enabled", "value": unified},
			])
			open_ids(inp) == {"O19C-00-001800", "O19C-00-002000"}
		}
	}
	both_gone := json.patch(green, [
		{"op": "remove", "path": "/oracle/parameters/audit_trail"},
		{"op": "remove", "path": "/oracle/unified_audit_policies_enabled"},
	])
	open_ids(both_gone) == {"O19C-00-001800", "O19C-00-002000"}
}
