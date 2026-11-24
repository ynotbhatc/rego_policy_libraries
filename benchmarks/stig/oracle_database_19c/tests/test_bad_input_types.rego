package stig.oracle_database_19c.bad_input_types_test

# Wrong-typed facts never pass (audit 2026-11-24). Oracle reports limits and parameters as text ("3",
# "UNLIMITED"), so a decimal string and a number are both read as numbers; null, booleans, lists and other
# text are not. to_number(null) is 0 and to_number(true) is 1, which used to satisfy "<= 3" and ">= 0".
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
		every bad in [null, true, false, "UNLIMITED", "DEFAULT", "abc", "", ["3"], {"value": 3}] {
			compliant(set(p, bad)) == false
		}
	}
}

test_numeric_value_removed_does_not_pass if {
	every p in numeric_text {
		compliant(json.patch(green, [{"op": "remove", "path": p}])) == false
	}
}

# both shapes a collector can send for a number stay accepted
test_number_and_decimal_string_pass if {
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 3)) == true
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", " 3 ")) == true
	compliant(set("/oracle/parameters/max_idle_time", 15)) == true
	compliant(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", "4")) == false
}

test_profile_limit_null_is_not_set if {
	every bad in [null, true, "DEFAULT", "NULL", "", " "] {
		compliant(set("/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_VERIFY_FUNCTION", bad)) == false
	}
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
	every p in ["/oracle/unauthorized_object_owners", "/oracle/direct_admin_privilege_grantees", "/oracle/unauthorized_db_links"] {
		every bad in ["", {}, null, 0, false] {
			compliant(set(p, bad)) == false
		}
	}
}
