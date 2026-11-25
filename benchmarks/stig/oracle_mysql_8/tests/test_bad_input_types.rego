package stig.oracle_mysql_8.bad_input_types_test

# Wrong-typed facts never pass (audit 2026-11-24, round 2). MySQL returns every system variable as text
# (SHOW VARIABLES, performance_schema.global_variables.VARIABLE_VALUE), so a numeric variable is read from a
# decimal string or a number; null, booleans, lists and other text are not numbers. to_number(null) is 0 and
# to_number(true) is 1, which used to satisfy "> 0". count() of a string is its length and count("") is 0,
# which used to satisfy "an audit filter is defined" and "no rows returned".

import rego.v1

green := data.stig.oracle_mysql_8_test.green_fixture

compliant(inp) := c if {
	r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
	c := r.compliant
}

open_ids(inp) := {f.stig_id |
	r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
	some f in r.open_findings
}

set(path, v) := json.patch(green, [{"op": "add", "path": path, "value": v}])

drop(path) := json.patch(green, [{"op": "remove", "path": path}])

test_green_fixture_is_compliant if {
	compliant(green) == true
	r := data.stig.oracle_mysql_8.main.compliance_report with input as green
	r.failed_controls == 0
	r.passed_controls == r.total_controls
}

test_empty_input_fails if {
	every inp in [{}, {"mysql": {}}, {"mysql": null}] {
		r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
		r.compliant == false
		r.failed_controls == r.total_controls
	}
}

# variable -> the rule that reads it as a number
numeric_variables := {
	"/mysql/variables/max_user_connections": "MYS8-00-000200",
	"/mysql/variables/validate_password.length": "MYS8-00-005000",
	"/mysql/variables/audit_log_rotate_on_size": "MYS8-00-009600",
}

test_numeric_variable_of_the_wrong_type_opens_its_rule if {
	every p, id in numeric_variables {
		every bad in [null, true, false, "", " ", "abc", "ON", "1e3", "0x20", ["50"], {"value": 50}] {
			id in open_ids(set(p, bad))
		}
		id in open_ids(drop(p))
	}
}

# both shapes of a number stay accepted, and the comparison is still made
test_number_and_decimal_string_pass if {
	compliant(set("/mysql/variables/max_user_connections", 50)) == true
	compliant(set("/mysql/variables/max_user_connections", " 50 ")) == true
	compliant(set("/mysql/variables/validate_password.length", 15)) == true
	"MYS8-00-000200" in open_ids(set("/mysql/variables/max_user_connections", "0"))
	"MYS8-00-000200" in open_ids(set("/mysql/variables/max_user_connections", 0))
	"MYS8-00-005000" in open_ids(set("/mysql/variables/validate_password.length", "14"))
	"MYS8-00-009600" in open_ids(set("/mysql/variables/audit_log_rotate_on_size", "0"))
}

# "the query returns no rows" is an empty array; "", {}, null, 0 and false are not that evidence
empty_query_results := [
	"/mysql/unauthorized_audit_admins",
	"/mysql/sample_schemas_present",
	"/mysql/unused_plugins_installed",
	"/mysql/unused_integrated_components_enabled",
	"/mysql/unauthorized_ddl_grantees",
	"/mysql/unauthorized_create_routine_grantees",
	"/mysql/unauthorized_definer_routines",
]

test_empty_query_result_must_be_an_empty_array if {
	every p in empty_query_results {
		every bad in ["", {}, null, 0, false, "none", ["row"]] {
			compliant(set(p, bad)) == false
		}
		compliant(drop(p)) == false
	}
}

test_every_empty_query_result_is_in_the_fixture if {
	count(empty_query_results) == count([k | some k, v in green.mysql; v == []])
}

# the audit rules need a real list of filter names: "log_all" (a string of length 7) is not a list
test_audit_filters_must_be_a_list_of_names if {
	every bad in ["log_all", "", [], [null], [""], [7], {"log_all": true}, null, true, 1] {
		ids := open_ids(set("/mysql/audit/filters", bad))
		"MYS8-00-000300" in ids
		"MYS8-00-004600" in ids
	}
	"MYS8-00-000300" in open_ids(drop("/mysql/audit/filters"))
}

test_users_must_be_a_list_of_rows if {
	every bad in ["caching_sha2_password", "", [], {}, null, true, 1, [null], ["app"], [{"user": "app"}], [{"user": "app", "plugin": null}], [{"user": "app", "plugin": "mysql_native_password"}]] {
		"MYS8-00-005100" in open_ids(set("/mysql/users", bad))
	}
	"MYS8-00-005100" in open_ids(drop("/mysql/users"))
}

# every boolean of the fixture: its string forms, null, 0/1 and removal fail the module
bool_paths := [p |
	walk(green, [path, v])
	is_boolean(v)
	p := concat("", [sprintf("/%v", [k]) | some k in path])
]

test_fixture_has_the_expected_booleans if count(bool_paths) == 39

test_boolean_of_the_wrong_type_does_not_pass if {
	every p in bool_paths {
		every bad in ["true", "false", "yes", "no", null, 0, 1] {
			compliant(set(p, bad)) == false
		}
		compliant(drop(p)) == false
	}
}

# text facts: status and variable values are strings; null, booleans and numbers are not ACTIVE / ON
text_facts := [
	"/mysql/plugins/audit_log",
	"/mysql/plugins/validate_password",
	"/mysql/variables/validate_password.policy",
	"/mysql/variables/require_secure_transport",
	"/mysql/variables/ssl_fips_mode",
]

test_text_fact_of_the_wrong_type_does_not_pass if {
	every p in text_facts {
		every bad in [null, true, 1, "", ["ON"], {"v": "ON"}] {
			compliant(set(p, bad)) == false
		}
		compliant(drop(p)) == false
	}
}
