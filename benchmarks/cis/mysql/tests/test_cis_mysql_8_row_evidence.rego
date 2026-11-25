# A user or privilege row that lacks a field a check selects on must be a finding, not skipped
# (`[u | u := users[_]; not contains(u.sql_mode, ...)]` leaves a row without sql_mode out of the list).
package cis.mysql_8_row_evidence_test

import rego.v1

_user := {
	"host": "localhost", "user": "app", "password": "x", "password_strength": "strong", "sql_mode": "STRICT_TRANS_TABLES",
	"roles": ["r1"], "default_roles": ["r1"], "password_lifetime": 90, "ssl_type": "X509", "user_type": "application",
	"privileges": {
		"all_privileges": "N", "file_priv": "N", "process_priv": "N", "super_priv": "N", "shutdown_priv": "N",
		"create_user_priv": "N", "grant_priv": "N", "repl_slave_priv": "N",
	},
}

_input(u) := {"mysql": {
	"users": [u],
	"database_privileges": {"mysql_db": [{"user": "mysql.sys"}]},
	"database_grants": [{"db": "app"}],
	"databases": [{"name": "app"}],
	"user_profiles": [{"content": "x"}],
	"replication": {"users": [{"privileges": {"super_priv": "N", "file_priv": "N", "process_priv": "N"}}]},
}}

_cases := [
	["host", "2.21"], ["user", "2.22"], ["privileges", "5.1"], ["sql_mode", "5.12"], ["password_strength", "5.13"],
	["password", "5.14"], ["roles", "5.17"], ["user_type", "5.18"], ["default_roles", "7.10"],
	["password_lifetime", "7.11"], ["ssl_type", "8.6"],
]

test_complete_rows_have_no_evidence_findings if {
	vs := data.cis.mysql_8.mysql_row_evidence_violations with input as _input(_user)
	count(vs) == 0
}

test_a_user_row_without_a_field_is_a_finding if {
	every c in _cases {
		vs := data.cis.mysql_8.mysql_row_evidence_violations with input as _input(object.remove(_user, [c[0]]))
		some v in vs
		startswith(v, concat("", [c[1], ": evidence missing"]))
	}
}

test_a_privilege_flag_missing_is_a_finding if {
	every flag in ["all_privileges", "file_priv", "super_priv", "repl_slave_priv"] {
		u := object.union(object.remove(_user, ["privileges"]), {"privileges": object.remove(_user.privileges, [flag])})
		vs := data.cis.mysql_8.mysql_row_evidence_violations with input as _input(u)
		some v in vs
		contains(v, sprintf("privileges.%s not collected", [flag]))
	}
}

test_the_finding_reaches_the_report if {
	vs := data.cis.mysql_8.violations with input as _input(object.remove(_user, ["sql_mode"]))
	"5.12: evidence missing — mysql.users[0].sql_mode not collected" in vs
}

test_a_row_without_a_user_name_in_the_mysql_db_check_is_a_finding if {
	i := {"mysql": {"database_privileges": {"mysql_db": [{"host": "%"}]}}}
	vs := data.cis.mysql_8.mysql_row_evidence_violations with input as i
	"1.7: evidence missing — mysql.database_privileges.mysql_db[0].user not collected" in vs
}
