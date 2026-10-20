package cis.sql_server_2025_test

import rego.v1

import data.cis.sql_server_2025 as b
import data.cis.sql_server_2025.main as m

green := {
	 "sql": {
	  "attest": {
	   "latest_cumulative_update_installed": true,
	   "single_function_member_server": true,
	   "unnecessary_protocols_disabled": true,
	   "mssql_service_account_not_admin": true,
	   "sqlagent_service_account_not_admin": true,
	   "fulltext_service_account_not_admin": true,
	   "sysadmin_membership_reviewed": true,
	   "control_server_grants_reviewed": true,
	   "external_rest_endpoint_access_reviewed": true,
	   "must_change_reviewed": true,
	   "input_sanitization_reviewed": true,
	   "browser_service_reviewed": true
	  },
	  "configurations": {
	   "ad hoc distributed queries": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "clr enabled": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "cross db ownership chaining": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "database mail xps": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "ole automation procedures": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "remote access": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "remote admin connections": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "scan for startup procs": {
	    "value_configured": 0,
	    "value_in_use": 0
	   },
	   "clr strict security": {
	    "value_configured": 1,
	    "value_in_use": 1
	   },
	   "default trace enabled": {
	    "value_configured": 1,
	    "value_in_use": 1
	   }
	  },
	  "is_clustered": false,
	  "databases_trustworthy_on": [],
	  "tcp_port_1433_count": 0,
	  "hide_instance": 1,
	  "sa_account_disabled": true,
	  "sa_login_name": "dbadmin_x",
	  "contained_databases_auto_close_on": [],
	  "logins_named_sa": [],
	  "is_integrated_security_only": 1,
	  "guest_connect_grants": [],
	  "orphaned_users": [],
	  "contained_db_sql_auth_users": [],
	  "public_role_extra_permissions": [],
	  "builtin_logins": [],
	  "local_group_logins": [],
	  "msdb_public_proxy_grants": [],
	  "msdb_admin_role_members": [],
	  "sysadmin_logins_without_expiration_check": [],
	  "sql_logins_without_check_policy": [],
	  "num_error_logs": 12,
	  "login_audit_level": "failure",
	  "server_audit_actions": [
	   {
	    "audit_action_name": "AUDIT_CHANGE_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   },
	   {
	    "audit_action_name": "FAILED_LOGIN_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   },
	   {
	    "audit_action_name": "SUCCESSFUL_LOGIN_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   },
	   {
	    "audit_action_name": "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   },
	   {
	    "audit_action_name": "SERVER_ROLE_MEMBER_CHANGE_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   },
	   {
	    "audit_action_name": "SERVER_OPERATION_GROUP",
	    "audit_enabled": true,
	    "specification_enabled": true,
	    "audited_result": "SUCCESS AND FAILURE"
	   }
	  ],
	  "has_contained_databases": false,
	  "user_assemblies": [
	   {
	    "database": "AppDB",
	    "name": "SafeLib",
	    "permission_set_desc": "SAFE_ACCESS"
	   }
	  ],
	  "symmetric_keys": [
	   {
	    "database": "AppDB",
	    "name": "AppKey",
	    "algorithm_desc": "AES_256"
	   }
	  ],
	  "asymmetric_keys": [
	   {
	    "database": "AppDB",
	    "name": "AppAsym",
	    "key_length": 2048
	   }
	  ],
	  "unencrypted_backups": [],
	  "connection_encrypt_options": [
	   "TRUE"
	  ],
	  "databases_without_tde": []
	 }
	}

test_green_instance_is_compliant if {
	r := b.compliance_report with input as green
	r.compliant == true
	count(r.violations) == 0
	r.total_controls == 49
	r.standard_total == 49
}

test_main_alias_matches if {
	r := m.compliance_report with input as green
	r.compliant == true
	r.facts_supplied == true
	m.compliant with input as green
}

test_fail_closed_on_empty_input if {
	r := b.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
	m.compliance_report.facts_supplied == false with input as {}
}

test_every_recommendation_fires_without_facts if {
	v := b.violations with input as {"sql": {}}
	ids := {id | some msg in v; id := split(msg, ":")[0]}
	count(ids) == 49
}

test_recommendations_cover_the_workbook if {
	count(b.recommendations) == 49
	count([r | some r in b.recommendations; r.assessment == "Manual"]) == 12
	count([r | some r in b.recommendations; r.level == 2]) == 3
}

test_profile_scopes if {
	count(b.in_scope) == 49 with input as green
	count(b.in_scope) == 46 with input as object.union(green, {"cis_profile": {"level": 1}})
	count(b.in_scope) == 30 with input as object.union(green, {"cis_profile": {"platform": "aws_rds", "level": 1}})
}

test_out_of_scope_recommendation_is_silent if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/databases_without_tde"}])
	v := b.violations with input as object.union(bad, {"cis_profile": {"level": 1}})
	count([msg | some msg in v; startswith(msg, "7.5:")]) == 0
}

test_rds_allowances_only_apply_on_rds if {
	g := json.patch(green, [{"op": "replace", "path": "/sql/guest_connect_grants", "value": [{"database": "rdsadmin"}]}, {"op": "replace", "path": "/sql/builtin_logins", "value": [{"name": "[BUILTIN]\\Administrators"}]}, {"op": "replace", "path": "/sql/sysadmin_logins_without_expiration_check", "value": [{"name": "rdsa"}]}])
	b.compliant with input as object.union(g, {"cis_profile": {"platform": "aws_rds", "level": 1}})
	v := b.violations with input as g
	count([msg | some msg in v; regex.match(`^(3\.2|3\.9|4\.2):`, msg)]) == 3
}

test_2_2_not_applicable_when_clr_strict_security_on if {
	ok := json.patch(green, [{"op": "add", "path": "/sql/configurations/clr enabled", "value": {"value_configured": 1, "value_in_use": 1}}])
	b.compliant with input as ok
}

test_2_7_not_applicable_on_cluster if {
	ok := json.patch(green, [{"op": "replace", "path": "/sql/is_clustered", "value": true}, {"op": "remove", "path": "/sql/configurations/remote admin connections"}])
	b.compliant with input as ok
}

test_config_names_match_case_insensitively if {
	ok := json.patch(green, [{"op": "remove", "path": "/sql/configurations/database mail xps"}, {"op": "add", "path": "/sql/configurations/Database Mail XPs", "value": {"value_configured": "0", "value_in_use": "0"}}])
	b.compliant with input as ok
}

test_5_1_unlimited_error_logs_passes if {
	ok := json.patch(green, [{"op": "replace", "path": "/sql/num_error_logs", "value": -1}])
	b.compliant with input as ok
}

test_5_3_all_logins_passes if {
	ok := json.patch(green, [{"op": "replace", "path": "/sql/login_audit_level", "value": "ALL"}])
	b.compliant with input as ok
}

test_5_4_contained_groups_satisfy_contained_requirement if {
	rows := array.concat(green.sql.server_audit_actions, [{"audit_action_name": g, "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"} | some g in ["SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP", "FAILED_DATABASE_AUTHENTICATION_GROUP"]])
	ok := json.patch(green, [{"op": "replace", "path": "/sql/has_contained_databases", "value": true}, {"op": "replace", "path": "/sql/server_audit_actions", "value": rows}])
	b.compliant with input as ok
}

# 1.1 (Manual)
test_1_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.1:")]) == 0
}

test_1_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/latest_cumulative_update_installed", "value": false}])
	"1.1: Ensure Latest SQL Server Cumulative and Security Updates are Installed (manual review not attested)" in b.violations with input as bad
}

test_1_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/latest_cumulative_update_installed"}])
	"1.1: Ensure Latest SQL Server Cumulative and Security Updates are Installed (manual review not attested)" in b.violations with input as bad
}

# 1.2 (Manual)
test_1_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.2:")]) == 0
}

test_1_2_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/single_function_member_server", "value": false}])
	"1.2: Ensure Single-Function Member Servers are Used (manual review not attested)" in b.violations with input as bad
}

test_1_2_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/single_function_member_server"}])
	"1.2: Ensure Single-Function Member Servers are Used (manual review not attested)" in b.violations with input as bad
}

# 2.1 (Automated)
test_2_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.1:")]) == 0
}

test_2_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/ad hoc distributed queries/value_in_use", "value": 1}])
	"2.1: Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_1_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/ad hoc distributed queries/value_configured", "value": 1}])
	"2.1: Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/ad hoc distributed queries"}])
	"2.1: evidence missing — sql.configurations['ad hoc distributed queries'] not collected" in b.violations with input as bad
}

# 2.2 (Automated)
test_2_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.2:")]) == 0
}

test_2_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/clr strict security", "value": {"value_configured": 0, "value_in_use": 0}}, {"op": "replace", "path": "/sql/configurations/clr enabled", "value": {"value_configured": 1, "value_in_use": 1}}])
	"2.2: Ensure 'CLR Enabled' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_2_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/clr strict security", "value": {"value_configured": 0, "value_in_use": 0}}, {"op": "remove", "path": "/sql/configurations/clr enabled"}])
	"2.2: evidence missing — sql.configurations['clr enabled'] not collected" in b.violations with input as bad
}

# 2.3 (Automated)
test_2_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.3:")]) == 0
}

test_2_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/cross db ownership chaining/value_in_use", "value": 1}])
	"2.3: Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_3_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/cross db ownership chaining/value_configured", "value": 1}])
	"2.3: Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/cross db ownership chaining"}])
	"2.3: evidence missing — sql.configurations['cross db ownership chaining'] not collected" in b.violations with input as bad
}

# 2.4 (Automated)
test_2_4_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.4:")]) == 0
}

test_2_4_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/database mail xps/value_in_use", "value": 1}])
	"2.4: Ensure 'Database Mail XPs' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_4_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/database mail xps/value_configured", "value": 1}])
	"2.4: Ensure 'Database Mail XPs' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/database mail xps"}])
	"2.4: evidence missing — sql.configurations['database mail xps'] not collected" in b.violations with input as bad
}

# 2.5 (Automated)
test_2_5_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.5:")]) == 0
}

test_2_5_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/ole automation procedures/value_in_use", "value": 1}])
	"2.5: Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_5_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/ole automation procedures/value_configured", "value": 1}])
	"2.5: Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/ole automation procedures"}])
	"2.5: evidence missing — sql.configurations['ole automation procedures'] not collected" in b.violations with input as bad
}

# 2.6 (Automated)
test_2_6_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.6:")]) == 0
}

test_2_6_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/remote access/value_in_use", "value": 1}])
	"2.6: Ensure 'Remote Access' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_6_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/remote access/value_configured", "value": 1}])
	"2.6: Ensure 'Remote Access' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/remote access"}])
	"2.6: evidence missing — sql.configurations['remote access'] not collected" in b.violations with input as bad
}

# 2.7 (Automated)
test_2_7_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.7:")]) == 0
}

test_2_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/remote admin connections", "value": {"value_configured": 1, "value_in_use": 0}}])
	"2.7: Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/is_clustered"}])
	"2.7: evidence missing — sql.is_clustered / sql.configurations['remote admin connections'] not collected" in b.violations with input as bad
}

# 2.8 (Automated)
test_2_8_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.8:")]) == 0
}

test_2_8_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/scan for startup procs/value_in_use", "value": 1}])
	"2.8: Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_8_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/scan for startup procs/value_configured", "value": 1}])
	"2.8: Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'" in b.violations with input as bad
}

test_2_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/scan for startup procs"}])
	"2.8: evidence missing — sql.configurations['scan for startup procs'] not collected" in b.violations with input as bad
}

# 2.9 (Automated)
test_2_9_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.9:")]) == 0
}

test_2_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/databases_trustworthy_on", "value": [{"database": "AppDB"}]}])
	"2.9: Ensure 'Trustworthy' Database Property is set to 'Off'" in b.violations with input as bad
}

test_2_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/databases_trustworthy_on"}])
	"2.9: evidence missing — sql.databases_trustworthy_on not collected" in b.violations with input as bad
}

# 2.10 (Manual)
test_2_10_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.10:")]) == 0
}

test_2_10_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/unnecessary_protocols_disabled", "value": false}])
	"2.10: Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (manual review not attested)" in b.violations with input as bad
}

test_2_10_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/unnecessary_protocols_disabled"}])
	"2.10: Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (manual review not attested)" in b.violations with input as bad
}

# 2.11 (Automated)
test_2_11_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.11:")]) == 0
}

test_2_11_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/tcp_port_1433_count", "value": 1}])
	"2.11: Ensure SQL Server is configured to use non-standard ports" in b.violations with input as bad
}

test_2_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/tcp_port_1433_count"}])
	"2.11: evidence missing — sql.tcp_port_1433_count not collected" in b.violations with input as bad
}

# 2.12 (Automated)
test_2_12_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.12:")]) == 0
}

test_2_12_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/hide_instance", "value": 0}])
	"2.12: Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances" in b.violations with input as bad
}

test_2_12_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/hide_instance"}])
	"2.12: evidence missing — sql.hide_instance not collected" in b.violations with input as bad
}

# 2.13 (Automated)
test_2_13_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.13:")]) == 0
}

test_2_13_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/sa_account_disabled", "value": false}])
	"2.13: Ensure the 'sa' Login Account is set to 'Disabled'" in b.violations with input as bad
}

test_2_13_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/sa_account_disabled"}])
	"2.13: evidence missing — sql.sa_account_disabled not collected" in b.violations with input as bad
}

# 2.14 (Automated)
test_2_14_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.14:")]) == 0
}

test_2_14_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/sa_login_name", "value": "sa"}])
	"2.14: Ensure the 'sa' Login Account has been renamed" in b.violations with input as bad
}

test_2_14_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/sa_login_name", "value": "SA"}])
	"2.14: Ensure the 'sa' Login Account has been renamed" in b.violations with input as bad
}

test_2_14_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/sa_login_name"}])
	"2.14: evidence missing — sql.sa_login_name not collected" in b.violations with input as bad
}

# 2.15 (Automated)
test_2_15_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.15:")]) == 0
}

test_2_15_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/contained_databases_auto_close_on", "value": [{"database": "ContainedDB"}]}])
	"2.15: Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases" in b.violations with input as bad
}

test_2_15_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/contained_databases_auto_close_on"}])
	"2.15: evidence missing — sql.contained_databases_auto_close_on not collected" in b.violations with input as bad
}

# 2.16 (Automated)
test_2_16_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.16:")]) == 0
}

test_2_16_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/logins_named_sa", "value": [{"principal_id": 270, "name": "sa"}]}])
	"2.16: Ensure no login exists with the name 'sa'" in b.violations with input as bad
}

test_2_16_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/logins_named_sa"}])
	"2.16: evidence missing — sql.logins_named_sa not collected" in b.violations with input as bad
}

# 2.17 (Automated)
test_2_17_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.17:")]) == 0
}

test_2_17_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/clr strict security/value_in_use", "value": 0}])
	"2.17: Ensure 'clr strict security' Server Configuration Option is set to '1'" in b.violations with input as bad
}

test_2_17_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/clr strict security/value_configured", "value": 0}])
	"2.17: Ensure 'clr strict security' Server Configuration Option is set to '1'" in b.violations with input as bad
}

test_2_17_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/clr strict security"}])
	"2.17: evidence missing — sql.configurations['clr strict security'] not collected" in b.violations with input as bad
}

# 3.1 (Automated)
test_3_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.1:")]) == 0
}

test_3_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/is_integrated_security_only", "value": 0}])
	"3.1: Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'" in b.violations with input as bad
}

test_3_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/is_integrated_security_only"}])
	"3.1: evidence missing — sql.is_integrated_security_only not collected" in b.violations with input as bad
}

# 3.2 (Automated)
test_3_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.2:")]) == 0
}

test_3_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/guest_connect_grants", "value": [{"database": "AppDB"}]}])
	"3.2: Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases" in b.violations with input as bad
}

test_3_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/guest_connect_grants"}])
	"3.2: evidence missing — sql.guest_connect_grants not collected" in b.violations with input as bad
}

# 3.3 (Automated)
test_3_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.3:")]) == 0
}

test_3_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/orphaned_users", "value": [{"database": "AppDB", "name": "old_user"}]}])
	"3.3: Ensure 'Orphaned Users' are Dropped From SQL Server Databases" in b.violations with input as bad
}

test_3_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/orphaned_users"}])
	"3.3: evidence missing — sql.orphaned_users not collected" in b.violations with input as bad
}

# 3.4 (Automated)
test_3_4_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.4:")]) == 0
}

test_3_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/contained_db_sql_auth_users", "value": [{"database": "ContainedDB", "name": "app_sql_user"}]}])
	"3.4: Ensure SQL Authentication is not used in contained databases" in b.violations with input as bad
}

test_3_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/contained_db_sql_auth_users"}])
	"3.4: evidence missing — sql.contained_db_sql_auth_users not collected" in b.violations with input as bad
}

# 3.5 (Manual)
test_3_5_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.5:")]) == 0
}

test_3_5_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/mssql_service_account_not_admin", "value": false}])
	"3.5: Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

test_3_5_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/mssql_service_account_not_admin"}])
	"3.5: Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

# 3.6 (Manual)
test_3_6_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.6:")]) == 0
}

test_3_6_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/sqlagent_service_account_not_admin", "value": false}])
	"3.6: Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

test_3_6_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/sqlagent_service_account_not_admin"}])
	"3.6: Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

# 3.7 (Manual)
test_3_7_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.7:")]) == 0
}

test_3_7_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/fulltext_service_account_not_admin", "value": false}])
	"3.7: Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

test_3_7_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/fulltext_service_account_not_admin"}])
	"3.7: Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (manual review not attested)" in b.violations with input as bad
}

# 3.8 (Automated)
test_3_8_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.8:")]) == 0
}

test_3_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/public_role_extra_permissions", "value": [{"permission_name": "VIEW SERVER STATE", "class_desc": "SERVER"}]}])
	"3.8: Ensure only the default permissions specified by Microsoft are granted to the public server role" in b.violations with input as bad
}

test_3_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/public_role_extra_permissions"}])
	"3.8: evidence missing — sql.public_role_extra_permissions not collected" in b.violations with input as bad
}

# 3.9 (Automated)
test_3_9_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.9:")]) == 0
}

test_3_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/builtin_logins", "value": [{"name": "BUILTIN\\Users", "permission_name": "CONNECT SQL"}]}])
	"3.9: Ensure Windows BUILTIN groups are not SQL Logins" in b.violations with input as bad
}

test_3_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/builtin_logins"}])
	"3.9: evidence missing — sql.builtin_logins not collected" in b.violations with input as bad
}

# 3.10 (Automated)
test_3_10_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.10:")]) == 0
}

test_3_10_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/local_group_logins", "value": [{"name": "HOST01\\SQLAdmins", "permission_name": "CONNECT SQL"}]}])
	"3.10: Ensure Windows local groups are not SQL Logins" in b.violations with input as bad
}

test_3_10_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/local_group_logins"}])
	"3.10: evidence missing — sql.local_group_logins not collected" in b.violations with input as bad
}

# 3.11 (Automated)
test_3_11_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.11:")]) == 0
}

test_3_11_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/msdb_public_proxy_grants", "value": [{"proxyname": "ssis_proxy"}]}])
	"3.11: Ensure the public role in the msdb database is not granted access to SQL Agent proxies" in b.violations with input as bad
}

test_3_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/msdb_public_proxy_grants"}])
	"3.11: evidence missing — sql.msdb_public_proxy_grants not collected" in b.violations with input as bad
}

# 3.12 (Manual)
test_3_12_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.12:")]) == 0
}

test_3_12_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/sysadmin_membership_reviewed", "value": false}])
	"3.12: Ensure the 'SYSADMIN' Role is Limited to Administrative or Built-in Accounts (manual review not attested)" in b.violations with input as bad
}

test_3_12_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/sysadmin_membership_reviewed"}])
	"3.12: Ensure the 'SYSADMIN' Role is Limited to Administrative or Built-in Accounts (manual review not attested)" in b.violations with input as bad
}

# 3.13 (Automated)
test_3_13_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.13:")]) == 0
}

test_3_13_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/msdb_admin_role_members", "value": [{"role": "db_owner", "member": "app_user"}]}])
	"3.13: Ensure no admin role membership in MSDB database" in b.violations with input as bad
}

test_3_13_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/msdb_admin_role_members"}])
	"3.13: evidence missing — sql.msdb_admin_role_members not collected" in b.violations with input as bad
}

# 3.14 (Manual)
test_3_14_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.14:")]) == 0
}

test_3_14_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/control_server_grants_reviewed", "value": false}])
	"3.14: Ensure 'Control Server' permission is not granted (manual review not attested)" in b.violations with input as bad
}

test_3_14_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/control_server_grants_reviewed"}])
	"3.14: Ensure 'Control Server' permission is not granted (manual review not attested)" in b.violations with input as bad
}

# 3.15 (Manual)
test_3_15_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "3.15:")]) == 0
}

test_3_15_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/external_rest_endpoint_access_reviewed", "value": false}])
	"3.15: Ensure access to 'sp_invoke_external_rest_endpoint' is limited to trusted accounts only (manual review not attested)" in b.violations with input as bad
}

test_3_15_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/external_rest_endpoint_access_reviewed"}])
	"3.15: Ensure access to 'sp_invoke_external_rest_endpoint' is limited to trusted accounts only (manual review not attested)" in b.violations with input as bad
}

# 4.1 (Manual)
test_4_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "4.1:")]) == 0
}

test_4_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/must_change_reviewed", "value": false}])
	"4.1: Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (manual review not attested)" in b.violations with input as bad
}

test_4_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/must_change_reviewed"}])
	"4.1: Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (manual review not attested)" in b.violations with input as bad
}

# 4.2 (Automated)
test_4_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "4.2:")]) == 0
}

test_4_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/sysadmin_logins_without_expiration_check", "value": [{"name": "app_admin"}]}])
	"4.2: Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role" in b.violations with input as bad
}

test_4_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/sysadmin_logins_without_expiration_check"}])
	"4.2: evidence missing — sql.sysadmin_logins_without_expiration_check not collected" in b.violations with input as bad
}

# 4.3 (Automated)
test_4_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "4.3:")]) == 0
}

test_4_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/sql_logins_without_check_policy", "value": [{"name": "app_user", "is_disabled": 0}]}])
	"4.3: Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins" in b.violations with input as bad
}

test_4_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/sql_logins_without_check_policy"}])
	"4.3: evidence missing — sql.sql_logins_without_check_policy not collected" in b.violations with input as bad
}

# 5.1 (Automated)
test_5_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "5.1:")]) == 0
}

test_5_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/num_error_logs", "value": 6}])
	"5.1: Ensure 'Maximum number of error log files' is set to greater than or equal to '12'" in b.violations with input as bad
}

test_5_1_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/num_error_logs", "value": 0}])
	"5.1: Ensure 'Maximum number of error log files' is set to greater than or equal to '12'" in b.violations with input as bad
}

test_5_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/num_error_logs"}])
	"5.1: evidence missing — sql.num_error_logs not collected" in b.violations with input as bad
}

# 5.2 (Automated)
test_5_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "5.2:")]) == 0
}

test_5_2_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/default trace enabled/value_in_use", "value": 0}])
	"5.2: Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'" in b.violations with input as bad
}

test_5_2_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/configurations/default trace enabled/value_configured", "value": 0}])
	"5.2: Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'" in b.violations with input as bad
}

test_5_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/configurations/default trace enabled"}])
	"5.2: evidence missing — sql.configurations['default trace enabled'] not collected" in b.violations with input as bad
}

# 5.3 (Automated)
test_5_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "5.3:")]) == 0
}

test_5_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/login_audit_level", "value": "none"}])
	"5.3: Ensure 'Login Auditing' is set to 'failed logins'" in b.violations with input as bad
}

test_5_3_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/login_audit_level", "value": "success"}])
	"5.3: Ensure 'Login Auditing' is set to 'failed logins'" in b.violations with input as bad
}

test_5_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/login_audit_level"}])
	"5.3: evidence missing — sql.login_audit_level not collected" in b.violations with input as bad
}

# 5.4 (Automated)
test_5_4_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "5.4:")]) == 0
}

test_5_4_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/server_audit_actions", "value": [{"audit_action_name": "AUDIT_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SUCCESSFUL_LOGIN_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "DATABASE_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_OPERATION_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}]}])
	"5.4: Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'" in b.violations with input as bad
}

test_5_4_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/server_audit_actions", "value": [{"audit_action_name": "AUDIT_CHANGE_GROUP", "audit_enabled": false, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "FAILED_LOGIN_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SUCCESSFUL_LOGIN_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "DATABASE_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_OPERATION_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}]}])
	"5.4: Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'" in b.violations with input as bad
}

test_5_4_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/server_audit_actions", "value": [{"audit_action_name": "AUDIT_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "FAILED_LOGIN_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SUCCESSFUL_LOGIN_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS"}, {"audit_action_name": "DATABASE_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_ROLE_MEMBER_CHANGE_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}, {"audit_action_name": "SERVER_OPERATION_GROUP", "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}]}])
	"5.4: Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'" in b.violations with input as bad
}

test_5_4_fail_4 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/has_contained_databases", "value": true}])
	"5.4: Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'" in b.violations with input as bad
}

test_5_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/server_audit_actions"}])
	"5.4: evidence missing — sql.server_audit_actions / sql.has_contained_databases not collected" in b.violations with input as bad
}

# 6.1 (Manual)
test_6_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "6.1:")]) == 0
}

test_6_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/input_sanitization_reviewed", "value": false}])
	"6.1: Ensure Database and Application User Input is Sanitized (manual review not attested)" in b.violations with input as bad
}

test_6_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/input_sanitization_reviewed"}])
	"6.1: Ensure Database and Application User Input is Sanitized (manual review not attested)" in b.violations with input as bad
}

# 6.2 (Automated)
test_6_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "6.2:")]) == 0
}

test_6_2_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/user_assemblies", "value": [{"database": "AppDB", "name": "SafeLib", "permission_set_desc": "UNSAFE_ACCESS"}]}])
	"6.2: Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies" in b.violations with input as bad
}

test_6_2_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/user_assemblies", "value": [{"database": "AppDB", "name": "ExtLib", "permission_set_desc": "EXTERNAL_ACCESS"}]}])
	"6.2: Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies" in b.violations with input as bad
}

test_6_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/user_assemblies"}])
	"6.2: evidence missing — sql.user_assemblies not collected" in b.violations with input as bad
}

# 7.1 (Automated)
test_7_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "7.1:")]) == 0
}

test_7_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/symmetric_keys", "value": [{"database": "AppDB", "name": "OldKey", "algorithm_desc": "TRIPLE_DES"}]}])
	"7.1: Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases" in b.violations with input as bad
}

test_7_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/symmetric_keys"}])
	"7.1: evidence missing — sql.symmetric_keys not collected" in b.violations with input as bad
}

# 7.2 (Automated)
test_7_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "7.2:")]) == 0
}

test_7_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/asymmetric_keys", "value": [{"database": "AppDB", "name": "WeakAsym", "key_length": 1024}]}])
	"7.2: Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases" in b.violations with input as bad
}

test_7_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/asymmetric_keys"}])
	"7.2: evidence missing — sql.asymmetric_keys not collected" in b.violations with input as bad
}

# 7.3 (Automated)
test_7_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "7.3:")]) == 0
}

test_7_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/unencrypted_backups", "value": [{"database_name": "AppDB", "backup_finish_date": "2026-10-01T00:00:00"}]}])
	"7.3: Ensure Database Backups are Encrypted" in b.violations with input as bad
}

test_7_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/unencrypted_backups"}])
	"7.3: evidence missing — sql.unencrypted_backups not collected" in b.violations with input as bad
}

# 7.4 (Automated)
test_7_4_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "7.4:")]) == 0
}

test_7_4_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/connection_encrypt_options", "value": ["TRUE", "FALSE"]}])
	"7.4: Ensure Network Encryption is Configured and Enabled" in b.violations with input as bad
}

test_7_4_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/connection_encrypt_options", "value": []}])
	"7.4: Ensure Network Encryption is Configured and Enabled" in b.violations with input as bad
}

test_7_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/connection_encrypt_options"}])
	"7.4: evidence missing — sql.connection_encrypt_options not collected" in b.violations with input as bad
}

# 7.5 (Automated)
test_7_5_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "7.5:")]) == 0
}

test_7_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/databases_without_tde", "value": [{"database_id": 5, "name": "AppDB"}]}])
	"7.5: Ensure Databases are Encrypted with TDE" in b.violations with input as bad
}

test_7_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/databases_without_tde"}])
	"7.5: evidence missing — sql.databases_without_tde not collected" in b.violations with input as bad
}

# 8.1 (Manual)
test_8_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "8.1:")]) == 0
}

test_8_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/sql/attest/browser_service_reviewed", "value": false}])
	"8.1: Ensure 'SQL Server Browser Service' is configured correctly (manual review not attested)" in b.violations with input as bad
}

test_8_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/sql/attest/browser_service_reviewed"}])
	"8.1: Ensure 'SQL Server Browser Service' is configured correctly (manual review not attested)" in b.violations with input as bad
}
