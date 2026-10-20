package cis.oracle_26ai_test

import rego.v1

import data.cis.oracle_26ai as b

green := {
	 "oracle": {
	  "patches": {
	   "latest_cpu_applied": true
	  },
	  "listener": {
	   "extproc_configured": false
	  },
	  "sqlnet": {
	   "SQLNET.ALLOWED_LOGON_VERSION_CLIENT": "12a",
	   "SQLNET.ALLOWED_LOGON_VERSION_SERVER": "12a",
	   "SQLNET.ENCRYPTION_CLIENT": "REQUIRED",
	   "SQLNET.ENCRYPTION_SERVER": "REQUIRED",
	   "SQLNET.ENCRYPTION_TYPES_CLIENT": "AES256",
	   "SQLNET.ENCRYPTION_TYPES_SERVER": "AES256",
	   "SQLNET.CRYPTO_CHECKSUM_CLIENT": "REQUIRED",
	   "SQLNET.CRYPTO_CHECKSUM_SERVER": "REQUIRED",
	   "SSL_CERT_REVOCATION": "REQUIRED",
	   "ACCEPT_MD5_CERTS": "FALSE"
	  },
	  "parameters": {
	   "background_core_dump": "PARTIAL",
	   "shadow_core_dump": "PARTIAL",
	   "mle_prog_languages": "OFF",
	   "allow_group_access_to_sga": "FALSE",
	   "os_roles": "FALSE",
	   "remote_os_roles": "FALSE",
	   "sec_max_failed_login_attempts": "3",
	   "sec_protocol_error_further_action": "(DROP,3)",
	   "sec_protocol_error_trace_action": "LOG",
	   "sec_return_server_release_banner": "FALSE",
	   "remote_login_passwordfile": "NONE",
	   "remote_listener": "",
	   "resource_limit": "TRUE"
	  },
	  "attest": {
	   "underscore_parameters_reviewed": true,
	   "password_verify_function_meets_cis": true,
	   "ras_users_reviewed": true,
	   "schema_privileges_reviewed": true,
	   "column_privileges_reviewed": true,
	   "proxy_user_privileges_reviewed": true,
	   "custom_java_privileges_reviewed": true,
	   "directory_object_access_reviewed": true,
	   "directory_object_privileges_reviewed": true,
	   "external_table_preprocessors_reviewed": true,
	   "external_tables_reviewed": true
	  },
	  "profiles": {
	   "ORA_STIG_PROFILE": {
	    "FAILED_LOGIN_ATTEMPTS": "3",
	    "PASSWORD_LOCK_TIME": "1",
	    "PASSWORD_LIFE_TIME": "60",
	    "PASSWORD_GRACE_TIME": "5",
	    "PASSWORD_REUSE_MAX": "UNLIMITED",
	    "PASSWORD_VERIFY_FUNCTION": "ORA12C_STIG_VERIFY_FUNCTION",
	    "PASSWORD_ROLLOVER_TIME": "0",
	    "INACTIVE_ACCOUNT_TIME": "35"
	   }
	  },
	  "users_with_default_password": [],
	  "custom_oracle_maintained_users": [],
	  "users_with_old_password_versions": [],
	  "password_file_format": "12.2",
	  "pwfile_users_not_on_all_instances": [],
	  "public_db_links": [],
	  "db_links_with_legacy_password_encryption": [],
	  "audit": {
	   "unaudited_system_actions": [],
	   "enabled_options": [
	    "EXPORT",
	    "LOGOFF",
	    "LOGON"
	   ],
	   "audited_packages": [
	    "DBMS_AW",
	    "DBMS_CRYPTO",
	    "DBMS_FGA",
	    "DBMS_JAVA_TEST",
	    "DBMS_JOB",
	    "DBMS_LOGMNR",
	    "DBMS_NETWORK_ACL_ADMIN",
	    "DBMS_REDACT",
	    "DBMS_REDEFINITION",
	    "DBMS_RLS",
	    "DBMS_SCHEDULER",
	    "DBMS_SQL_TRANSLATOR",
	    "DBMS_SYS_SQL",
	    "DBMS_TSDP_MANAGE",
	    "DBMS_TSDP_PROTECT",
	    "DBMS_XMLGEN",
	    "DBMS_XMLSTORE",
	    "OWA_UTIL"
	   ],
	   "all_actions_audited_users": [
	    "SYS",
	    "SYSBACKUP",
	    "SYSDG",
	    "SYSKM",
	    "SYSRAC",
	    "PUBLIC"
	   ]
	  },
	  "grants": {
	   "sys_privs": [],
	   "role_privs": [],
	   "tab_privs": []
	  },
	  "authorized_grantees": [
	   "DBA_TEAM"
	  ],
	  "listener_ora": {
	   "ADMIN_RESTRICTIONS_LISTENER": "ON"
	  }
	 }
	}

test_green_database_is_compliant if {
	r := b.compliance_report with input as green
	r.compliant == true
	count(r.violations) == 0
	r.total_controls == 94
}

test_fail_closed_on_empty_input if {
	r := b.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_every_recommendation_fires_without_facts if {
	v := b.violations with input as {"oracle": {}}
	ids := {id | some m in v; id := split(m, ":")[0]}
	count(ids) == 94
}

test_recommendations_cover_the_workbook if {
	count(b.recommendations) == 94
	count([r | some r in b.recommendations; r.assessment == "Manual"]) == 13
	count([r | some r in b.recommendations; "Level 1 - RDBMS On Windows Server Host OS" in r.profiles]) == 16
}

test_authorized_dba_grant_is_not_a_finding if {
	ok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "DBA_TEAM", "granted_role": "DBA", "oracle_maintained": false}]}])
	b.compliant with input as ok
}

test_oracle_maintained_grant_is_not_a_finding if {
	ok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "SYS", "granted_role": "DBA", "oracle_maintained": "Y"}]}])
	b.compliant with input as ok
}

test_grant_row_without_oracle_maintained_flag_is_a_finding if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DBA"}]}])
	"6.2.1: Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_3_3_unlimited_grace_fails if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME", "value": "UNLIMITED"}])
	"3.3: Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'" in b.violations with input as bad
}

test_3_3_exactly_365_days_passes if {
	ok := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME", "value": "360"}])
	b.compliant with input as ok
}

# 1.1 (Manual)
test_1_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "1.1:")]) == 0
}

test_1_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/patches/latest_cpu_applied", "value": false}])
	"1.1: Ensure That Appropriate Version/Patches For Oracle Software Are Installed" in b.violations with input as bad
}

test_1_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/patches/latest_cpu_applied"}])
	"1.1: evidence missing — oracle.patches.latest_cpu_applied not collected" in b.violations with input as bad
}

# 2.1.1 (Automated)
test_2_1_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.1.1:")]) == 0
}

test_2_1_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/listener/extproc_configured", "value": true}])
	"2.1.1: Ensure 'extproc' Is Not Present In 'listener.ora'" in b.violations with input as bad
}

test_2_1_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/listener/extproc_configured"}])
	"2.1.1: evidence missing — oracle.listener.extproc_configured not collected" in b.violations with input as bad
}

# 2.1.2 (Automated)
test_2_1_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.1.2:")]) == 0
}

test_2_1_2_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/listener_ora/ACCEPT_MD5_CERTS", "value": "TRUE"}])
	"2.1.2: Ensure 'ACCEPT_MD5_CERTS' Is Configured Correctly" in b.violations with input as bad
}

test_2_1_2_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/listener_ora", "value": {}}])
	"2.1.2: evidence missing — oracle.listener_ora not collected" in b.violations with input as bad
}

# 2.1.3 (Automated)
test_2_1_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.1.3:")]) == 0
}

test_2_1_3_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/listener_ora/ACCEPT_SHA1_CERTS", "value": "TRUE"}])
	"2.1.3: Ensure 'ACCEPT_SHA1_CERTS' Is Configured Correctly" in b.violations with input as bad
}

test_2_1_3_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/listener_ora", "value": {}}])
	"2.1.3: evidence missing — oracle.listener_ora not collected" in b.violations with input as bad
}

# 2.1.4 (Automated)
test_2_1_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.1.4:")]) == 0
}

test_2_1_4_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/listener_ora/ALLOWED_WEAK_CERT_ALGORITHMS", "value": "TRUE"}])
	"2.1.4: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS’ Is NOT Set." in b.violations with input as bad
}

test_2_1_4_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/listener_ora", "value": {}}])
	"2.1.4: evidence missing — oracle.listener_ora not collected" in b.violations with input as bad
}

# 2.2.1 (Automated)
test_2_2_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.1:")]) == 0
}

test_2_2_1_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/sqlnet/ACCEPT_MD5_CERTS", "value": "TRUE"}])
	"2.2.1: Ensure 'ACCEPT_MD5_CERTS' Is NOT SET" in b.violations with input as bad
}

test_2_2_1_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.1: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.2 (Automated)
test_2_2_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.2:")]) == 0
}

test_2_2_2_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/sqlnet/ACCEPT_SHA1_CERTS", "value": "TRUE"}])
	"2.2.2: Ensure 'ACCEPT_SHA1_CERTS' Is NOT Set" in b.violations with input as bad
}

test_2_2_2_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.2: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.3 (Automated)
test_2_2_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.3:")]) == 0
}

test_2_2_3_fail if {
	bad := json.patch(green, [{"op": "add", "path": "/oracle/sqlnet/ALLOWED_WEAK_CERT_ALGORITHMS", "value": "TRUE"}])
	"2.2.3: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS' Is NOT Set" in b.violations with input as bad
}

test_2_2_3_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.3: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.4 (Automated)
test_2_2_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.4:")]) == 0
}

test_2_2_4_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ALLOWED_LOGON_VERSION_CLIENT", "value": "BOGUS"}])
	"2.2.4: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_CLIENT' Is Set To 12a" in b.violations with input as bad
}

test_2_2_4_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ALLOWED_LOGON_VERSION_CLIENT"}])
	"2.2.4: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_CLIENT' Is Set To 12a" in b.violations with input as bad
}

test_2_2_4_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.4: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.5 (Automated)
test_2_2_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.5:")]) == 0
}

test_2_2_5_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ALLOWED_LOGON_VERSION_SERVER", "value": "BOGUS"}])
	"2.2.5: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_SERVER' Is Set To 12a" in b.violations with input as bad
}

test_2_2_5_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ALLOWED_LOGON_VERSION_SERVER"}])
	"2.2.5: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_SERVER' Is Set To 12a" in b.violations with input as bad
}

test_2_2_5_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.5: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.6 (Automated)
test_2_2_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.6:")]) == 0
}

test_2_2_6_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_CLIENT", "value": "BOGUS"}])
	"2.2.6: Ensure 'SQLNET.ENCRYPTION_CLIENT Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_6_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_CLIENT"}])
	"2.2.6: Ensure 'SQLNET.ENCRYPTION_CLIENT Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_6_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.6: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.7 (Automated)
test_2_2_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.7:")]) == 0
}

test_2_2_7_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_SERVER", "value": "BOGUS"}])
	"2.2.7: Ensure 'SQLNET.ENCRYPTION_SERVER' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_7_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_SERVER"}])
	"2.2.7: Ensure 'SQLNET.ENCRYPTION_SERVER' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_7_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.7: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.8 (Automated)
test_2_2_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.8:")]) == 0
}

test_2_2_8_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_TYPES_CLIENT", "value": "BOGUS"}])
	"2.2.8: Ensure 'SQLNET.ENCRYPTION_TYPES_CLIENT' Is Set To 'AES256'" in b.violations with input as bad
}

test_2_2_8_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_TYPES_CLIENT"}])
	"2.2.8: Ensure 'SQLNET.ENCRYPTION_TYPES_CLIENT' Is Set To 'AES256'" in b.violations with input as bad
}

test_2_2_8_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.8: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.9 (Manual)
test_2_2_9_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.9:")]) == 0
}

test_2_2_9_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_TYPES_SERVER", "value": "BOGUS"}])
	"2.2.9: Ensure 'SQLNET.ENCRYPTION_TYPES_SERVER' Is Set To AES256" in b.violations with input as bad
}

test_2_2_9_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.ENCRYPTION_TYPES_SERVER"}])
	"2.2.9: Ensure 'SQLNET.ENCRYPTION_TYPES_SERVER' Is Set To AES256" in b.violations with input as bad
}

test_2_2_9_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.9: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.10 (Automated)
test_2_2_10_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.10:")]) == 0
}

test_2_2_10_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.CRYPTO_CHECKSUM_CLIENT", "value": "BOGUS"}])
	"2.2.10: Ensure 'SQLNET.CRYPTO_CHECKSUM_CLIENT' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_10_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.CRYPTO_CHECKSUM_CLIENT"}])
	"2.2.10: Ensure 'SQLNET.CRYPTO_CHECKSUM_CLIENT' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_10_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.10: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.11 (Automated)
test_2_2_11_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.11:")]) == 0
}

test_2_2_11_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SQLNET.CRYPTO_CHECKSUM_SERVER", "value": "BOGUS"}])
	"2.2.11: Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_11_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SQLNET.CRYPTO_CHECKSUM_SERVER"}])
	"2.2.11: Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_11_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.11: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.2.12 (Automated)
test_2_2_12_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.2.12:")]) == 0
}

test_2_2_12_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet/SSL_CERT_REVOCATION", "value": "BOGUS"}])
	"2.2.12: Ensure 'SSL_CERT_REVOCATION' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_12_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/sqlnet/SSL_CERT_REVOCATION"}])
	"2.2.12: Ensure 'SSL_CERT_REVOCATION' Is Set To 'REQUIRED'" in b.violations with input as bad
}

test_2_2_12_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/sqlnet", "value": {}}])
	"2.2.12: evidence missing — oracle.sqlnet not collected" in b.violations with input as bad
}

# 2.3.1 (Automated)
test_2_3_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.1:")]) == 0
}

test_2_3_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/background_core_dump", "value": "FULL"}])
	"2.3.1: Ensure 'BACKGROUND_CORE_DUMP' Is Not Set To 'Full'" in b.violations with input as bad
}

test_2_3_1_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters", "value": {}}])
	"2.3.1: evidence missing — oracle.parameters not collected" in b.violations with input as bad
}

# 2.3.2 (Automated)
test_2_3_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.2:")]) == 0
}

test_2_3_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/shadow_core_dump", "value": "FULL"}])
	"2.3.2: Ensure 'SHADOW_CORE_DUMP' Is Not Set To 'Full'" in b.violations with input as bad
}

test_2_3_2_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters", "value": {}}])
	"2.3.2: evidence missing — oracle.parameters not collected" in b.violations with input as bad
}

# 2.3.3 (Automated)
test_2_3_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.3:")]) == 0
}

test_2_3_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/mle_prog_languages", "value": "BOGUS"}])
	"2.3.3: Ensure 'MLE_PROG_LANGUAGES' Is Set To 'OFF'" in b.violations with input as bad
}

test_2_3_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/mle_prog_languages"}])
	"2.3.3: evidence missing — oracle.parameters.mle_prog_languages not collected" in b.violations with input as bad
}

# 2.3.4 (Automated)
test_2_3_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.4:")]) == 0
}

test_2_3_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/allow_group_access_to_sga", "value": "TRUE"}])
	"2.3.4: Ensure 'ALLOW_GROUP_ACCESS_TO_SGA' Is Set To `FALSE`" in b.violations with input as bad
}

test_2_3_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/allow_group_access_to_sga"}])
	"2.3.4: evidence missing — oracle.parameters.allow_group_access_to_sga not collected" in b.violations with input as bad
}

# 2.3.5 (Manual)
test_2_3_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.5:")]) == 0
}

test_2_3_5_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/underscore_parameters_reviewed", "value": false}])
	"2.3.5: Review Undocumented (Underscore) Parameters Not Set To 'DEFAULT' Values (manual review not attested)" in b.violations with input as bad
}

test_2_3_5_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/underscore_parameters_reviewed"}])
	"2.3.5: Review Undocumented (Underscore) Parameters Not Set To 'DEFAULT' Values (manual review not attested)" in b.violations with input as bad
}

# 2.3.6 (Automated)
test_2_3_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.6:")]) == 0
}

test_2_3_6_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/os_roles", "value": "TRUE"}])
	"2.3.6: Ensure 'OS_ROLES' Is Set To 'FALSE'" in b.violations with input as bad
}

test_2_3_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/os_roles"}])
	"2.3.6: evidence missing — oracle.parameters.os_roles not collected" in b.violations with input as bad
}

# 2.3.7 (Automated)
test_2_3_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.7:")]) == 0
}

test_2_3_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/remote_os_roles", "value": "TRUE"}])
	"2.3.7: Ensure 'REMOTE_OS_ROLES' Is Set To 'FALSE'" in b.violations with input as bad
}

test_2_3_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/remote_os_roles"}])
	"2.3.7: evidence missing — oracle.parameters.remote_os_roles not collected" in b.violations with input as bad
}

# 2.3.8 (Automated)
test_2_3_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.8:")]) == 0
}

test_2_3_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/sec_max_failed_login_attempts", "value": "4"}])
	"2.3.8: Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is Set To '3' Or Less" in b.violations with input as bad
}

test_2_3_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/sec_max_failed_login_attempts"}])
	"2.3.8: evidence missing — oracle.parameters.sec_max_failed_login_attempts not collected" in b.violations with input as bad
}

# 2.3.9 (Automated)
test_2_3_9_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.9:")]) == 0
}

test_2_3_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/sec_protocol_error_further_action", "value": "(DROP,10)"}])
	"2.3.9: Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set To '(DROP,3)'" in b.violations with input as bad
}

test_2_3_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/sec_protocol_error_further_action"}])
	"2.3.9: evidence missing — oracle.parameters.sec_protocol_error_further_action not collected" in b.violations with input as bad
}

# 2.3.10 (Automated)
test_2_3_10_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.10:")]) == 0
}

test_2_3_10_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/sec_protocol_error_trace_action", "value": "NONE"}])
	"2.3.10: Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set To 'LOG'" in b.violations with input as bad
}

test_2_3_10_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/sec_protocol_error_trace_action"}])
	"2.3.10: evidence missing — oracle.parameters.sec_protocol_error_trace_action not collected" in b.violations with input as bad
}

# 2.3.11 (Automated)
test_2_3_11_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.11:")]) == 0
}

test_2_3_11_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/sec_return_server_release_banner", "value": "TRUE"}])
	"2.3.11: Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set To 'FALSE'" in b.violations with input as bad
}

test_2_3_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/sec_return_server_release_banner"}])
	"2.3.11: evidence missing — oracle.parameters.sec_return_server_release_banner not collected" in b.violations with input as bad
}

# 2.3.12 (Automated)
test_2_3_12_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.12:")]) == 0
}

test_2_3_12_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/remote_login_passwordfile", "value": "EXCLUSIVE"}])
	"2.3.12: Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set To 'NONE'" in b.violations with input as bad
}

test_2_3_12_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/remote_login_passwordfile"}])
	"2.3.12: evidence missing — oracle.parameters.remote_login_passwordfile not collected" in b.violations with input as bad
}

# 2.3.13 (Automated)
test_2_3_13_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.13:")]) == 0
}

test_2_3_13_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/remote_listener", "value": "lsnr-scan:1521"}])
	"2.3.13: Ensure 'REMOTE_LISTENER' Is Empty" in b.violations with input as bad
}

test_2_3_13_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters", "value": {}}])
	"2.3.13: evidence missing — oracle.parameters not collected" in b.violations with input as bad
}

# 2.3.14 (Automated)
test_2_3_14_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "2.3.14:")]) == 0
}

test_2_3_14_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/resource_limit", "value": "FALSE"}])
	"2.3.14: Ensure 'RESOURCE_LIMIT' Is Set To 'TRUE'" in b.violations with input as bad
}

test_2_3_14_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/parameters/resource_limit"}])
	"2.3.14: evidence missing — oracle.parameters.resource_limit not collected" in b.violations with input as bad
}

# 3.1 (Automated)
test_3_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.1:")]) == 0
}

test_3_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", "value": "6"}])
	"3.1: Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less Than Or Equal To '5'" in b.violations with input as bad
}

test_3_1_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.1: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.2 (Automated)
test_3_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.2:")]) == 0
}

test_3_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LOCK_TIME", "value": "0"}])
	"3.2: Ensure 'PASSWORD_LOCK_TIME' Is Greater Than Or Equal To '1'" in b.violations with input as bad
}

test_3_2_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.2: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.3 (Automated)
test_3_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.3:")]) == 0
}

test_3_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME", "value": "UNLIMITED"}])
	"3.3: Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'" in b.violations with input as bad
}

test_3_3_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME", "value": "360"}, {"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME", "value": "6"}])
	"3.3: Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'" in b.violations with input as bad
}

test_3_3_fail_3 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME"}])
	"3.3: Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'" in b.violations with input as bad
}

test_3_3_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.3: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.4 (Automated)
test_3_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.4:")]) == 0
}

test_3_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_REUSE_MAX", "value": "10"}])
	"3.4: Ensure 'PASSWORD_REUSE_MAX' Is Set To 'UNLIMITED'" in b.violations with input as bad
}

test_3_4_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.4: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.5 (Automated)
test_3_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.5:")]) == 0
}

test_3_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_VERIFY_FUNCTION", "value": "NULL"}])
	"3.5: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set For All Profiles" in b.violations with input as bad
}

test_3_5_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.5: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.6 (Manual)
test_3_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.6:")]) == 0
}

test_3_6_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/password_verify_function_meets_cis", "value": false}])
	"3.6: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Configured Correctly (manual review not attested)" in b.violations with input as bad
}

test_3_6_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/password_verify_function_meets_cis"}])
	"3.6: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Configured Correctly (manual review not attested)" in b.violations with input as bad
}

# 3.7 (Automated)
test_3_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.7:")]) == 0
}

test_3_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_ROLLOVER_TIME", "value": "1"}])
	"3.7: Ensure 'PASSWORD_ROLLOVER_TIME' Is set to '0'" in b.violations with input as bad
}

test_3_7_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.7: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 3.8 (Automated)
test_3_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "3.8:")]) == 0
}

test_3_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/INACTIVE_ACCOUNT_TIME", "value": "121"}])
	"3.8: Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120'" in b.violations with input as bad
}

test_3_8_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles", "value": {}}])
	"3.8: evidence missing — oracle.profiles not collected" in b.violations with input as bad
}

# 4.1 (Automated)
test_4_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.1:")]) == 0
}

test_4_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/users_with_default_password", "value": ["SCOTT"]}])
	"4.1: Ensure All Default Passwords Are Changed" in b.violations with input as bad
}

test_4_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/users_with_default_password"}])
	"4.1: evidence missing — oracle.users_with_default_password not collected" in b.violations with input as bad
}

# 4.2 (Automated)
test_4_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.2:")]) == 0
}

test_4_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/custom_oracle_maintained_users", "value": ["APP_OWNER"]}])
	"4.2: Ensure No Custom 'ORACLE_MAINTAINED' Users Exist" in b.violations with input as bad
}

test_4_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/custom_oracle_maintained_users"}])
	"4.2: evidence missing — oracle.custom_oracle_maintained_users not collected" in b.violations with input as bad
}

# 4.3 (Manual)
test_4_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.3:")]) == 0
}

test_4_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/ras_users_reviewed", "value": false}])
	"4.3: Review The Users Created Through Real Application Security (manual review not attested)" in b.violations with input as bad
}

test_4_3_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/ras_users_reviewed"}])
	"4.3: Review The Users Created Through Real Application Security (manual review not attested)" in b.violations with input as bad
}

# 4.4 (Automated)
test_4_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.4:")]) == 0
}

test_4_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/users_with_old_password_versions", "value": ["LEGACY_USER"]}])
	"4.4: Ensure Old Password Versions Are Not Used" in b.violations with input as bad
}

test_4_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/users_with_old_password_versions"}])
	"4.4: evidence missing — oracle.users_with_old_password_versions not collected" in b.violations with input as bad
}

# 4.5 (Automated)
test_4_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.5:")]) == 0
}

test_4_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/password_file_format", "value": "12"}])
	"4.5: Ensure The Latest Version of The Password File Is Used" in b.violations with input as bad
}

test_4_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/password_file_format"}])
	"4.5: evidence missing — oracle.password_file_format not collected" in b.violations with input as bad
}

# 4.6 (Automated)
test_4_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.6:")]) == 0
}

test_4_6_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/pwfile_users_not_on_all_instances", "value": ["C##ADMIN"]}])
	"4.6: Ensure That Users In Different RAC Instances Are Identical In PW Files" in b.violations with input as bad
}

test_4_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/pwfile_users_not_on_all_instances"}])
	"4.6: evidence missing — oracle.pwfile_users_not_on_all_instances not collected" in b.violations with input as bad
}

# 4.7 (Automated)
test_4_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.7:")]) == 0
}

test_4_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/public_db_links", "value": ["REMOTE_DB"]}])
	"4.7: Ensure No Public Database Links Exist" in b.violations with input as bad
}

test_4_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/public_db_links"}])
	"4.7: evidence missing — oracle.public_db_links not collected" in b.violations with input as bad
}

# 4.8 (Automated)
test_4_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "4.8:")]) == 0
}

test_4_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/db_links_with_legacy_password_encryption", "value": ["OLD_LINK"]}])
	"4.8: Ensure That Database Link Passwords Are Using The Latest Encryption" in b.violations with input as bad
}

test_4_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/db_links_with_legacy_password_encryption"}])
	"4.8: evidence missing — oracle.db_links_with_legacy_password_encryption not collected" in b.violations with input as bad
}

# 5.1 (Automated)
test_5_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "5.1:")]) == 0
}

test_5_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/audit/unaudited_system_actions", "value": ["CREATE TABLE"]}])
	"5.1: Ensure All Auditable System Actions Commands Are Audited" in b.violations with input as bad
}

test_5_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/audit/unaudited_system_actions"}])
	"5.1: evidence missing — oracle.audit.unaudited_system_actions not collected" in b.violations with input as bad
}

# 5.2 (Automated)
test_5_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "5.2:")]) == 0
}

test_5_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/audit/enabled_options", "value": ["LOGON"]}])
	"5.2: Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled" in b.violations with input as bad
}

test_5_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/audit/enabled_options"}])
	"5.2: evidence missing — oracle.audit.enabled_options not collected" in b.violations with input as bad
}

# 5.3 (Automated)
test_5_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "5.3:")]) == 0
}

test_5_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/audit/audited_packages", "value": ["DBMS_AW", "DBMS_CRYPTO", "DBMS_FGA", "DBMS_JAVA_TEST", "DBMS_JOB", "DBMS_LOGMNR", "DBMS_NETWORK_ACL_ADMIN", "DBMS_REDACT", "DBMS_REDEFINITION", "DBMS_RLS", "DBMS_SCHEDULER", "DBMS_SQL_TRANSLATOR", "DBMS_SYS_SQL", "DBMS_TSDP_MANAGE", "DBMS_TSDP_PROTECT", "DBMS_XMLGEN", "DBMS_XMLSTORE"]}])
	"5.3: Ensure Critical Packages Are Audited" in b.violations with input as bad
}

test_5_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/audit/audited_packages"}])
	"5.3: evidence missing — oracle.audit.audited_packages not collected" in b.violations with input as bad
}

# 5.4 (Automated)
test_5_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "5.4:")]) == 0
}

test_5_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/audit/enabled_options", "value": ["LOGON", "LOGOFF"]}])
	"5.4: Ensure All Export Activities Are Audited" in b.violations with input as bad
}

test_5_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/audit/enabled_options"}])
	"5.4: evidence missing — oracle.audit.enabled_options not collected" in b.violations with input as bad
}

# 5.5 (Automated)
test_5_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "5.5:")]) == 0
}

test_5_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/audit/all_actions_audited_users", "value": ["SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC"]}])
	"5.5: Ensure The Use Of SYS* Privileges Is Audited" in b.violations with input as bad
}

test_5_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/audit/all_actions_audited_users"}])
	"5.5: evidence missing — oracle.audit.all_actions_audited_users not collected" in b.violations with input as bad
}

# 6.1.1 (Automated)
test_6_1_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.1:")]) == 0
}

test_6_1_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "SELECT ANY TABLE", "oracle_maintained": "N"}]}])
	"6.1.1: Ensure '%ANY%' Is Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.1: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.2 (Automated)
test_6_1_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.2:")]) == 0
}

test_6_1_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "CREATE SESSION", "oracle_maintained": "N", "admin_option": true}]}])
	"6.1.2: Ensure Admin Privileges Are Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.2: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.3 (Automated)
test_6_1_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.3:")]) == 0
}

test_6_1_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "EXPORT FULL DATABASE", "oracle_maintained": "N"}]}])
	"6.1.3: Ensure 'IMPORT' And 'EXPORT' 'FULL DATABASE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_3_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "IMPORT FULL DATABASE", "oracle_maintained": "N"}]}])
	"6.1.3: Ensure 'IMPORT' And 'EXPORT' 'FULL DATABASE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.3: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.4 (Automated)
test_6_1_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.4:")]) == 0
}

test_6_1_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "CREATE EXTERNAL JOB", "oracle_maintained": "N"}]}])
	"6.1.4: Ensure 'CREATE EXTERNAL JOB' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.4: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.5 (Automated)
test_6_1_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.5:")]) == 0
}

test_6_1_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "BECOME USER", "oracle_maintained": "N"}]}])
	"6.1.5: Ensure 'BECOME USER' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.5: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.6 (Automated)
test_6_1_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.6:")]) == 0
}

test_6_1_6_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "TEXT DATASTORE ACCESS", "oracle_maintained": "N"}]}])
	"6.1.6: Ensure 'TEXT DATASTORE ACCESS' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.6: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.7 (Automated)
test_6_1_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.7:")]) == 0
}

test_6_1_7_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "CREATE PUBLIC DATABASE LINK", "oracle_maintained": "N"}]}])
	"6.1.7: Ensure 'CREATE', 'ALTER', And 'DROP' 'PUBLIC DATABASE LINK' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_7_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "ALTER PUBLIC DATABASE LINK", "oracle_maintained": "N"}]}])
	"6.1.7: Ensure 'CREATE', 'ALTER', And 'DROP' 'PUBLIC DATABASE LINK' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_7_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "DROP PUBLIC DATABASE LINK", "oracle_maintained": "N"}]}])
	"6.1.7: Ensure 'CREATE', 'ALTER', And 'DROP' 'PUBLIC DATABASE LINK' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.7: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.8 (Automated)
test_6_1_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.8:")]) == 0
}

test_6_1_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "LOGMINING", "oracle_maintained": "N"}]}])
	"6.1.8: Ensure 'LOGMINING' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.8: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.9 (Automated)
test_6_1_9_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.9:")]) == 0
}

test_6_1_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "ALTER SYSTEM", "oracle_maintained": "N"}]}])
	"6.1.9: Ensure 'ALTER SYSTEM' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.9: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.10 (Automated)
test_6_1_10_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.10:")]) == 0
}

test_6_1_10_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "CREATE LIBRARY", "oracle_maintained": "N"}]}])
	"6.1.10: Ensure 'CREATE LIBRARY' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_10_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.10: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.1.11 (Automated)
test_6_1_11_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.1.11:")]) == 0
}

test_6_1_11_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/sys_privs", "value": [{"grantee": "APP_USER", "privilege": "CREATE SESSION", "oracle_maintained": "N"}]}])
	"6.1.11: Ensure All `SYSTEM` Privileges Are Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_1_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/sys_privs"}])
	"6.1.11: evidence missing — oracle.grants.sys_privs not collected" in b.violations with input as bad
}

# 6.2.1 (Automated)
test_6_2_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.1:")]) == 0
}

test_6_2_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DBA", "oracle_maintained": "N"}]}])
	"6.2.1: Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.1: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.2 (Automated)
test_6_2_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.2:")]) == 0
}

test_6_2_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "EXP_FULL_DATABASE", "oracle_maintained": "N"}]}])
	"6.2.2: Ensure 'EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.2: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.3 (Automated)
test_6_2_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.3:")]) == 0
}

test_6_2_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "IMP_FULL_DATABASE", "oracle_maintained": "N"}]}])
	"6.2.3: Ensure 'IMP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_3_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.3: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.4 (Automated)
test_6_2_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.4:")]) == 0
}

test_6_2_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DATAPUMP_EXP_FULL_DATABASE", "oracle_maintained": "N"}]}])
	"6.2.4: Ensure 'DATAPUMP_EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.4: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.5 (Automated)
test_6_2_5_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.5:")]) == 0
}

test_6_2_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DATAPUMP_IMP_FULL_DATABASE", "oracle_maintained": "N"}]}])
	"6.2.5: Ensure 'DATAPUMP_IMP_FULL_DATABASE' is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.5: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.6 (Automated)
test_6_2_6_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.6:")]) == 0
}

test_6_2_6_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DV_ADMIN", "oracle_maintained": "N"}]}])
	"6.2.6: Ensure 'DV_ADMIN’ Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.6: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.7 (Automated)
test_6_2_7_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.7:")]) == 0
}

test_6_2_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DV_AUDIT_CLEANUP", "oracle_maintained": "N"}]}])
	"6.2.7: Ensure 'DV_AUDIT_CLEANUP’ Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.7: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.8 (Automated)
test_6_2_8_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.8:")]) == 0
}

test_6_2_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "OLAP_DBA", "oracle_maintained": "N"}]}])
	"6.2.8: Ensure 'OLAP_DBA' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.8: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.9 (Automated)
test_6_2_9_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.9:")]) == 0
}

test_6_2_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "LBAC_DBA", "oracle_maintained": "N"}]}])
	"6.2.9: Ensure 'LBAC_DBA' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.9: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.10 (Automated)
test_6_2_10_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.10:")]) == 0
}

test_6_2_10_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "JAVA_ADMIN", "oracle_maintained": "N"}]}])
	"6.2.10: Ensure 'JAVA_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_10_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.10: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.11 (Automated)
test_6_2_11_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.11:")]) == 0
}

test_6_2_11_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "JAVASYSPRIVS", "oracle_maintained": "N"}]}])
	"6.2.11: Ensure 'JAVASYSPRIVS' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.11: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.12 (Automated)
test_6_2_12_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.12:")]) == 0
}

test_6_2_12_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "LOGSTDBY_ADMINISTRATOR", "oracle_maintained": "N"}]}])
	"6.2.12: Ensure 'LOGSTDBY_ADMINISTRATOR' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_12_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.12: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.13 (Automated)
test_6_2_13_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.13:")]) == 0
}

test_6_2_13_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "SQL_FIREWALL_ADMIN", "oracle_maintained": "N"}]}])
	"6.2.13: Ensure 'SQL_FIREWALL_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_13_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.13: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.14 (Automated)
test_6_2_14_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.14:")]) == 0
}

test_6_2_14_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "MAINTPLAN_APP", "oracle_maintained": "N"}]}])
	"6.2.14: Ensure 'MAINTPLAN_APP' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_14_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.14: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.15 (Automated)
test_6_2_15_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.15:")]) == 0
}

test_6_2_15_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "JAVADEBUGPRIV", "oracle_maintained": "N"}]}])
	"6.2.15: Ensure 'JAVADEBUGPRIV' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_15_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.15: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.16 (Automated)
test_6_2_16_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.16:")]) == 0
}

test_6_2_16_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DV_PATCH_ADMIN", "oracle_maintained": "N"}]}])
	"6.2.16: Ensure 'DV_PATCH_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_16_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.16: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.17 (Automated)
test_6_2_17_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.17:")]) == 0
}

test_6_2_17_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DV_POLICY_OWNER", "oracle_maintained": "N"}]}])
	"6.2.17: Ensure 'DV_POLICY_OWNER' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_17_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.17: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.18 (Automated)
test_6_2_18_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.18:")]) == 0
}

test_6_2_18_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "AUDIT_ADMIN", "oracle_maintained": "N"}]}])
	"6.2.18: Ensure AUDIT_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_18_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.18: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.19 (Automated)
test_6_2_19_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.19:")]) == 0
}

test_6_2_19_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "AUDIT_VIEWER", "oracle_maintained": "N"}]}])
	"6.2.19: Ensure 'AUDIT_VIEWER' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_19_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.19: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.20 (Automated)
test_6_2_20_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.20:")]) == 0
}

test_6_2_20_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "PDB_DBA", "oracle_maintained": "N"}]}])
	"6.2.20: Ensure 'PDB_DBA' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_20_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.20: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.21 (Automated)
test_6_2_21_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.21:")]) == 0
}

test_6_2_21_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "SELECT_CATALOG_ROLE", "oracle_maintained": "N"}]}])
	"6.2.21: Ensure 'SELECT_CATALOG_ROLE' Is Revoked From Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_21_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.21: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.2.22 (Automated)
test_6_2_22_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.2.22:")]) == 0
}

test_6_2_22_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "EXECUTE_CATALOG_ROLE", "oracle_maintained": "N"}]}])
	"6.2.22: Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_6_2_22_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/role_privs"}])
	"6.2.22: evidence missing — oracle.grants.role_privs not collected" in b.violations with input as bad
}

# 6.3.1 (Manual)
test_6_3_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.3.1:")]) == 0
}

test_6_3_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/schema_privileges_reviewed", "value": false}])
	"6.3.1: Ensure 'CDB_SCHEMA_PRIVS' Does Not Have Unauthorized Privileges (manual review not attested)" in b.violations with input as bad
}

test_6_3_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/schema_privileges_reviewed"}])
	"6.3.1: Ensure 'CDB_SCHEMA_PRIVS' Does Not Have Unauthorized Privileges (manual review not attested)" in b.violations with input as bad
}

# 6.4.1 (Automated)
test_6_4_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.4.1:")]) == 0
}

test_6_4_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/tab_privs", "value": [{"grantee": "APP_USER", "owner": "SYS", "table_name": "USER$", "privilege": "ALL"}]}])
	"6.4.1: Ensure 'ALL' Is Revoked On 'Sensitive' Tables" in b.violations with input as bad
}

test_6_4_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/grants/tab_privs"}])
	"6.4.1: evidence missing — oracle.grants.tab_privs not collected" in b.violations with input as bad
}

# 6.5.1 (Manual)
test_6_5_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.5.1:")]) == 0
}

test_6_5_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/column_privileges_reviewed", "value": false}])
	"6.5.1: Ensure ‘DBA_COL_PRIVS’ Is Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

test_6_5_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/column_privileges_reviewed"}])
	"6.5.1: Ensure ‘DBA_COL_PRIVS’ Is Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

# 6.6.1 (Manual)
test_6_6_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.6.1:")]) == 0
}

test_6_6_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/proxy_user_privileges_reviewed", "value": false}])
	"6.6.1: Ensure Proxy User Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

test_6_6_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/proxy_user_privileges_reviewed"}])
	"6.6.1: Ensure Proxy User Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

# 6.7.1 (Manual)
test_6_7_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.7.1:")]) == 0
}

test_6_7_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/custom_java_privileges_reviewed", "value": false}])
	"6.7.1: Ensure Custom Java Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

test_6_7_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/custom_java_privileges_reviewed"}])
	"6.7.1: Ensure Custom Java Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" in b.violations with input as bad
}

# 6.8.1 (Manual)
test_6_8_1_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.8.1:")]) == 0
}

test_6_8_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/directory_object_access_reviewed", "value": false}])
	"6.8.1: Ensure Directory Object Access Is Revoked From Unauthorized ‘GRANTEE’ (manual review not attested)" in b.violations with input as bad
}

test_6_8_1_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/directory_object_access_reviewed"}])
	"6.8.1: Ensure Directory Object Access Is Revoked From Unauthorized ‘GRANTEE’ (manual review not attested)" in b.violations with input as bad
}

# 6.8.2 (Manual)
test_6_8_2_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.8.2:")]) == 0
}

test_6_8_2_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/directory_object_privileges_reviewed", "value": false}])
	"6.8.2: Review Directory Objects Privileges (manual review not attested)" in b.violations with input as bad
}

test_6_8_2_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/directory_object_privileges_reviewed"}])
	"6.8.2: Review Directory Objects Privileges (manual review not attested)" in b.violations with input as bad
}

# 6.8.3 (Manual)
test_6_8_3_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.8.3:")]) == 0
}

test_6_8_3_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/external_table_preprocessors_reviewed", "value": false}])
	"6.8.3: Review External Tables With Preprocessor (manual review not attested)" in b.violations with input as bad
}

test_6_8_3_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/external_table_preprocessors_reviewed"}])
	"6.8.3: Review External Tables With Preprocessor (manual review not attested)" in b.violations with input as bad
}

# 6.8.4 (Manual)
test_6_8_4_pass if {
	v := b.violations with input as green
	count([m | some m in v; startswith(m, "6.8.4:")]) == 0
}

test_6_8_4_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/attest/external_tables_reviewed", "value": false}])
	"6.8.4: Review External Tables (manual review not attested)" in b.violations with input as bad
}

test_6_8_4_fail_2 if {
	bad := json.patch(green, [{"op": "remove", "path": "/oracle/attest/external_tables_reviewed"}])
	"6.8.4: Review External Tables (manual review not attested)" in b.violations with input as bad
}
