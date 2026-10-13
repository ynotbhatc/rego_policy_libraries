package cis.oracle_23ai_test

import rego.v1

import data.cis.oracle_23ai as b

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
	  "profiles": {
	   "ORA_STIG_PROFILE": {
	    "FAILED_LOGIN_ATTEMPTS": "3",
	    "PASSWORD_LOCK_TIME": "1",
	    "PASSWORD_REUSE_MAX": "UNLIMITED",
	    "PASSWORD_VERIFY_FUNCTION": "ORA12C_STIG_VERIFY_FUNCTION",
	    "PASSWORD_ROLLOVER_TIME": "0",
	    "INACTIVE_ACCOUNT_TIME": "35"
	   }
	  },
	  "attest": {
	   "password_verify_function_meets_cis": true,
	   "rac_password_files_identical": true,
	   "schema_privileges_reviewed": true,
	   "column_privileges_reviewed": true,
	   "proxy_user_privileges_reviewed": true,
	   "custom_java_privileges_reviewed": true,
	   "directory_object_access_reviewed": true
	  },
	  "users_with_default_password": [],
	  "custom_oracle_maintained_users": [],
	  "users_with_old_password_versions": [],
	  "password_file_format": "12.2",
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
	  "listener_ora": {}
	 }
	}

test_green_database_is_compliant if {
	r := b.compliance_report with input as green
	r.compliant == true
	count(r.violations) == 0
}

test_fail_closed_on_empty_input if {
	r := b.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_remote_os_roles_true_is_2_3_7 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/remote_os_roles", "value": "TRUE"}])
	"2.3.7: Ensure 'REMOTE_OS_ROLES' Is Set To 'FALSE'" in b.violations with input as bad
}

test_unauthorized_dba_grant_is_6_2_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DBA", "oracle_maintained": false}]}])
	"6.2.1: Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'" in b.violations with input as bad
}

test_authorized_dba_grant_is_not_a_finding if {
	ok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "DBA_TEAM", "granted_role": "DBA", "oracle_maintained": false}]}])
	b.compliant with input as ok
}

test_every_recommendation_fires_without_facts if {
	v := b.violations with input as {"oracle": {}}
	ids := {id | some m in v; id := split(m, ":")[0]}
	count(ids) >= 87
}
