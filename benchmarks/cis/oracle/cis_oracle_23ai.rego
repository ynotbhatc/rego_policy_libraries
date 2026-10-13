# METADATA
# title: "CIS Oracle Database 23ai Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_oracle_23ai
#   source: cis
#   domains: [database, oracle]
#   coverage:
#     checks: 88
#     cited: 88
#     expected: 87
#     found: 88
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package cis.oracle_23ai

# CIS Oracle Database 23ai Benchmark v1.0.0 (CIS lists v1.1.0 as current; a typo/version-text update)
# 87 recommendations, every one in the benchmark; ids and titles read from the benchmark text and the
# logic written from each recommendation's own audit SQL (tools/cis_generators/gen_oracle_db_23ai.py).
# 7 recommendations are Manual reviews and carry an attestation boolean.
#
# Input contract (shared with benchmarks/stig/oracle_database_19c so one collector feeds both):
#   input.oracle.parameters[<name>]           : V$SYSTEM_PARAMETER value, name lowercase
#   input.oracle.sqlnet[<PARAM>] / listener_ora[<PARAM>] : sqlnet.ora and listener.ora entries
#   input.oracle.profiles[<profile>][<RESOURCE>] : DBA_PROFILES limits (DEFAULT resolved by the collector)
#   input.oracle.grants.{sys_privs,role_privs,tab_privs}[] : {grantee, privilege|granted_role|table_name, owner,
#                                               admin_option, oracle_maintained}
#   input.oracle.authorized_grantees[]         : grantees the organization has authorized for restricted privileges
#   input.oracle.audit.enabled_options[] / audited_packages[] / all_actions_audited_users[] / unaudited_system_actions[]
#   input.oracle.<query result>                : rows the audit query must not return (lists), flags
#   input.oracle.attest.*                      : attestation booleans for the Manual recommendations

import rego.v1

default compliant := false

compliant if {
	input.oracle
	count(violations) == 0
}

# ── helpers ──────────────────────────────────────────────────────────────────
# Profiles: every profile the collector reports must satisfy the limit (DEFAULT resolved by the collector
# to the DEFAULT profile's value, as the benchmark's own DECODE does; UNLIMITED fails numeric comparisons).
profiles_every_le(resource, max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) <= max
	}
}

profiles_every_ge(resource, min) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) >= min
	}
}

profiles_every_eq(resource, val) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		upper(p[resource]) == val
	}
}

profiles_every_set(resource) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		not upper(p[resource]) in {"NULL", "DEFAULT", ""}
	}
}

# Privileges: the benchmark's queries list grants to grantees that are not ORACLE_MAINTAINED; a grant to a
# grantee the organization has authorized (input.oracle.authorized_grantees) is not a finding.
# ORACLE_MAINTAINED arrives as the view's 'Y'/'N' or as a boolean; anything else (missing, "N", false) is not Oracle's
_oracle_maintained(g) if g.oracle_maintained == true

_oracle_maintained(g) if upper(g.oracle_maintained) == "Y"

_unauthorized(g) if {
	not _oracle_maintained(g)
	not g.grantee in input.oracle.authorized_grantees
}

no_unauthorized_sys_priv(priv) if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; g.privilege == priv; _unauthorized(g)]) == 0
}

no_unauthorized_sys_priv_like(frag) if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; contains(g.privilege, frag); _unauthorized(g)]) == 0
}

no_unauthorized_role(r) if {
	is_array(input.oracle.grants.role_privs)
	count([g | some g in input.oracle.grants.role_privs; g.granted_role == r; _unauthorized(g)]) == 0
}

# 1.1 (Manual)
default r_1_1 := false
r_1_1 if {
	input.oracle.patches.latest_cpu_applied == true
}

violations contains "1.1: Ensure The Appropriate Version/Patches For Oracle Software Is Installed" if {
	not r_1_1
}

# 2.1.1 (Automated)
default r_2_1_1 := false
r_2_1_1 if {
	input.oracle.listener.extproc_configured == false
}

violations contains "2.1.1: Ensure 'extproc' Is Not Present In 'listener.ora'" if {
	not r_2_1_1
}

# 2.1.2 (Automated)
default r_2_1_2 := false
r_2_1_2 if {
	is_object(input.oracle.listener_ora)
	upper(object.get(input.oracle.listener_ora, "ACCEPT_MD5_CERTS", "FALSE")) != "TRUE"
}

violations contains "2.1.2: Ensure 'ACCEPT_MD5_CERTS' Is Configured Correctly" if {
	not r_2_1_2
}

# 2.1.3 (Automated)
default r_2_1_3 := false
r_2_1_3 if {
	is_object(input.oracle.listener_ora)
	upper(object.get(input.oracle.listener_ora, "ACCEPT_SHA1_CERTS", "FALSE")) != "TRUE"
}

violations contains "2.1.3: Ensure 'ACCEPT_SHA1_CERTS' Is Configured Correctly" if {
	not r_2_1_3
}

# 2.1.4 (Automated)
default r_2_1_4 := false
r_2_1_4 if {
	is_object(input.oracle.listener_ora)
	upper(object.get(input.oracle.listener_ora, "ALLOWED_WEAK_CERT_ALGORITHMS", "FALSE")) != "TRUE"
}

violations contains "2.1.4: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS’ Is NOT Set." if {
	not r_2_1_4
}

# 2.2.1 (Automated)
default r_2_2_1 := false
r_2_2_1 if {
	is_object(input.oracle.sqlnet)
	upper(object.get(input.oracle.sqlnet, "ACCEPT_MD5_CERTS", "FALSE")) != "TRUE"
}

violations contains "2.2.1: Ensure 'ACCEPT_MD5_CERTS' Is NOT SET" if {
	not r_2_2_1
}

# 2.2.2 (Automated)
default r_2_2_2 := false
r_2_2_2 if {
	is_object(input.oracle.sqlnet)
	upper(object.get(input.oracle.sqlnet, "ACCEPT_SHA1_CERTS", "FALSE")) != "TRUE"
}

violations contains "2.2.2: Ensure 'ACCEPT_SHA1_CERTS' Is NOT Set" if {
	not r_2_2_2
}

# 2.2.3 (Automated)
default r_2_2_3 := false
r_2_2_3 if {
	is_object(input.oracle.sqlnet)
	upper(object.get(input.oracle.sqlnet, "ALLOWED_WEAK_CERT_ALGORITHMS", "FALSE")) != "TRUE"
}

violations contains "2.2.3: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS' Is NOT Set" if {
	not r_2_2_3
}

# 2.2.4 (Automated)
default r_2_2_4 := false
r_2_2_4 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ALLOWED_LOGON_VERSION_CLIENT"]) == "12A"
}

violations contains "2.2.4: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_CLIENT' Is Set To 12a" if {
	not r_2_2_4
}

# 2.2.5 (Automated)
default r_2_2_5 := false
r_2_2_5 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ALLOWED_LOGON_VERSION_SERVER"]) == "12A"
}

violations contains "2.2.5: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_SERVER' Is Set To 12a" if {
	not r_2_2_5
}

# 2.2.6 (Automated)
default r_2_2_6 := false
r_2_2_6 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_CLIENT"]) == "REQUIRED"
}

violations contains "2.2.6: Ensure 'SQLNET.ENCRYPTION_CLIENT Is Set To 'REQUIRED'" if {
	not r_2_2_6
}

# 2.2.7 (Automated)
default r_2_2_7 := false
r_2_2_7 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_SERVER"]) == "REQUIRED"
}

violations contains "2.2.7: Ensure 'SQLNET.ENCRYPTION_SERVER' Is Set To 'REQUIRED'" if {
	not r_2_2_7
}

# 2.2.8 (Automated)
default r_2_2_8 := false
r_2_2_8 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_TYPES_CLIENT"]) == "AES256"
}

violations contains "2.2.8: Ensure 'SQLNET.ENCRYPTION_TYPES_CLIENT' Is Set To 'AES256'" if {
	not r_2_2_8
}

# 2.2.9 (Manual)
default r_2_2_9 := false
r_2_2_9 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_TYPES_SERVER"]) == "AES256"
}

violations contains "2.2.9: Ensure 'SQLNET.ENCRYPTION_TYPES_SERVER' Is Set To AES256" if {
	not r_2_2_9
}

# 2.2.10 (Automated)
default r_2_2_10 := false
r_2_2_10 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.CRYPTO_CHECKSUM_CLIENT"]) == "REQUIRED"
}

violations contains "2.2.10: Ensure 'SQLNET.CRYPTO_CHECKSUM_CLIENT' Is Set To 'REQUIRED'" if {
	not r_2_2_10
}

# 2.2.11 (Automated)
default r_2_2_11 := false
r_2_2_11 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SQLNET.CRYPTO_CHECKSUM_SERVER"]) == "REQUIRED"
}

violations contains "2.2.11: Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set To 'REQUIRED'" if {
	not r_2_2_11
}

# 2.2.12 (Automated)
default r_2_2_12 := false
r_2_2_12 if {
	is_object(input.oracle.sqlnet)
	upper(input.oracle.sqlnet["SSL_CERT_REVOCATION"]) == "REQUIRED"
}

violations contains "2.2.12: Ensure 'SSL_CERT_REVOCATION' Is Set To 'REQUIRED'" if {
	not r_2_2_12
}

# 2.3.1 (Automated)
default r_2_3_1 := false
r_2_3_1 if {
	is_object(input.oracle.parameters)
	upper(object.get(input.oracle.parameters, "background_core_dump", "")) != "FULL"
}

violations contains "2.3.1: Ensure 'BACKGROUND_CORE_DUMP' Is Not Set To 'Full'" if {
	not r_2_3_1
}

# 2.3.2 (Automated)
default r_2_3_2 := false
r_2_3_2 if {
	is_object(input.oracle.parameters)
	upper(object.get(input.oracle.parameters, "shadow_core_dump", "")) != "FULL"
}

violations contains "2.3.2: Ensure 'SHADOW_CORE_DUMP' Is Not Set To 'Full'" if {
	not r_2_3_2
}

# 2.3.3 (Automated)
default r_2_3_3 := false
r_2_3_3 if {
	upper(input.oracle.parameters["mle_prog_languages"]) == "OFF"
}

violations contains "2.3.3: Ensure 'MLE_PROG_LANGUAGES' Is Set To 'OFF'" if {
	not r_2_3_3
}

# 2.3.4 (Automated)
default r_2_3_4 := false
r_2_3_4 if {
	upper(input.oracle.parameters["allow_group_access_to_sga"]) == "FALSE"
}

violations contains "2.3.4: Ensure 'ALLOW_GROUP_ACCESS_TO_SGA' Is Set To `FALSE`" if {
	not r_2_3_4
}

# 2.3.6 (Automated)
default r_2_3_6 := false
r_2_3_6 if {
	upper(input.oracle.parameters["os_roles"]) == "FALSE"
}

violations contains "2.3.6: Ensure 'OS_ROLES' Is Set To 'FALSE'" if {
	not r_2_3_6
}

# 2.3.7 (Automated)
default r_2_3_7 := false
r_2_3_7 if {
	upper(input.oracle.parameters["remote_os_roles"]) == "FALSE"
}

violations contains "2.3.7: Ensure 'REMOTE_OS_ROLES' Is Set To 'FALSE'" if {
	not r_2_3_7
}

# 2.3.8 (Automated)
default r_2_3_8 := false
r_2_3_8 if {
	to_number(input.oracle.parameters["sec_max_failed_login_attempts"]) <= 3
}

violations contains "2.3.8: Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is Set To '3' Or Less" if {
	not r_2_3_8
}

# 2.3.9 (Automated)
default r_2_3_9 := false
r_2_3_9 if {
	upper(input.oracle.parameters["sec_protocol_error_further_action"]) in {"(DROP,3)", "(DROP, 3)"}
}

violations contains "2.3.9: Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set To '(DROP,3)'" if {
	not r_2_3_9
}

# 2.3.10 (Automated)
default r_2_3_10 := false
r_2_3_10 if {
	upper(input.oracle.parameters["sec_protocol_error_trace_action"]) == "LOG"
}

violations contains "2.3.10: Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set To 'LOG'" if {
	not r_2_3_10
}

# 2.3.11 (Automated)
default r_2_3_11 := false
r_2_3_11 if {
	upper(input.oracle.parameters["sec_return_server_release_banner"]) == "FALSE"
}

violations contains "2.3.11: Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set To 'FALSE'" if {
	not r_2_3_11
}

# 2.3.12 (Automated)
default r_2_3_12 := false
r_2_3_12 if {
	upper(input.oracle.parameters["remote_login_passwordfile"]) == "NONE"
}

violations contains "2.3.12: Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set To 'NONE'" if {
	not r_2_3_12
}

# 2.3.13 (Automated)
default r_2_3_13 := false
r_2_3_13 if {
	is_object(input.oracle.parameters)
	object.get(input.oracle.parameters, "remote_listener", "") == ""
}

violations contains "2.3.13: Ensure 'REMOTE_LISTENER' Is Empty" if {
	not r_2_3_13
}

# 2.3.14 (Automated)
default r_2_3_14 := false
r_2_3_14 if {
	upper(input.oracle.parameters["resource_limit"]) == "TRUE"
}

violations contains "2.3.14: Ensure 'RESOURCE_LIMIT' Is Set To 'TRUE'" if {
	not r_2_3_14
}

# 3.1 (Automated)
default r_3_1 := false
r_3_1 if {
	profiles_every_le("FAILED_LOGIN_ATTEMPTS", 5)
}

violations contains "3.1: Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less Than Or Equal To '5'" if {
	not r_3_1
}

# 3.2 (Automated)
default r_3_2 := false
r_3_2 if {
	profiles_every_ge("PASSWORD_LOCK_TIME", 1)
}

violations contains "3.2: Ensure 'PASSWORD_LOCK_TIME' Is Greater Than Or Equal To '1'" if {
	not r_3_2
}

# 3.4 (Automated)
default r_3_4 := false
r_3_4 if {
	profiles_every_eq("PASSWORD_REUSE_MAX", "UNLIMITED")
}

violations contains "3.4: Ensure 'PASSWORD_REUSE_MAX' Is Set To 'UNLIMITED'" if {
	not r_3_4
}

# 3.5 (Automated)
default r_3_5 := false
r_3_5 if {
	profiles_every_set("PASSWORD_VERIFY_FUNCTION")
}

violations contains "3.5: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set For All Profiles" if {
	not r_3_5
}

# 3.6 (Manual)
default r_3_6 := false
r_3_6 if {
	input.oracle.attest.password_verify_function_meets_cis == true
}

violations contains "3.6: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Configured Correctly" if {
	not r_3_6
}

# 3.7 (Automated)
default r_3_7 := false
r_3_7 if {
	profiles_every_le("PASSWORD_ROLLOVER_TIME", 0)
}

violations contains "3.7: Ensure 'PASSWORD_ROLLOVER_TIME' Is set to '0'" if {
	not r_3_7
}

# 3.8 (Automated)
default r_3_8 := false
r_3_8 if {
	profiles_every_le("INACTIVE_ACCOUNT_TIME", 120)
}

violations contains "3.8: Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120'" if {
	not r_3_8
}

# 4.1 (Automated)
default r_4_1 := false
r_4_1 if {
	count(input.oracle.users_with_default_password) == 0
}

violations contains "4.1: Ensure All Default Passwords Are Changed" if {
	not r_4_1
}

# 4.2 (Automated)
default r_4_2 := false
r_4_2 if {
	count(input.oracle.custom_oracle_maintained_users) == 0
}

violations contains "4.2: Ensure No Custom 'ORACLE_MAINTAINED' Users Exist" if {
	not r_4_2
}

# 4.4 (Automated)
default r_4_4 := false
r_4_4 if {
	count(input.oracle.users_with_old_password_versions) == 0
}

violations contains "4.4: Ensure Old Password Versions Are Not Used" if {
	not r_4_4
}

# 4.5 (Automated)
default r_4_5 := false
r_4_5 if {
	input.oracle.password_file_format == "12.2"
}

violations contains "4.5: Ensure The Latest Version of The Password File Is Used" if {
	not r_4_5
}

# 4.6 (Manual)
default r_4_6 := false
r_4_6 if {
	input.oracle.attest.rac_password_files_identical == true
}

violations contains "4.6: Ensure That Users In Different RAC Instances Are Identical In PW Files" if {
	not r_4_6
}

# 4.7 (Automated)
default r_4_7 := false
r_4_7 if {
	count(input.oracle.public_db_links) == 0
}

violations contains "4.7: Ensure No Public Database Links Exist" if {
	not r_4_7
}

# 4.8 (Automated)
default r_4_8 := false
r_4_8 if {
	count(input.oracle.db_links_with_legacy_password_encryption) == 0
}

violations contains "4.8: Ensure That Database Link Passwords Are Using The Latest Encryption" if {
	not r_4_8
}

# 5.1 (Automated)
default r_5_1 := false
r_5_1 if {
	count(input.oracle.audit.unaudited_system_actions) == 0
}

violations contains "5.1: Ensure All Auditable System Actions Commands Are Audited" if {
	not r_5_1
}

# 5.2 (Automated)
default r_5_2 := false
r_5_2 if {
	every a in {"LOGON", "LOGOFF"} { a in input.oracle.audit.enabled_options }
}

violations contains "5.2: Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled" if {
	not r_5_2
}

# 5.3 (Automated)
default r_5_3 := false
r_5_3 if {
	every p in ["DBMS_AW", "DBMS_CRYPTO", "DBMS_FGA", "DBMS_JAVA_TEST", "DBMS_JOB", "DBMS_LOGMNR", "DBMS_NETWORK_ACL_ADMIN", "DBMS_REDACT", "DBMS_REDEFINITION", "DBMS_RLS", "DBMS_SCHEDULER", "DBMS_SQL_TRANSLATOR", "DBMS_SYS_SQL", "DBMS_TSDP_MANAGE", "DBMS_TSDP_PROTECT", "DBMS_XMLGEN", "DBMS_XMLSTORE", "OWA_UTIL"] { p in input.oracle.audit.audited_packages }
}

violations contains "5.3: Ensure Critical Packages Are Audited" if {
	not r_5_3
}

# 5.4 (Automated)
default r_5_4 := false
r_5_4 if {
	every a in {"EXPORT"} { a in input.oracle.audit.enabled_options }
}

violations contains "5.4: Ensure All Export Activities Are Audited" if {
	not r_5_4
}

# 5.5 (Automated)
default r_5_5 := false
r_5_5 if {
	every u in {"SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "PUBLIC"} { u in input.oracle.audit.all_actions_audited_users }
}

violations contains "5.5: Ensure The Use Of SYS* Privileges Is Audited" if {
	not r_5_5
}

# 6.1.1 (Automated)
default r_6_1_1 := false
r_6_1_1 if {
	no_unauthorized_sys_priv_like("ANY")
}

violations contains "6.1.1: Ensure '%ANY%' Is Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_1_1
}

# 6.1.2 (Automated)
default r_6_1_2 := false
r_6_1_2 if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; g.admin_option == true; _unauthorized(g)]) == 0
}

violations contains "6.1.2: Ensure Admin Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_1_2
}

# 6.1.3 (Automated)
default r_6_1_3 := false
r_6_1_3 if {
	no_unauthorized_sys_priv("EXPORT FULL DATABASE")
	no_unauthorized_sys_priv("IMPORT FULL DATABASE")
}

violations contains "6.1.3: Ensure 'IMPORT' And 'EXPORT' 'FULL DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_3
}

# 6.1.4 (Automated)
default r_6_1_4 := false
r_6_1_4 if {
	no_unauthorized_sys_priv("CREATE EXTERNAL JOB")
}

violations contains "6.1.4: Ensure 'CREATE EXTERNAL JOB' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_4
}

# 6.1.5 (Automated)
default r_6_1_5 := false
r_6_1_5 if {
	no_unauthorized_sys_priv("BECOME USER")
}

violations contains "6.1.5: Ensure 'BECOME USER' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_5
}

# 6.1.6 (Automated)
default r_6_1_6 := false
r_6_1_6 if {
	no_unauthorized_sys_priv("TEXT DATASTORE ACCESS")
}

violations contains "6.1.6: Ensure 'TEXT DATASTORE ACCESS' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_6
}

# 6.1.8 (Automated)
default r_6_1_8 := false
r_6_1_8 if {
	no_unauthorized_sys_priv("LOGMINING")
}

violations contains "6.1.8: Ensure 'LOGMINING' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_8
}

# 6.1.9 (Automated)
default r_6_1_9 := false
r_6_1_9 if {
	no_unauthorized_sys_priv("ALTER SYSTEM")
}

violations contains "6.1.9: Ensure 'ALTER SYSTEM' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_9
}

# 6.1.10 (Automated)
default r_6_1_10 := false
r_6_1_10 if {
	no_unauthorized_sys_priv("CREATE LIBRARY")
}

violations contains "6.1.10: Ensure 'CREATE LIBRARY' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_1_10
}

# 6.1.11 (Automated)
default r_6_1_11 := false
r_6_1_11 if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; _unauthorized(g)]) == 0
}

violations contains "6.1.11: Ensure All `SYSTEM` Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_1_11
}

# 6.2.1 (Automated)
default r_6_2_1 := false
r_6_2_1 if {
	no_unauthorized_role("DBA")
}

violations contains "6.2.1: Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_2_1
}

# 6.2.2 (Automated)
default r_6_2_2 := false
r_6_2_2 if {
	no_unauthorized_role("EXP_FULL_DATABASE")
}

violations contains "6.2.2: Ensure 'EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_2
}

# 6.2.3 (Automated)
default r_6_2_3 := false
r_6_2_3 if {
	no_unauthorized_role("IMP_FULL_DATABASE")
}

violations contains "6.2.3: Ensure 'IMP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_3
}

# 6.2.4 (Automated)
default r_6_2_4 := false
r_6_2_4 if {
	no_unauthorized_role("DATAPUMP_EXP_FULL_DATABASE")
}

violations contains "6.2.4: Ensure 'DATAPUMP_EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_4
}

# 6.2.5 (Automated)
default r_6_2_5 := false
r_6_2_5 if {
	no_unauthorized_role("DATAPUMP_IMP_FULL_DATABASE")
}

violations contains "6.2.5: Ensure 'DATAPUMP_IMP_FULL_DATABASE' is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_5
}

# 6.2.6 (Automated)
default r_6_2_6 := false
r_6_2_6 if {
	no_unauthorized_role("DV_ADMIN")
}

violations contains "6.2.6: Ensure 'DV_ADMIN’ Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_6
}

# 6.2.7 (Automated)
default r_6_2_7 := false
r_6_2_7 if {
	no_unauthorized_role("DV_AUDIT_CLEANUP")
}

violations contains "6.2.7: Ensure 'DV_AUDIT_CLEANUP’ Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_7
}

# 6.2.8 (Automated)
default r_6_2_8 := false
r_6_2_8 if {
	no_unauthorized_role("OLAP_DBA")
}

violations contains "6.2.8: Ensure 'OLAP_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_8
}

# 6.2.9 (Automated)
default r_6_2_9 := false
r_6_2_9 if {
	no_unauthorized_role("LBAC_DBA")
}

violations contains "6.2.9: Ensure 'LBAC_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_9
}

# 6.2.10 (Automated)
default r_6_2_10 := false
r_6_2_10 if {
	no_unauthorized_role("JAVA_ADMIN")
}

violations contains "6.2.10: Ensure 'JAVA_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_10
}

# 6.2.11 (Automated)
default r_6_2_11 := false
r_6_2_11 if {
	no_unauthorized_role("JAVASYSPRIVS")
}

violations contains "6.2.11: Ensure 'JAVASYSPRIVS' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_11
}

# 6.2.12 (Automated)
default r_6_2_12 := false
r_6_2_12 if {
	no_unauthorized_role("LOGSTDBY_ADMINISTRATOR")
}

violations contains "6.2.12: Ensure 'LOGSTDBY_ADMINISTRATOR' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_12
}

# 6.2.13 (Automated)
default r_6_2_13 := false
r_6_2_13 if {
	no_unauthorized_role("SQL_FIREWALL_ADMIN")
}

violations contains "6.2.13: Ensure 'SQL_FIREWALL_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_13
}

# 6.2.14 (Automated)
default r_6_2_14 := false
r_6_2_14 if {
	no_unauthorized_role("MAINTPLAN_APP")
}

violations contains "6.2.14: Ensure 'MAINTPLAN_APP' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_14
}

# 6.2.15 (Automated)
default r_6_2_15 := false
r_6_2_15 if {
	no_unauthorized_role("JAVADEBUGPRIV")
}

violations contains "6.2.15: Ensure 'JAVADEBUGPRIV' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_15
}

# 6.2.16 (Automated)
default r_6_2_16 := false
r_6_2_16 if {
	no_unauthorized_role("DV_PATCH_ADMIN")
}

violations contains "6.2.16: Ensure 'DV_PATCH_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_16
}

# 6.2.17 (Automated)
default r_6_2_17 := false
r_6_2_17 if {
	no_unauthorized_role("DV_POLICY_OWNER")
}

violations contains "6.2.17: Ensure 'DV_POLICY_OWNER' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_17
}

# 6.2.18 (Automated)
default r_6_2_18 := false
r_6_2_18 if {
	no_unauthorized_role("AUDIT_ADMIN")
}

violations contains "6.2.18: Ensure AUDIT_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_18
}

# 6.2.19 (Automated)
default r_6_2_19 := false
r_6_2_19 if {
	no_unauthorized_role("AUDIT_VIEWER")
}

violations contains "6.2.19: Ensure 'AUDIT_VIEWER' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_19
}

# 6.2.20 (Automated)
default r_6_2_20 := false
r_6_2_20 if {
	no_unauthorized_role("PDB_DBA")
}

violations contains "6.2.20: Ensure 'PDB_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_20
}

# 6.2.21 (Automated)
default r_6_2_21 := false
r_6_2_21 if {
	no_unauthorized_role("SELECT_CATALOG_ROLE")
}

violations contains "6.2.21: Ensure 'SELECT_CATALOG_ROLE' Is Revoked From Unauthorized 'GRANTEE'" if {
	not r_6_2_21
}

# 6.2.22 (Automated)
default r_6_2_22 := false
r_6_2_22 if {
	no_unauthorized_role("EXECUTE_CATALOG_ROLE")
}

violations contains "6.2.22: Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_2_22
}

# 6.3.1 (Manual)
default r_6_3_1 := false
r_6_3_1 if {
	input.oracle.attest.schema_privileges_reviewed == true
}

violations contains "6.3.1: Ensure 'CDB_SCHEMA_PRIVS' Does Not Have Unauthorized Privileges" if {
	not r_6_3_1
}

# 6.4.1 (Automated)
default r_6_4_1 := false
r_6_4_1 if {
	is_array(input.oracle.grants.tab_privs)
	count([g | some g in input.oracle.grants.tab_privs; g.owner == "SYS"; g.table_name in ["CDB_LOCAL_ADMINAUTH$", "DEFAULT_PWD$", "ENC$", "HISTGRM$", "HIST_HEAD$", "LINK$", "PDB_SYNC$", "SCHEDULER$_CREDENTIAL", "USER$", "USER_HISTORY$", "XS$VERIFIERS"]; g.privilege == "ALL"]) == 0
}

violations contains "6.4.1: Ensure 'ALL' Is Revoked On 'Sensitive' Tables" if {
	not r_6_4_1
}

# 6.5.1 (Manual)
default r_6_5_1 := false
r_6_5_1 if {
	input.oracle.attest.column_privileges_reviewed == true
}

violations contains "6.5.1: Ensure ‘DBA_COL_PRIVS’ Is Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_5_1
}

# 6.6.1 (Manual)
default r_6_6_1 := false
r_6_6_1 if {
	input.oracle.attest.proxy_user_privileges_reviewed == true
}

violations contains "6.6.1: Ensure Proxy User Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_6_1
}

# 6.7.1 (Manual)
default r_6_7_1 := false
r_6_7_1 if {
	input.oracle.attest.custom_java_privileges_reviewed == true
}

violations contains "6.7.1: Ensure Custom Java Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	not r_6_7_1
}

# 6.8.1 (Manual)
default r_6_8_1 := false
r_6_8_1 if {
	input.oracle.attest.directory_object_access_reviewed == true
}

violations contains "6.8.1: Ensure Directory Object Access Is Revoked From Unauthorized ‘GRANTEE’" if {
	not r_6_8_1
}

violations contains "CIS Oracle 23ai: FAIL-CLOSED - facts 'input.oracle' were not supplied; the database was not evaluated" if {
	not input.oracle
}

sections := {
 "1": "Oracle Database Installation and Patching Requirements",
 "2": "Oracle Parameter Settings",
 "3": "Oracle Connection and Login Restrictions",
 "4": "Oracle User Access and Authorization Restrictions",
 "5": "Audit/Logging Policies and Procedures",
 "6": "Oracle Privileges"
}

compliance_report := {
	"benchmark": "CIS Oracle Database 23ai Benchmark v1.0.0",
	"total_controls": 87,
	"standard_total": 87,
	"standard_total_source": "CIS Oracle Database 23ai Benchmark v1.0.0, recommendations counted from the benchmark text",
	"sections": sections,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
