# METADATA
# title: "CIS Oracle Database 26ai Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_oracle_26ai
#   source: cis
#   domains: [database, oracle]
#   coverage:
#     checks: 189
#     cited: 95
#     expected: 94
#     found: 95
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis.oracle_26ai

# CIS Oracle Database 26ai Benchmark v1.0.0 (CIS renamed the Oracle Database 23ai benchmark to 26ai; supersedes cis.oracle_23ai).
# 94 recommendations (81 Automated, 13 Manual), every one in the benchmark; ids, titles,
# status and profiles read from the CIS workbook and the logic written from each audit procedure
# (tools/cis_generators/gen_oracle_db_26ai.py). All recommendations are Level 1.
# Profiles: 78 are 'Level 1 - RDBMS'; the 16 host-file recommendations (2.1, 2.2)
# are 'Level 1 - RDBMS On Linux Host OS' and, identically, 'Level 1 - RDBMS On Windows Server Host OS'.
# As in 23ai, one package evaluates every profile; `recommendations` lists each id's status and profiles.
# 11 Manual reviews carry an attestation boolean (not attested => violation). 1.1 and 2.2.9 are
# Manual in the workbook but have a decidable fact, so they are checked like Automated ones.
# Automated checks fail closed: facts not collected => '<id>: evidence missing — <field> not collected'.
#
# Input contract (same as cis.oracle_23ai and benchmarks/stig/oracle_database_19c, so one collector feeds all):
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

# 3.3: a password limit in days; UNLIMITED counts as 9999 days (so it always fails), as the benchmark does.
# A missing or non-numeric limit is undefined, so the profile fails.
_limit_days(v) := 9999 if upper(sprintf("%v", [v])) == "UNLIMITED"

_limit_days(v) := to_number(v) if upper(sprintf("%v", [v])) != "UNLIMITED"

profiles_every_life_plus_grace_le(max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		_limit_days(p.PASSWORD_LIFE_TIME) + _limit_days(p.PASSWORD_GRACE_TIME) <= max
	}
}

# Privileges: the benchmark's queries list grants to grantees that are not ORACLE_MAINTAINED; a grant to a
# grantee the organization has authorized (input.oracle.authorized_grantees) is not a finding. The queries
# also follow role hierarchies; the collector is expected to flatten role-inherited grants into these rows.
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

# 1.1 (Manual, Level 1 - RDBMS)
default r_1_1 := false
r_1_1 if {
	input.oracle.patches.latest_cpu_applied == true
}

default e_1_1 := false
e_1_1 if {
	is_boolean(input.oracle.patches.latest_cpu_applied)
}

violations contains "1.1: evidence missing — oracle.patches.latest_cpu_applied not collected" if {
	not e_1_1
}

violations contains "1.1: Ensure That Appropriate Version/Patches For Oracle Software Are Installed" if {
	e_1_1
	not r_1_1
}

# 2.1.1 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_1_1 := false
r_2_1_1 if {
	input.oracle.listener.extproc_configured == false
}

default e_2_1_1 := false
e_2_1_1 if {
	is_boolean(input.oracle.listener.extproc_configured)
}

violations contains "2.1.1: evidence missing — oracle.listener.extproc_configured not collected" if {
	not e_2_1_1
}

violations contains "2.1.1: Ensure 'extproc' Is Not Present In 'listener.ora'" if {
	e_2_1_1
	not r_2_1_1
}

# 2.1.2 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_1_2 := false
r_2_1_2 if {
	upper(object.get(input.oracle.listener_ora, "ACCEPT_MD5_CERTS", "FALSE")) != "TRUE"
}

default e_2_1_2 := false
e_2_1_2 if {
	is_object(input.oracle.listener_ora)
	count(input.oracle.listener_ora) > 0
}

violations contains "2.1.2: evidence missing — oracle.listener_ora not collected" if {
	not e_2_1_2
}

violations contains "2.1.2: Ensure 'ACCEPT_MD5_CERTS' Is Configured Correctly" if {
	e_2_1_2
	not r_2_1_2
}

# 2.1.3 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_1_3 := false
r_2_1_3 if {
	upper(object.get(input.oracle.listener_ora, "ACCEPT_SHA1_CERTS", "FALSE")) != "TRUE"
}

default e_2_1_3 := false
e_2_1_3 if {
	is_object(input.oracle.listener_ora)
	count(input.oracle.listener_ora) > 0
}

violations contains "2.1.3: evidence missing — oracle.listener_ora not collected" if {
	not e_2_1_3
}

violations contains "2.1.3: Ensure 'ACCEPT_SHA1_CERTS' Is Configured Correctly" if {
	e_2_1_3
	not r_2_1_3
}

# 2.1.4 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_1_4 := false
r_2_1_4 if {
	upper(object.get(input.oracle.listener_ora, "ALLOWED_WEAK_CERT_ALGORITHMS", "FALSE")) != "TRUE"
}

default e_2_1_4 := false
e_2_1_4 if {
	is_object(input.oracle.listener_ora)
	count(input.oracle.listener_ora) > 0
}

violations contains "2.1.4: evidence missing — oracle.listener_ora not collected" if {
	not e_2_1_4
}

violations contains "2.1.4: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS’ Is NOT Set." if {
	e_2_1_4
	not r_2_1_4
}

# 2.2.1 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_1 := false
r_2_2_1 if {
	upper(object.get(input.oracle.sqlnet, "ACCEPT_MD5_CERTS", "FALSE")) != "TRUE"
}

default e_2_2_1 := false
e_2_2_1 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.1: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_1
}

violations contains "2.2.1: Ensure 'ACCEPT_MD5_CERTS' Is NOT SET" if {
	e_2_2_1
	not r_2_2_1
}

# 2.2.2 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_2 := false
r_2_2_2 if {
	upper(object.get(input.oracle.sqlnet, "ACCEPT_SHA1_CERTS", "FALSE")) != "TRUE"
}

default e_2_2_2 := false
e_2_2_2 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.2: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_2
}

violations contains "2.2.2: Ensure 'ACCEPT_SHA1_CERTS' Is NOT Set" if {
	e_2_2_2
	not r_2_2_2
}

# 2.2.3 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_3 := false
r_2_2_3 if {
	upper(object.get(input.oracle.sqlnet, "ALLOWED_WEAK_CERT_ALGORITHMS", "FALSE")) != "TRUE"
}

default e_2_2_3 := false
e_2_2_3 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.3: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_3
}

violations contains "2.2.3: Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS' Is NOT Set" if {
	e_2_2_3
	not r_2_2_3
}

# 2.2.4 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_4 := false
r_2_2_4 if {
	upper(input.oracle.sqlnet["SQLNET.ALLOWED_LOGON_VERSION_CLIENT"]) == "12A"
}

default e_2_2_4 := false
e_2_2_4 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.4: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_4
}

violations contains "2.2.4: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_CLIENT' Is Set To 12a" if {
	e_2_2_4
	not r_2_2_4
}

# 2.2.5 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_5 := false
r_2_2_5 if {
	upper(input.oracle.sqlnet["SQLNET.ALLOWED_LOGON_VERSION_SERVER"]) == "12A"
}

default e_2_2_5 := false
e_2_2_5 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.5: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_5
}

violations contains "2.2.5: Ensure 'SQLNET.ALLOWED_LOGON_VERSION_SERVER' Is Set To 12a" if {
	e_2_2_5
	not r_2_2_5
}

# 2.2.6 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_6 := false
r_2_2_6 if {
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_CLIENT"]) == "REQUIRED"
}

default e_2_2_6 := false
e_2_2_6 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.6: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_6
}

violations contains "2.2.6: Ensure 'SQLNET.ENCRYPTION_CLIENT Is Set To 'REQUIRED'" if {
	e_2_2_6
	not r_2_2_6
}

# 2.2.7 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_7 := false
r_2_2_7 if {
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_SERVER"]) == "REQUIRED"
}

default e_2_2_7 := false
e_2_2_7 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.7: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_7
}

violations contains "2.2.7: Ensure 'SQLNET.ENCRYPTION_SERVER' Is Set To 'REQUIRED'" if {
	e_2_2_7
	not r_2_2_7
}

# 2.2.8 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_8 := false
r_2_2_8 if {
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_TYPES_CLIENT"]) == "AES256"
}

default e_2_2_8 := false
e_2_2_8 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.8: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_8
}

violations contains "2.2.8: Ensure 'SQLNET.ENCRYPTION_TYPES_CLIENT' Is Set To 'AES256'" if {
	e_2_2_8
	not r_2_2_8
}

# 2.2.9 (Manual, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_9 := false
r_2_2_9 if {
	upper(input.oracle.sqlnet["SQLNET.ENCRYPTION_TYPES_SERVER"]) == "AES256"
}

default e_2_2_9 := false
e_2_2_9 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.9: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_9
}

violations contains "2.2.9: Ensure 'SQLNET.ENCRYPTION_TYPES_SERVER' Is Set To AES256" if {
	e_2_2_9
	not r_2_2_9
}

# 2.2.10 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_10 := false
r_2_2_10 if {
	upper(input.oracle.sqlnet["SQLNET.CRYPTO_CHECKSUM_CLIENT"]) == "REQUIRED"
}

default e_2_2_10 := false
e_2_2_10 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.10: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_10
}

violations contains "2.2.10: Ensure 'SQLNET.CRYPTO_CHECKSUM_CLIENT' Is Set To 'REQUIRED'" if {
	e_2_2_10
	not r_2_2_10
}

# 2.2.11 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_11 := false
r_2_2_11 if {
	upper(input.oracle.sqlnet["SQLNET.CRYPTO_CHECKSUM_SERVER"]) == "REQUIRED"
}

default e_2_2_11 := false
e_2_2_11 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.11: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_11
}

violations contains "2.2.11: Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set To 'REQUIRED'" if {
	e_2_2_11
	not r_2_2_11
}

# 2.2.12 (Automated, Level 1 - RDBMS On Linux Host OS; Level 1 - RDBMS On Windows Server Host OS)
default r_2_2_12 := false
r_2_2_12 if {
	upper(input.oracle.sqlnet["SSL_CERT_REVOCATION"]) == "REQUIRED"
}

default e_2_2_12 := false
e_2_2_12 if {
	is_object(input.oracle.sqlnet)
	count(input.oracle.sqlnet) > 0
}

violations contains "2.2.12: evidence missing — oracle.sqlnet not collected" if {
	not e_2_2_12
}

violations contains "2.2.12: Ensure 'SSL_CERT_REVOCATION' Is Set To 'REQUIRED'" if {
	e_2_2_12
	not r_2_2_12
}

# 2.3.1 (Automated, Level 1 - RDBMS)
default r_2_3_1 := false
r_2_3_1 if {
	upper(object.get(input.oracle.parameters, "background_core_dump", "")) != "FULL"
}

default e_2_3_1 := false
e_2_3_1 if {
	is_object(input.oracle.parameters)
	count(input.oracle.parameters) > 0
}

violations contains "2.3.1: evidence missing — oracle.parameters not collected" if {
	not e_2_3_1
}

violations contains "2.3.1: Ensure 'BACKGROUND_CORE_DUMP' Is Not Set To 'Full'" if {
	e_2_3_1
	not r_2_3_1
}

# 2.3.2 (Automated, Level 1 - RDBMS)
default r_2_3_2 := false
r_2_3_2 if {
	upper(object.get(input.oracle.parameters, "shadow_core_dump", "")) != "FULL"
}

default e_2_3_2 := false
e_2_3_2 if {
	is_object(input.oracle.parameters)
	count(input.oracle.parameters) > 0
}

violations contains "2.3.2: evidence missing — oracle.parameters not collected" if {
	not e_2_3_2
}

violations contains "2.3.2: Ensure 'SHADOW_CORE_DUMP' Is Not Set To 'Full'" if {
	e_2_3_2
	not r_2_3_2
}

# 2.3.3 (Automated, Level 1 - RDBMS)
default r_2_3_3 := false
r_2_3_3 if {
	upper(input.oracle.parameters["mle_prog_languages"]) == "OFF"
}

default e_2_3_3 := false
e_2_3_3 if {
	"mle_prog_languages" in object.keys(input.oracle.parameters)
}

violations contains "2.3.3: evidence missing — oracle.parameters.mle_prog_languages not collected" if {
	not e_2_3_3
}

violations contains "2.3.3: Ensure 'MLE_PROG_LANGUAGES' Is Set To 'OFF'" if {
	e_2_3_3
	not r_2_3_3
}

# 2.3.4 (Automated, Level 1 - RDBMS)
default r_2_3_4 := false
r_2_3_4 if {
	upper(input.oracle.parameters["allow_group_access_to_sga"]) == "FALSE"
}

default e_2_3_4 := false
e_2_3_4 if {
	"allow_group_access_to_sga" in object.keys(input.oracle.parameters)
}

violations contains "2.3.4: evidence missing — oracle.parameters.allow_group_access_to_sga not collected" if {
	not e_2_3_4
}

violations contains "2.3.4: Ensure 'ALLOW_GROUP_ACCESS_TO_SGA' Is Set To `FALSE`" if {
	e_2_3_4
	not r_2_3_4
}

# 2.3.5 (Manual, Level 1 - RDBMS)
default r_2_3_5 := false
r_2_3_5 if {
	input.oracle.attest.underscore_parameters_reviewed == true
}

violations contains "2.3.5: Review Undocumented (Underscore) Parameters Not Set To 'DEFAULT' Values (manual review not attested)" if {
	not r_2_3_5
}

# 2.3.6 (Automated, Level 1 - RDBMS)
default r_2_3_6 := false
r_2_3_6 if {
	upper(input.oracle.parameters["os_roles"]) == "FALSE"
}

default e_2_3_6 := false
e_2_3_6 if {
	"os_roles" in object.keys(input.oracle.parameters)
}

violations contains "2.3.6: evidence missing — oracle.parameters.os_roles not collected" if {
	not e_2_3_6
}

violations contains "2.3.6: Ensure 'OS_ROLES' Is Set To 'FALSE'" if {
	e_2_3_6
	not r_2_3_6
}

# 2.3.7 (Automated, Level 1 - RDBMS)
default r_2_3_7 := false
r_2_3_7 if {
	upper(input.oracle.parameters["remote_os_roles"]) == "FALSE"
}

default e_2_3_7 := false
e_2_3_7 if {
	"remote_os_roles" in object.keys(input.oracle.parameters)
}

violations contains "2.3.7: evidence missing — oracle.parameters.remote_os_roles not collected" if {
	not e_2_3_7
}

violations contains "2.3.7: Ensure 'REMOTE_OS_ROLES' Is Set To 'FALSE'" if {
	e_2_3_7
	not r_2_3_7
}

# 2.3.8 (Automated, Level 1 - RDBMS)
default r_2_3_8 := false
r_2_3_8 if {
	to_number(input.oracle.parameters["sec_max_failed_login_attempts"]) <= 3
}

default e_2_3_8 := false
e_2_3_8 if {
	"sec_max_failed_login_attempts" in object.keys(input.oracle.parameters)
}

violations contains "2.3.8: evidence missing — oracle.parameters.sec_max_failed_login_attempts not collected" if {
	not e_2_3_8
}

violations contains "2.3.8: Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is Set To '3' Or Less" if {
	e_2_3_8
	not r_2_3_8
}

# 2.3.9 (Automated, Level 1 - RDBMS)
default r_2_3_9 := false
r_2_3_9 if {
	upper(input.oracle.parameters["sec_protocol_error_further_action"]) in {"(DROP,3)", "(DROP, 3)"}
}

default e_2_3_9 := false
e_2_3_9 if {
	"sec_protocol_error_further_action" in object.keys(input.oracle.parameters)
}

violations contains "2.3.9: evidence missing — oracle.parameters.sec_protocol_error_further_action not collected" if {
	not e_2_3_9
}

violations contains "2.3.9: Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set To '(DROP,3)'" if {
	e_2_3_9
	not r_2_3_9
}

# 2.3.10 (Automated, Level 1 - RDBMS)
default r_2_3_10 := false
r_2_3_10 if {
	upper(input.oracle.parameters["sec_protocol_error_trace_action"]) == "LOG"
}

default e_2_3_10 := false
e_2_3_10 if {
	"sec_protocol_error_trace_action" in object.keys(input.oracle.parameters)
}

violations contains "2.3.10: evidence missing — oracle.parameters.sec_protocol_error_trace_action not collected" if {
	not e_2_3_10
}

violations contains "2.3.10: Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set To 'LOG'" if {
	e_2_3_10
	not r_2_3_10
}

# 2.3.11 (Automated, Level 1 - RDBMS)
default r_2_3_11 := false
r_2_3_11 if {
	upper(input.oracle.parameters["sec_return_server_release_banner"]) == "FALSE"
}

default e_2_3_11 := false
e_2_3_11 if {
	"sec_return_server_release_banner" in object.keys(input.oracle.parameters)
}

violations contains "2.3.11: evidence missing — oracle.parameters.sec_return_server_release_banner not collected" if {
	not e_2_3_11
}

violations contains "2.3.11: Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set To 'FALSE'" if {
	e_2_3_11
	not r_2_3_11
}

# 2.3.12 (Automated, Level 1 - RDBMS)
default r_2_3_12 := false
r_2_3_12 if {
	upper(input.oracle.parameters["remote_login_passwordfile"]) == "NONE"
}

default e_2_3_12 := false
e_2_3_12 if {
	"remote_login_passwordfile" in object.keys(input.oracle.parameters)
}

violations contains "2.3.12: evidence missing — oracle.parameters.remote_login_passwordfile not collected" if {
	not e_2_3_12
}

violations contains "2.3.12: Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set To 'NONE'" if {
	e_2_3_12
	not r_2_3_12
}

# 2.3.13 (Automated, Level 1 - RDBMS)
default r_2_3_13 := false
r_2_3_13 if {
	object.get(input.oracle.parameters, "remote_listener", "") == ""
}

default e_2_3_13 := false
e_2_3_13 if {
	is_object(input.oracle.parameters)
	count(input.oracle.parameters) > 0
}

violations contains "2.3.13: evidence missing — oracle.parameters not collected" if {
	not e_2_3_13
}

violations contains "2.3.13: Ensure 'REMOTE_LISTENER' Is Empty" if {
	e_2_3_13
	not r_2_3_13
}

# 2.3.14 (Automated, Level 1 - RDBMS)
default r_2_3_14 := false
r_2_3_14 if {
	upper(input.oracle.parameters["resource_limit"]) == "TRUE"
}

default e_2_3_14 := false
e_2_3_14 if {
	"resource_limit" in object.keys(input.oracle.parameters)
}

violations contains "2.3.14: evidence missing — oracle.parameters.resource_limit not collected" if {
	not e_2_3_14
}

violations contains "2.3.14: Ensure 'RESOURCE_LIMIT' Is Set To 'TRUE'" if {
	e_2_3_14
	not r_2_3_14
}

# 3.1 (Automated, Level 1 - RDBMS)
default r_3_1 := false
r_3_1 if {
	profiles_every_le("FAILED_LOGIN_ATTEMPTS", 5)
}

default e_3_1 := false
e_3_1 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.1: evidence missing — oracle.profiles not collected" if {
	not e_3_1
}

violations contains "3.1: Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less Than Or Equal To '5'" if {
	e_3_1
	not r_3_1
}

# 3.2 (Automated, Level 1 - RDBMS)
default r_3_2 := false
r_3_2 if {
	profiles_every_ge("PASSWORD_LOCK_TIME", 1)
}

default e_3_2 := false
e_3_2 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.2: evidence missing — oracle.profiles not collected" if {
	not e_3_2
}

violations contains "3.2: Ensure 'PASSWORD_LOCK_TIME' Is Greater Than Or Equal To '1'" if {
	e_3_2
	not r_3_2
}

# 3.3 (Automated, Level 1 - RDBMS)
default r_3_3 := false
r_3_3 if {
	profiles_every_life_plus_grace_le(365)
}

default e_3_3 := false
e_3_3 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.3: evidence missing — oracle.profiles not collected" if {
	not e_3_3
}

violations contains "3.3: Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'" if {
	e_3_3
	not r_3_3
}

# 3.4 (Automated, Level 1 - RDBMS)
default r_3_4 := false
r_3_4 if {
	profiles_every_eq("PASSWORD_REUSE_MAX", "UNLIMITED")
}

default e_3_4 := false
e_3_4 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.4: evidence missing — oracle.profiles not collected" if {
	not e_3_4
}

violations contains "3.4: Ensure 'PASSWORD_REUSE_MAX' Is Set To 'UNLIMITED'" if {
	e_3_4
	not r_3_4
}

# 3.5 (Automated, Level 1 - RDBMS)
default r_3_5 := false
r_3_5 if {
	profiles_every_set("PASSWORD_VERIFY_FUNCTION")
}

default e_3_5 := false
e_3_5 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.5: evidence missing — oracle.profiles not collected" if {
	not e_3_5
}

violations contains "3.5: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set For All Profiles" if {
	e_3_5
	not r_3_5
}

# 3.6 (Manual, Level 1 - RDBMS)
default r_3_6 := false
r_3_6 if {
	input.oracle.attest.password_verify_function_meets_cis == true
}

violations contains "3.6: Ensure 'PASSWORD_VERIFY_FUNCTION' Is Configured Correctly (manual review not attested)" if {
	not r_3_6
}

# 3.7 (Automated, Level 1 - RDBMS)
default r_3_7 := false
r_3_7 if {
	profiles_every_le("PASSWORD_ROLLOVER_TIME", 0)
}

default e_3_7 := false
e_3_7 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.7: evidence missing — oracle.profiles not collected" if {
	not e_3_7
}

violations contains "3.7: Ensure 'PASSWORD_ROLLOVER_TIME' Is set to '0'" if {
	e_3_7
	not r_3_7
}

# 3.8 (Automated, Level 1 - RDBMS)
default r_3_8 := false
r_3_8 if {
	profiles_every_le("INACTIVE_ACCOUNT_TIME", 120)
}

default e_3_8 := false
e_3_8 if {
	is_object(input.oracle.profiles)
	count(input.oracle.profiles) > 0
}

violations contains "3.8: evidence missing — oracle.profiles not collected" if {
	not e_3_8
}

violations contains "3.8: Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120'" if {
	e_3_8
	not r_3_8
}

# 4.1 (Automated, Level 1 - RDBMS)
default r_4_1 := false
r_4_1 if {
	count(input.oracle.users_with_default_password) == 0
}

default e_4_1 := false
e_4_1 if {
	is_array(input.oracle.users_with_default_password)
}

violations contains "4.1: evidence missing — oracle.users_with_default_password not collected" if {
	not e_4_1
}

violations contains "4.1: Ensure All Default Passwords Are Changed" if {
	e_4_1
	not r_4_1
}

# 4.2 (Automated, Level 1 - RDBMS)
default r_4_2 := false
r_4_2 if {
	count(input.oracle.custom_oracle_maintained_users) == 0
}

default e_4_2 := false
e_4_2 if {
	is_array(input.oracle.custom_oracle_maintained_users)
}

violations contains "4.2: evidence missing — oracle.custom_oracle_maintained_users not collected" if {
	not e_4_2
}

violations contains "4.2: Ensure No Custom 'ORACLE_MAINTAINED' Users Exist" if {
	e_4_2
	not r_4_2
}

# 4.3 (Manual, Level 1 - RDBMS)
default r_4_3 := false
r_4_3 if {
	input.oracle.attest.ras_users_reviewed == true
}

violations contains "4.3: Review The Users Created Through Real Application Security (manual review not attested)" if {
	not r_4_3
}

# 4.4 (Automated, Level 1 - RDBMS)
default r_4_4 := false
r_4_4 if {
	count(input.oracle.users_with_old_password_versions) == 0
}

default e_4_4 := false
e_4_4 if {
	is_array(input.oracle.users_with_old_password_versions)
}

violations contains "4.4: evidence missing — oracle.users_with_old_password_versions not collected" if {
	not e_4_4
}

violations contains "4.4: Ensure Old Password Versions Are Not Used" if {
	e_4_4
	not r_4_4
}

# 4.5 (Automated, Level 1 - RDBMS)
default r_4_5 := false
r_4_5 if {
	input.oracle.password_file_format == "12.2"
}

default e_4_5 := false
e_4_5 if {
	is_string(input.oracle.password_file_format)
}

violations contains "4.5: evidence missing — oracle.password_file_format not collected" if {
	not e_4_5
}

violations contains "4.5: Ensure The Latest Version of The Password File Is Used" if {
	e_4_5
	not r_4_5
}

# 4.6 (Automated, Level 1 - RDBMS)
default r_4_6 := false
r_4_6 if {
	count(input.oracle.pwfile_users_not_on_all_instances) == 0
}

default e_4_6 := false
e_4_6 if {
	is_array(input.oracle.pwfile_users_not_on_all_instances)
}

violations contains "4.6: evidence missing — oracle.pwfile_users_not_on_all_instances not collected" if {
	not e_4_6
}

violations contains "4.6: Ensure That Users In Different RAC Instances Are Identical In PW Files" if {
	e_4_6
	not r_4_6
}

# 4.7 (Automated, Level 1 - RDBMS)
default r_4_7 := false
r_4_7 if {
	count(input.oracle.public_db_links) == 0
}

default e_4_7 := false
e_4_7 if {
	is_array(input.oracle.public_db_links)
}

violations contains "4.7: evidence missing — oracle.public_db_links not collected" if {
	not e_4_7
}

violations contains "4.7: Ensure No Public Database Links Exist" if {
	e_4_7
	not r_4_7
}

# 4.8 (Automated, Level 1 - RDBMS)
default r_4_8 := false
r_4_8 if {
	count(input.oracle.db_links_with_legacy_password_encryption) == 0
}

default e_4_8 := false
e_4_8 if {
	is_array(input.oracle.db_links_with_legacy_password_encryption)
}

violations contains "4.8: evidence missing — oracle.db_links_with_legacy_password_encryption not collected" if {
	not e_4_8
}

violations contains "4.8: Ensure That Database Link Passwords Are Using The Latest Encryption" if {
	e_4_8
	not r_4_8
}

# 5.1 (Automated, Level 1 - RDBMS)
default r_5_1 := false
r_5_1 if {
	count(input.oracle.audit.unaudited_system_actions) == 0
}

default e_5_1 := false
e_5_1 if {
	is_array(input.oracle.audit.unaudited_system_actions)
}

violations contains "5.1: evidence missing — oracle.audit.unaudited_system_actions not collected" if {
	not e_5_1
}

violations contains "5.1: Ensure All Auditable System Actions Commands Are Audited" if {
	e_5_1
	not r_5_1
}

# 5.2 (Automated, Level 1 - RDBMS)
default r_5_2 := false
r_5_2 if {
	every a in ["LOGON", "LOGOFF"] { a in input.oracle.audit.enabled_options }
}

default e_5_2 := false
e_5_2 if {
	is_array(input.oracle.audit.enabled_options)
}

violations contains "5.2: evidence missing — oracle.audit.enabled_options not collected" if {
	not e_5_2
}

violations contains "5.2: Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled" if {
	e_5_2
	not r_5_2
}

# 5.3 (Automated, Level 1 - RDBMS)
default r_5_3 := false
r_5_3 if {
	every a in ["DBMS_AW", "DBMS_CRYPTO", "DBMS_FGA", "DBMS_JAVA_TEST", "DBMS_JOB", "DBMS_LOGMNR", "DBMS_NETWORK_ACL_ADMIN", "DBMS_REDACT", "DBMS_REDEFINITION", "DBMS_RLS", "DBMS_SCHEDULER", "DBMS_SQL_TRANSLATOR", "DBMS_SYS_SQL", "DBMS_TSDP_MANAGE", "DBMS_TSDP_PROTECT", "DBMS_XMLGEN", "DBMS_XMLSTORE", "OWA_UTIL"] { a in input.oracle.audit.audited_packages }
}

default e_5_3 := false
e_5_3 if {
	is_array(input.oracle.audit.audited_packages)
}

violations contains "5.3: evidence missing — oracle.audit.audited_packages not collected" if {
	not e_5_3
}

violations contains "5.3: Ensure Critical Packages Are Audited" if {
	e_5_3
	not r_5_3
}

# 5.4 (Automated, Level 1 - RDBMS)
default r_5_4 := false
r_5_4 if {
	every a in ["EXPORT"] { a in input.oracle.audit.enabled_options }
}

default e_5_4 := false
e_5_4 if {
	is_array(input.oracle.audit.enabled_options)
}

violations contains "5.4: evidence missing — oracle.audit.enabled_options not collected" if {
	not e_5_4
}

violations contains "5.4: Ensure All Export Activities Are Audited" if {
	e_5_4
	not r_5_4
}

# 5.5 (Automated, Level 1 - RDBMS)
default r_5_5 := false
r_5_5 if {
	every a in ["SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "PUBLIC"] { a in input.oracle.audit.all_actions_audited_users }
}

default e_5_5 := false
e_5_5 if {
	is_array(input.oracle.audit.all_actions_audited_users)
}

violations contains "5.5: evidence missing — oracle.audit.all_actions_audited_users not collected" if {
	not e_5_5
}

violations contains "5.5: Ensure The Use Of SYS* Privileges Is Audited" if {
	e_5_5
	not r_5_5
}

# 6.1.1 (Automated, Level 1 - RDBMS)
default r_6_1_1 := false
r_6_1_1 if {
	no_unauthorized_sys_priv_like("ANY")
}

default e_6_1_1 := false
e_6_1_1 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.1: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_1
}

violations contains "6.1.1: Ensure '%ANY%' Is Revoked from Unauthorized 'GRANTEE'" if {
	e_6_1_1
	not r_6_1_1
}

# 6.1.2 (Automated, Level 1 - RDBMS)
default r_6_1_2 := false
r_6_1_2 if {
	count([g | some g in input.oracle.grants.sys_privs; g.admin_option == true; _unauthorized(g)]) == 0
}

default e_6_1_2 := false
e_6_1_2 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.2: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_2
}

violations contains "6.1.2: Ensure Admin Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	e_6_1_2
	not r_6_1_2
}

# 6.1.3 (Automated, Level 1 - RDBMS)
default r_6_1_3 := false
r_6_1_3 if {
	no_unauthorized_sys_priv("EXPORT FULL DATABASE")
	no_unauthorized_sys_priv("IMPORT FULL DATABASE")
}

default e_6_1_3 := false
e_6_1_3 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.3: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_3
}

violations contains "6.1.3: Ensure 'IMPORT' And 'EXPORT' 'FULL DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_3
	not r_6_1_3
}

# 6.1.4 (Automated, Level 1 - RDBMS)
default r_6_1_4 := false
r_6_1_4 if {
	no_unauthorized_sys_priv("CREATE EXTERNAL JOB")
}

default e_6_1_4 := false
e_6_1_4 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.4: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_4
}

violations contains "6.1.4: Ensure 'CREATE EXTERNAL JOB' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_4
	not r_6_1_4
}

# 6.1.5 (Automated, Level 1 - RDBMS)
default r_6_1_5 := false
r_6_1_5 if {
	no_unauthorized_sys_priv("BECOME USER")
}

default e_6_1_5 := false
e_6_1_5 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.5: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_5
}

violations contains "6.1.5: Ensure 'BECOME USER' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_5
	not r_6_1_5
}

# 6.1.6 (Automated, Level 1 - RDBMS)
default r_6_1_6 := false
r_6_1_6 if {
	no_unauthorized_sys_priv("TEXT DATASTORE ACCESS")
}

default e_6_1_6 := false
e_6_1_6 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.6: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_6
}

violations contains "6.1.6: Ensure 'TEXT DATASTORE ACCESS' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_6
	not r_6_1_6
}

# 6.1.7 (Automated, Level 1 - RDBMS)
default r_6_1_7 := false
r_6_1_7 if {
	no_unauthorized_sys_priv("CREATE PUBLIC DATABASE LINK")
	no_unauthorized_sys_priv("ALTER PUBLIC DATABASE LINK")
	no_unauthorized_sys_priv("DROP PUBLIC DATABASE LINK")
}

default e_6_1_7 := false
e_6_1_7 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.7: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_7
}

violations contains "6.1.7: Ensure 'CREATE', 'ALTER', And 'DROP' 'PUBLIC DATABASE LINK' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_7
	not r_6_1_7
}

# 6.1.8 (Automated, Level 1 - RDBMS)
default r_6_1_8 := false
r_6_1_8 if {
	no_unauthorized_sys_priv("LOGMINING")
}

default e_6_1_8 := false
e_6_1_8 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.8: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_8
}

violations contains "6.1.8: Ensure 'LOGMINING' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_8
	not r_6_1_8
}

# 6.1.9 (Automated, Level 1 - RDBMS)
default r_6_1_9 := false
r_6_1_9 if {
	no_unauthorized_sys_priv("ALTER SYSTEM")
}

default e_6_1_9 := false
e_6_1_9 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.9: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_9
}

violations contains "6.1.9: Ensure 'ALTER SYSTEM' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_9
	not r_6_1_9
}

# 6.1.10 (Automated, Level 1 - RDBMS)
default r_6_1_10 := false
r_6_1_10 if {
	no_unauthorized_sys_priv("CREATE LIBRARY")
}

default e_6_1_10 := false
e_6_1_10 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.10: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_10
}

violations contains "6.1.10: Ensure 'CREATE LIBRARY' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_1_10
	not r_6_1_10
}

# 6.1.11 (Automated, Level 1 - RDBMS)
default r_6_1_11 := false
r_6_1_11 if {
	count([g | some g in input.oracle.grants.sys_privs; _unauthorized(g)]) == 0
}

default e_6_1_11 := false
e_6_1_11 if {
	is_array(input.oracle.grants.sys_privs)
}

violations contains "6.1.11: evidence missing — oracle.grants.sys_privs not collected" if {
	not e_6_1_11
}

violations contains "6.1.11: Ensure All `SYSTEM` Privileges Are Revoked from Unauthorized 'GRANTEE'" if {
	e_6_1_11
	not r_6_1_11
}

# 6.2.1 (Automated, Level 1 - RDBMS)
default r_6_2_1 := false
r_6_2_1 if {
	no_unauthorized_role("DBA")
}

default e_6_2_1 := false
e_6_2_1 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.1: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_1
}

violations contains "6.2.1: Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'" if {
	e_6_2_1
	not r_6_2_1
}

# 6.2.2 (Automated, Level 1 - RDBMS)
default r_6_2_2 := false
r_6_2_2 if {
	no_unauthorized_role("EXP_FULL_DATABASE")
}

default e_6_2_2 := false
e_6_2_2 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.2: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_2
}

violations contains "6.2.2: Ensure 'EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_2
	not r_6_2_2
}

# 6.2.3 (Automated, Level 1 - RDBMS)
default r_6_2_3 := false
r_6_2_3 if {
	no_unauthorized_role("IMP_FULL_DATABASE")
}

default e_6_2_3 := false
e_6_2_3 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.3: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_3
}

violations contains "6.2.3: Ensure 'IMP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_3
	not r_6_2_3
}

# 6.2.4 (Automated, Level 1 - RDBMS)
default r_6_2_4 := false
r_6_2_4 if {
	no_unauthorized_role("DATAPUMP_EXP_FULL_DATABASE")
}

default e_6_2_4 := false
e_6_2_4 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.4: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_4
}

violations contains "6.2.4: Ensure 'DATAPUMP_EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_4
	not r_6_2_4
}

# 6.2.5 (Automated, Level 1 - RDBMS)
default r_6_2_5 := false
r_6_2_5 if {
	no_unauthorized_role("DATAPUMP_IMP_FULL_DATABASE")
}

default e_6_2_5 := false
e_6_2_5 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.5: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_5
}

violations contains "6.2.5: Ensure 'DATAPUMP_IMP_FULL_DATABASE' is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_5
	not r_6_2_5
}

# 6.2.6 (Automated, Level 1 - RDBMS)
default r_6_2_6 := false
r_6_2_6 if {
	no_unauthorized_role("DV_ADMIN")
}

default e_6_2_6 := false
e_6_2_6 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.6: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_6
}

violations contains "6.2.6: Ensure 'DV_ADMIN’ Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_6
	not r_6_2_6
}

# 6.2.7 (Automated, Level 1 - RDBMS)
default r_6_2_7 := false
r_6_2_7 if {
	no_unauthorized_role("DV_AUDIT_CLEANUP")
}

default e_6_2_7 := false
e_6_2_7 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.7: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_7
}

violations contains "6.2.7: Ensure 'DV_AUDIT_CLEANUP’ Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_7
	not r_6_2_7
}

# 6.2.8 (Automated, Level 1 - RDBMS)
default r_6_2_8 := false
r_6_2_8 if {
	no_unauthorized_role("OLAP_DBA")
}

default e_6_2_8 := false
e_6_2_8 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.8: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_8
}

violations contains "6.2.8: Ensure 'OLAP_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_8
	not r_6_2_8
}

# 6.2.9 (Automated, Level 1 - RDBMS)
default r_6_2_9 := false
r_6_2_9 if {
	no_unauthorized_role("LBAC_DBA")
}

default e_6_2_9 := false
e_6_2_9 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.9: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_9
}

violations contains "6.2.9: Ensure 'LBAC_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_9
	not r_6_2_9
}

# 6.2.10 (Automated, Level 1 - RDBMS)
default r_6_2_10 := false
r_6_2_10 if {
	no_unauthorized_role("JAVA_ADMIN")
}

default e_6_2_10 := false
e_6_2_10 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.10: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_10
}

violations contains "6.2.10: Ensure 'JAVA_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_10
	not r_6_2_10
}

# 6.2.11 (Automated, Level 1 - RDBMS)
default r_6_2_11 := false
r_6_2_11 if {
	no_unauthorized_role("JAVASYSPRIVS")
}

default e_6_2_11 := false
e_6_2_11 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.11: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_11
}

violations contains "6.2.11: Ensure 'JAVASYSPRIVS' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_11
	not r_6_2_11
}

# 6.2.12 (Automated, Level 1 - RDBMS)
default r_6_2_12 := false
r_6_2_12 if {
	no_unauthorized_role("LOGSTDBY_ADMINISTRATOR")
}

default e_6_2_12 := false
e_6_2_12 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.12: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_12
}

violations contains "6.2.12: Ensure 'LOGSTDBY_ADMINISTRATOR' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_12
	not r_6_2_12
}

# 6.2.13 (Automated, Level 1 - RDBMS)
default r_6_2_13 := false
r_6_2_13 if {
	no_unauthorized_role("SQL_FIREWALL_ADMIN")
}

default e_6_2_13 := false
e_6_2_13 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.13: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_13
}

violations contains "6.2.13: Ensure 'SQL_FIREWALL_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_13
	not r_6_2_13
}

# 6.2.14 (Automated, Level 1 - RDBMS)
default r_6_2_14 := false
r_6_2_14 if {
	no_unauthorized_role("MAINTPLAN_APP")
}

default e_6_2_14 := false
e_6_2_14 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.14: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_14
}

violations contains "6.2.14: Ensure 'MAINTPLAN_APP' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_14
	not r_6_2_14
}

# 6.2.15 (Automated, Level 1 - RDBMS)
default r_6_2_15 := false
r_6_2_15 if {
	no_unauthorized_role("JAVADEBUGPRIV")
}

default e_6_2_15 := false
e_6_2_15 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.15: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_15
}

violations contains "6.2.15: Ensure 'JAVADEBUGPRIV' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_15
	not r_6_2_15
}

# 6.2.16 (Automated, Level 1 - RDBMS)
default r_6_2_16 := false
r_6_2_16 if {
	no_unauthorized_role("DV_PATCH_ADMIN")
}

default e_6_2_16 := false
e_6_2_16 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.16: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_16
}

violations contains "6.2.16: Ensure 'DV_PATCH_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_16
	not r_6_2_16
}

# 6.2.17 (Automated, Level 1 - RDBMS)
default r_6_2_17 := false
r_6_2_17 if {
	no_unauthorized_role("DV_POLICY_OWNER")
}

default e_6_2_17 := false
e_6_2_17 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.17: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_17
}

violations contains "6.2.17: Ensure 'DV_POLICY_OWNER' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_17
	not r_6_2_17
}

# 6.2.18 (Automated, Level 1 - RDBMS)
default r_6_2_18 := false
r_6_2_18 if {
	no_unauthorized_role("AUDIT_ADMIN")
}

default e_6_2_18 := false
e_6_2_18 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.18: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_18
}

violations contains "6.2.18: Ensure AUDIT_ADMIN' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_18
	not r_6_2_18
}

# 6.2.19 (Automated, Level 1 - RDBMS)
default r_6_2_19 := false
r_6_2_19 if {
	no_unauthorized_role("AUDIT_VIEWER")
}

default e_6_2_19 := false
e_6_2_19 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.19: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_19
}

violations contains "6.2.19: Ensure 'AUDIT_VIEWER' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_19
	not r_6_2_19
}

# 6.2.20 (Automated, Level 1 - RDBMS)
default r_6_2_20 := false
r_6_2_20 if {
	no_unauthorized_role("PDB_DBA")
}

default e_6_2_20 := false
e_6_2_20 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.20: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_20
}

violations contains "6.2.20: Ensure 'PDB_DBA' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_20
	not r_6_2_20
}

# 6.2.21 (Automated, Level 1 - RDBMS)
default r_6_2_21 := false
r_6_2_21 if {
	no_unauthorized_role("SELECT_CATALOG_ROLE")
}

default e_6_2_21 := false
e_6_2_21 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.21: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_21
}

violations contains "6.2.21: Ensure 'SELECT_CATALOG_ROLE' Is Revoked From Unauthorized 'GRANTEE'" if {
	e_6_2_21
	not r_6_2_21
}

# 6.2.22 (Automated, Level 1 - RDBMS)
default r_6_2_22 := false
r_6_2_22 if {
	no_unauthorized_role("EXECUTE_CATALOG_ROLE")
}

default e_6_2_22 := false
e_6_2_22 if {
	is_array(input.oracle.grants.role_privs)
}

violations contains "6.2.22: evidence missing — oracle.grants.role_privs not collected" if {
	not e_6_2_22
}

violations contains "6.2.22: Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE'" if {
	e_6_2_22
	not r_6_2_22
}

# 6.3.1 (Manual, Level 1 - RDBMS)
default r_6_3_1 := false
r_6_3_1 if {
	input.oracle.attest.schema_privileges_reviewed == true
}

violations contains "6.3.1: Ensure 'CDB_SCHEMA_PRIVS' Does Not Have Unauthorized Privileges (manual review not attested)" if {
	not r_6_3_1
}

# 6.4.1 (Automated, Level 1 - RDBMS)
default r_6_4_1 := false
r_6_4_1 if {
	count([g | some g in input.oracle.grants.tab_privs; g.owner == "SYS"; g.table_name in ["CDB_LOCAL_ADMINAUTH$", "DEFAULT_PWD$", "ENC$", "HISTGRM$", "HIST_HEAD$", "LINK$", "PDB_SYNC$", "SCHEDULER$_CREDENTIAL", "USER$", "USER_HISTORY$", "XS$VERIFIERS"]; g.privilege == "ALL"]) == 0
}

default e_6_4_1 := false
e_6_4_1 if {
	is_array(input.oracle.grants.tab_privs)
}

violations contains "6.4.1: evidence missing — oracle.grants.tab_privs not collected" if {
	not e_6_4_1
}

violations contains "6.4.1: Ensure 'ALL' Is Revoked On 'Sensitive' Tables" if {
	e_6_4_1
	not r_6_4_1
}

# 6.5.1 (Manual, Level 1 - RDBMS)
default r_6_5_1 := false
r_6_5_1 if {
	input.oracle.attest.column_privileges_reviewed == true
}

violations contains "6.5.1: Ensure ‘DBA_COL_PRIVS’ Is Revoked from Unauthorized 'GRANTEE' (manual review not attested)" if {
	not r_6_5_1
}

# 6.6.1 (Manual, Level 1 - RDBMS)
default r_6_6_1 := false
r_6_6_1 if {
	input.oracle.attest.proxy_user_privileges_reviewed == true
}

violations contains "6.6.1: Ensure Proxy User Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" if {
	not r_6_6_1
}

# 6.7.1 (Manual, Level 1 - RDBMS)
default r_6_7_1 := false
r_6_7_1 if {
	input.oracle.attest.custom_java_privileges_reviewed == true
}

violations contains "6.7.1: Ensure Custom Java Privileges Are Revoked from Unauthorized 'GRANTEE' (manual review not attested)" if {
	not r_6_7_1
}

# 6.8.1 (Manual, Level 1 - RDBMS)
default r_6_8_1 := false
r_6_8_1 if {
	input.oracle.attest.directory_object_access_reviewed == true
}

violations contains "6.8.1: Ensure Directory Object Access Is Revoked From Unauthorized ‘GRANTEE’ (manual review not attested)" if {
	not r_6_8_1
}

# 6.8.2 (Manual, Level 1 - RDBMS)
default r_6_8_2 := false
r_6_8_2 if {
	input.oracle.attest.directory_object_privileges_reviewed == true
}

violations contains "6.8.2: Review Directory Objects Privileges (manual review not attested)" if {
	not r_6_8_2
}

# 6.8.3 (Manual, Level 1 - RDBMS)
default r_6_8_3 := false
r_6_8_3 if {
	input.oracle.attest.external_table_preprocessors_reviewed == true
}

violations contains "6.8.3: Review External Tables With Preprocessor (manual review not attested)" if {
	not r_6_8_3
}

# 6.8.4 (Manual, Level 1 - RDBMS)
default r_6_8_4 := false
r_6_8_4 if {
	input.oracle.attest.external_tables_reviewed == true
}

violations contains "6.8.4: Review External Tables (manual review not attested)" if {
	not r_6_8_4
}

violations contains "CIS Oracle 26ai: FAIL-CLOSED - facts 'input.oracle' were not supplied; the database was not evaluated" if {
	not input.oracle
}

sections := {
 "1": "Oracle Database Installation and Patching Requirements",
 "2": "Oracle Parameter Settings",
 "3": "Oracle Connection and Login Restrictions",
 "4": "Users",
 "5": "Unified Auditing",
 "6": "Privileges & Grants & ACLs"
}

# id -> CIS title, level, Automated/Manual status and the workbook profiles it belongs to
recommendations := {
 "1.1": {
  "title": "Ensure That Appropriate Version/Patches For Oracle Software Are Installed",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.1.1": {
  "title": "Ensure 'extproc' Is Not Present In 'listener.ora'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.1.2": {
  "title": "Ensure 'ACCEPT_MD5_CERTS' Is Configured Correctly",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.1.3": {
  "title": "Ensure 'ACCEPT_SHA1_CERTS' Is Configured Correctly",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.1.4": {
  "title": "Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS’ Is NOT Set.",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.1": {
  "title": "Ensure 'ACCEPT_MD5_CERTS' Is NOT SET",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.2": {
  "title": "Ensure 'ACCEPT_SHA1_CERTS' Is NOT Set",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.3": {
  "title": "Ensure 'ALLOWED_WEAK_CERT_ALGORITHMS' Is NOT Set",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.4": {
  "title": "Ensure 'SQLNET.ALLOWED_LOGON_VERSION_CLIENT' Is Set To 12a",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.5": {
  "title": "Ensure 'SQLNET.ALLOWED_LOGON_VERSION_SERVER' Is Set To 12a",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.6": {
  "title": "Ensure 'SQLNET.ENCRYPTION_CLIENT Is Set To 'REQUIRED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.7": {
  "title": "Ensure 'SQLNET.ENCRYPTION_SERVER' Is Set To 'REQUIRED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.8": {
  "title": "Ensure 'SQLNET.ENCRYPTION_TYPES_CLIENT' Is Set To 'AES256'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.9": {
  "title": "Ensure 'SQLNET.ENCRYPTION_TYPES_SERVER' Is Set To AES256",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.10": {
  "title": "Ensure 'SQLNET.CRYPTO_CHECKSUM_CLIENT' Is Set To 'REQUIRED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.11": {
  "title": "Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set To 'REQUIRED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.2.12": {
  "title": "Ensure 'SSL_CERT_REVOCATION' Is Set To 'REQUIRED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS On Linux Host OS",
   "Level 1 - RDBMS On Windows Server Host OS"
  ]
 },
 "2.3.1": {
  "title": "Ensure 'BACKGROUND_CORE_DUMP' Is Not Set To 'Full'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.2": {
  "title": "Ensure 'SHADOW_CORE_DUMP' Is Not Set To 'Full'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.3": {
  "title": "Ensure 'MLE_PROG_LANGUAGES' Is Set To 'OFF'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.4": {
  "title": "Ensure 'ALLOW_GROUP_ACCESS_TO_SGA' Is Set To `FALSE`",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.5": {
  "title": "Review Undocumented (Underscore) Parameters Not Set To 'DEFAULT' Values",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.6": {
  "title": "Ensure 'OS_ROLES' Is Set To 'FALSE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.7": {
  "title": "Ensure 'REMOTE_OS_ROLES' Is Set To 'FALSE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.8": {
  "title": "Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is Set To '3' Or Less",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.9": {
  "title": "Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set To '(DROP,3)'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.10": {
  "title": "Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set To 'LOG'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.11": {
  "title": "Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set To 'FALSE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.12": {
  "title": "Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set To 'NONE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.13": {
  "title": "Ensure 'REMOTE_LISTENER' Is Empty",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "2.3.14": {
  "title": "Ensure 'RESOURCE_LIMIT' Is Set To 'TRUE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.1": {
  "title": "Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less Than Or Equal To '5'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.2": {
  "title": "Ensure 'PASSWORD_LOCK_TIME' Is Greater Than Or Equal To '1'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.3": {
  "title": "Ensure 'PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME' Is Less Than Or Equal To '365'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.4": {
  "title": "Ensure 'PASSWORD_REUSE_MAX' Is Set To 'UNLIMITED'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.5": {
  "title": "Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set For All Profiles",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.6": {
  "title": "Ensure 'PASSWORD_VERIFY_FUNCTION' Is Configured Correctly",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.7": {
  "title": "Ensure 'PASSWORD_ROLLOVER_TIME' Is set to '0'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "3.8": {
  "title": "Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.1": {
  "title": "Ensure All Default Passwords Are Changed",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.2": {
  "title": "Ensure No Custom 'ORACLE_MAINTAINED' Users Exist",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.3": {
  "title": "Review The Users Created Through Real Application Security",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.4": {
  "title": "Ensure Old Password Versions Are Not Used",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.5": {
  "title": "Ensure The Latest Version of The Password File Is Used",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.6": {
  "title": "Ensure That Users In Different RAC Instances Are Identical In PW Files",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.7": {
  "title": "Ensure No Public Database Links Exist",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "4.8": {
  "title": "Ensure That Database Link Passwords Are Using The Latest Encryption",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "5.1": {
  "title": "Ensure All Auditable System Actions Commands Are Audited",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "5.2": {
  "title": "Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "5.3": {
  "title": "Ensure Critical Packages Are Audited",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "5.4": {
  "title": "Ensure All Export Activities Are Audited",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "5.5": {
  "title": "Ensure The Use Of SYS* Privileges Is Audited",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.1": {
  "title": "Ensure '%ANY%' Is Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.2": {
  "title": "Ensure Admin Privileges Are Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.3": {
  "title": "Ensure 'IMPORT' And 'EXPORT' 'FULL DATABASE' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.4": {
  "title": "Ensure 'CREATE EXTERNAL JOB' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.5": {
  "title": "Ensure 'BECOME USER' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.6": {
  "title": "Ensure 'TEXT DATASTORE ACCESS' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.7": {
  "title": "Ensure 'CREATE', 'ALTER', And 'DROP' 'PUBLIC DATABASE LINK' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.8": {
  "title": "Ensure 'LOGMINING' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.9": {
  "title": "Ensure 'ALTER SYSTEM' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.10": {
  "title": "Ensure 'CREATE LIBRARY' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.1.11": {
  "title": "Ensure All `SYSTEM` Privileges Are Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.1": {
  "title": "Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.2": {
  "title": "Ensure 'EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.3": {
  "title": "Ensure 'IMP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.4": {
  "title": "Ensure 'DATAPUMP_EXP_FULL_DATABASE' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.5": {
  "title": "Ensure 'DATAPUMP_IMP_FULL_DATABASE' is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.6": {
  "title": "Ensure 'DV_ADMIN’ Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.7": {
  "title": "Ensure 'DV_AUDIT_CLEANUP’ Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.8": {
  "title": "Ensure 'OLAP_DBA' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.9": {
  "title": "Ensure 'LBAC_DBA' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.10": {
  "title": "Ensure 'JAVA_ADMIN' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.11": {
  "title": "Ensure 'JAVASYSPRIVS' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.12": {
  "title": "Ensure 'LOGSTDBY_ADMINISTRATOR' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.13": {
  "title": "Ensure 'SQL_FIREWALL_ADMIN' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.14": {
  "title": "Ensure 'MAINTPLAN_APP' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.15": {
  "title": "Ensure 'JAVADEBUGPRIV' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.16": {
  "title": "Ensure 'DV_PATCH_ADMIN' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.17": {
  "title": "Ensure 'DV_POLICY_OWNER' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.18": {
  "title": "Ensure AUDIT_ADMIN' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.19": {
  "title": "Ensure 'AUDIT_VIEWER' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.20": {
  "title": "Ensure 'PDB_DBA' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.21": {
  "title": "Ensure 'SELECT_CATALOG_ROLE' Is Revoked From Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.2.22": {
  "title": "Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.3.1": {
  "title": "Ensure 'CDB_SCHEMA_PRIVS' Does Not Have Unauthorized Privileges",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.4.1": {
  "title": "Ensure 'ALL' Is Revoked On 'Sensitive' Tables",
  "level": 1,
  "assessment": "Automated",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.5.1": {
  "title": "Ensure ‘DBA_COL_PRIVS’ Is Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.6.1": {
  "title": "Ensure Proxy User Privileges Are Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.7.1": {
  "title": "Ensure Custom Java Privileges Are Revoked from Unauthorized 'GRANTEE'",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.8.1": {
  "title": "Ensure Directory Object Access Is Revoked From Unauthorized ‘GRANTEE’",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.8.2": {
  "title": "Review Directory Objects Privileges",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.8.3": {
  "title": "Review External Tables With Preprocessor",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 },
 "6.8.4": {
  "title": "Review External Tables",
  "level": 1,
  "assessment": "Manual",
  "profiles": [
   "Level 1 - RDBMS"
  ]
 }
}

compliance_report := {
	"benchmark": "CIS Oracle Database 26ai Benchmark v1.0.0",
	"total_controls": 94,
	"standard_total": 94,
	"standard_total_source": "CIS Oracle Database 26ai Benchmark v1.0.0, recommendations counted from the CIS workbook",
	"sections": sections,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
