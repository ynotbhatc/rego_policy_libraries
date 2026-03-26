package cis_oracle.database_parameters

# CIS Oracle Database 19c Benchmark - Section 2.2
# Database Parameters
# Validates critical Oracle init parameters

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := [v | some v in parameter_violations]

# =============================================================================
# CIS 2.2.1 - AUDIT_SYS_OPERATIONS
# =============================================================================

parameter_violations contains violation if {
	input.parameters.AUDIT_SYS_OPERATIONS != "TRUE"
	violation := sprintf("CIS 2.2.1: AUDIT_SYS_OPERATIONS is '%s' (should be 'TRUE' to audit SYS/SYSDBA operations)", [
		input.parameters.AUDIT_SYS_OPERATIONS,
	])
}

# =============================================================================
# CIS 2.2.2 - AUDIT_TRAIL
# =============================================================================

parameter_violations contains violation if {
	input.parameters.AUDIT_TRAIL
	not input.parameters.AUDIT_TRAIL in ["DB", "XML", "OS", "DB,EXTENDED", "XML,EXTENDED", "DB, EXTENDED", "XML, EXTENDED"]
	violation := sprintf("CIS 2.2.2: AUDIT_TRAIL is '%s' (should be 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED')", [
		input.parameters.AUDIT_TRAIL,
	])
}

parameter_violations contains violation if {
	input.parameters.AUDIT_TRAIL == "NONE"
	violation := "CIS 2.2.2: AUDIT_TRAIL is 'NONE' (auditing is disabled - CRITICAL security issue)"
}

# =============================================================================
# CIS 2.2.3 - GLOBAL_NAMES
# =============================================================================

parameter_violations contains violation if {
	input.parameters.GLOBAL_NAMES != "TRUE"
	violation := sprintf("CIS 2.2.3: GLOBAL_NAMES is '%s' (should be 'TRUE' to enforce global naming)", [
		input.parameters.GLOBAL_NAMES,
	])
}

# =============================================================================
# CIS 2.2.4 - OS_ROLES
# =============================================================================

parameter_violations contains violation if {
	input.parameters.OS_ROLES != "FALSE"
	violation := sprintf("CIS 2.2.4: OS_ROLES is '%s' (should be 'FALSE' to prevent OS authentication)", [
		input.parameters.OS_ROLES,
	])
}

# =============================================================================
# CIS 2.2.5 - REMOTE_LISTENER
# =============================================================================

parameter_violations contains violation if {
	input.parameters.REMOTE_LISTENER != ""
	input.parameters.REMOTE_LISTENER != null
	violation := sprintf("CIS 2.2.5: REMOTE_LISTENER is set to '%s' (should be empty for security)", [
		input.parameters.REMOTE_LISTENER,
	])
}

# =============================================================================
# CIS 2.2.6 - REMOTE_LOGIN_PASSWORDFILE
# =============================================================================

parameter_violations contains violation if {
	input.parameters.REMOTE_LOGIN_PASSWORDFILE != "NONE"
	input.parameters.REMOTE_LOGIN_PASSWORDFILE != "EXCLUSIVE"
	violation := sprintf("CIS 2.2.6: REMOTE_LOGIN_PASSWORDFILE is '%s' (should be 'NONE' or 'EXCLUSIVE')", [
		input.parameters.REMOTE_LOGIN_PASSWORDFILE,
	])
}

# =============================================================================
# CIS 2.2.7 - REMOTE_OS_AUTHENT
# =============================================================================

parameter_violations contains violation if {
	input.parameters.REMOTE_OS_AUTHENT != "FALSE"
	violation := sprintf("CIS 2.2.7: REMOTE_OS_AUTHENT is '%s' (should be 'FALSE' - CRITICAL: allows remote OS authentication)", [
		input.parameters.REMOTE_OS_AUTHENT,
	])
}

# =============================================================================
# CIS 2.2.8 - REMOTE_OS_ROLES
# =============================================================================

parameter_violations contains violation if {
	input.parameters.REMOTE_OS_ROLES != "FALSE"
	violation := sprintf("CIS 2.2.8: REMOTE_OS_ROLES is '%s' (should be 'FALSE' to prevent remote OS role management)", [
		input.parameters.REMOTE_OS_ROLES,
	])
}

# =============================================================================
# CIS 2.2.9 - SEC_CASE_SENSITIVE_LOGON
# =============================================================================

parameter_violations contains violation if {
	input.parameters.SEC_CASE_SENSITIVE_LOGON != "TRUE"
	violation := sprintf("CIS 2.2.9: SEC_CASE_SENSITIVE_LOGON is '%s' (should be 'TRUE' for case-sensitive passwords)", [
		input.parameters.SEC_CASE_SENSITIVE_LOGON,
	])
}

# =============================================================================
# CIS 2.2.10 - SEC_MAX_FAILED_LOGIN_ATTEMPTS
# =============================================================================

parameter_violations contains violation if {
	input.parameters.SEC_MAX_FAILED_LOGIN_ATTEMPTS
	to_number(input.parameters.SEC_MAX_FAILED_LOGIN_ATTEMPTS) > 10
	violation := sprintf("CIS 2.2.10: SEC_MAX_FAILED_LOGIN_ATTEMPTS is %s (should be 10 or less)", [
		input.parameters.SEC_MAX_FAILED_LOGIN_ATTEMPTS,
	])
}

parameter_violations contains violation if {
	input.parameters.SEC_MAX_FAILED_LOGIN_ATTEMPTS
	to_number(input.parameters.SEC_MAX_FAILED_LOGIN_ATTEMPTS) == 0
	violation := "CIS 2.2.10: SEC_MAX_FAILED_LOGIN_ATTEMPTS is 0 (unlimited login attempts allowed)"
}

# =============================================================================
# CIS 2.2.11 - SEC_RETURN_SERVER_RELEASE_BANNER
# =============================================================================

parameter_violations contains violation if {
	input.parameters.SEC_RETURN_SERVER_RELEASE_BANNER != "FALSE"
	violation := sprintf("CIS 2.2.11: SEC_RETURN_SERVER_RELEASE_BANNER is '%s' (should be 'FALSE' to hide version info)", [
		input.parameters.SEC_RETURN_SERVER_RELEASE_BANNER,
	])
}

# =============================================================================
# CIS 2.2.12 - SQL92_SECURITY
# =============================================================================

parameter_violations contains violation if {
	input.parameters.SQL92_SECURITY != "TRUE"
	violation := sprintf("CIS 2.2.12: SQL92_SECURITY is '%s' (should be 'TRUE' for SQL92 compliance)", [
		input.parameters.SQL92_SECURITY,
	])
}

# =============================================================================
# CIS 2.2.13 - O7_DICTIONARY_ACCESSIBILITY
# =============================================================================

parameter_violations contains violation if {
	input.parameters.O7_DICTIONARY_ACCESSIBILITY != "FALSE"
	violation := sprintf("CIS 2.2.13: O7_DICTIONARY_ACCESSIBILITY is '%s' (should be 'FALSE' - CRITICAL: restricts SYS access)", [
		input.parameters.O7_DICTIONARY_ACCESSIBILITY,
	])
}

# =============================================================================
# UNIFIED AUDITING (Oracle 12c+)
# =============================================================================

parameter_violations contains violation if {
	input.oracle_version.major >= 12
	not input.unified_auditing.enabled
	violation := "CIS 2.2: Unified Auditing is not enabled (recommended for Oracle 12c+)"
}

# =============================================================================
# PASSWORD SECURITY PARAMETERS
# =============================================================================

parameter_violations contains violation if {
	input.parameters.SEC_PROTOCOL_ERROR_FURTHER_ACTION != "DROP,3"
	input.parameters.SEC_PROTOCOL_ERROR_FURTHER_ACTION != "DELAY,3"
	violation := sprintf("CIS 2.2: SEC_PROTOCOL_ERROR_FURTHER_ACTION is '%s' (should be 'DROP,3' or 'DELAY,3')", [
		input.parameters.SEC_PROTOCOL_ERROR_FURTHER_ACTION,
	])
}

# =============================================================================
# NETWORK ENCRYPTION
# =============================================================================

parameter_violations contains violation if {
	not input.network_encryption.enabled
	violation := "CIS 2.2: Network encryption is not enabled (sqlnet.ora SQLNET.ENCRYPTION_SERVER)"
}

parameter_violations contains violation if {
	input.network_encryption.enabled
	input.network_encryption.crypto_checksumming != "REQUIRED"
	input.network_encryption.crypto_checksumming != "REQUESTED"
	violation := sprintf("CIS 2.2: Network crypto checksumming is '%s' (should be 'REQUIRED' or 'REQUESTED')", [
		input.network_encryption.crypto_checksumming,
	])
}

# =============================================================================
# REPORTING
# =============================================================================

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"critical_parameters": critical_parameter_summary,
	"audit_configuration": {
		"audit_sys_operations": input.parameters.AUDIT_SYS_OPERATIONS,
		"audit_trail": input.parameters.AUDIT_TRAIL,
		"unified_auditing_enabled": input.unified_auditing.enabled,
	},
	"security_parameters": {
		"remote_os_authent": input.parameters.REMOTE_OS_AUTHENT,
		"remote_os_roles": input.parameters.REMOTE_OS_ROLES,
		"os_roles": input.parameters.OS_ROLES,
		"case_sensitive_logon": input.parameters.SEC_CASE_SENSITIVE_LOGON,
	},
	"risk_level": risk_level,
	"collection_timestamp": input.collection_timestamp,
}

critical_parameter_summary := {
	"remote_os_authent_disabled": input.parameters.REMOTE_OS_AUTHENT == "FALSE",
	"remote_os_roles_disabled": input.parameters.REMOTE_OS_ROLES == "FALSE",
	"auditing_enabled": input.parameters.AUDIT_TRAIL != "NONE",
	"o7_dictionary_protected": input.parameters.O7_DICTIONARY_ACCESSIBILITY == "FALSE",
}

risk_level := "critical" if {
	input.parameters.REMOTE_OS_AUTHENT != "FALSE"
} else := "critical" if {
	input.parameters.AUDIT_TRAIL == "NONE"
} else := "critical" if {
	input.parameters.O7_DICTIONARY_ACCESSIBILITY != "FALSE"
} else := "high" if {
	input.parameters.REMOTE_OS_ROLES != "FALSE"
} else := "high" if {
	count(violations) > 5
} else := "medium" if {
	count(violations) > 0
} else := "low"
