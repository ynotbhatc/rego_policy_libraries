package cis_oracle.user_account_management

# CIS Oracle Database 19c Benchmark - Section 3
# User Account Management
# Validates Oracle user accounts, profiles, and authentication

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		[v | some v in default_account_violations],
		[v | some v in password_policy_violations],
	),
	array.concat(
		[v | some v in privilege_violations],
		[v | some v in account_lockout_violations],
	),
)

# =============================================================================
# CIS 3.1 - DEFAULT ACCOUNTS
# =============================================================================

default_account_violations contains violation if {
	some account in input.default_accounts
	account.status == "OPEN"
	account.account_name != "SYS"
	account.account_name != "SYSTEM"
	violation := sprintf("CIS 3.1: Default account '%s' is OPEN (should be LOCKED or DROPPED)", [
		account.account_name,
	])
}

default_account_violations contains violation if {
	some account in input.default_accounts
	account.status == "OPEN"
	not account.password_changed
	violation := sprintf("CIS 3.1: Default account '%s' has never changed password (CRITICAL: using default password)", [
		account.account_name,
	])
}

# Common default accounts that should be locked/dropped
default_accounts_to_lock := [
	"ANONYMOUS",
	"APPQOSSYS",
	"CTXSYS",
	"DBSNMP",
	"DIP",
	"GSMADMIN_INTERNAL",
	"GSMCATUSER",
	"GSMUSER",
	"LBACSYS",
	"MDDATA",
	"MDSYS",
	"ORACLE_OCM",
	"OUTLN",
	"REMOTE_SCHEDULER_AGENT",
	"SI_INFORMTN_SCHEMA",
	"SPATIAL_CSW_ADMIN_USR",
	"SPATIAL_WFS_ADMIN_USR",
	"WMSYS",
	"XDB",
	"XS$NULL",
]

default_account_violations contains violation if {
	some default_account in default_accounts_to_lock
	some account in input.all_accounts
	account.account_name == default_account
	account.status == "OPEN"
	violation := sprintf("CIS 3.1: Default Oracle account '%s' is OPEN (should be LOCKED)", [
		default_account,
	])
}

# =============================================================================
# CIS 3.2 - PASSWORD PROFILES
# =============================================================================

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.profile_name == "DEFAULT"
	profile.PASSWORD_LIFE_TIME == "UNLIMITED"
	violation := "CIS 3.2: DEFAULT profile has PASSWORD_LIFE_TIME=UNLIMITED (passwords never expire)"
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.PASSWORD_REUSE_TIME == "UNLIMITED"
	profile.PASSWORD_REUSE_MAX == "UNLIMITED"
	violation := sprintf("CIS 3.2: Profile '%s' allows unlimited password reuse", [
		profile.profile_name,
	])
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.PASSWORD_LIFE_TIME
	to_number(profile.PASSWORD_LIFE_TIME) > 90
	violation := sprintf("CIS 3.2: Profile '%s' has PASSWORD_LIFE_TIME=%s days (should be 90 or less)", [
		profile.profile_name,
		profile.PASSWORD_LIFE_TIME,
	])
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.PASSWORD_GRACE_TIME
	to_number(profile.PASSWORD_GRACE_TIME) > 5
	violation := sprintf("CIS 3.2: Profile '%s' has PASSWORD_GRACE_TIME=%s days (should be 5 or less)", [
		profile.profile_name,
		profile.PASSWORD_GRACE_TIME,
	])
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.FAILED_LOGIN_ATTEMPTS
	to_number(profile.FAILED_LOGIN_ATTEMPTS) > 5
	violation := sprintf("CIS 3.2: Profile '%s' has FAILED_LOGIN_ATTEMPTS=%s (should be 5 or less)", [
		profile.profile_name,
		profile.FAILED_LOGIN_ATTEMPTS,
	])
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	profile.PASSWORD_LOCK_TIME
	to_number(profile.PASSWORD_LOCK_TIME) < 1
	profile.PASSWORD_LOCK_TIME != "UNLIMITED"
	violation := sprintf("CIS 3.2: Profile '%s' has PASSWORD_LOCK_TIME=%s (should be 1 day or UNLIMITED)", [
		profile.profile_name,
		profile.PASSWORD_LOCK_TIME,
	])
}

password_policy_violations contains violation if {
	some profile in input.password_profiles
	not profile.PASSWORD_VERIFY_FUNCTION
	profile.PASSWORD_VERIFY_FUNCTION == "NULL"
	violation := sprintf("CIS 3.2: Profile '%s' has no password complexity function (PASSWORD_VERIFY_FUNCTION=NULL)", [
		profile.profile_name,
	])
}

# =============================================================================
# CIS 3.3 - PRIVILEGED ACCOUNTS
# =============================================================================

privilege_violations contains violation if {
	some account in input.privileged_accounts
	account.account_status == "OPEN"
	account.authentication_type == "PASSWORD"
	not account.password_recently_changed
	violation := sprintf("CIS 3.3: Privileged account '%s' has old password (last changed: %s)", [
		account.account_name,
		account.password_last_changed,
	])
}

privilege_violations contains violation if {
	some account in input.dba_users
	not account.account_name in ["SYS", "SYSTEM"]
	account.granted_role == "DBA"
	violation := sprintf("CIS 3.3: Account '%s' has DBA role granted directly (should use custom roles)", [
		account.account_name,
	])
}

privilege_violations contains violation if {
	some account in input.all_accounts
	account.sysdba_privilege
	account.authentication_type == "PASSWORD"
	violation := sprintf("CIS 3.3: Account '%s' has SYSDBA using password authentication (should use OS or certificate auth)", [
		account.account_name,
	])
}

# =============================================================================
# CIS 3.4 - ACCOUNT LOCKOUT
# =============================================================================

account_lockout_violations contains violation if {
	some account in input.locked_accounts
	account.lock_reason == "FAILED_LOGIN_ATTEMPTS"
	account.locked_days > 30
	violation := sprintf("CIS 3.4: Account '%s' has been locked for %d days (should be reviewed/dropped)", [
		account.account_name,
		account.locked_days,
	])
}

account_lockout_violations contains violation if {
	some account in input.inactive_accounts
	account.last_login_days > 90
	account.status == "OPEN"
	violation := sprintf("CIS 3.4: Account '%s' has not logged in for %d days (should be locked)", [
		account.account_name,
		account.last_login_days,
	])
}

# =============================================================================
# CIS 3.5 - ANONYMOUS ACCESS
# =============================================================================

privilege_violations contains violation if {
	some account in input.all_accounts
	account.account_name == "ANONYMOUS"
	account.status == "OPEN"
	violation := "CIS 3.5: ANONYMOUS account is OPEN (should be LOCKED - allows anonymous HTTP access)"
}

# =============================================================================
# CIS 3.6 - PUBLIC PRIVILEGES
# =============================================================================

privilege_violations contains violation if {
	some priv in input.public_privileges.dangerous_privileges
	violation := sprintf("CIS 3.6: Dangerous privilege '%s' is granted to PUBLIC (should be revoked)", [
		priv,
	])
}

dangerous_public_privileges := [
	"CREATE ANY TABLE",
	"CREATE ANY PROCEDURE",
	"DROP ANY TABLE",
	"EXECUTE ANY PROCEDURE",
	"SELECT ANY TABLE",
	"UPDATE ANY TABLE",
	"DELETE ANY TABLE",
]

privilege_violations contains violation if {
	some dangerous_priv in dangerous_public_privileges
	some granted_priv in input.public_privileges.granted_privileges
	granted_priv == dangerous_priv
	violation := sprintf("CIS 3.6: CRITICAL: '%s' is granted to PUBLIC", [
		dangerous_priv,
	])
}

# =============================================================================
# REPORTING
# =============================================================================

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"account_summary": {
		"total_accounts": count(input.all_accounts),
		"open_accounts": count([a | some a in input.all_accounts; a.status == "OPEN"]),
		"locked_accounts": count([a | some a in input.all_accounts; a.status == "LOCKED"]),
		"expired_accounts": count([a | some a in input.all_accounts; a.status == "EXPIRED"]),
		"default_accounts_open": count([a | some a in input.default_accounts; a.status == "OPEN"]),
		"privileged_accounts": count(input.privileged_accounts),
		"dba_users": count(input.dba_users),
		"inactive_accounts": count([a | some a in input.inactive_accounts; a.last_login_days > 90]),
	},
	"password_policy_status": {
		"default_profile_secure": default_profile_secure,
		"profiles_with_complexity": count([p | some p in input.password_profiles; p.PASSWORD_VERIFY_FUNCTION; p.PASSWORD_VERIFY_FUNCTION != "NULL"]),
		"profiles_total": count(input.password_profiles),
	},
	"risk_level": risk_level,
	"collection_timestamp": input.collection_timestamp,
}

default_profile_secure if {
	some profile in input.password_profiles
	profile.profile_name == "DEFAULT"
	profile.PASSWORD_LIFE_TIME != "UNLIMITED"
	to_number(profile.PASSWORD_LIFE_TIME) <= 90
	to_number(profile.FAILED_LOGIN_ATTEMPTS) <= 5
}

risk_level := "critical" if {
	some account in input.default_accounts
	account.status == "OPEN"
	not account.password_changed
} else := "critical" if {
	input.parameters.REMOTE_OS_AUTHENT != "FALSE"
} else := "critical" if {
	some account in input.all_accounts
	account.account_name == "ANONYMOUS"
	account.status == "OPEN"
} else := "high" if {
	count([a | some a in input.default_accounts; a.status == "OPEN"]) > 2
} else := "high" if {
	count(input.public_privileges.dangerous_privileges) > 0
} else := "medium" if {
	count(violations) > 0
} else := "low"
