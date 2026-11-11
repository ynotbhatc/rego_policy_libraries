# METADATA
# title: "CIS Oracle Database 19c Benchmark v2.0.0"
# custom:
#   class: security
#   framework: cis_oracle
#   source: cis
#   domains: [database, oracle]
#   coverage:
#     checks: 178
#     cited: 178
#     expected: 178
#     found: 178
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis.oracle_19c

import rego.v1

# CIS Oracle Database 19c Benchmark v2.0.0
# This policy implements the CIS benchmarks for Oracle Database 19c
# Reference: https://www.cisecurity.org/benchmark/oracle_database

# Main compliance evaluation
default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		installation_configuration_violations,
		listener_violations,
		logging_auditing_violations,
		user_accounts_violations,
		privileges_roles_violations,
		fine_grained_access_violations,
		encryption_violations,
		network_security_violations,
	]
	v := arrays[_][_]
]

# Generate compliance report
compliance_report := {
	"benchmark": "CIS Oracle Database 19c Benchmark v2.0.0",
	"timestamp": time.now_ns(),
	"total_controls": 178,
	"compliant": compliant,
	"violations_count": count(violations),
	"violations": violations,
	"sections": {
		"installation_configuration": {
			"violations": count(installation_configuration_violations),
			"controls": 28,
		},
		"listener": {
			"violations": count(listener_violations),
			"controls": 18,
		},
		"logging_auditing": {
			"violations": count(logging_auditing_violations),
			"controls": 32,
		},
		"user_accounts": {
			"violations": count(user_accounts_violations),
			"controls": 24,
		},
		"privileges_roles": {
			"violations": count(privileges_roles_violations),
			"controls": 28,
		},
		"fine_grained_access": {
			"violations": count(fine_grained_access_violations),
			"controls": 22,
		},
		"encryption": {
			"violations": count(encryption_violations),
			"controls": 16,
		},
		"network_security": {
			"violations": count(network_security_violations),
			"controls": 10,
		},
	},
}

# Section 1: Installation and Configuration
installation_configuration_violations := [v |
	arrays := [
		["1.1: Oracle Installation must be From Authorized Sources" | not oracle_from_authorized_sources],
		["1.2: Latest Oracle Patches must be Applied" | not latest_patches_applied],
		["1.3: Oracle Home Directory Permissions must be Restricted" | not oracle_home_permissions_restricted],
		["1.4: Oracle Base Directory Permissions must be Restricted" | not oracle_base_permissions_restricted],
		["1.5: Oracle Data Files must be on Non-System Partitions" | not data_files_non_system_partitions],
		["1.6: Oracle Software must be Not Installed on System Partitions" | not software_not_on_system_partitions],
		["1.7: checked condition — Oracle processes do not run as root or with root privileges" | not oracle_not_root],
		["1.8: ORACLE_HOME and PATH environment variables must be secured" | not environment_variables_secured],
		["1.9: Oracle inventory must be secured" | not oracle_inventory_secured],
		["1.10: tnsnames.ora file must be secured" | not tnsnames_secured],
		["1.11: sqlnet.ora file must be secured" | not sqlnet_secured],
		["1.12: listener.ora file must be secured" | not listener_ora_secured],
		["1.13: default database accounts must be secured" | not default_accounts_secured],
		["1.14: sample schemas must be removed" | not sample_schemas_removed],
		["1.15: database links must be secured" | not database_links_secured],
		["1.16: external procedures must be secured" | not external_procedures_secured],
		["1.17: required value of parameter UTL_FILE_DIR is not set" | not utl_file_dir_not_set],
		["1.18: required value of parameter REMOTE_OS_AUTHENT is FALSE" | not remote_os_authent_false],
		["1.19: required value of parameter REMOTE_OS_ROLES is FALSE" | not remote_os_roles_false],
		["1.20: required value of parameter SQL92_SECURITY is TRUE" | not sql92_security_true],
		["1.21: required value of parameter O7_DICTIONARY_ACCESSIBILITY is FALSE" | not o7_dictionary_accessibility_false],
		["1.22: required value of parameter SEC_CASE_SENSITIVE_LOGON is TRUE" | not sec_case_sensitive_logon_true],
		["1.23: SEC_MAX_FAILED_LOGIN_ATTEMPTS parameter must match the approved value" | not sec_max_failed_login_attempts_set],
		["1.24: required value of SEC_PROTOCOL_ERROR_TRACE_ACTION parameter is LOG" | not sec_protocol_error_trace_action_log],
		["1.25: SEC_PROTOCOL_ERROR_FURTHER_ACTION parameter must match the approved value" | not sec_protocol_error_further_action_set],
		["1.26: required value of parameter SEC_RETURN_SERVER_RELEASE_BANNER is FALSE" | not sec_return_server_release_banner_false],
		["1.27: required value of parameter GLOBAL_NAMES is TRUE" | not global_names_true],
		["1.28: database character set must use an approved value" | not database_character_set_appropriate],
	]
	v := arrays[_][_]
]

oracle_from_authorized_sources if {
	installation := input.oracle.installation
	installation.source == "oracle_official"
	installation.checksum_verified == true
}

latest_patches_applied if {
	patches := input.oracle.patches
	patches.current_psu == patches.latest_available_psu
	patches.security_patches_current == true
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings). Decisions 2026-10-19: replaces exact-string mode compares.
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

oracle_home_permissions_restricted if {
	oracle_home := input.oracle.directories.oracle_home
	oracle_home.owner == "oracle"
	oracle_home.group == "oinstall"
	mode_within(oracle_home.mode, "755")
}

oracle_base_permissions_restricted if {
	oracle_base := input.oracle.directories.oracle_base
	oracle_base.owner == "oracle"
	oracle_base.group == "oinstall"
	mode_within(oracle_base.mode, "755")
}

# true when path is the system mount point itself or lies beneath it ("/" matches only "/")
on_system_partition(path, partitions) if {
	some p in partitions
	trim_right(path, "/") == p
}

on_system_partition(path, partitions) if {
	some p in partitions
	p != ""
	startswith(path, concat("", [p, "/"]))
}

data_files_non_system_partitions if {
	data_files := input.oracle.data_files
	data_on_system := [df |
		df := data_files[_]
		on_system_partition(df.path, ["", "/usr", "/var", "/etc"])
	]
	count(data_on_system) == 0
}

software_not_on_system_partitions if {
	oracle_home := input.oracle.directories.oracle_home.path
	not on_system_partition(oracle_home, ["", "/usr", "/var"])
}

oracle_not_root if {
	processes := input.oracle.processes
	root_processes := [p | p := processes[_]; p.user == "root"]
	count(root_processes) == 0
}

environment_variables_secured if {
	env_vars := input.oracle.environment
	env_vars.oracle_home_secured == true
	env_vars.path_secured == true
	env_vars.ld_library_path_secured == true
}

oracle_inventory_secured if {
	inventory := input.oracle.inventory
	inventory.owner == "oracle"
	inventory.group == "oinstall"
	mode_within(inventory.mode, "644")
}

tnsnames_secured if {
	tnsnames := input.oracle.network_config.tnsnames_ora
	tnsnames.owner == "oracle"
	tnsnames.group == "oinstall"
	mode_within(tnsnames.mode, "644")
}

sqlnet_secured if {
	sqlnet := input.oracle.network_config.sqlnet_ora
	sqlnet.owner == "oracle"
	sqlnet.group == "oinstall"
	mode_within(sqlnet.mode, "644")
}

listener_ora_secured if {
	listener := input.oracle.network_config.listener_ora
	listener.owner == "oracle"
	listener.group == "oinstall"
	mode_within(listener.mode, "644")
}

default_accounts_secured if {
	default_accounts := input.oracle.default_accounts
	unlocked_defaults := [acc | acc := default_accounts[_]; acc.status == "OPEN"]
	count(unlocked_defaults) == 0
}

sample_schemas_removed if {
	schemas := input.oracle.schemas
	sample_schemas := ["HR", "OE", "PM", "IX", "SH", "BI", "SCOTT"]
	existing_samples := [s | s := schemas[_]; s.name in sample_schemas]
	count(existing_samples) == 0
}

database_links_secured if {
	db_links := input.oracle.database_links
	public_links := [link | link := db_links[_]; link.owner == "PUBLIC"]
	insecure_links := [link |
		link := db_links[_]
		link.password_stored == true
		link.encrypted == false
	]
	count(public_links) == 0
	count(insecure_links) == 0
}

external_procedures_secured if {
	external_proc := input.oracle.external_procedures
	external_proc.enabled == false
}

external_procedures_secured if {
	external_proc := input.oracle.external_procedures
	external_proc.enabled == true
	external_proc.secured == true
	external_proc.user != "oracle"
}

utl_file_dir_not_set if {
	parameters := input.oracle.init_parameters
	parameters.utl_file_dir == ""
}

remote_os_authent_false if {
	parameters := input.oracle.init_parameters
	parameters.remote_os_authent == "FALSE"
}

remote_os_roles_false if {
	parameters := input.oracle.init_parameters
	parameters.remote_os_roles == "FALSE"
}

sql92_security_true if {
	parameters := input.oracle.init_parameters
	parameters.sql92_security == "TRUE"
}

o7_dictionary_accessibility_false if {
	parameters := input.oracle.init_parameters
	parameters.o7_dictionary_accessibility == "FALSE"
}

sec_case_sensitive_logon_true if {
	parameters := input.oracle.init_parameters
	parameters.sec_case_sensitive_logon == "TRUE"
}

sec_max_failed_login_attempts_set if {
	parameters := input.oracle.init_parameters
	attempts := parameters.sec_max_failed_login_attempts
	attempts >= 3
	attempts <= 5
}

sec_protocol_error_trace_action_log if {
	parameters := input.oracle.init_parameters
	parameters.sec_protocol_error_trace_action == "LOG"
}

sec_protocol_error_further_action_set if {
	parameters := input.oracle.init_parameters
	action := parameters.sec_protocol_error_further_action
	action in ["CONTINUE", "DELAY", "DROP"]
}

sec_return_server_release_banner_false if {
	parameters := input.oracle.init_parameters
	parameters.sec_return_server_release_banner == "FALSE"
}

global_names_true if {
	parameters := input.oracle.init_parameters
	parameters.global_names == "TRUE"
}

database_character_set_appropriate if {
	charset := input.oracle.character_set
	charset.database_charset in ["AL32UTF8", "UTF8"]
	charset.national_charset == "AL16UTF16"
}

# Section 2: Listener Security
listener_violations := [v |
	arrays := [
		["2.1: the Listener must not be use the default port of 1521" | not listener_not_default_port],
		["2.2: the Listener Password must be Set" | not listener_password_set],
		["2.3: required value of 'ADMIN_RESTRICTIONS' is 'ON'" | not admin_restrictions_on],
		["2.4: 'LOCAL_OS_AUTHENTICATION' must be turned off" | not local_os_auth_disabled],
		["2.5: required value of 'SECURE_REGISTER' is 'ON'" | not secure_register_on],
		["2.6: required value of 'SECURE_CONTROL' is 'ON'" | not secure_control_on],
		["2.7: checked condition — the listener process runs as a non-privileged user" | not listener_non_privileged_user],
		["2.8: listener logging must be turned on" | not listener_logging_enabled],
		["2.9: listener log files must be protected" | not listener_log_files_protected],
		["2.10: connection rate limiting must be explicitly configured" | not connection_rate_limiting_configured],
		["2.11: listener registration must be secured" | not listener_registration_secured],
		["2.12: TNS_ADMIN must match the approved value" | not tns_admin_set_appropriately],
		["2.13: NAMES.DIRECTORY_PATH parameter must match the approved value" | not names_directory_path_correct],
		["2.14: SQLNET.AUTHENTICATION_SERVICES parameter must match the approved value" | not sqlnet_auth_services_correct],
		["2.15: SQLNET.AUTHENTICATION_GSSAPI_SERVICE parameter must match the approved value" | not sqlnet_gssapi_service_correct],
		["2.16: required value of parameter SQLNET.CRYPTO_SEED is configured" | not sqlnet_crypto_seed_configured],
		["2.17: connection timeout must be explicitly configured" | not connection_timeout_configured],
		["2.18: listener must be explicitly configured for SSL/TLS" | not listener_ssl_configured],
	]
	v := arrays[_][_]
]

listener_not_default_port if {
	listener_config := input.oracle.listener
	listener_config.port != 1521
}

listener_password_set if {
	listener_config := input.oracle.listener
	listener_config.password_protected == true
	listener_config.password_encrypted == true
}

admin_restrictions_on if {
	listener_config := input.oracle.listener
	listener_config.admin_restrictions == "ON"
}

local_os_auth_disabled if {
	listener_config := input.oracle.listener
	listener_config.local_os_authentication == "OFF"
}

secure_register_on if {
	listener_config := input.oracle.listener
	listener_config.secure_register == "ON"
}

secure_control_on if {
	listener_config := input.oracle.listener
	listener_config.secure_control == "ON"
}

listener_non_privileged_user if {
	listener_process := input.oracle.listener_process
	listener_process.user == "oracle"
	listener_process.effective_uid != 0
}

listener_logging_enabled if {
	listener_logging := input.oracle.listener_logging
	listener_logging.enabled == true
	listener_logging.log_level in ["SUPPORT", "ADMIN"]
}

listener_log_files_protected if {
	log_files := input.oracle.listener_log_files
	log_files.owner == "oracle"
	log_files.group == "oinstall"
	mode_within(log_files.mode, "640")
}

connection_rate_limiting_configured if {
	rate_limiting := input.oracle.connection_rate_limiting
	rate_limiting.enabled == true
	rate_limiting.max_connections_per_second <= 10
}

listener_registration_secured if {
	registration := input.oracle.listener_registration
	registration.dynamic_registration_restricted == true
	registration.static_registration_preferred == true
}

tns_admin_set_appropriately if {
	tns_admin := input.oracle.environment.tns_admin
	tns_admin != ""
	startswith(tns_admin, "/oracle")
}

names_directory_path_correct if {
	sqlnet_config := input.oracle.sqlnet_config
	directory_path := sqlnet_config.names_directory_path
	tokens := names_path_tokens(directory_path)
	"TNSNAMES" in tokens
	not "HOSTNAME" in tokens
}

# NAMES.DIRECTORY_PATH may be a list or a comma separated string
names_path_tokens(path) := {upper(trim_space(t)) | some t in split(path, ",")} if is_string(path)

names_path_tokens(path) := {upper(trim_space(t)) | some t in path} if is_array(path)

sqlnet_auth_services_correct if {
	sqlnet_config := input.oracle.sqlnet_config
	auth_services := sqlnet_config.authentication_services
	auth_services == "NONE"
}

sqlnet_gssapi_service_correct if {
	sqlnet_config := input.oracle.sqlnet_config
	gssapi_service := sqlnet_config.authentication_gssapi_service
	gssapi_service != ""
}

sqlnet_crypto_seed_configured if {
	sqlnet_config := input.oracle.sqlnet_config
	crypto_seed := sqlnet_config.crypto_seed
	crypto_seed != ""
	count(crypto_seed) >= 10
}

connection_timeout_configured if {
	sqlnet_config := input.oracle.sqlnet_config
	inbound_timeout := sqlnet_config.inbound_connect_timeout
	expire_time := sqlnet_config.expire_time
	inbound_timeout <= 60
	expire_time <= 10
}

listener_ssl_configured if {
	ssl_config := input.oracle.ssl_config
	ssl_config.listener_ssl_enabled == true
	ssl_config.ssl_cert_configured == true
	ssl_config.ssl_cipher_suites != ""
}

# Section 3: Logging and Auditing
logging_auditing_violations := [v |
	arrays := [
		["3.1: required value of 'AUDIT_SYS_OPERATIONS' is 'TRUE'" | not audit_sys_operations_true],
		["3.2: required value of 'AUDIT_TRAIL' is 'DB', 'OS', 'DB, EXTENDED', or 'XML, EXTENDED'" | not audit_trail_appropriate],
		["3.3: required value of 'AUDIT_FILE_DEST' is a Dedicated Directory" | not audit_file_dest_dedicated],
		["3.4: required value of 'DB_ULTRA_SAFE' is 'DATA_AND_INDEX'" | not db_ultra_safe_set],
		["3.5: audit files must be protected" | not audit_files_protected],
		["3.6: audit trail destinations must be secured" | not audit_destinations_secured],
		["3.7: comprehensive database activity auditing must be turned on" | not comprehensive_auditing_enabled],
		["3.8: auditing of failed logon attempts must be turned on" | not failed_logon_auditing_enabled],
		["3.9: auditing of successful logon attempts must be turned on" | not successful_logon_auditing_enabled],
		["3.10: auditing of logoff events must be turned on" | not logoff_auditing_enabled],
		["3.11: auditing of database schema changes must be turned on" | not schema_changes_auditing_enabled],
		["3.12: auditing of privilege grants and revokes must be turned on" | not privilege_changes_auditing_enabled],
		["3.13: auditing of data access must be turned on for sensitive tables" | not sensitive_data_access_auditing],
		["3.14: auditing of data modification must be turned on for sensitive tables" | not sensitive_data_modification_auditing],
		["3.15: auditing of administrative operations must be turned on" | not admin_operations_auditing_enabled],
		["3.16: auditing of user creation and deletion must be turned on" | not user_management_auditing_enabled],
		["3.17: auditing of role assignment changes must be turned on" | not role_assignment_auditing_enabled],
		["3.18: auditing of system privilege operations must be turned on" | not system_privilege_auditing_enabled],
		["3.19: auditing of object privilege operations must be turned on" | not object_privilege_auditing_enabled],
		["3.20: auditing of database startup and shutdown must be turned on" | not startup_shutdown_auditing_enabled],
		["3.21: log retention policies must be explicitly configured" | not log_retention_policies_configured],
		["3.22: audit log monitoring and alerting must be explicitly configured" | not audit_monitoring_configured],
		["3.23: Fine Grained Auditing (FGA) must be turned on for sensitive data" | not fga_enabled_sensitive_data],
		["3.24: Database Vault auditing must be turned on" | not database_vault_auditing_enabled],
		["3.25: audit cleanup jobs must be explicitly configured" | not audit_cleanup_jobs_configured],
		["3.26: SYS and SYSTEM operations must be audited" | not sys_system_operations_audited],
		["3.27: public synonym operations must be audited" | not public_synonym_operations_audited],
		["3.28: directory operations must be audited" | not directory_operations_audited],
		["3.29: database link operations must be audited" | not database_link_operations_audited],
		["3.30: external procedure operations must be audited" | not external_procedure_operations_audited],
		["3.31: network operations must be audited" | not network_operations_audited],
		["3.32: SQL*Loader operations must be audited" | not sql_loader_operations_audited],
	]
	v := arrays[_][_]
]

audit_sys_operations_true if {
	parameters := input.oracle.init_parameters
	parameters.audit_sys_operations == "TRUE"
}

audit_trail_appropriate if {
	parameters := input.oracle.init_parameters
	audit_trail := parameters.audit_trail

	# Oracle reports "DB, EXTENDED"; ignore whitespace and case
	normalized := upper(regex.replace(audit_trail, `\s+`, ""))
	normalized in ["DB", "OS", "DB,EXTENDED", "XML,EXTENDED"]
}

audit_file_dest_dedicated if {
	parameters := input.oracle.init_parameters
	audit_file_dest := parameters.audit_file_dest
	audit_file_dest != ""

	# any absolute directory other than the default <base>/admin/<sid>/adump
	startswith(audit_file_dest, "/")
	not regex.match(`^/.*/admin/[^/]+/adump/?$`, audit_file_dest)
}

db_ultra_safe_set if {
	parameters := input.oracle.init_parameters
	parameters.db_ultra_safe == "DATA_AND_INDEX"
}

audit_files_protected if {
	audit_files := input.oracle.audit_files
	audit_files.owner == "oracle"
	audit_files.group == "oinstall"
	mode_within(audit_files.mode, "640")
}

audit_destinations_secured if {
	audit_config := input.oracle.audit_config
	audit_config.destinations_secured == true
	audit_config.destination_permissions_restricted == true
}

comprehensive_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.session == true
	audit_settings.alter_session == true
	audit_settings.alter_system == true
}

failed_logon_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.session_by_access == true
	audit_settings.logon_failures == true
}

successful_logon_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.session_by_access == true
	audit_settings.logon_successes == true
}

logoff_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.session_by_access == true
}

schema_changes_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.create_table == true
	audit_settings.drop_table == true
	audit_settings.alter_table == true
}

privilege_changes_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.grant == true
	audit_settings.revoke == true
}

sensitive_data_access_auditing if {
	fga_policies := input.oracle.fga_policies
	sensitive_tables := input.oracle.sensitive_tables
	audited_tables := [policy.table_name | policy := fga_policies[_]]
	unaudited_sensitive := [table | table := sensitive_tables[_]; not table in audited_tables]

	# an empty sensitive-table inventory is not evidence of anything: require a declared inventory
	count(sensitive_tables) > 0
	count(unaudited_sensitive) == 0
}

sensitive_data_modification_auditing if {
	audit_settings := input.oracle.audit_settings
	audit_settings.insert == true
	audit_settings.update == true
	audit_settings.delete == true
}

admin_operations_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.alter_system == true
	audit_settings.alter_database == true
	audit_settings.create_user == true
	audit_settings.drop_user == true
}

user_management_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.create_user == true
	audit_settings.drop_user == true
	audit_settings.alter_user == true
}

role_assignment_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.grant_role == true
	audit_settings.revoke_role == true
}

system_privilege_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.grant_system_privilege == true
	audit_settings.revoke_system_privilege == true
}

object_privilege_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.grant_object_privilege == true
	audit_settings.revoke_object_privilege == true
}

startup_shutdown_auditing_enabled if {
	audit_settings := input.oracle.audit_settings
	audit_settings.startup == true
	audit_settings.shutdown == true
}

log_retention_policies_configured if {
	log_retention := input.oracle.log_retention
	log_retention.policy_defined == true
	log_retention.retention_days >= 90
	log_retention.automated_cleanup == true
}

audit_monitoring_configured if {
	audit_monitoring := input.oracle.audit_monitoring
	audit_monitoring.enabled == true
	audit_monitoring.real_time_alerts == true
	audit_monitoring.log_analysis == true
}

fga_enabled_sensitive_data if {
	fga_config := input.oracle.fga_config
	fga_config.enabled == true
	fga_config.comprehensive_coverage == true
	fga_config.sensitive_data_covered == true
}

database_vault_auditing_enabled if {
	database_vault := input.oracle.database_vault
	database_vault.enabled == true
	database_vault.auditing_enabled == true
}

audit_cleanup_jobs_configured if {
	audit_cleanup := input.oracle.audit_cleanup
	audit_cleanup.jobs_configured == true
	audit_cleanup.automated_execution == true
}

sys_system_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.sys_operations == true
	audit_settings.system_operations == true
}

public_synonym_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.public_synonym == true
}

directory_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.directory == true
}

database_link_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.database_link == true
}

external_procedure_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.procedure == true
}

network_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.network_access == true
}

sql_loader_operations_audited if {
	audit_settings := input.oracle.audit_settings
	audit_settings.sql_loader == true
}

# Section 4: User Accounts and Authentication
user_accounts_violations := [v |
	arrays := [
		["4.1: All Default Passwords must be Changed" | not default_passwords_changed],
		["4.2: All Sample Data and Users must be Removed" | not sample_data_users_removed],
		["4.3: All Unnecessary Accounts must be Removed" | not unnecessary_accounts_removed],
		["4.4: All Default Accounts That must be Not Needed Are Locked" | not unneeded_default_accounts_locked],
		["4.5: Password Complexity must be Enforced" | not password_complexity_enforced],
		["4.6: Password Expiration must be Enforced" | not password_expiration_enforced],
		["4.7: Password Reuse must be limited to named principals" | not password_reuse_limited],
		["4.8: Account Lockout Policy must be Enforced" | not account_lockout_enforced],
		["4.9: Password Grace Period must be limited to named principals" | not password_grace_period_limited],
		["4.10: Strong Authentication Methods must be Used" | not strong_authentication_used],
		["4.11: Database Authentication must be Not Used for Application Accounts" | not db_auth_not_used_for_apps],
		["4.12: External Authentication must be Secured" | not external_auth_secured],
		["4.13: Global Authentication must be Secured" | not global_auth_secured],
		["4.14: Database User Session Management must be explicitly configured" | not session_management_configured],
		["4.15: Idle Time Limits must be Enforced" | not idle_time_limits_enforced],
		["4.16: Connect Time Limits must be Enforced" | not connect_time_limits_enforced],
		["4.17: Concurrent Session Limits must be Enforced" | not concurrent_session_limits_enforced],
		["4.18: User Profile Management must be Implemented" | not user_profile_management_implemented],
		["4.19: Application User Account Management must be Secured" | not app_user_account_management_secured],
		["4.20: Service Account Management must be Secured" | not service_account_management_secured],
		["4.21: Administrative Account Usage must be Monitored" | not admin_account_usage_monitored],
		["4.22: Emergency Account Procedures must be Defined" | not emergency_account_procedures_defined],
		["4.23: Account Lifecycle Management must be Implemented" | not account_lifecycle_management_implemented],
		["4.24: Shared Account Usage must be Eliminated or Controlled" | not shared_account_usage_controlled],
	]
	v := arrays[_][_]
]

default_passwords_changed if {
	default_accounts := input.oracle.default_accounts
	accounts_with_default_passwords := [acc |
		acc := default_accounts[_]
		acc.password_changed == false
	]
	count(accounts_with_default_passwords) == 0
}

sample_data_users_removed if {
	users := input.oracle.users
	sample_users := ["HR", "OE", "PM", "IX", "SH", "BI", "SCOTT", "DEMO"]
	existing_sample_users := [user | user := users[_]; user.username in sample_users]
	count(existing_sample_users) == 0
}

unnecessary_accounts_removed if {
	accounts := input.oracle.accounts
	unnecessary_accounts := [acc |
		acc := accounts[_]
		acc.necessary == false
		acc.status == "OPEN"
	]
	count(unnecessary_accounts) == 0
}

unneeded_default_accounts_locked if {
	default_accounts := input.oracle.default_accounts
	unneeded_accounts := [acc |
		acc := default_accounts[_]
		acc.needed == false
		acc.status != "LOCKED"
	]
	count(unneeded_accounts) == 0
}

password_complexity_enforced if {
	password_policy := input.oracle.password_policy
	password_policy.complexity_function_enabled == true
	password_policy.min_length >= 8
	password_policy.mixed_case_required == true
	password_policy.numbers_required == true
	password_policy.special_chars_required == true
}

password_expiration_enforced if {
	password_policy := input.oracle.password_policy
	password_policy.password_life_time <= 90
	password_policy.password_life_time > 0
}

password_reuse_limited if {
	password_policy := input.oracle.password_policy
	password_policy.password_reuse_max >= 5
	password_policy.password_reuse_time >= 365
}

account_lockout_enforced if {
	password_policy := input.oracle.password_policy
	password_policy.failed_login_attempts <= 5
	password_policy.failed_login_attempts > 0
	password_policy.password_lock_time >= 1
}

password_grace_period_limited if {
	password_policy := input.oracle.password_policy
	password_policy.password_grace_time <= 7
	password_policy.password_grace_time >= 0
}

strong_authentication_used if {
	auth_methods := input.oracle.authentication_methods
	strong_methods := ["KERBEROS", "PKI", "RADIUS", "LDAP"]
	strong_auth_enabled := [method | method := auth_methods[_]; method in strong_methods]
	count(strong_auth_enabled) > 0
}

db_auth_not_used_for_apps if {
	app_accounts := input.oracle.application_accounts
	db_auth_app_accounts := [acc |
		acc := app_accounts[_]
		acc.authentication_method == "DATABASE"
	]
	count(db_auth_app_accounts) == 0
}

external_auth_secured if {
	external_auth := input.oracle.external_authentication
	external_auth.enabled == true
	external_auth.ssl_required == true
	external_auth.certificate_validation == true
}

external_auth_secured if {
	external_auth := input.oracle.external_authentication
	external_auth.enabled == false
}

global_auth_secured if {
	global_auth := input.oracle.global_authentication
	global_auth.enabled == true
	global_auth.ssl_required == true
	global_auth.directory_secured == true
}

global_auth_secured if {
	global_auth := input.oracle.global_authentication
	global_auth.enabled == false
}

session_management_configured if {
	session_config := input.oracle.session_management
	session_config.resource_limits_enabled == true
	session_config.profiles_assigned == true
}

idle_time_limits_enforced if {
	resource_limits := input.oracle.resource_limits
	resource_limits.idle_time <= 60
	resource_limits.idle_time > 0
}

connect_time_limits_enforced if {
	resource_limits := input.oracle.resource_limits
	resource_limits.connect_time <= 480
	resource_limits.connect_time > 0
}

concurrent_session_limits_enforced if {
	resource_limits := input.oracle.resource_limits
	resource_limits.sessions_per_user <= 5
	resource_limits.sessions_per_user > 0
}

user_profile_management_implemented if {
	profile_management := input.oracle.profile_management
	profile_management.default_profile_secured == true
	profile_management.custom_profiles_used == true
	profile_management.profile_assignment_documented == true
}

app_user_account_management_secured if {
	app_account_mgmt := input.oracle.app_account_management
	app_account_mgmt.dedicated_accounts == true
	app_account_mgmt.least_privilege == true
	app_account_mgmt.regular_review == true
}

service_account_management_secured if {
	service_account_mgmt := input.oracle.service_account_management
	service_account_mgmt.documented == true
	service_account_mgmt.monitored == true
	service_account_mgmt.limited_privileges == true
}

admin_account_usage_monitored if {
	admin_monitoring := input.oracle.admin_account_monitoring
	admin_monitoring.enabled == true
	admin_monitoring.real_time_alerts == true
	admin_monitoring.activity_logged == true
}

emergency_account_procedures_defined if {
	emergency_procedures := input.oracle.emergency_account_procedures
	emergency_procedures.documented == true
	emergency_procedures.break_glass_accounts == true
	emergency_procedures.approval_process == true
}

account_lifecycle_management_implemented if {
	lifecycle_mgmt := input.oracle.account_lifecycle_management
	lifecycle_mgmt.provisioning_process == true
	lifecycle_mgmt.deprovisioning_process == true
	lifecycle_mgmt.regular_review == true
}

shared_account_usage_controlled if {
	shared_accounts := input.oracle.shared_accounts
	count(shared_accounts) == 0
}

shared_account_usage_controlled if {
	shared_accounts := input.oracle.shared_accounts
	count(shared_accounts) > 0
	controlled_shared := [acc |
		acc := shared_accounts[_]
		acc.justified == true
		acc.monitored == true
		acc.access_controlled == true
	]
	count(controlled_shared) == count(shared_accounts)
}

# Section 5: Privileges and Roles
privileges_roles_violations := [v |
	arrays := [
		["5.1: All Unnecessary Roles must be Dropped" | not unnecessary_roles_dropped],
		["5.2: No Users must have the DBA Role" | not no_users_have_dba_role],
		["5.3: DBA Roles must be Protected" | not dba_roles_protected],
		["5.4: checked condition — Custom DBA Roles Follow Principle of Least Privilege" | not custom_dba_roles_least_privilege],
		["5.5: All Roles must be Password Protected" | not all_roles_password_protected],
		["5.6: No Roles must be Granted to PUBLIC" | not no_roles_granted_to_public],
		["5.7: DBA and Other Administrative Privileges must be Granted Only Where Needed" | not admin_privileges_granted_appropriately],
		["5.8: privilege 'GRANT ANY ROLE' must be limited to approved grantees" | not grant_any_role_restricted],
		["5.9: privilege 'GRANT ANY PRIVILEGE' must be limited to approved grantees" | not grant_any_privilege_restricted],
		["5.10: privilege 'GRANT ANY OBJECT PRIVILEGE' must be limited to approved grantees" | not grant_any_object_privilege_restricted],
		["5.11: System Privileges must be Granted Appropriately" | not system_privileges_granted_appropriately],
		["5.12: Object Privileges must be Granted Appropriately" | not object_privileges_granted_appropriately],
		["5.13: WITH ADMIN OPTION must be Restricted" | not with_admin_option_restricted],
		["5.14: WITH GRANT OPTION must be Restricted" | not with_grant_option_restricted],
		["5.15: Role Hierarchies must be Appropriately Designed" | not role_hierarchies_appropriate],
		["5.16: Application Roles must be Used for Application Access" | not application_roles_used],
		["5.17: Database Link Privileges must be Restricted" | not database_link_privileges_restricted],
		["5.18: Directory Object Privileges must be Restricted" | not directory_object_privileges_restricted],
		["5.19: Java Privileges must be Restricted" | not java_privileges_restricted],
		["5.20: External Procedure Privileges must be Restricted" | not external_procedure_privileges_restricted],
		["5.21: Network Access Control List (ACL) must be explicitly configured" | not network_acl_configured],
		["5.22: Privilege Analysis must be Implemented" | not privilege_analysis_implemented],
		["5.23: Regular Privilege Reviews must be Conducted" | not regular_privilege_reviews_conducted],
		["5.24: Privilege Escalation must be Monitored" | not privilege_escalation_monitored],
		["5.25: Administrative Privilege Usage must be Logged" | not admin_privilege_usage_logged],
		["5.26: Application Context Usage must be Secured" | not application_context_secured],
		["5.27: Virtual Private Database Policies must be Implemented" | not vpd_policies_implemented],
		["5.28: Definer Rights must be Used Appropriately" | not definer_rights_appropriate],
	]
	v := arrays[_][_]
]

unnecessary_roles_dropped if {
	roles := input.oracle.roles
	unnecessary_roles := ["CONNECT", "RESOURCE"]
	existing_unnecessary := [role | role := roles[_]; role.role_name in unnecessary_roles]
	count(existing_unnecessary) == 0
}

no_users_have_dba_role if {
	user_roles := input.oracle.user_roles
	users_with_dba := [ur | ur := user_roles[_]; ur.role_name == "DBA"]
	count(users_with_dba) == 0
}

dba_roles_protected if {
	dba_role_grants := input.oracle.dba_role_grants
	dba_role_grants.password_protected == true
	dba_role_grants.admin_option_restricted == true
}

custom_dba_roles_least_privilege if {
	custom_admin_roles := input.oracle.custom_admin_roles
	least_privilege_roles := [role |
		role := custom_admin_roles[_]
		role.follows_least_privilege == true
	]
	count(least_privilege_roles) == count(custom_admin_roles)
}

all_roles_password_protected if {
	roles := input.oracle.roles
	non_system_roles := [role | role := roles[_]; not role.system_role]
	password_protected_roles := [role |
		role := non_system_roles[_]
		role.password_protected == true
	]
	count(password_protected_roles) == count(non_system_roles)
}

no_roles_granted_to_public if {
	public_grants := input.oracle.public_grants
	role_grants_to_public := [grant | grant := public_grants[_]; grant.grant_type == "ROLE"]
	count(role_grants_to_public) == 0
}

admin_privileges_granted_appropriately if {
	admin_privilege_grants := input.oracle.admin_privilege_grants
	inappropriate_grants := [grant |
		grant := admin_privilege_grants[_]
		grant.justified == false
	]
	count(inappropriate_grants) == 0
}

grant_any_role_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_role_grants := [priv |
		priv := system_privileges[_]
		priv.privilege == "GRANT ANY ROLE"
	]
	count(grant_any_role_grants) == 0
}

grant_any_privilege_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_privilege_grants := [priv |
		priv := system_privileges[_]
		priv.privilege == "GRANT ANY PRIVILEGE"
	]
	count(grant_any_privilege_grants) == 0
}

grant_any_object_privilege_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_object_privilege_grants := [priv |
		priv := system_privileges[_]
		priv.privilege == "GRANT ANY OBJECT PRIVILEGE"
	]
	count(grant_any_object_privilege_grants) == 0
}

system_privileges_granted_appropriately if {
	system_privilege_grants := input.oracle.system_privilege_grants
	inappropriate_system_grants := [grant |
		grant := system_privilege_grants[_]
		grant.justified == false
	]
	count(inappropriate_system_grants) == 0
}

object_privileges_granted_appropriately if {
	object_privilege_grants := input.oracle.object_privilege_grants
	inappropriate_object_grants := [grant |
		grant := object_privilege_grants[_]
		grant.justified == false
	]
	count(inappropriate_object_grants) == 0
}

with_admin_option_restricted if {
	admin_option_grants := input.oracle.admin_option_grants
	inappropriate_admin_option := [grant |
		grant := admin_option_grants[_]
		grant.justified == false
	]
	count(inappropriate_admin_option) == 0
}

with_grant_option_restricted if {
	grant_option_grants := input.oracle.grant_option_grants
	inappropriate_grant_option := [grant |
		grant := grant_option_grants[_]
		grant.justified == false
	]
	count(inappropriate_grant_option) == 0
}

role_hierarchies_appropriate if {
	role_hierarchies := input.oracle.role_hierarchies
	role_hierarchies.well_designed == true
	role_hierarchies.documented == true
	role_hierarchies.minimal_nesting == true
}

application_roles_used if {
	application_access := input.oracle.application_access
	application_access.uses_application_roles == true
	application_access.no_direct_privilege_grants == true
}

database_link_privileges_restricted if {
	database_link_privileges := input.oracle.database_link_privileges
	public_link_privileges := [priv |
		priv := database_link_privileges[_]
		priv.grantee == "PUBLIC"
	]
	count(public_link_privileges) == 0
}

directory_object_privileges_restricted if {
	directory_privileges := input.oracle.directory_privileges
	public_directory_privileges := [priv |
		priv := directory_privileges[_]
		priv.grantee == "PUBLIC"
	]
	count(public_directory_privileges) == 0
}

java_privileges_restricted if {
	java_privileges := input.oracle.java_privileges
	public_java_privileges := [priv |
		priv := java_privileges[_]
		priv.grantee == "PUBLIC"
	]
	count(public_java_privileges) == 0
}

external_procedure_privileges_restricted if {
	external_proc_privileges := input.oracle.external_procedure_privileges
	public_external_proc_privileges := [priv |
		priv := external_proc_privileges[_]
		priv.grantee == "PUBLIC"
	]
	count(public_external_proc_privileges) == 0
}

network_acl_configured if {
	network_acl := input.oracle.network_acl
	network_acl.configured == true
	network_acl.restrictive_policies == true
	network_acl.documented == true
}

privilege_analysis_implemented if {
	privilege_analysis := input.oracle.privilege_analysis
	privilege_analysis.enabled == true
	privilege_analysis.regular_analysis == true
	privilege_analysis.results_reviewed == true
}

regular_privilege_reviews_conducted if {
	privilege_reviews := input.oracle.privilege_reviews
	privilege_reviews.scheduled == true
	privilege_reviews.frequency_appropriate == true
	privilege_reviews.documented == true
}

privilege_escalation_monitored if {
	privilege_monitoring := input.oracle.privilege_monitoring
	privilege_monitoring.escalation_detection == true
	privilege_monitoring.real_time_alerts == true
}

admin_privilege_usage_logged if {
	admin_privilege_logging := input.oracle.admin_privilege_logging
	admin_privilege_logging.comprehensive == true
	admin_privilege_logging.real_time == true
}

application_context_secured if {
	app_context := input.oracle.application_context
	app_context.secure_implementation == true
	app_context.proper_validation == true
}

vpd_policies_implemented if {
	vpd_policies := input.oracle.vpd_policies
	vpd_policies.implemented == true
	vpd_policies.comprehensive_coverage == true
	vpd_policies.properly_tested == true
}

definer_rights_appropriate if {
	definer_rights := input.oracle.definer_rights
	definer_rights.appropriately_used == true
	definer_rights.security_reviewed == true
}

# Section 6: Fine Grained Access Control
fine_grained_access_violations := [v |
	arrays := [
		["6.1: Virtual Private Database (VPD) must be explicitly configured for Sensitive Data" | not vpd_configured_sensitive_data],
		["6.2: Application Contexts must be Secure" | not application_contexts_secure],
		["6.3: Label Security must be explicitly configured Where Appropriate" | not label_security_configured],
		["6.4: Data Redaction must be explicitly configured for Sensitive Data" | not data_redaction_configured],
		["6.5: Column-Level Security must be Implemented" | not column_level_security_implemented],
		["6.6: Row-Level Security must be Implemented" | not row_level_security_implemented],
		["6.7: Views must be Used to Restrict Data Access" | not views_restrict_data_access],
		["6.8: Synonyms must be Used Appropriately" | not synonyms_used_appropriately],
		["6.9: Database Vault must be explicitly configured" | not database_vault_configured],
		["6.10: Real Application Security must be Implemented" | not ras_implemented],
		["6.11: Fine Grained Auditing (FGA) must be explicitly configured" | not fga_configured],
		["6.12: Data Classification must be Implemented" | not data_classification_implemented],
		["6.13: Sensitive Data Discovery must be Implemented" | not sensitive_data_discovery_implemented],
		["6.14: Data Masking must be explicitly configured" | not data_masking_configured],
		["6.15: Data Pump Security must be explicitly configured" | not data_pump_security_configured],
		["6.16: SQL*Loader Security must be explicitly configured" | not sql_loader_security_configured],
		["6.17: External Table Security must be explicitly configured" | not external_table_security_configured],
		["6.18: UTL_FILE Security must be explicitly configured" | not utl_file_security_configured],
		["6.19: DBMS_SCHEDULER Security must be explicitly configured" | not dbms_scheduler_security_configured],
		["6.20: Advanced Queuing Security must be explicitly configured" | not aq_security_configured],
		["6.21: XML Security must be explicitly configured" | not xml_security_configured],
		["6.22: JSON Security must be explicitly configured" | not json_security_configured],
	]
	v := arrays[_][_]
]

vpd_configured_sensitive_data if {
	vpd_config := input.oracle.vpd_configuration
	vpd_config.enabled == true
	vpd_config.sensitive_tables_covered == true
	vpd_config.policies_comprehensive == true
}

application_contexts_secure if {
	app_contexts := input.oracle.application_contexts
	secure_contexts := [ctx |
		ctx := app_contexts[_]
		ctx.secure_application_role == true
		ctx.properly_validated == true
	]
	count(secure_contexts) == count(app_contexts)
}

label_security_configured if {
	label_security := input.oracle.label_security
	label_security.enabled == true
	label_security.policies_configured == true
	label_security.labels_assigned == true
}

label_security_configured if {
	sensitive_data := input.oracle.sensitive_data
	sensitive_data.requires_label_security == false
}

data_redaction_configured if {
	data_redaction := input.oracle.data_redaction
	data_redaction.enabled == true
	data_redaction.sensitive_columns_covered == true
	data_redaction.policies_comprehensive == true
}

column_level_security_implemented if {
	column_security := input.oracle.column_security
	column_security.implemented == true
	column_security.sensitive_columns_protected == true
}

row_level_security_implemented if {
	row_security := input.oracle.row_security
	row_security.implemented == true
	row_security.vpd_policies_active == true
}

views_restrict_data_access if {
	security_views := input.oracle.security_views
	security_views.implemented == true
	security_views.replace_direct_table_access == true
}

synonyms_used_appropriately if {
	synonyms := input.oracle.synonyms
	public_synonyms := [syn | syn := synonyms[_]; syn.type == "PUBLIC"]
	inappropriate_public_synonyms := [syn |
		syn := public_synonyms[_]
		syn.security_reviewed == false
	]
	count(inappropriate_public_synonyms) == 0
}

database_vault_configured if {
	database_vault := input.oracle.database_vault
	database_vault.enabled == true
	database_vault.realms_configured == true
	database_vault.command_rules_configured == true
}

# Conditional applicability (decision 2026-10-19: kept as a documented reviewer attestation): passes only when the reviewer
# declares the control not required (CIS "if applicable"). The attestation is the reviewer's; the policy does not verify it.
database_vault_configured if {
	database_vault := input.oracle.database_vault
	database_vault.required == false
}

ras_implemented if {
	ras := input.oracle.real_application_security
	ras.enabled == true
	ras.application_privileges_configured == true
	ras.data_security_policies_active == true
}

# Conditional applicability (decision 2026-10-19: kept as a documented reviewer attestation): passes only when the reviewer
# declares the control not required (CIS "if applicable"). The attestation is the reviewer's; the policy does not verify it.
ras_implemented if {
	ras := input.oracle.real_application_security
	ras.required == false
}

fga_configured if {
	fga := input.oracle.fine_grained_auditing
	fga.enabled == true
	fga.sensitive_operations_covered == true
	fga.comprehensive_monitoring == true
}

data_classification_implemented if {
	data_classification := input.oracle.data_classification
	data_classification.implemented == true
	data_classification.sensitive_data_identified == true
	data_classification.classification_maintained == true
}

sensitive_data_discovery_implemented if {
	data_discovery := input.oracle.sensitive_data_discovery
	data_discovery.implemented == true
	data_discovery.regular_scans == true
	data_discovery.results_acted_upon == true
}

data_masking_configured if {
	data_masking := input.oracle.data_masking
	data_masking.enabled == true
	data_masking.sensitive_data_masked == true
	data_masking.production_like_environments == true
}

data_pump_security_configured if {
	data_pump := input.oracle.data_pump_security
	data_pump.access_controlled == true
	data_pump.encryption_enabled == true
	data_pump.auditing_enabled == true
}

sql_loader_security_configured if {
	sql_loader := input.oracle.sql_loader_security
	sql_loader.access_controlled == true
	sql_loader.direct_path_restricted == true
	sql_loader.auditing_enabled == true
}

external_table_security_configured if {
	external_tables := input.oracle.external_table_security
	external_tables.access_controlled == true
	external_tables.directory_permissions_restricted == true
	external_tables.auditing_enabled == true
}

utl_file_security_configured if {
	utl_file := input.oracle.utl_file_security
	utl_file.directory_restrictions == true
	utl_file.access_controlled == true
	utl_file.auditing_enabled == true
}

dbms_scheduler_security_configured if {
	scheduler := input.oracle.dbms_scheduler_security
	scheduler.access_controlled == true
	scheduler.job_privileges_restricted == true
	scheduler.auditing_enabled == true
}

aq_security_configured if {
	aq := input.oracle.advanced_queuing_security
	aq.access_controlled == true
	aq.queue_privileges_restricted == true
	aq.auditing_enabled == true
}

xml_security_configured if {
	xml := input.oracle.xml_security
	xml.access_controlled == true
	xml.schema_validation_enabled == true
	xml.xss_protection_enabled == true
}

json_security_configured if {
	json := input.oracle.json_security
	json.access_controlled == true
	json.validation_enabled == true
	json.injection_protection_enabled == true
}

# Section 7: Encryption
encryption_violations := [v |
	arrays := [
		["7.1: Transparent Data Encryption (TDE) must be explicitly configured" | not tde_configured],
		["7.2: checked condition — TDE Wallet Security" | not tde_wallet_security],
		["7.3: checked condition — TDE Key Management" | not tde_key_management],
		["7.4: Network Encryption must be explicitly configured" | not network_encryption_configured],
		["7.5: Strong Encryption Algorithms must be Used" | not strong_encryption_algorithms],
		["7.6: Backup Encryption must be explicitly configured" | not backup_encryption_configured],
		["7.7: Data Pump Encryption must be explicitly configured" | not data_pump_encryption_configured],
		["7.8: RMAN Encryption must be explicitly configured" | not rman_encryption_configured],
		["7.9: checked condition — Secure External Password Store" | not secure_external_password_store],
		["7.10: Crypto-related Init Parameters must be Set Securely" | not crypto_init_params_secure],
		["7.11: Key Rotation Policies must be Implemented" | not key_rotation_policies_implemented],
		["7.12: checked condition — Encryption Key Backup and Recovery" | not encryption_key_backup_recovery],
		["7.13: Application-Level Encryption must be Considered" | not application_level_encryption_considered],
		["7.14: Encryption Compliance Requirements must be Met" | not encryption_compliance_requirements_met],
		["7.15: Encryption Performance Impact must be Monitored" | not encryption_performance_monitored],
		["7.16: checked condition — Hardware Security Module (HSM) Integration" | not hsm_integration],
	]
	v := arrays[_][_]
]

tde_configured if {
	tde := input.oracle.tde
	tde.enabled == true
	tde.tablespace_encryption == true
	tde.column_encryption_configured == true
}

tde_wallet_security if {
	wallet := input.oracle.tde_wallet
	wallet.auto_open_disabled == true
	wallet.password_protected == true
	wallet.file_permissions_restricted == true
}

tde_key_management if {
	key_management := input.oracle.tde_key_management
	key_management.master_key_secure == true
	key_management.key_rotation_enabled == true
	key_management.key_backup_configured == true
}

network_encryption_configured if {
	network_encryption := input.oracle.network_encryption
	network_encryption.client_server_encryption == true
	network_encryption.strong_algorithms == true
	network_encryption.checksum_enabled == true
}

strong_encryption_algorithms if {
	encryption_algorithms := input.oracle.encryption_algorithms
	weak_algorithms := ["DES", "3DES", "RC4", "MD5"]
	strong_algorithms := ["AES256", "SHA256", "SHA384", "SHA512"]

	algorithms_in_use := encryption_algorithms.algorithms_in_use
	weak_in_use := [alg | alg := weak_algorithms[_]; alg in algorithms_in_use]
	strong_in_use := [alg | alg := strong_algorithms[_]; alg in algorithms_in_use]

	count(weak_in_use) == 0
	count(strong_in_use) > 0
}

backup_encryption_configured if {
	backup_encryption := input.oracle.backup_encryption
	backup_encryption.rman_encryption == true
	backup_encryption.data_pump_encryption == true
	backup_encryption.export_encryption == true
}

data_pump_encryption_configured if {
	data_pump_encryption := input.oracle.data_pump_encryption
	data_pump_encryption.encryption_enabled == true
	data_pump_encryption.strong_algorithm == true
	data_pump_encryption.password_protected == true
}

rman_encryption_configured if {
	rman_encryption := input.oracle.rman_encryption
	rman_encryption.encryption_enabled == true
	rman_encryption.wallet_based == true
	rman_encryption.algorithm_configured == true
}

secure_external_password_store if {
	external_password_store := input.oracle.external_password_store
	external_password_store.enabled == true
	external_password_store.wallet_secured == true
	external_password_store.access_controlled == true
}

crypto_init_params_secure if {
	crypto_params := input.oracle.crypto_init_parameters
	crypto_params.encryption_wallet_location_set == true
	crypto_params.encryption_wallet_type_secure == true
}

key_rotation_policies_implemented if {
	key_rotation := input.oracle.key_rotation
	key_rotation.policy_defined == true
	key_rotation.automated_rotation == true
	key_rotation.rotation_frequency_appropriate == true
}

encryption_key_backup_recovery if {
	key_backup := input.oracle.encryption_key_backup
	key_backup.backup_configured == true
	key_backup.secure_storage == true
	key_backup.recovery_tested == true
}

application_level_encryption_considered if {
	app_encryption := input.oracle.application_level_encryption
	app_encryption.assessment_completed == true
	app_encryption.implemented_where_needed == true
}

encryption_compliance_requirements_met if {
	encryption_compliance := input.oracle.encryption_compliance
	encryption_compliance.requirements_identified == true
	encryption_compliance.controls_implemented == true
	encryption_compliance.regularly_audited == true
}

encryption_performance_monitored if {
	encryption_performance := input.oracle.encryption_performance
	encryption_performance.monitoring_enabled == true
	encryption_performance.impact_assessed == true
	encryption_performance.optimization_implemented == true
}

hsm_integration if {
	hsm := input.oracle.hsm_integration
	hsm.enabled == true
	hsm.properly_configured == true
	hsm.key_management_secure == true
}

# Conditional applicability (decision 2026-10-19: kept as a documented reviewer attestation): passes only when the reviewer
# declares the control not required (CIS "if applicable"). The attestation is the reviewer's; the policy does not verify it.
hsm_integration if {
	hsm := input.oracle.hsm_integration
	hsm.required == false
}

# Section 8: Network Security
network_security_violations := [v |
	arrays := [
		["8.1: Database must be Not Directly Accessible from Untrusted Networks" | not db_not_accessible_untrusted_networks],
		["8.2: Network Access Control Lists must be explicitly configured" | not network_acls_configured],
		["8.3: Valid Node Checking must be turned on" | not valid_node_checking_enabled],
		["8.4: Connection Rate Limiting must be explicitly configured" | not connection_rate_limiting_enabled],
		["8.5: Network Encryption must be turned on" | not network_encryption_enabled],
		["8.6: Network Data Integrity must be turned on" | not network_data_integrity_enabled],
		["8.7: Strong Authentication must be Used for Network Connections" | not strong_network_authentication],
		["8.8: Kerberos Authentication must be explicitly configured Where Appropriate" | not kerberos_auth_configured],
		["8.9: SSL/TLS must be explicitly configured for Database Connections" | not ssl_tls_configured],
		["8.10: checked condition — Network Monitoring and Intrusion Detection" | not network_monitoring_ids],
	]
	v := arrays[_][_]
]

db_not_accessible_untrusted_networks if {
	network_access := input.oracle.network_access
	network_access.firewall_configured == true
	network_access.private_network_only == true
	network_access.public_access_disabled == true
}

network_acls_configured if {
	network_acls := input.oracle.network_acls
	network_acls.configured == true
	network_acls.restrictive_policies == true
	network_acls.regularly_reviewed == true
}

valid_node_checking_enabled if {
	node_checking := input.oracle.valid_node_checking
	node_checking.enabled == true
	node_checking.invited_nodes_configured == true
	node_checking.excluded_nodes_configured == true
}

connection_rate_limiting_enabled if {
	rate_limiting := input.oracle.connection_rate_limiting
	rate_limiting.enabled == true
	rate_limiting.thresholds_appropriate == true
}

network_encryption_enabled if {
	network_encryption := input.oracle.network_encryption
	network_encryption.enabled == true
	network_encryption.strong_algorithms == true
	network_encryption.all_connections_encrypted == true
}

network_data_integrity_enabled if {
	data_integrity := input.oracle.network_data_integrity
	data_integrity.enabled == true
	data_integrity.checksum_algorithms_strong == true
}

strong_network_authentication if {
	network_auth := input.oracle.network_authentication
	strong_methods := ["KERBEROS", "PKI", "RADIUS"]
	weak_methods := ["NONE", "PASSWORD"]

	methods_in_use := network_auth.methods_in_use
	strong_in_use := [method | method := methods_in_use[_]; method in strong_methods]
	weak_in_use := [method | method := methods_in_use[_]; method in weak_methods]

	count(strong_in_use) > 0
	count(weak_in_use) == 0
}

kerberos_auth_configured if {
	kerberos := input.oracle.kerberos_authentication
	kerberos.enabled == true
	kerberos.properly_configured == true
	kerberos.realm_configured == true
}

# Conditional applicability (decision 2026-10-19: kept as a documented reviewer attestation): passes only when the reviewer
# declares the control not required (CIS "if applicable"). The attestation is the reviewer's; the policy does not verify it.
kerberos_auth_configured if {
	kerberos := input.oracle.kerberos_authentication
	kerberos.required == false
}

ssl_tls_configured if {
	ssl_tls := input.oracle.ssl_tls_configuration
	ssl_tls.enabled == true
	ssl_tls.strong_ciphers == true
	ssl_tls.certificate_validation == true
}

network_monitoring_ids if {
	monitoring := input.oracle.network_monitoring
	monitoring.enabled == true
	monitoring.intrusion_detection == true
	monitoring.real_time_alerts == true
}
