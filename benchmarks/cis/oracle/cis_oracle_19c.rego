package cis.oracle_19c

import rego.v1

# CIS Oracle Database 19c Benchmark v1.1.0
# This policy implements the CIS benchmarks for Oracle Database 19c
# Reference: https://www.cisecurity.org/benchmark/oracle_database

# Main compliance evaluation
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
		network_security_violations
	]
	v := arrays[_][_]
]

# Generate compliance report
compliance_report := {
	"benchmark": "CIS Oracle Database 19c Benchmark v1.1.0",
	"timestamp": time.now_ns(),
	"total_controls": 178,
	"compliant": compliant,
	"violations_count": count(violations),
	"violations": violations,
	"sections": {
		"installation_configuration": {
			"violations": count(installation_configuration_violations),
			"controls": 28
		},
		"listener": {
			"violations": count(listener_violations),
			"controls": 18
		},
		"logging_auditing": {
			"violations": count(logging_auditing_violations),
			"controls": 32
		},
		"user_accounts": {
			"violations": count(user_accounts_violations),
			"controls": 24
		},
		"privileges_roles": {
			"violations": count(privileges_roles_violations),
			"controls": 28
		},
		"fine_grained_access": {
			"violations": count(fine_grained_access_violations),
			"controls": 22
		},
		"encryption": {
			"violations": count(encryption_violations),
			"controls": 16
		},
		"network_security": {
			"violations": count(network_security_violations),
			"controls": 10
		}
	}
}

# Section 1: Installation and Configuration
installation_configuration_violations := [v |
	arrays := [
		["1.1: Ensure Oracle Installation Is From Authorized Sources" | not oracle_from_authorized_sources],
		["1.2: Ensure Latest Oracle Patches Are Applied" | not latest_patches_applied],
		["1.3: Ensure Oracle Home Directory Permissions Are Restricted" | not oracle_home_permissions_restricted],
		["1.4: Ensure Oracle Base Directory Permissions Are Restricted" | not oracle_base_permissions_restricted],
		["1.5: Ensure Oracle Data Files Are on Non-System Partitions" | not data_files_non_system_partitions],
		["1.6: Ensure Oracle Software Is Not Installed on System Partitions" | not software_not_on_system_partitions],
		["1.7: Ensure Oracle processes do not run as root or with root privileges" | not oracle_not_root],
		["1.8: Ensure ORACLE_HOME and PATH environment variables are secured" | not environment_variables_secured],
		["1.9: Ensure Oracle inventory is secured" | not oracle_inventory_secured],
		["1.10: Ensure tnsnames.ora file is secured" | not tnsnames_secured],
		["1.11: Ensure sqlnet.ora file is secured" | not sqlnet_secured],
		["1.12: Ensure listener.ora file is secured" | not listener_ora_secured],
		["1.13: Ensure default database accounts are secured" | not default_accounts_secured],
		["1.14: Ensure sample schemas are removed" | not sample_schemas_removed],
		["1.15: Ensure database links are secured" | not database_links_secured],
		["1.16: Ensure external procedures are secured" | not external_procedures_secured],
		["1.17: Ensure UTL_FILE_DIR parameter is not set" | not utl_file_dir_not_set],
		["1.18: Ensure REMOTE_OS_AUTHENT parameter is FALSE" | not remote_os_authent_false],
		["1.19: Ensure REMOTE_OS_ROLES parameter is FALSE" | not remote_os_roles_false],
		["1.20: Ensure SQL92_SECURITY parameter is TRUE" | not sql92_security_true],
		["1.21: Ensure O7_DICTIONARY_ACCESSIBILITY parameter is FALSE" | not o7_dictionary_accessibility_false],
		["1.22: Ensure SEC_CASE_SENSITIVE_LOGON parameter is TRUE" | not sec_case_sensitive_logon_true],
		["1.23: Ensure SEC_MAX_FAILED_LOGIN_ATTEMPTS parameter is set appropriately" | not sec_max_failed_login_attempts_set],
		["1.24: Ensure SEC_PROTOCOL_ERROR_TRACE_ACTION parameter is set to LOG" | not sec_protocol_error_trace_action_log],
		["1.25: Ensure SEC_PROTOCOL_ERROR_FURTHER_ACTION parameter is set appropriately" | not sec_protocol_error_further_action_set],
		["1.26: Ensure SEC_RETURN_SERVER_RELEASE_BANNER parameter is FALSE" | not sec_return_server_release_banner_false],
		["1.27: Ensure GLOBAL_NAMES parameter is TRUE" | not global_names_true],
		["1.28: Ensure database character set is appropriate" | not database_character_set_appropriate]
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

oracle_home_permissions_restricted if {
	oracle_home := input.oracle.directories.oracle_home
	oracle_home.owner == "oracle"
	oracle_home.group == "oinstall"
	oracle_home.mode == "755"
}

oracle_base_permissions_restricted if {
	oracle_base := input.oracle.directories.oracle_base
	oracle_base.owner == "oracle"
	oracle_base.group == "oinstall"
	oracle_base.mode == "755"
}

data_files_non_system_partitions if {
	data_files := input.oracle.data_files
	system_partitions := ["/", "/usr", "/var", "/etc"]
	data_on_system := [df | df := data_files[_]; 
		partition := system_partitions[_]; 
		startswith(df.path, partition)]
	count(data_on_system) == 0
}

software_not_on_system_partitions if {
	oracle_home := input.oracle.directories.oracle_home.path
	not startswith(oracle_home, "/")
	not startswith(oracle_home, "/usr")
	not startswith(oracle_home, "/var")
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
	inventory.mode == "644"
}

tnsnames_secured if {
	tnsnames := input.oracle.network_config.tnsnames_ora
	tnsnames.owner == "oracle"
	tnsnames.group == "oinstall"
	tnsnames.mode == "644"
}

sqlnet_secured if {
	sqlnet := input.oracle.network_config.sqlnet_ora
	sqlnet.owner == "oracle"
	sqlnet.group == "oinstall"
	sqlnet.mode == "644"
}

listener_ora_secured if {
	listener := input.oracle.network_config.listener_ora
	listener.owner == "oracle"
	listener.group == "oinstall"
	listener.mode == "644"
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
	insecure_links := [link | link := db_links[_]; 
		link.password_stored == true; 
		link.encrypted == false]
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
		["2.1: Ensure the Listener is not set to use the default port of 1521" | not listener_not_default_port],
		["2.2: Ensure the Listener Password is Set" | not listener_password_set],
		["2.3: Ensure 'ADMIN_RESTRICTIONS' Is Set to 'ON'" | not admin_restrictions_on],
		["2.4: Ensure 'LOCAL_OS_AUTHENTICATION' is disabled" | not local_os_auth_disabled],
		["2.5: Ensure 'SECURE_REGISTER' is set to 'ON'" | not secure_register_on],
		["2.6: Ensure 'SECURE_CONTROL' is set to 'ON'" | not secure_control_on],
		["2.7: Ensure the listener process runs as a non-privileged user" | not listener_non_privileged_user],
		["2.8: Ensure listener logging is enabled" | not listener_logging_enabled],
		["2.9: Ensure listener log files are protected" | not listener_log_files_protected],
		["2.10: Ensure connection rate limiting is configured" | not connection_rate_limiting_configured],
		["2.11: Ensure listener registration is secured" | not listener_registration_secured],
		["2.12: Ensure TNS_ADMIN is set appropriately" | not tns_admin_set_appropriately],
		["2.13: Ensure NAMES.DIRECTORY_PATH parameter is set correctly" | not names_directory_path_correct],
		["2.14: Ensure SQLNET.AUTHENTICATION_SERVICES parameter is set correctly" | not sqlnet_auth_services_correct],
		["2.15: Ensure SQLNET.AUTHENTICATION_GSSAPI_SERVICE parameter is set correctly" | not sqlnet_gssapi_service_correct],
		["2.16: Ensure SQLNET.CRYPTO_SEED parameter is configured" | not sqlnet_crypto_seed_configured],
		["2.17: Ensure connection timeout is configured" | not connection_timeout_configured],
		["2.18: Ensure listener is configured for SSL/TLS" | not listener_ssl_configured]
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
	log_files.mode == "640"
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
	"TNSNAMES" in directory_path
	not "HOSTNAME" in directory_path
}

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
		["3.1: Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'" | not audit_sys_operations_true],
		["3.2: Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'OS', 'DB, EXTENDED', or 'XML, EXTENDED'" | not audit_trail_appropriate],
		["3.3: Ensure 'AUDIT_FILE_DEST' Is Set to a Dedicated Directory" | not audit_file_dest_dedicated],
		["3.4: Ensure 'DB_ULTRA_SAFE' Is Set to 'DATA_AND_INDEX'" | not db_ultra_safe_set],
		["3.5: Ensure audit files are protected" | not audit_files_protected],
		["3.6: Ensure audit trail destinations are secured" | not audit_destinations_secured],
		["3.7: Ensure comprehensive database activity auditing is enabled" | not comprehensive_auditing_enabled],
		["3.8: Ensure auditing of failed logon attempts is enabled" | not failed_logon_auditing_enabled],
		["3.9: Ensure auditing of successful logon attempts is enabled" | not successful_logon_auditing_enabled],
		["3.10: Ensure auditing of logoff events is enabled" | not logoff_auditing_enabled],
		["3.11: Ensure auditing of database schema changes is enabled" | not schema_changes_auditing_enabled],
		["3.12: Ensure auditing of privilege grants and revokes is enabled" | not privilege_changes_auditing_enabled],
		["3.13: Ensure auditing of data access is enabled for sensitive tables" | not sensitive_data_access_auditing],
		["3.14: Ensure auditing of data modification is enabled for sensitive tables" | not sensitive_data_modification_auditing],
		["3.15: Ensure auditing of administrative operations is enabled" | not admin_operations_auditing_enabled],
		["3.16: Ensure auditing of user creation and deletion is enabled" | not user_management_auditing_enabled],
		["3.17: Ensure auditing of role assignment changes is enabled" | not role_assignment_auditing_enabled],
		["3.18: Ensure auditing of system privilege operations is enabled" | not system_privilege_auditing_enabled],
		["3.19: Ensure auditing of object privilege operations is enabled" | not object_privilege_auditing_enabled],
		["3.20: Ensure auditing of database startup and shutdown is enabled" | not startup_shutdown_auditing_enabled],
		["3.21: Ensure log retention policies are configured" | not log_retention_policies_configured],
		["3.22: Ensure audit log monitoring and alerting is configured" | not audit_monitoring_configured],
		["3.23: Ensure Fine Grained Auditing (FGA) is enabled for sensitive data" | not fga_enabled_sensitive_data],
		["3.24: Ensure Database Vault auditing is enabled" | not database_vault_auditing_enabled],
		["3.25: Ensure audit cleanup jobs are configured" | not audit_cleanup_jobs_configured],
		["3.26: Ensure SYS and SYSTEM operations are audited" | not sys_system_operations_audited],
		["3.27: Ensure public synonym operations are audited" | not public_synonym_operations_audited],
		["3.28: Ensure directory operations are audited" | not directory_operations_audited],
		["3.29: Ensure database link operations are audited" | not database_link_operations_audited],
		["3.30: Ensure external procedure operations are audited" | not external_procedure_operations_audited],
		["3.31: Ensure network operations are audited" | not network_operations_audited],
		["3.32: Ensure SQL*Loader operations are audited" | not sql_loader_operations_audited]
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
	audit_trail in ["DB", "OS", "DB,EXTENDED", "XML,EXTENDED"]
}

audit_file_dest_dedicated if {
	parameters := input.oracle.init_parameters
	audit_file_dest := parameters.audit_file_dest
	audit_file_dest != ""
	not audit_file_dest == "/oracle/admin/orcl/adump"
	startswith(audit_file_dest, "/audit")
}

db_ultra_safe_set if {
	parameters := input.oracle.init_parameters
	parameters.db_ultra_safe == "DATA_AND_INDEX"
}

audit_files_protected if {
	audit_files := input.oracle.audit_files
	audit_files.owner == "oracle"
	audit_files.group == "oinstall"
	audit_files.mode == "640"
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
		["4.1: Ensure All Default Passwords Are Changed" | not default_passwords_changed],
		["4.2: Ensure All Sample Data and Users Are Removed" | not sample_data_users_removed],
		["4.3: Ensure All Unnecessary Accounts Are Removed" | not unnecessary_accounts_removed],
		["4.4: Ensure All Default Accounts That Are Not Needed Are Locked" | not unneeded_default_accounts_locked],
		["4.5: Ensure Password Complexity Is Enforced" | not password_complexity_enforced],
		["4.6: Ensure Password Expiration Is Enforced" | not password_expiration_enforced],
		["4.7: Ensure Password Reuse Is Limited" | not password_reuse_limited],
		["4.8: Ensure Account Lockout Policy Is Enforced" | not account_lockout_enforced],
		["4.9: Ensure Password Grace Period Is Limited" | not password_grace_period_limited],
		["4.10: Ensure Strong Authentication Methods Are Used" | not strong_authentication_used],
		["4.11: Ensure Database Authentication Is Not Used for Application Accounts" | not db_auth_not_used_for_apps],
		["4.12: Ensure External Authentication Is Secured" | not external_auth_secured],
		["4.13: Ensure Global Authentication Is Secured" | not global_auth_secured],
		["4.14: Ensure Database User Session Management Is Configured" | not session_management_configured],
		["4.15: Ensure Idle Time Limits Are Enforced" | not idle_time_limits_enforced],
		["4.16: Ensure Connect Time Limits Are Enforced" | not connect_time_limits_enforced],
		["4.17: Ensure Concurrent Session Limits Are Enforced" | not concurrent_session_limits_enforced],
		["4.18: Ensure User Profile Management Is Implemented" | not user_profile_management_implemented],
		["4.19: Ensure Application User Account Management Is Secured" | not app_user_account_management_secured],
		["4.20: Ensure Service Account Management Is Secured" | not service_account_management_secured],
		["4.21: Ensure Administrative Account Usage Is Monitored" | not admin_account_usage_monitored],
		["4.22: Ensure Emergency Account Procedures Are Defined" | not emergency_account_procedures_defined],
		["4.23: Ensure Account Lifecycle Management Is Implemented" | not account_lifecycle_management_implemented],
		["4.24: Ensure Shared Account Usage Is Eliminated or Controlled" | not shared_account_usage_controlled]
	]
	v := arrays[_][_]
]

default_passwords_changed if {
	default_accounts := input.oracle.default_accounts
	accounts_with_default_passwords := [acc | acc := default_accounts[_]; 
		acc.password_changed == false]
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
	unnecessary_accounts := [acc | acc := accounts[_]; 
		acc.necessary == false; 
		acc.status == "OPEN"]
	count(unnecessary_accounts) == 0
}

unneeded_default_accounts_locked if {
	default_accounts := input.oracle.default_accounts
	unneeded_accounts := [acc | acc := default_accounts[_]; 
		acc.needed == false; 
		acc.status != "LOCKED"]
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
	weak_methods := ["OS", "PASSWORD"]
	strong_auth_enabled := [method | method := auth_methods[_]; method in strong_methods]
	weak_auth_only := [method | method := auth_methods[_]; method in weak_methods]
	count(strong_auth_enabled) > 0
}

db_auth_not_used_for_apps if {
	app_accounts := input.oracle.application_accounts
	db_auth_app_accounts := [acc | acc := app_accounts[_]; 
		acc.authentication_method == "DATABASE"]
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
	controlled_shared := [acc | acc := shared_accounts[_]; 
		acc.justified == true; 
		acc.monitored == true; 
		acc.access_controlled == true]
	count(controlled_shared) == count(shared_accounts)
}

# Section 5: Privileges and Roles
privileges_roles_violations := [v |
	arrays := [
		["5.1: Ensure All Unnecessary Roles Are Dropped" | not unnecessary_roles_dropped],
		["5.2: Ensure No Users Have the DBA Role" | not no_users_have_dba_role],
		["5.3: Ensure DBA Roles Are Protected" | not dba_roles_protected],
		["5.4: Ensure Custom DBA Roles Follow Principle of Least Privilege" | not custom_dba_roles_least_privilege],
		["5.5: Ensure All Roles are Password Protected" | not all_roles_password_protected],
		["5.6: Ensure No Roles Are Granted to PUBLIC" | not no_roles_granted_to_public],
		["5.7: Ensure DBA and Other Administrative Privileges Are Granted Only Where Needed" | not admin_privileges_granted_appropriately],
		["5.8: Ensure 'GRANT ANY ROLE' Privilege Is Restricted" | not grant_any_role_restricted],
		["5.9: Ensure 'GRANT ANY PRIVILEGE' Privilege Is Restricted" | not grant_any_privilege_restricted],
		["5.10: Ensure 'GRANT ANY OBJECT PRIVILEGE' Privilege Is Restricted" | not grant_any_object_privilege_restricted],
		["5.11: Ensure System Privileges Are Granted Appropriately" | not system_privileges_granted_appropriately],
		["5.12: Ensure Object Privileges Are Granted Appropriately" | not object_privileges_granted_appropriately],
		["5.13: Ensure WITH ADMIN OPTION Is Restricted" | not with_admin_option_restricted],
		["5.14: Ensure WITH GRANT OPTION Is Restricted" | not with_grant_option_restricted],
		["5.15: Ensure Role Hierarchies Are Appropriately Designed" | not role_hierarchies_appropriate],
		["5.16: Ensure Application Roles Are Used for Application Access" | not application_roles_used],
		["5.17: Ensure Database Link Privileges Are Restricted" | not database_link_privileges_restricted],
		["5.18: Ensure Directory Object Privileges Are Restricted" | not directory_object_privileges_restricted],
		["5.19: Ensure Java Privileges Are Restricted" | not java_privileges_restricted],
		["5.20: Ensure External Procedure Privileges Are Restricted" | not external_procedure_privileges_restricted],
		["5.21: Ensure Network Access Control List (ACL) Is Configured" | not network_acl_configured],
		["5.22: Ensure Privilege Analysis Is Implemented" | not privilege_analysis_implemented],
		["5.23: Ensure Regular Privilege Reviews Are Conducted" | not regular_privilege_reviews_conducted],
		["5.24: Ensure Privilege Escalation Is Monitored" | not privilege_escalation_monitored],
		["5.25: Ensure Administrative Privilege Usage Is Logged" | not admin_privilege_usage_logged],
		["5.26: Ensure Application Context Usage Is Secured" | not application_context_secured],
		["5.27: Ensure Virtual Private Database Policies Are Implemented" | not vpd_policies_implemented],
		["5.28: Ensure Definer Rights Are Used Appropriately" | not definer_rights_appropriate]
	]
	v := arrays[_][_]
]

unnecessary_roles_dropped if {
	roles := input.oracle.roles
	predefined_roles := ["CONNECT", "RESOURCE", "DBA", "IMP_FULL_DATABASE", "EXP_FULL_DATABASE"]
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
	least_privilege_roles := [role | role := custom_admin_roles[_]; 
		role.follows_least_privilege == true]
	count(least_privilege_roles) == count(custom_admin_roles)
}

all_roles_password_protected if {
	roles := input.oracle.roles
	non_system_roles := [role | role := roles[_]; not role.system_role]
	password_protected_roles := [role | role := non_system_roles[_]; 
		role.password_protected == true]
	count(password_protected_roles) == count(non_system_roles)
}

no_roles_granted_to_public if {
	public_grants := input.oracle.public_grants
	role_grants_to_public := [grant | grant := public_grants[_]; grant.grant_type == "ROLE"]
	count(role_grants_to_public) == 0
}

admin_privileges_granted_appropriately if {
	admin_privilege_grants := input.oracle.admin_privilege_grants
	inappropriate_grants := [grant | grant := admin_privilege_grants[_]; 
		grant.justified == false]
	count(inappropriate_grants) == 0
}

grant_any_role_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_role_grants := [priv | priv := system_privileges[_]; 
		priv.privilege == "GRANT ANY ROLE"]
	count(grant_any_role_grants) <= 1
}

grant_any_privilege_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_privilege_grants := [priv | priv := system_privileges[_]; 
		priv.privilege == "GRANT ANY PRIVILEGE"]
	count(grant_any_privilege_grants) == 0
}

grant_any_object_privilege_restricted if {
	system_privileges := input.oracle.system_privileges
	grant_any_object_privilege_grants := [priv | priv := system_privileges[_]; 
		priv.privilege == "GRANT ANY OBJECT PRIVILEGE"]
	count(grant_any_object_privilege_grants) == 0
}

system_privileges_granted_appropriately if {
	system_privilege_grants := input.oracle.system_privilege_grants
	inappropriate_system_grants := [grant | grant := system_privilege_grants[_]; 
		grant.justified == false]
	count(inappropriate_system_grants) == 0
}

object_privileges_granted_appropriately if {
	object_privilege_grants := input.oracle.object_privilege_grants
	inappropriate_object_grants := [grant | grant := object_privilege_grants[_]; 
		grant.justified == false]
	count(inappropriate_object_grants) == 0
}

with_admin_option_restricted if {
	admin_option_grants := input.oracle.admin_option_grants
	inappropriate_admin_option := [grant | grant := admin_option_grants[_]; 
		grant.justified == false]
	count(inappropriate_admin_option) == 0
}

with_grant_option_restricted if {
	grant_option_grants := input.oracle.grant_option_grants
	inappropriate_grant_option := [grant | grant := grant_option_grants[_]; 
		grant.justified == false]
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
	public_link_privileges := [priv | priv := database_link_privileges[_]; 
		priv.grantee == "PUBLIC"]
	count(public_link_privileges) == 0
}

directory_object_privileges_restricted if {
	directory_privileges := input.oracle.directory_privileges
	public_directory_privileges := [priv | priv := directory_privileges[_]; 
		priv.grantee == "PUBLIC"]
	count(public_directory_privileges) == 0
}

java_privileges_restricted if {
	java_privileges := input.oracle.java_privileges
	public_java_privileges := [priv | priv := java_privileges[_]; 
		priv.grantee == "PUBLIC"]
	count(public_java_privileges) == 0
}

external_procedure_privileges_restricted if {
	external_proc_privileges := input.oracle.external_procedure_privileges
	public_external_proc_privileges := [priv | priv := external_proc_privileges[_]; 
		priv.grantee == "PUBLIC"]
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
		["6.1: Ensure Virtual Private Database (VPD) Is Configured for Sensitive Data" | not vpd_configured_sensitive_data],
		["6.2: Ensure Application Contexts Are Secure" | not application_contexts_secure],
		["6.3: Ensure Label Security Is Configured Where Appropriate" | not label_security_configured],
		["6.4: Ensure Data Redaction Is Configured for Sensitive Data" | not data_redaction_configured],
		["6.5: Ensure Column-Level Security Is Implemented" | not column_level_security_implemented],
		["6.6: Ensure Row-Level Security Is Implemented" | not row_level_security_implemented],
		["6.7: Ensure Views Are Used to Restrict Data Access" | not views_restrict_data_access],
		["6.8: Ensure Synonyms Are Used Appropriately" | not synonyms_used_appropriately],
		["6.9: Ensure Database Vault Is Configured" | not database_vault_configured],
		["6.10: Ensure Real Application Security Is Implemented" | not ras_implemented],
		["6.11: Ensure Fine Grained Auditing (FGA) Is Configured" | not fga_configured],
		["6.12: Ensure Data Classification Is Implemented" | not data_classification_implemented],
		["6.13: Ensure Sensitive Data Discovery Is Implemented" | not sensitive_data_discovery_implemented],
		["6.14: Ensure Data Masking Is Configured" | not data_masking_configured],
		["6.15: Ensure Data Pump Security Is Configured" | not data_pump_security_configured],
		["6.16: Ensure SQL*Loader Security Is Configured" | not sql_loader_security_configured],
		["6.17: Ensure External Table Security Is Configured" | not external_table_security_configured],
		["6.18: Ensure UTL_FILE Security Is Configured" | not utl_file_security_configured],
		["6.19: Ensure DBMS_SCHEDULER Security Is Configured" | not dbms_scheduler_security_configured],
		["6.20: Ensure Advanced Queuing Security Is Configured" | not aq_security_configured],
		["6.21: Ensure XML Security Is Configured" | not xml_security_configured],
		["6.22: Ensure JSON Security Is Configured" | not json_security_configured]
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
	secure_contexts := [ctx | ctx := app_contexts[_]; 
		ctx.secure_application_role == true; 
		ctx.properly_validated == true]
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
	inappropriate_public_synonyms := [syn | syn := public_synonyms[_]; 
		syn.security_reviewed == false]
	count(inappropriate_public_synonyms) == 0
}

database_vault_configured if {
	database_vault := input.oracle.database_vault
	database_vault.enabled == true
	database_vault.realms_configured == true
	database_vault.command_rules_configured == true
}

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
		["7.1: Ensure Transparent Data Encryption (TDE) Is Configured" | not tde_configured],
		["7.2: Ensure TDE Wallet Security" | not tde_wallet_security],
		["7.3: Ensure TDE Key Management" | not tde_key_management],
		["7.4: Ensure Network Encryption Is Configured" | not network_encryption_configured],
		["7.5: Ensure Strong Encryption Algorithms Are Used" | not strong_encryption_algorithms],
		["7.6: Ensure Backup Encryption Is Configured" | not backup_encryption_configured],
		["7.7: Ensure Data Pump Encryption Is Configured" | not data_pump_encryption_configured],
		["7.8: Ensure RMAN Encryption Is Configured" | not rman_encryption_configured],
		["7.9: Ensure Secure External Password Store" | not secure_external_password_store],
		["7.10: Ensure Crypto-related Init Parameters Are Set Securely" | not crypto_init_params_secure],
		["7.11: Ensure Key Rotation Policies Are Implemented" | not key_rotation_policies_implemented],
		["7.12: Ensure Encryption Key Backup and Recovery" | not encryption_key_backup_recovery],
		["7.13: Ensure Application-Level Encryption Is Considered" | not application_level_encryption_considered],
		["7.14: Ensure Encryption Compliance Requirements Are Met" | not encryption_compliance_requirements_met],
		["7.15: Ensure Encryption Performance Impact Is Monitored" | not encryption_performance_monitored],
		["7.16: Ensure Hardware Security Module (HSM) Integration" | not hsm_integration]
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

hsm_integration if {
	hsm := input.oracle.hsm_integration
	hsm.required == false
}

# Section 8: Network Security
network_security_violations := [v |
	arrays := [
		["8.1: Ensure Database Is Not Directly Accessible from Untrusted Networks" | not db_not_accessible_untrusted_networks],
		["8.2: Ensure Network Access Control Lists Are Configured" | not network_acls_configured],
		["8.3: Ensure Valid Node Checking Is Enabled" | not valid_node_checking_enabled],
		["8.4: Ensure Connection Rate Limiting Is Configured" | not connection_rate_limiting_enabled],
		["8.5: Ensure Network Encryption Is Enabled" | not network_encryption_enabled],
		["8.6: Ensure Network Data Integrity Is Enabled" | not network_data_integrity_enabled],
		["8.7: Ensure Strong Authentication Is Used for Network Connections" | not strong_network_authentication],
		["8.8: Ensure Kerberos Authentication Is Configured Where Appropriate" | not kerberos_auth_configured],
		["8.9: Ensure SSL/TLS Is Configured for Database Connections" | not ssl_tls_configured],
		["8.10: Ensure Network Monitoring and Intrusion Detection" | not network_monitoring_ids]
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