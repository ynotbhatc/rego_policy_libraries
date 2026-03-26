package cis.postgresql_14

import rego.v1

# CIS PostgreSQL 14 Benchmark v1.1.0
# This policy implements the CIS benchmarks for PostgreSQL 14 Database Server
# Reference: https://www.cisecurity.org/benchmark/postgresql

# Main compliance evaluation
compliant if {
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		installation_violations,
		directory_file_permissions_violations,
		logging_violations,
		user_access_violations,
		connection_ssl_violations,
		postgresql_settings_violations,
		replication_violations,
		special_requirements_violations
	]
	v := arrays[_][_]
]

# Generate compliance report
compliance_report := {
	"benchmark": "CIS PostgreSQL 14 Benchmark v1.1.0",
	"timestamp": time.now_ns(),
	"total_controls": 168,
	"compliant": compliant,
	"violations_count": count(violations),
	"violations": violations,
	"sections": {
		"installation": {
			"violations": count(installation_violations),
			"controls": 12
		},
		"directory_file_permissions": {
			"violations": count(directory_file_permissions_violations),
			"controls": 18
		},
		"logging": {
			"violations": count(logging_violations),
			"controls": 26
		},
		"user_access": {
			"violations": count(user_access_violations),
			"controls": 30
		},
		"connection_ssl": {
			"violations": count(connection_ssl_violations),
			"controls": 24
		},
		"postgresql_settings": {
			"violations": count(postgresql_settings_violations),
			"controls": 40
		},
		"replication": {
			"violations": count(replication_violations),
			"controls": 10
		},
		"special_requirements": {
			"violations": count(special_requirements_violations),
			"controls": 8
		}
	}
}

# Section 1: Installation and Patches
installation_violations := [v |
	arrays := [
		["1.1: Ensure packages are obtained from authorized repositories" | not packages_from_authorized_repos],
		["1.2: Ensure systemd service files are enabled" | not systemd_service_enabled],
		["1.3: Ensure data cluster initialized successfully" | not data_cluster_initialized],
		["1.4: Ensure the installation is up to date" | not installation_up_to_date],
		["1.5: Ensure PostgreSQL is not running as root" | not postgresql_not_running_as_root],
		["1.6: Ensure PostgreSQL installation directories are secured" | not installation_directories_secured],
		["1.7: Ensure PostgreSQL configuration files are secured" | not config_files_secured],
		["1.8: Ensure PostgreSQL subdirectory locations are outside system directories" | not subdirs_outside_system],
		["1.9: Ensure PostgreSQL backup and recovery procedures are in place" | not backup_recovery_procedures],
		["1.10: Ensure PostgreSQL monitoring is configured" | not monitoring_configured],
		["1.11: Ensure PostgreSQL timezone is set appropriately" | not timezone_set_appropriately],
		["1.12: Ensure PostgreSQL locale settings are configured" | not locale_settings_configured]
	]
	v := arrays[_][_]
]

packages_from_authorized_repos if {
	installation := input.postgresql.installation
	installation.source == "official_repository"
	installation.verified_signature == true
}

systemd_service_enabled if {
	service := input.postgresql.service
	service.enabled == true
	service.status == "active"
}

data_cluster_initialized if {
	cluster := input.postgresql.cluster
	cluster.initialized == true
	cluster.version == "14"
}

installation_up_to_date if {
	version := input.postgresql.version
	version.current == version.latest_patch
	version.security_updates_applied == true
}

postgresql_not_running_as_root if {
	process := input.postgresql.process
	process.user != "root"
	process.effective_uid != 0
}

installation_directories_secured if {
	dirs := input.postgresql.directories
	dirs.bin_directory.owner == "root"
	dirs.bin_directory.group == "postgres"
	dirs.bin_directory.mode == "755"
}

config_files_secured if {
	config := input.postgresql.config_files
	config.postgresql_conf.owner == "postgres"
	config.postgresql_conf.group == "postgres"
	config.postgresql_conf.mode == "600"
	config.pg_hba_conf.mode == "600"
}

subdirs_outside_system if {
	dirs := input.postgresql.directories
	data_dir := dirs.data_directory
	not startswith(data_dir, "/")
	not startswith(data_dir, "/usr")
	not startswith(data_dir, "/etc")
}

backup_recovery_procedures if {
	backup := input.postgresql.backup
	backup.procedure_documented == true
	backup.automated_backups == true
	backup.recovery_tested == true
}

monitoring_configured if {
	monitoring := input.postgresql.monitoring
	monitoring.enabled == true
	monitoring.log_monitoring == true
	monitoring.performance_monitoring == true
}

timezone_set_appropriately if {
	settings := input.postgresql.settings
	settings.timezone != ""
	settings.timezone != "localtime"
}

locale_settings_configured if {
	locale := input.postgresql.locale
	locale.lc_collate != ""
	locale.lc_ctype != ""
	locale.encoding == "UTF8"
}

# Section 2: Directory and File Permissions
directory_file_permissions_violations := [v |
	arrays := [
		["2.1: Ensure the file permissions mask is correct" | not file_permissions_mask_correct],
		["2.2: Ensure the PostgreSQL Data Cluster is initialized" | not data_cluster_perms_correct],
		["2.3: Ensure the data directory has appropriate permissions" | not data_directory_permissions],
		["2.4: Ensure the configuration files have appropriate permissions" | not config_file_permissions],
		["2.5: Ensure the log files have appropriate permissions" | not log_file_permissions],
		["2.6: Ensure the backup files have appropriate permissions" | not backup_file_permissions],
		["2.7: Ensure WAL archive files have appropriate permissions" | not wal_archive_permissions],
		["2.8: Ensure temporary files have appropriate permissions" | not temp_file_permissions],
		["2.9: Ensure tablespace files have appropriate permissions" | not tablespace_permissions],
		["2.10: Ensure socket files have appropriate permissions" | not socket_file_permissions],
		["2.11: Ensure certificate files have appropriate permissions" | not certificate_file_permissions],
		["2.12: Ensure private key files have appropriate permissions" | not private_key_permissions],
		["2.13: Ensure SSL CRL files have appropriate permissions" | not ssl_crl_permissions],
		["2.14: Ensure external configuration files have appropriate permissions" | not external_config_permissions],
		["2.15: Ensure pgpass files have appropriate permissions" | not pgpass_file_permissions],
		["2.16: Ensure service files have appropriate permissions" | not service_file_permissions],
		["2.17: Ensure script files have appropriate permissions" | not script_file_permissions],
		["2.18: Ensure extension files have appropriate permissions" | not extension_file_permissions]
	]
	v := arrays[_][_]
]

file_permissions_mask_correct if {
	umask := input.postgresql.system.umask
	umask == "077"
}

data_cluster_perms_correct if {
	cluster_perms := input.postgresql.file_permissions.data_cluster
	cluster_perms.owner == "postgres"
	cluster_perms.group == "postgres"
	cluster_perms.mode == "700"
}

data_directory_permissions if {
	data_perms := input.postgresql.file_permissions.data_directory
	data_perms.owner == "postgres"
	data_perms.group == "postgres"
	data_perms.mode == "700"
}

config_file_permissions if {
	config_perms := input.postgresql.file_permissions.config_files
	config_perms.postgresql_conf.mode == "600"
	config_perms.pg_hba_conf.mode == "600"
	config_perms.pg_ident_conf.mode == "600"
}

log_file_permissions if {
	log_perms := input.postgresql.file_permissions.log_files
	log_perms.owner == "postgres"
	log_perms.group == "postgres"
	log_perms.mode == "600"
}

backup_file_permissions if {
	backup_perms := input.postgresql.file_permissions.backup_files
	backup_perms.owner == "postgres"
	backup_perms.group == "postgres"
	backup_perms.mode == "600"
}

wal_archive_permissions if {
	wal_perms := input.postgresql.file_permissions.wal_archive
	wal_perms.owner == "postgres"
	wal_perms.group == "postgres"
	wal_perms.mode == "700"
}

temp_file_permissions if {
	temp_perms := input.postgresql.file_permissions.temp_files
	temp_perms.owner == "postgres"
	temp_perms.group == "postgres"
	temp_perms.mode == "600"
}

tablespace_permissions if {
	tablespace_perms := input.postgresql.file_permissions.tablespaces
	tablespace_perms.owner == "postgres"
	tablespace_perms.group == "postgres"
	tablespace_perms.mode == "700"
}

socket_file_permissions if {
	socket_perms := input.postgresql.file_permissions.socket_files
	socket_perms.owner == "postgres"
	socket_perms.group == "postgres"
	socket_perms.mode == "755"
}

certificate_file_permissions if {
	cert_perms := input.postgresql.file_permissions.certificates
	cert_perms.owner == "postgres"
	cert_perms.group == "postgres"
	cert_perms.mode == "644"
}

private_key_permissions if {
	key_perms := input.postgresql.file_permissions.private_keys
	key_perms.owner == "postgres"
	key_perms.group == "postgres"
	key_perms.mode == "600"
}

ssl_crl_permissions if {
	crl_perms := input.postgresql.file_permissions.ssl_crl
	crl_perms.owner == "postgres"
	crl_perms.group == "postgres"
	crl_perms.mode == "644"
}

external_config_permissions if {
	ext_config_perms := input.postgresql.file_permissions.external_config
	ext_config_perms.owner == "postgres"
	ext_config_perms.group == "postgres"
	ext_config_perms.mode == "600"
}

pgpass_file_permissions if {
	pgpass_perms := input.postgresql.file_permissions.pgpass
	pgpass_perms.owner == "postgres"
	pgpass_perms.group == "postgres"
	pgpass_perms.mode == "600"
}

service_file_permissions if {
	service_perms := input.postgresql.file_permissions.service_files
	service_perms.owner == "root"
	service_perms.group == "root"
	service_perms.mode == "644"
}

script_file_permissions if {
	script_perms := input.postgresql.file_permissions.scripts
	script_perms.owner == "postgres"
	script_perms.group == "postgres"
	script_perms.mode == "755"
}

extension_file_permissions if {
	ext_perms := input.postgresql.file_permissions.extensions
	ext_perms.owner == "root"
	ext_perms.group == "postgres"
	ext_perms.mode == "644"
}

# Section 3: Logging Monitoring and Auditing
logging_violations := [v |
	arrays := [
		["3.1: Ensure the log destinations are set correctly" | not log_destinations_correct],
		["3.2: Ensure the logging collector is enabled" | not logging_collector_enabled],
		["3.3: Ensure the log file destination directory is set correctly" | not log_directory_correct],
		["3.4: Ensure the filename pattern for log files is set correctly" | not log_filename_pattern_correct],
		["3.5: Ensure the log file permissions are set correctly" | not log_permissions_correct],
		["3.6: Ensure log_truncate_on_rotation is disabled" | not log_truncate_disabled],
		["3.7: Ensure the maximum log file lifetime is set correctly" | not log_rotation_age_correct],
		["3.8: Ensure the maximum log file size is set correctly" | not log_rotation_size_correct],
		["3.9: Ensure the appropriate syslog facility is selected" | not syslog_facility_correct],
		["3.10: Ensure the program name for PostgreSQL syslog messages is correct" | not syslog_ident_correct],
		["3.11: Ensure the correct syslog sequence numbers are logged" | not syslog_sequence_numbers],
		["3.12: Ensure the correct syslog split messages are logged" | not syslog_split_messages],
		["3.13: Ensure 'log_connections' is enabled" | not log_connections_enabled],
		["3.14: Ensure 'log_disconnections' is enabled" | not log_disconnections_enabled],
		["3.15: Ensure 'log_error_verbosity' is set correctly" | not log_error_verbosity_correct],
		["3.16: Ensure 'log_hostname' is set correctly" | not log_hostname_correct],
		["3.17: Ensure 'log_line_prefix' is set correctly" | not log_line_prefix_correct],
		["3.18: Ensure 'log_statement' is set correctly" | not log_statement_correct],
		["3.19: Ensure 'log_timezone' is set correctly" | not log_timezone_correct],
		["3.20: Ensure 'shared_preload_libraries' is set correctly" | not shared_preload_libraries_correct],
		["3.21: Ensure 'pgaudit.log' is set correctly" | not pgaudit_log_correct],
		["3.22: Ensure 'pgaudit.log_catalog' is enabled" | not pgaudit_log_catalog_enabled],
		["3.23: Ensure 'pgaudit.log_parameter' is enabled" | not pgaudit_log_parameter_enabled],
		["3.24: Ensure 'pgaudit.log_level' is set correctly" | not pgaudit_log_level_correct],
		["3.25: Ensure 'log_checkpoints' is enabled" | not log_checkpoints_enabled],
		["3.26: Ensure 'log_lock_waits' is enabled" | not log_lock_waits_enabled]
	]
	v := arrays[_][_]
]

log_destinations_correct if {
	log_config := input.postgresql.logging
	destinations := log_config.log_destination
	"stderr" in destinations
	not "syslog" in destinations
}

log_destinations_correct if {
	log_config := input.postgresql.logging
	destinations := log_config.log_destination
	"stderr" in destinations
	"syslog" in destinations
	log_config.syslog_configured == true
}

logging_collector_enabled if {
	input.postgresql.logging.logging_collector == "on"
}

log_directory_correct if {
	log_dir := input.postgresql.logging.log_directory
	log_dir != ""
	not startswith(log_dir, "/tmp")
	startswith(log_dir, "/var/log/postgresql")
}

log_directory_correct if {
	log_dir := input.postgresql.logging.log_directory
	log_dir != ""
	not startswith(log_dir, "/tmp")
	startswith(log_dir, "log")
}

log_filename_pattern_correct if {
	log_filename := input.postgresql.logging.log_filename
	contains(log_filename, "%Y")
	contains(log_filename, "%m")
	contains(log_filename, "%d")
}

log_permissions_correct if {
	log_perms := input.postgresql.logging.log_file_mode
	log_perms == "0600"
}

log_truncate_disabled if {
	input.postgresql.logging.log_truncate_on_rotation == "off"
}

log_rotation_age_correct if {
	rotation_age := input.postgresql.logging.log_rotation_age
	rotation_age_hours := to_number(split(rotation_age, "h")[0])
	rotation_age_hours <= 24
	rotation_age_hours > 0
}

log_rotation_size_correct if {
	rotation_size := input.postgresql.logging.log_rotation_size
	rotation_size != "0"
	rotation_size_mb := to_number(split(rotation_size, "MB")[0])
	rotation_size_mb <= 1024
}

syslog_facility_correct if {
	syslog_facility := input.postgresql.logging.syslog_facility
	syslog_facility in ["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]
}

syslog_ident_correct if {
	syslog_ident := input.postgresql.logging.syslog_ident
	syslog_ident == "postgres"
}

syslog_sequence_numbers if {
	input.postgresql.logging.syslog_sequence_numbers == "on"
}

syslog_split_messages if {
	input.postgresql.logging.syslog_split_messages == "on"
}

log_connections_enabled if {
	input.postgresql.logging.log_connections == "on"
}

log_disconnections_enabled if {
	input.postgresql.logging.log_disconnections == "on"
}

log_error_verbosity_correct if {
	error_verbosity := input.postgresql.logging.log_error_verbosity
	error_verbosity in ["default", "verbose"]
}

log_hostname_correct if {
	input.postgresql.logging.log_hostname == "on"
}

log_line_prefix_correct if {
	line_prefix := input.postgresql.logging.log_line_prefix
	contains(line_prefix, "%t")
	contains(line_prefix, "%u")
	contains(line_prefix, "%d")
	contains(line_prefix, "%p")
}

log_statement_correct if {
	log_statement := input.postgresql.logging.log_statement
	log_statement in ["ddl", "mod", "all"]
}

log_timezone_correct if {
	log_timezone := input.postgresql.logging.log_timezone
	log_timezone != ""
}

shared_preload_libraries_correct if {
	preload_libs := input.postgresql.settings.shared_preload_libraries
	"pgaudit" in preload_libs
}

pgaudit_log_correct if {
	pgaudit_log := input.postgresql.pgaudit.log
	pgaudit_settings := split(pgaudit_log, ",")
	"ddl" in pgaudit_settings
	"write" in pgaudit_settings
}

pgaudit_log_catalog_enabled if {
	input.postgresql.pgaudit.log_catalog == "on"
}

pgaudit_log_parameter_enabled if {
	input.postgresql.pgaudit.log_parameter == "on"
}

pgaudit_log_level_correct if {
	pgaudit_log_level := input.postgresql.pgaudit.log_level
	pgaudit_log_level in ["log", "notice"]
}

log_checkpoints_enabled if {
	input.postgresql.logging.log_checkpoints == "on"
}

log_lock_waits_enabled if {
	input.postgresql.logging.log_lock_waits == "on"
}

# Section 4: User Access and Authorization
user_access_violations := [v |
	arrays := [
		["4.1: Ensure sudo is configured correctly" | not sudo_configured_correctly],
		["4.2: Ensure excessive administrative privileges are revoked" | not excessive_admin_privileges_revoked],
		["4.3: Ensure excessive function privileges are revoked" | not excessive_function_privileges_revoked],
		["4.4: Ensure excessive DML privileges are revoked" | not excessive_dml_privileges_revoked],
		["4.5: Ensure row level security is enabled when supported" | not row_level_security_enabled],
		["4.6: Ensure the PostgreSQL default administrative database 'postgres' is protected" | not postgres_db_protected],
		["4.7: Ensure database names are not descriptive or default" | not database_names_appropriate],
		["4.8: Ensure the PostgreSQL version is not easily identifiable" | not version_not_identifiable],
		["4.9: Ensure role-based authentication is configured" | not role_based_auth_configured],
		["4.10: Ensure password authentication is required for local connections" | not password_auth_local_required],
		["4.11: Ensure password complexity rules are configured" | not password_complexity_configured],
		["4.12: Ensure password expiration is enforced" | not password_expiration_enforced],
		["4.13: Ensure account lockout policies are enforced" | not account_lockout_enforced],
		["4.14: Ensure minimum password age is enforced" | not min_password_age_enforced],
		["4.15: Ensure password history is enforced" | not password_history_enforced],
		["4.16: Ensure login events are monitored" | not login_events_monitored],
		["4.17: Ensure superuser account usage is limited" | not superuser_usage_limited],
		["4.18: Ensure role membership is controlled" | not role_membership_controlled],
		["4.19: Ensure object ownership is controlled" | not object_ownership_controlled],
		["4.20: Ensure schema usage is controlled" | not schema_usage_controlled],
		["4.21: Ensure table access is controlled" | not table_access_controlled],
		["4.22: Ensure column-level security is implemented" | not column_level_security_implemented],
		["4.23: Ensure function execution is controlled" | not function_execution_controlled],
		["4.24: Ensure sequence access is controlled" | not sequence_access_controlled],
		["4.25: Ensure foreign data wrapper access is controlled" | not fdw_access_controlled],
		["4.26: Ensure language usage is controlled" | not language_usage_controlled],
		["4.27: Ensure large object access is controlled" | not large_object_access_controlled],
		["4.28: Ensure tablespace usage is controlled" | not tablespace_usage_controlled],
		["4.29: Ensure publication and subscription security" | not publication_subscription_security],
		["4.30: Ensure parallel query security is configured" | not parallel_query_security]
	]
	v := arrays[_][_]
]

sudo_configured_correctly if {
	sudo_config := input.postgresql.system.sudo_config
	postgres_sudo := [rule | rule := sudo_config[_]; rule.user == "postgres"]
	count(postgres_sudo) > 0
	postgres_rule := postgres_sudo[0]
	not postgres_rule.allow_all_commands
}

excessive_admin_privileges_revoked if {
	users := input.postgresql.users
	superusers := [u | u := users[_]; u.is_superuser == true]
	superuser_count := count(superusers)
	superuser_count <= 2
}

excessive_function_privileges_revoked if {
	functions := input.postgresql.functions
	public_functions := [f | f := functions[_]; "public" in f.execute_privileges]
	dangerous_public_functions := [f | f := public_functions[_]; 
		f.language in ["plpgsql", "c", "internal"]]
	count(dangerous_public_functions) == 0
}

excessive_dml_privileges_revoked if {
	roles := input.postgresql.roles
	public_role := [r | r := roles[_]; r.name == "public"][0]
	not "CONNECT" in public_role.privileges
	not "CREATE" in public_role.privileges
}

row_level_security_enabled if {
	tables := input.postgresql.tables
	sensitive_tables := [t | t := tables[_]; t.contains_sensitive_data == true]
	rls_enabled_tables := [t | t := sensitive_tables[_]; t.row_level_security == true]
	count(rls_enabled_tables) == count(sensitive_tables)
}

postgres_db_protected if {
	databases := input.postgresql.databases
	postgres_db := [db | db := databases[_]; db.name == "postgres"][0]
	postgres_db.public_access == false
	postgres_db.connection_limit > 0
}

database_names_appropriate if {
	databases := input.postgresql.databases
	default_names := ["postgres", "template0", "template1"]
	user_databases := [db | db := databases[_]; not db.name in default_names]
	prod_names := [db | db := user_databases[_]; contains(lower(db.name), "prod")]
	test_names := [db | db := user_databases[_]; contains(lower(db.name), "test")]
	dev_names := [db | db := user_databases[_]; contains(lower(db.name), "dev")]
	count(prod_names) == 0
	count(test_names) == 0
	count(dev_names) == 0
}

version_not_identifiable if {
	server_settings := input.postgresql.settings
	server_settings.server_version_num_hidden == true
}

role_based_auth_configured if {
	auth_config := input.postgresql.authentication
	role_based_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method in ["md5", "scram-sha-256"]]
	count(role_based_entries) > 0
}

password_auth_local_required if {
	auth_config := input.postgresql.authentication
	local_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.connection_type == "local"]
	password_local_entries := [entry | entry := local_entries[_]; 
		entry.auth_method in ["md5", "scram-sha-256"]]
	count(password_local_entries) == count(local_entries)
}

password_complexity_configured if {
	password_config := input.postgresql.password_policy
	password_config.min_length >= 8
	password_config.require_mixed_case == true
	password_config.require_numbers == true
	password_config.require_symbols == true
}

password_expiration_enforced if {
	users := input.postgresql.users
	users_with_expiration := [u | u := users[_]; u.password_expires_at != null]
	count(users_with_expiration) == count(users)
}

account_lockout_enforced if {
	lockout_config := input.postgresql.account_lockout
	lockout_config.enabled == true
	lockout_config.max_failed_attempts <= 5
	lockout_config.lockout_duration >= 300 # 5 minutes
}

min_password_age_enforced if {
	password_config := input.postgresql.password_policy
	password_config.min_age_days >= 1
}

password_history_enforced if {
	password_config := input.postgresql.password_policy
	password_config.history_count >= 5
}

login_events_monitored if {
	monitoring := input.postgresql.monitoring
	monitoring.login_events == true
	monitoring.failed_login_events == true
}

superuser_usage_limited if {
	superuser_activity := input.postgresql.superuser_activity
	superuser_activity.regular_usage == false
	superuser_activity.emergency_only == true
}

role_membership_controlled if {
	roles := input.postgresql.roles
	inherited_roles := [r | r := roles[_]; count(r.members) > 0]
	documented_roles := [r | r := inherited_roles[_]; r.membership_documented == true]
	count(documented_roles) == count(inherited_roles)
}

object_ownership_controlled if {
	objects := input.postgresql.objects
	owned_by_users := [obj | obj := objects[_]; obj.owner_type == "user"]
	sensitive_owned := [obj | obj := owned_by_users[_]; obj.sensitive == true]
	count(sensitive_owned) == 0
}

schema_usage_controlled if {
	schemas := input.postgresql.schemas
	public_schema := [s | s := schemas[_]; s.name == "public"][0]
	not "CREATE" in public_schema.default_privileges
	not "USAGE" in public_schema.default_privileges
}

table_access_controlled if {
	tables := input.postgresql.tables
	public_readable_tables := [t | t := tables[_]; "public" in t.select_privileges]
	count(public_readable_tables) == 0
}

column_level_security_implemented if {
	columns := input.postgresql.columns
	sensitive_columns := [c | c := columns[_]; c.contains_pii == true]
	secured_columns := [c | c := sensitive_columns[_]; c.access_controlled == true]
	count(secured_columns) == count(sensitive_columns)
}

function_execution_controlled if {
	functions := input.postgresql.functions
	public_executable := [f | f := functions[_]; "public" in f.execute_privileges]
	security_definer_functions := [f | f := public_executable[_]; f.security_definer == true]
	count(security_definer_functions) == 0
}

sequence_access_controlled if {
	sequences := input.postgresql.sequences
	public_sequences := [s | s := sequences[_]; "public" in s.usage_privileges]
	count(public_sequences) == 0
}

fdw_access_controlled if {
	fdws := input.postgresql.foreign_data_wrappers
	public_fdws := [f | f := fdws[_]; "public" in f.usage_privileges]
	count(public_fdws) == 0
}

language_usage_controlled if {
	languages := input.postgresql.languages
	trusted_languages := [l | l := languages[_]; l.trusted == true]
	public_languages := [l | l := trusted_languages[_]; "public" in l.usage_privileges]
	count(public_languages) == 0
}

large_object_access_controlled if {
	large_objects := input.postgresql.large_objects
	public_readable_los := [lo | lo := large_objects[_]; "public" in lo.select_privileges]
	count(public_readable_los) == 0
}

tablespace_usage_controlled if {
	tablespaces := input.postgresql.tablespaces
	public_tablespaces := [ts | ts := tablespaces[_]; "public" in ts.create_privileges]
	count(public_tablespaces) == 0
}

publication_subscription_security if {
	publications := input.postgresql.publications
	subscriptions := input.postgresql.subscriptions
	
	secure_publications := [p | p := publications[_]; p.access_controlled == true]
	secure_subscriptions := [s | s := subscriptions[_]; s.ssl_required == true]
	
	count(secure_publications) == count(publications)
	count(secure_subscriptions) == count(subscriptions)
}

parallel_query_security if {
	parallel_config := input.postgresql.parallel_query
	parallel_config.max_parallel_workers_per_gather <= 4
	parallel_config.parallel_tuple_cost >= 0.1
}

# Section 5: Connection and Login (Enhanced for PostgreSQL 14)
connection_ssl_violations := [v |
	arrays := [
		["5.1: Ensure login via 'local' socket is configured correctly" | not local_socket_configured],
		["5.2: Ensure login via 'host' TCP/IP socket is configured correctly" | not host_tcp_configured],
		["5.3: Ensure SSL is enabled and configured correctly" | not ssl_enabled_configured],
		["5.4: Ensure SSL certificate and key files are correctly configured" | not ssl_cert_key_configured],
		["5.5: Ensure SSL certificate authority file is correctly configured" | not ssl_ca_configured],
		["5.6: Ensure SSL certificate revocation list is configured" | not ssl_crl_configured],
		["5.7: Ensure SSL ciphers are configured appropriately" | not ssl_ciphers_appropriate],
		["5.8: Ensure SSL key exchange is configured appropriately" | not ssl_key_exchange_appropriate],
		["5.9: Ensure connection_limit is configured" | not connection_limit_configured],
		["5.10: Ensure connection timeout is configured" | not connection_timeout_configured],
		["5.11: Ensure superuser connection restrictions are configured" | not superuser_connection_restricted],
		["5.12: Ensure database connection restrictions are configured" | not database_connection_restricted],
		["5.13: Ensure IP address restrictions are configured" | not ip_address_restrictions_configured],
		["5.14: Ensure authentication timeout is configured" | not authentication_timeout_configured],
		["5.15: Ensure TCP keepalives are configured" | not tcp_keepalives_configured],
		["5.16: Ensure statement timeout is configured" | not statement_timeout_configured],
		["5.17: Ensure idle timeout is configured" | not idle_timeout_configured],
		["5.18: Ensure connection encryption is required" | not connection_encryption_required],
		["5.19: Ensure client authentication is properly configured" | not client_auth_configured],
		["5.20: Ensure trust authentication is not used" | not trust_auth_not_used],
		["5.21: Ensure peer authentication is used appropriately" | not peer_auth_appropriate],
		["5.22: Ensure certificate authentication is configured for appropriate connections" | not cert_auth_configured],
		["5.23: Ensure GSSAPI authentication is configured securely" | not gssapi_auth_secure],
		["5.24: Ensure SCRAM-SHA-256 is preferred over MD5" | not scram_sha256_preferred]
	]
	v := arrays[_][_]
]

local_socket_configured if {
	auth_config := input.postgresql.authentication
	local_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.connection_type == "local"]
	count(local_entries) > 0
	appropriate_local := [entry | entry := local_entries[_]; 
		entry.auth_method in ["peer", "md5", "scram-sha-256"]]
	count(appropriate_local) == count(local_entries)
}

host_tcp_configured if {
	auth_config := input.postgresql.authentication
	host_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.connection_type == "host"]
	ssl_required_entries := [entry | entry := host_entries[_]; 
		entry.ssl_required == true]
	count(ssl_required_entries) == count(host_entries)
}

ssl_enabled_configured if {
	ssl_config := input.postgresql.ssl
	ssl_config.enabled == true
	ssl_config.ssl_cert_file != ""
	ssl_config.ssl_key_file != ""
}

ssl_cert_key_configured if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_cert_file != ""
	ssl_config.ssl_key_file != ""
	ssl_config.certificate_valid == true
	ssl_config.private_key_valid == true
}

ssl_ca_configured if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_ca_file != ""
	ssl_config.ca_certificate_valid == true
}

ssl_crl_configured if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_crl_file != ""
}

ssl_ciphers_appropriate if {
	ssl_config := input.postgresql.ssl
	ssl_ciphers := ssl_config.ssl_ciphers
	weak_ciphers := ["NULL", "aNULL", "eNULL", "EXPORT", "DES", "RC4", "MD5"]
	weak_found := [cipher | cipher := weak_ciphers[_]; contains(ssl_ciphers, cipher)]
	count(weak_found) == 0
}

ssl_key_exchange_appropriate if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_ecdh_curve != ""
	ssl_config.ssl_dh_params_file != ""
}

connection_limit_configured if {
	connection_config := input.postgresql.connection
	connection_config.max_connections > 0
	connection_config.max_connections <= 200
}

connection_timeout_configured if {
	timeout_config := input.postgresql.timeouts
	timeout_config.tcp_user_timeout > 0
	timeout_config.tcp_user_timeout <= 60000
}

superuser_connection_restricted if {
	superuser_config := input.postgresql.superuser_restrictions
	superuser_config.connection_limit <= 5
	superuser_config.source_ip_restricted == true
}

database_connection_restricted if {
	databases := input.postgresql.databases
	restricted_dbs := [db | db := databases[_]; db.connection_limit > 0]
	count(restricted_dbs) == count(databases)
}

ip_address_restrictions_configured if {
	auth_config := input.postgresql.authentication
	host_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.connection_type == "host"]
	wildcard_entries := [entry | entry := host_entries[_]; 
		entry.address in ["0.0.0.0/0", "::/0", "all"]]
	count(wildcard_entries) == 0
}

authentication_timeout_configured if {
	auth_config := input.postgresql.authentication
	auth_config.authentication_timeout <= 60
	auth_config.authentication_timeout > 0
}

tcp_keepalives_configured if {
	tcp_config := input.postgresql.tcp_keepalives
	tcp_config.tcp_keepalives_idle <= 600
	tcp_config.tcp_keepalives_interval <= 30
	tcp_config.tcp_keepalives_count <= 3
}

statement_timeout_configured if {
	timeout_config := input.postgresql.timeouts
	timeout_config.statement_timeout > 0
	timeout_config.statement_timeout <= 1800000 # 30 minutes
}

idle_timeout_configured if {
	timeout_config := input.postgresql.timeouts
	timeout_config.idle_in_transaction_session_timeout > 0
	timeout_config.idle_in_transaction_session_timeout <= 600000 # 10 minutes
}

connection_encryption_required if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_prefer_server_ciphers == true
	ssl_config.ssl_min_protocol_version in ["TLSv1.2", "TLSv1.3"]
}

client_auth_configured if {
	auth_config := input.postgresql.authentication
	strong_auth_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method in ["scram-sha-256", "cert", "ldap", "radius"]]
	count(strong_auth_entries) > 0
}

trust_auth_not_used if {
	auth_config := input.postgresql.authentication
	trust_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method == "trust"]
	count(trust_entries) == 0
}

peer_auth_appropriate if {
	auth_config := input.postgresql.authentication
	peer_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method == "peer"]
	local_peer_entries := [entry | entry := peer_entries[_]; 
		entry.connection_type == "local"]
	count(local_peer_entries) == count(peer_entries)
}

cert_auth_configured if {
	auth_config := input.postgresql.authentication
	cert_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method == "cert"]
	ssl_cert_entries := [entry | entry := cert_entries[_]; 
		entry.ssl_required == true]
	count(ssl_cert_entries) == count(cert_entries)
}

gssapi_auth_secure if {
	auth_config := input.postgresql.authentication
	gssapi_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method == "gss"]
	secure_gssapi_entries := [entry | entry := gssapi_entries[_]; 
		entry.include_realm == false; 
		entry.krb_realm != ""]
	count(secure_gssapi_entries) == count(gssapi_entries)
}

scram_sha256_preferred if {
	auth_config := input.postgresql.authentication
	password_entries := [entry | entry := auth_config.pg_hba_entries[_]; 
		entry.auth_method in ["md5", "scram-sha-256"]]
	scram_entries := [entry | entry := password_entries[_]; 
		entry.auth_method == "scram-sha-256"]
	count(scram_entries) >= count(password_entries) / 2
}

# Section 6: PostgreSQL Settings (Enhanced for PostgreSQL 14)
postgresql_settings_violations := [v |
	arrays := [
		["6.1: Ensure 'backend' runtime parameters are configured correctly" | not backend_params_configured],
		["6.2: Ensure 'postgresql.conf' file is secured" | not postgresql_conf_secured],
		["6.3: Ensure 'FIPS 140-2' OpenSSL Cryptography Is Used" | not fips_140_2_used],
		["6.4: Ensure 'ssl_renegotiation_limit' is disabled" | not ssl_renegotiation_disabled],
		["6.5: Ensure 'shared_preload_libraries' is configured correctly" | not shared_preload_libs_configured],
		["6.6: Ensure 'dynamic_library_path' is empty" | not dynamic_library_path_empty],
		["6.7: Ensure 'local_preload_libraries' is empty" | not local_preload_libraries_empty],
		["6.8: Ensure 'session_preload_libraries' is empty" | not session_preload_libraries_empty],
		["6.9: Ensure 'shared_buffers' is configured correctly" | not shared_buffers_configured],
		["6.10: Ensure 'max_connections' is configured correctly" | not max_connections_configured],
		["6.11: Ensure 'work_mem' is configured correctly" | not work_mem_configured],
		["6.12: Ensure 'maintenance_work_mem' is configured correctly" | not maintenance_work_mem_configured],
		["6.13: Ensure 'effective_cache_size' is configured correctly" | not effective_cache_size_configured],
		["6.14: Ensure 'checkpoint_completion_target' is configured correctly" | not checkpoint_completion_target_configured],
		["6.15: Ensure 'wal_buffers' is configured correctly" | not wal_buffers_configured],
		["6.16: Ensure 'max_wal_senders' is configured correctly" | not max_wal_senders_configured],
		["6.17: Ensure 'max_replication_slots' is configured correctly" | not max_replication_slots_configured],
		["6.18: Ensure 'hot_standby' is set correctly" | not hot_standby_configured],
		["6.19: Ensure 'wal_level' is configured correctly" | not wal_level_configured],
		["6.20: Ensure 'archive_mode' is enabled" | not archive_mode_enabled],
		["6.21: Ensure 'archive_command' is set correctly" | not archive_command_configured],
		["6.22: Ensure 'archive_timeout' is configured correctly" | not archive_timeout_configured],
		["6.23: Ensure 'max_wal_size' is set correctly" | not max_wal_size_configured],
		["6.24: Ensure 'min_wal_size' is set correctly" | not min_wal_size_configured],
		["6.25: Ensure 'wal_keep_size' is configured correctly" | not wal_keep_size_configured],
		["6.26: Ensure 'wal_compression' is enabled" | not wal_compression_enabled],
		["6.27: Ensure 'fsync' is enabled" | not fsync_enabled],
		["6.28: Ensure 'synchronous_commit' is enabled" | not synchronous_commit_enabled],
		["6.29: Ensure 'full_page_writes' is enabled" | not full_page_writes_enabled],
		["6.30: Ensure 'wal_sync_method' is set correctly" | not wal_sync_method_configured],
		["6.31: Ensure 'random_page_cost' is set correctly" | not random_page_cost_configured],
		["6.32: Ensure 'seq_page_cost' is set correctly" | not seq_page_cost_configured],
		["6.33: Ensure 'cpu_tuple_cost' is set correctly" | not cpu_tuple_cost_configured],
		["6.34: Ensure 'cpu_index_tuple_cost' is set correctly" | not cpu_index_tuple_cost_configured],
		["6.35: Ensure 'cpu_operator_cost' is set correctly" | not cpu_operator_cost_configured],
		["6.36: Ensure 'vacuum_cost_delay' is configured correctly" | not vacuum_cost_delay_configured],
		["6.37: Ensure 'autovacuum' is enabled" | not autovacuum_enabled],
		["6.38: Ensure 'track_counts' is enabled" | not track_counts_enabled],
		["6.39: Ensure 'huge_pages' is configured appropriately" | not huge_pages_configured],
		["6.40: Ensure 'max_parallel_workers' is configured correctly" | not max_parallel_workers_configured]
	]
	v := arrays[_][_]
]

backend_params_configured if {
	backend_config := input.postgresql.backend_settings
	backend_config.track_activities == true
	backend_config.track_counts == true
	backend_config.track_io_timing == true
}

postgresql_conf_secured if {
	config_security := input.postgresql.config_security
	config_security.postgresql_conf_readable_by_postgres_only == true
	config_security.includes_secured == true
}

fips_140_2_used if {
	crypto_config := input.postgresql.cryptography
	crypto_config.fips_140_2_enabled == true
	crypto_config.openssl_fips_mode == true
}

ssl_renegotiation_disabled if {
	ssl_config := input.postgresql.ssl
	ssl_config.ssl_renegotiation_limit == 0
}

shared_preload_libs_configured if {
	preload_config := input.postgresql.preload_libraries
	shared_libs := preload_config.shared_preload_libraries
	approved_libs := ["pgaudit", "pg_stat_statements", "auto_explain"]
	unapproved_libs := [lib | lib := shared_libs[_]; not lib in approved_libs]
	count(unapproved_libs) == 0
}

dynamic_library_path_empty if {
	library_config := input.postgresql.library_settings
	library_config.dynamic_library_path == ""
}

local_preload_libraries_empty if {
	preload_config := input.postgresql.preload_libraries
	preload_config.local_preload_libraries == ""
}

session_preload_libraries_empty if {
	preload_config := input.postgresql.preload_libraries
	preload_config.session_preload_libraries == ""
}

shared_buffers_configured if {
	memory_config := input.postgresql.memory_settings
	shared_buffers_mb := memory_config.shared_buffers_mb
	total_memory_mb := memory_config.total_system_memory_mb
	shared_buffers_percent := (shared_buffers_mb / total_memory_mb) * 100
	shared_buffers_percent >= 20
	shared_buffers_percent <= 40
}

max_connections_configured if {
	connection_config := input.postgresql.connection_settings
	max_connections := connection_config.max_connections
	max_connections >= 10
	max_connections <= 500
}

work_mem_configured if {
	memory_config := input.postgresql.memory_settings
	work_mem_mb := memory_config.work_mem_mb
	work_mem_mb >= 4
	work_mem_mb <= 1024
}

maintenance_work_mem_configured if {
	memory_config := input.postgresql.memory_settings
	maintenance_work_mem_mb := memory_config.maintenance_work_mem_mb
	maintenance_work_mem_mb >= 64
	maintenance_work_mem_mb <= 2048
}

effective_cache_size_configured if {
	memory_config := input.postgresql.memory_settings
	effective_cache_size_mb := memory_config.effective_cache_size_mb
	total_memory_mb := memory_config.total_system_memory_mb
	cache_size_percent := (effective_cache_size_mb / total_memory_mb) * 100
	cache_size_percent >= 50
	cache_size_percent <= 75
}

checkpoint_completion_target_configured if {
	checkpoint_config := input.postgresql.checkpoint_settings
	completion_target := checkpoint_config.checkpoint_completion_target
	completion_target >= 0.5
	completion_target <= 0.9
}

wal_buffers_configured if {
	wal_config := input.postgresql.wal_settings
	wal_buffers_mb := wal_config.wal_buffers_mb
	wal_buffers_mb >= 16
	wal_buffers_mb <= 64
}

max_wal_senders_configured if {
	replication_config := input.postgresql.replication_settings
	max_wal_senders := replication_config.max_wal_senders
	max_wal_senders >= 0
	max_wal_senders <= 10
}

max_replication_slots_configured if {
	replication_config := input.postgresql.replication_settings
	max_replication_slots := replication_config.max_replication_slots
	max_replication_slots >= 0
	max_replication_slots <= 10
}

hot_standby_configured if {
	standby_config := input.postgresql.standby_settings
	standby_config.hot_standby == "on"
}

wal_level_configured if {
	wal_config := input.postgresql.wal_settings
	wal_level := wal_config.wal_level
	wal_level in ["replica", "logical"]
}

archive_mode_enabled if {
	archive_config := input.postgresql.archive_settings
	archive_config.archive_mode == "on"
}

archive_command_configured if {
	archive_config := input.postgresql.archive_settings
	archive_command := archive_config.archive_command
	archive_command != ""
	not archive_command == "test ! -f /tmp/%f && cp %p /tmp/%f"
}

archive_timeout_configured if {
	archive_config := input.postgresql.archive_settings
	archive_timeout := archive_config.archive_timeout
	archive_timeout > 0
	archive_timeout <= 3600 # 1 hour
}

max_wal_size_configured if {
	wal_config := input.postgresql.wal_settings
	max_wal_size_gb := wal_config.max_wal_size_gb
	max_wal_size_gb >= 1
	max_wal_size_gb <= 100
}

min_wal_size_configured if {
	wal_config := input.postgresql.wal_settings
	min_wal_size_mb := wal_config.min_wal_size_mb
	min_wal_size_mb >= 80
	min_wal_size_mb <= 2048
}

wal_keep_size_configured if {
	wal_config := input.postgresql.wal_settings
	wal_keep_size_mb := wal_config.wal_keep_size_mb
	wal_keep_size_mb >= 1024
	wal_keep_size_mb <= 32768
}

wal_compression_enabled if {
	wal_config := input.postgresql.wal_settings
	wal_config.wal_compression == "on"
}

fsync_enabled if {
	durability_config := input.postgresql.durability_settings
	durability_config.fsync == "on"
}

synchronous_commit_enabled if {
	durability_config := input.postgresql.durability_settings
	synchronous_commit := durability_config.synchronous_commit
	synchronous_commit in ["on", "remote_apply", "remote_write"]
}

full_page_writes_enabled if {
	durability_config := input.postgresql.durability_settings
	durability_config.full_page_writes == "on"
}

wal_sync_method_configured if {
	wal_config := input.postgresql.wal_settings
	wal_sync_method := wal_config.wal_sync_method
	wal_sync_method in ["fdatasync", "fsync", "open_sync", "open_datasync"]
}

random_page_cost_configured if {
	cost_config := input.postgresql.cost_settings
	random_page_cost := cost_config.random_page_cost
	random_page_cost >= 1.0
	random_page_cost <= 4.0
}

seq_page_cost_configured if {
	cost_config := input.postgresql.cost_settings
	seq_page_cost := cost_config.seq_page_cost
	seq_page_cost == 1.0
}

cpu_tuple_cost_configured if {
	cost_config := input.postgresql.cost_settings
	cpu_tuple_cost := cost_config.cpu_tuple_cost
	cpu_tuple_cost >= 0.01
	cpu_tuple_cost <= 0.1
}

cpu_index_tuple_cost_configured if {
	cost_config := input.postgresql.cost_settings
	cpu_index_tuple_cost := cost_config.cpu_index_tuple_cost
	cpu_index_tuple_cost >= 0.005
	cpu_index_tuple_cost <= 0.05
}

cpu_operator_cost_configured if {
	cost_config := input.postgresql.cost_settings
	cpu_operator_cost := cost_config.cpu_operator_cost
	cpu_operator_cost >= 0.0025
	cpu_operator_cost <= 0.025
}

vacuum_cost_delay_configured if {
	vacuum_config := input.postgresql.vacuum_settings
	vacuum_cost_delay := vacuum_config.vacuum_cost_delay
	vacuum_cost_delay >= 0
	vacuum_cost_delay <= 100
}

autovacuum_enabled if {
	vacuum_config := input.postgresql.vacuum_settings
	vacuum_config.autovacuum == "on"
}

track_counts_enabled if {
	stats_config := input.postgresql.statistics_settings
	stats_config.track_counts == "on"
}

huge_pages_configured if {
	memory_config := input.postgresql.memory_settings
	huge_pages := memory_config.huge_pages
	huge_pages in ["on", "try"]
}

max_parallel_workers_configured if {
	parallel_config := input.postgresql.parallel_settings
	max_parallel_workers := parallel_config.max_parallel_workers
	max_parallel_workers >= 2
	max_parallel_workers <= 32
}

# Section 7: Replication (Updated for PostgreSQL 14)
replication_violations := [v |
	arrays := [
		["7.1: Ensure a backup and recovery policy is in place" | not backup_recovery_policy_in_place],
		["7.2: Ensure the backup is done using pg_basebackup or similar tools" | not backup_using_appropriate_tools],
		["7.3: Ensure that WAL archiving is configured and functional" | not wal_archiving_functional],
		["7.4: Ensure streaming replication is configured securely" | not streaming_replication_secure],
		["7.5: Ensure replication user accounts are properly secured" | not replication_users_secured],
		["7.6: Ensure replication connections are authenticated" | not replication_connections_authenticated],
		["7.7: Ensure replication traffic is encrypted" | not replication_traffic_encrypted],
		["7.8: Ensure standby servers are configured appropriately" | not standby_servers_configured],
		["7.9: Ensure synchronous replication is used for critical data" | not synchronous_replication_critical_data],
		["7.10: Ensure replication lag monitoring is in place" | not replication_lag_monitoring]
	]
	v := arrays[_][_]
]

backup_recovery_policy_in_place if {
	backup_policy := input.postgresql.backup_policy
	backup_policy.documented == true
	backup_policy.automated == true
	backup_policy.tested_regularly == true
}

backup_using_appropriate_tools if {
	backup_methods := input.postgresql.backup_methods
	appropriate_tools := ["pg_basebackup", "pg_dump", "pg_dumpall", "barman", "pgbackrest"]
	used_tools := [tool | tool := backup_methods[_]; tool in appropriate_tools]
	count(used_tools) > 0
}

wal_archiving_functional if {
	archive_config := input.postgresql.archive_config
	archive_config.archive_mode == "on"
	archive_config.archive_command_functional == true
	archive_config.archive_status_monitored == true
}

streaming_replication_secure if {
	replication_config := input.postgresql.streaming_replication
	replication_config.ssl_enabled == true
	replication_config.authentication_required == true
	replication_config.dedicated_user == true
}

replication_users_secured if {
	replication_users := input.postgresql.replication_users
	secured_users := [u | u := replication_users[_]; 
		u.password_authentication == true;
		u.ssl_required == true;
		u.limited_privileges == true]
	count(secured_users) == count(replication_users)
}

replication_connections_authenticated if {
	replication_auth := input.postgresql.replication_authentication
	replication_auth.method in ["md5", "scram-sha-256", "cert"]
	replication_auth.trust_not_used == true
}

replication_traffic_encrypted if {
	replication_ssl := input.postgresql.replication_ssl
	replication_ssl.enabled == true
	replication_ssl.certificate_validation == true
	replication_ssl.strong_ciphers == true
}

standby_servers_configured if {
	standby_config := input.postgresql.standby_configuration
	standby_config.hot_standby == "on"
	standby_config.primary_conninfo_secured == true
	standby_config.standby_signal_file_present == true
}

synchronous_replication_critical_data if {
	sync_replication := input.postgresql.synchronous_replication
	sync_replication.enabled == true
	sync_replication.synchronous_standby_names != ""
	sync_replication.synchronous_commit in ["on", "remote_apply"]
}

replication_lag_monitoring if {
	lag_monitoring := input.postgresql.replication_monitoring
	lag_monitoring.enabled == true
	lag_monitoring.alert_thresholds_configured == true
	lag_monitoring.automated_alerts == true
}

# Section 8: Special Configuration Considerations
special_requirements_violations := [v |
	arrays := [
		["8.1: Ensure PostgreSQL version is supported" | not postgresql_version_supported],
		["8.2: Ensure security updates are applied promptly" | not security_updates_prompt],
		["8.3: Ensure database server is in a protected network segment" | not server_network_protected],
		["8.4: Ensure unnecessary PostgreSQL extensions are disabled" | not unnecessary_extensions_disabled],
		["8.5: Ensure PostgreSQL processes run with minimal privileges" | not processes_minimal_privileges],
		["8.6: Ensure resource limits are configured" | not resource_limits_configured],
		["8.7: Ensure security monitoring is implemented" | not security_monitoring_implemented],
		["8.8: Ensure compliance requirements are met" | not compliance_requirements_met]
	]
	v := arrays[_][_]
]

postgresql_version_supported if {
	version_info := input.postgresql.version_info
	version_info.supported == true
	version_info.security_support == true
	version_info.end_of_life_date > time.now_ns()
}

security_updates_prompt if {
	update_policy := input.postgresql.update_policy
	update_policy.automated_security_updates == true
	update_policy.patch_window_defined == true
	update_policy.emergency_patching_procedure == true
}

server_network_protected if {
	network_config := input.postgresql.network_security
	network_config.firewall_configured == true
	network_config.network_segmentation == true
	network_config.intrusion_detection == true
}

unnecessary_extensions_disabled if {
	extensions := input.postgresql.extensions
	enabled_extensions := [ext | ext := extensions[_]; ext.enabled == true]
	approved_extensions := ["pgaudit", "pg_stat_statements", "uuid-ossp", "citext", "pgcrypto"]
	unapproved_extensions := [ext | ext := enabled_extensions[_]; not ext.name in approved_extensions]
	count(unapproved_extensions) == 0
}

processes_minimal_privileges if {
	process_security := input.postgresql.process_security
	process_security.non_root_user == true
	process_security.dedicated_user == true
	process_security.limited_system_access == true
}

resource_limits_configured if {
	resource_limits := input.postgresql.resource_limits
	resource_limits.memory_limits == true
	resource_limits.cpu_limits == true
	resource_limits.connection_limits == true
}

security_monitoring_implemented if {
	security_monitoring := input.postgresql.security_monitoring
	security_monitoring.log_analysis == true
	security_monitoring.anomaly_detection == true
	security_monitoring.incident_response == true
}

compliance_requirements_met if {
	compliance := input.postgresql.compliance
	compliance.requirements_documented == true
	compliance.controls_implemented == true
	compliance.regular_audits == true
}