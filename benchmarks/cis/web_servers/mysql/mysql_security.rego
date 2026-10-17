# METADATA
# title: "CIS MySQL Benchmark"
# custom:
#   class: security
#   framework: cis_web_servers
#   source: cis
#   domains: [database, mysql]
#   coverage:
#     checks: 32
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.server.mysql

import rego.v1

# CIS MySQL Benchmark
# Database Server Security Configuration

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# Collections may arrive as a list of names or as a string (raw command output).
# `contains` on a list never matches, so handle both explicitly.
databases_collected if is_array(input.mysql_databases)

databases_collected if is_string(input.mysql_databases)

has_database(name) if name in input.mysql_databases

has_database(name) if {
	is_string(input.mysql_databases)
	name in split(input.mysql_databases, "\n")
}

has_database(name) if {
	is_string(input.mysql_databases)
	name in split(input.mysql_databases, ",")
}

startup_options_collected if is_array(input.mysql_startup_options)

startup_options_collected if is_string(input.mysql_startup_options)

has_startup_option(opt) if {
	is_array(input.mysql_startup_options)
	some o in input.mysql_startup_options
	contains(o, opt)
}

has_startup_option(opt) if {
	is_string(input.mysql_startup_options)
	contains(input.mysql_startup_options, opt)
}

# An empty user list is not evidence: mysql always has at least the root account.
users_collected if count(input.mysql_users) > 0

has_global_privilege(user) if {
	is_string(user.privileges)
	contains(user.privileges, "*.*")
}

has_global_privilege(user) if {
	is_array(user.privileges)
	some p in user.privileges
	contains(p, "*.*")
}

# bind-address may be a comma-separated list (MySQL 8.0.13+); any wildcard entry exposes all interfaces
wildcard_binds := {"", "*", "0.0.0.0", "::", "[::]", "::0", "0:0:0:0:0:0:0:0"}

bind_address_has_wildcard if {
	some a in split(input.mysql_config.bind_address, ",")
	trim_space(a) in wildcard_binds
}

# CIS 1.1 - Ensure Latest MySQL Version is Used
default latest_version_used := false

latest_version_used if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    major >= 8
}

latest_version_used if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    minor := to_number(version_parts[1])
    major == 5
    minor >= 7
}

# CIS 1.2 - Ensure the Test Database is Not Installed
default mysql_test_db_not_installed := false

mysql_test_db_not_installed if {
    databases_collected
    not has_database("test")
}

# CIS 2.1 - Ensure the MySQL Data Directory is Configured Properly
default data_directory_configured := false

data_directory_configured if {
    input.mysql_config.datadir != ""
    input.file_permissions[input.mysql_config.datadir].owner == "mysql"
    input.file_permissions[input.mysql_config.datadir].group == "mysql"
    mode_within(input.file_permissions[input.mysql_config.datadir].mode, "0750")
}

# CIS 2.2 - Ensure the MySQL Binary and Configuration Files Are Owned by mysql User
default mysql_files_owned_correctly := false

mysql_files_owned_correctly if {
    input.file_permissions[input.mysql_config.basedir].owner == "mysql"
    input.file_permissions["/etc/mysql/my.cnf"].owner == "mysql"
    input.file_permissions["/etc/mysql/my.cnf"].group == "mysql"
}

# CIS 2.3 - Ensure the MySQL Configuration File Permissions Are Restrictive
default config_file_permissions_restrictive := false

config_file_permissions_restrictive if {
    mode_within(input.file_permissions["/etc/mysql/my.cnf"].mode, "0600")
}

# CIS 2.4 - Ensure the MySQL Data Directory Permissions Are Restrictive
default data_directory_permissions_restrictive := false

data_directory_permissions_restrictive if {
    mode_within(input.file_permissions[input.mysql_config.datadir].mode, "0750")
}

# CIS 2.5 - Ensure the MySQL Error Log File Permissions Are Restrictive
default error_log_permissions_restrictive := false

error_log_permissions_restrictive if {
    mode_within(input.file_permissions[input.mysql_config.log_error].mode, "0640")
    input.file_permissions[input.mysql_config.log_error].owner == "mysql"
    input.file_permissions[input.mysql_config.log_error].group == "mysql"
}

# CIS 2.6 - Ensure the MySQL Slow Query Log File Permissions Are Restrictive
default slow_query_log_permissions_restrictive := false

slow_query_log_permissions_restrictive if {
    input.mysql_config.slow_query_log == "ON"
    mode_within(input.file_permissions[input.mysql_config.slow_query_log_file].mode, "0640")
    input.file_permissions[input.mysql_config.slow_query_log_file].owner == "mysql"
}

# CIS 2.7 - Ensure the MySQL Relay Log File Permissions Are Restrictive
default relay_log_permissions_restrictive := false

relay_log_permissions_restrictive if {
    input.mysql_config.relay_log != ""
    mode_within(input.file_permissions[input.mysql_config.relay_log].mode, "0640")
    input.file_permissions[input.mysql_config.relay_log].owner == "mysql"
}

# CIS 2.8 - Ensure the MySQL General Log File Permissions Are Restrictive
default general_log_permissions_restrictive := false

general_log_permissions_restrictive if {
    input.mysql_config.general_log == "ON"
    mode_within(input.file_permissions[input.mysql_config.general_log_file].mode, "0640")
    input.file_permissions[input.mysql_config.general_log_file].owner == "mysql"
}

# CIS 2.9 - Ensure the MySQL SSL Key File Permissions Are Restrictive
default ssl_key_permissions_restrictive := false

ssl_key_permissions_restrictive if {
    input.mysql_config.ssl_key != ""
    mode_within(input.file_permissions[input.mysql_config.ssl_key].mode, "0400")
    input.file_permissions[input.mysql_config.ssl_key].owner == "mysql"
}

# CIS 2.10 - Ensure the MySQL SSL Certificate File Permissions Are Restrictive
default ssl_cert_permissions_restrictive := false

ssl_cert_permissions_restrictive if {
    input.mysql_config.ssl_cert != ""
    mode_within(input.file_permissions[input.mysql_config.ssl_cert].mode, "0444")
    input.file_permissions[input.mysql_config.ssl_cert].owner == "mysql"
}

# CIS 3.1 - Ensure 'skip-networking' is Enabled
default skip_networking_enabled := false

skip_networking_enabled if {
    input.mysql_config.skip_networking == "ON"
}

# CIS 3.2 - Ensure 'bind-address' is Set to a Specific Interface
default bind_address_specific := false

bind_address_specific if {
    is_string(input.mysql_config.bind_address)
    not bind_address_has_wildcard
}

# CIS 3.3 - Ensure 'local_infile' is Disabled
default local_infile_disabled := false

local_infile_disabled if {
    input.mysql_config.local_infile == "OFF"
}

# CIS 3.4 - Ensure 'mysqld' is Not Started with '--skip-grant-tables'
default skip_grant_tables_not_used := false

skip_grant_tables_not_used if {
    startup_options_collected
    not has_startup_option("--skip-grant-tables")
}

# CIS 3.5 - Ensure 'mysqld' is Not Started with '--skip-show-database'
default skip_show_database_not_used := false

skip_show_database_not_used if {
    startup_options_collected
    not has_startup_option("--skip-show-database")
}

# CIS 4.1 - Ensure Anonymous Accounts Are Removed
default anonymous_accounts_removed := false

anonymous_accounts_removed if {
    users_collected
    count([user | user := input.mysql_users[_]; user.user == ""]) == 0
}

# CIS 4.2 - Ensure MySQL Root Password is Set
default root_password_set := false

root_password_set if {
    count([user | user := input.mysql_users[_]; user.user == "root"; user.password != ""; user.authentication_string != ""]) > 0
}

# CIS 4.3 - Ensure 'test' Database is Removed
default mysql_test_db_removed := false

mysql_test_db_removed if {
    mysql_test_db_not_installed # Already covered in 1.2
}

# CIS 4.4 - Ensure Remote Root Login is Disabled
default remote_root_login_disabled := false

remote_root_login_disabled if {
    users_collected
    count([user | user := input.mysql_users[_]; user.user == "root"; user.host != "localhost"; user.host != "127.0.0.1"; user.host != "::1"]) == 0
}

# CIS 4.5 - Ensure MySQL Users Are Assigned Appropriate Privileges
default users_appropriate_privileges := false

users_appropriate_privileges if {
    users_collected
    count([user | user := input.mysql_users[_]; user.user != "root"; has_global_privilege(user)]) == 0
}

# CIS 4.6 - Ensure No Users Have Wildcard Hostnames
default no_wildcard_hostnames := false

no_wildcard_hostnames if {
    users_collected
    count([user | user := input.mysql_users[_]; contains(user.host, "%")]) == 0
}

# CIS 4.7 - Ensure No Anonymous Users Exist
default no_anonymous_users := false

no_anonymous_users if {
    anonymous_accounts_removed # Already covered in 4.1
}

# CIS 5.1 - Ensure 'sql_mode' Contains 'STRICT_TRANS_TABLES'
default sql_mode_strict := false

sql_mode_strict if {
    contains(input.mysql_config.sql_mode, "STRICT_TRANS_TABLES")
}

# CIS 5.2 - Ensure 'log_error' is Configured
default log_error_configured := false

log_error_configured if {
    input.mysql_config.log_error != ""
    input.mysql_config.log_error != "OFF"
}

# CIS 5.3 - Ensure 'log-raw' is Set to 'OFF'
default log_raw_disabled := false

log_raw_disabled if {
    input.mysql_config.log_raw == "OFF"
}

# CIS 6.1 - Ensure 'log_error_verbosity' is Set to '2' or Higher
default log_error_verbosity_appropriate := false

log_error_verbosity_appropriate if {
    input.mysql_config.log_error_verbosity >= 2
}

# CIS 6.2 - Ensure 'log_warnings' is Set to '2' or Higher (MySQL 5.7)
default log_warnings_appropriate := false

log_warnings_appropriate if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    major >= 8
}

log_warnings_appropriate if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    minor := to_number(version_parts[1])
    major == 5
    minor == 7
    input.mysql_config.log_warnings >= 2
}

# CIS 7.1 - Ensure 'old_passwords' is Disabled
default old_passwords_disabled := false

old_passwords_disabled if {
    input.mysql_config.old_passwords == "OFF"
}

# CIS 7.2 - Ensure 'secure_auth' is Enabled
default secure_auth_enabled := false

secure_auth_enabled if {
    input.mysql_config.secure_auth == "ON"
}

# CIS 7.3 - Ensure Password Length is Configured
default password_length_configured := false

password_length_configured if {
    input.mysql_config.validate_password_length >= 14
}

# CIS 7.4 - Ensure Password Complexity is Configured
default password_complexity_configured := false

password_complexity_configured if {
    policy := input.mysql_config.validate_password_policy
    some valid_policy in ["MEDIUM", "STRONG"]
    policy == valid_policy
    input.mysql_config.validate_password_mixed_case_count >= 1
    input.mysql_config.validate_password_number_count >= 1
    input.mysql_config.validate_password_special_char_count >= 1
}

# CIS 8.1 - Ensure 'have_ssl' is Set to 'YES'
default ssl_enabled := false

ssl_enabled if {
    input.mysql_config.have_ssl == "YES"
}

# CIS 8.2 - Ensure 'ssl_type' is Set for All Remote Users
default ssl_required_remote_users := false

ssl_required_remote_users if {
    every user in input.mysql_users {
        user_ssl_valid(user)
    }
}

user_ssl_valid(user) if {
    user.host in ["localhost", "127.0.0.1", "::1"]
}

user_ssl_valid(user) if {
    user.ssl_type in ["X509", "SPECIFIED"]
}

# Aggregate MySQL server compliance
default mysql_server_compliant := false

mysql_server_compliant if {
    latest_version_used
    mysql_test_db_not_installed
    data_directory_configured
    mysql_files_owned_correctly
    config_file_permissions_restrictive
    data_directory_permissions_restrictive
    error_log_permissions_restrictive
    slow_query_log_permissions_restrictive
    relay_log_permissions_restrictive
    general_log_permissions_restrictive
    ssl_key_permissions_restrictive
    ssl_cert_permissions_restrictive
    skip_networking_enabled
    bind_address_specific
    local_infile_disabled
    skip_grant_tables_not_used
    skip_show_database_not_used
    anonymous_accounts_removed
    root_password_set
    remote_root_login_disabled
    users_appropriate_privileges
    no_wildcard_hostnames
    sql_mode_strict
    log_error_configured
    log_raw_disabled
    log_error_verbosity_appropriate
    log_warnings_appropriate
    old_passwords_disabled
    secure_auth_enabled
    password_length_configured
    password_complexity_configured
    ssl_enabled
    ssl_required_remote_users
}

# Detailed MySQL server compliance report
mysql_server_compliance := {
    "latest_version_used": latest_version_used,
    "mysql_test_db_not_installed": mysql_test_db_not_installed,
    "data_directory_configured": data_directory_configured,
    "mysql_files_owned_correctly": mysql_files_owned_correctly,
    "config_file_permissions_restrictive": config_file_permissions_restrictive,
    "data_directory_permissions_restrictive": data_directory_permissions_restrictive,
    "error_log_permissions_restrictive": error_log_permissions_restrictive,
    "slow_query_log_permissions_restrictive": slow_query_log_permissions_restrictive,
    "relay_log_permissions_restrictive": relay_log_permissions_restrictive,
    "general_log_permissions_restrictive": general_log_permissions_restrictive,
    "ssl_key_permissions_restrictive": ssl_key_permissions_restrictive,
    "ssl_cert_permissions_restrictive": ssl_cert_permissions_restrictive,
    "skip_networking_enabled": skip_networking_enabled,
    "bind_address_specific": bind_address_specific,
    "local_infile_disabled": local_infile_disabled,
    "skip_grant_tables_not_used": skip_grant_tables_not_used,
    "skip_show_database_not_used": skip_show_database_not_used,
    "anonymous_accounts_removed": anonymous_accounts_removed,
    "root_password_set": root_password_set,
    "remote_root_login_disabled": remote_root_login_disabled,
    "users_appropriate_privileges": users_appropriate_privileges,
    "no_wildcard_hostnames": no_wildcard_hostnames,
    "sql_mode_strict": sql_mode_strict,
    "log_error_configured": log_error_configured,
    "log_raw_disabled": log_raw_disabled,
    "log_error_verbosity_appropriate": log_error_verbosity_appropriate,
    "log_warnings_appropriate": log_warnings_appropriate,
    "old_passwords_disabled": old_passwords_disabled,
    "secure_auth_enabled": secure_auth_enabled,
    "password_length_configured": password_length_configured,
    "password_complexity_configured": password_complexity_configured,
    "ssl_enabled": ssl_enabled,
    "ssl_required_remote_users": ssl_required_remote_users,
    "overall_compliant": mysql_server_compliant
}