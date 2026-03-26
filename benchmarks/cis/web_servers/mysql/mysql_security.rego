package cis.server.mysql

import rego.v1

# CIS MySQL Benchmark
# Database Server Security Configuration

# CIS 1.1 - Ensure Latest MySQL Version is Used
latest_version_used if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    minor := to_number(version_parts[1])
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
mysql_test_db_not_installed if {
    not contains(input.mysql_databases, "test")
}

# CIS 2.1 - Ensure the MySQL Data Directory is Configured Properly
data_directory_configured if {
    input.mysql_config.datadir != ""
    input.file_permissions[input.mysql_config.datadir].owner == "mysql"
    input.file_permissions[input.mysql_config.datadir].group == "mysql"
    input.file_permissions[input.mysql_config.datadir].mode == "0750"
}

# CIS 2.2 - Ensure the MySQL Binary and Configuration Files Are Owned by mysql User
mysql_files_owned_correctly if {
    input.file_permissions[input.mysql_config.basedir].owner == "mysql"
    input.file_permissions["/etc/mysql/my.cnf"].owner == "mysql"
    input.file_permissions["/etc/mysql/my.cnf"].group == "mysql"
}

# CIS 2.3 - Ensure the MySQL Configuration File Permissions Are Restrictive
config_file_permissions_restrictive if {
    input.file_permissions["/etc/mysql/my.cnf"].mode == "0600"
}

# CIS 2.4 - Ensure the MySQL Data Directory Permissions Are Restrictive
data_directory_permissions_restrictive if {
    input.file_permissions[input.mysql_config.datadir].mode == "0750"
}

# CIS 2.5 - Ensure the MySQL Error Log File Permissions Are Restrictive
error_log_permissions_restrictive if {
    input.file_permissions[input.mysql_config.log_error].mode == "0640"
    input.file_permissions[input.mysql_config.log_error].owner == "mysql"
    input.file_permissions[input.mysql_config.log_error].group == "mysql"
}

# CIS 2.6 - Ensure the MySQL Slow Query Log File Permissions Are Restrictive
slow_query_log_permissions_restrictive if {
    input.mysql_config.slow_query_log == "ON"
    input.file_permissions[input.mysql_config.slow_query_log_file].mode == "0640"
    input.file_permissions[input.mysql_config.slow_query_log_file].owner == "mysql"
}

# CIS 2.7 - Ensure the MySQL Relay Log File Permissions Are Restrictive
relay_log_permissions_restrictive if {
    input.mysql_config.relay_log != ""
    input.file_permissions[input.mysql_config.relay_log].mode == "0640"
    input.file_permissions[input.mysql_config.relay_log].owner == "mysql"
}

# CIS 2.8 - Ensure the MySQL General Log File Permissions Are Restrictive
general_log_permissions_restrictive if {
    input.mysql_config.general_log == "ON"
    input.file_permissions[input.mysql_config.general_log_file].mode == "0640"
    input.file_permissions[input.mysql_config.general_log_file].owner == "mysql"
}

# CIS 2.9 - Ensure the MySQL SSL Key File Permissions Are Restrictive
ssl_key_permissions_restrictive if {
    input.mysql_config.ssl_key != ""
    input.file_permissions[input.mysql_config.ssl_key].mode == "0400"
    input.file_permissions[input.mysql_config.ssl_key].owner == "mysql"
}

# CIS 2.10 - Ensure the MySQL SSL Certificate File Permissions Are Restrictive
ssl_cert_permissions_restrictive if {
    input.mysql_config.ssl_cert != ""
    input.file_permissions[input.mysql_config.ssl_cert].mode == "0444"
    input.file_permissions[input.mysql_config.ssl_cert].owner == "mysql"
}

# CIS 3.1 - Ensure 'skip-networking' is Enabled
skip_networking_enabled if {
    input.mysql_config.skip_networking == "ON"
}

# CIS 3.2 - Ensure 'bind-address' is Set to a Specific Interface
bind_address_specific if {
    input.mysql_config.bind_address != "0.0.0.0"
    input.mysql_config.bind_address != "*"
    input.mysql_config.bind_address != ""
}

# CIS 3.3 - Ensure 'local_infile' is Disabled
local_infile_disabled if {
    input.mysql_config.local_infile == "OFF"
}

# CIS 3.4 - Ensure 'mysqld' is Not Started with '--skip-grant-tables'
skip_grant_tables_not_used if {
    not contains(input.mysql_startup_options, "--skip-grant-tables")
}

# CIS 3.5 - Ensure 'mysqld' is Not Started with '--skip-show-database'
skip_show_database_not_used if {
    not contains(input.mysql_startup_options, "--skip-show-database")
}

# CIS 4.1 - Ensure Anonymous Accounts Are Removed
anonymous_accounts_removed if {
    count([user | user := input.mysql_users[_]; user.user == ""]) == 0
}

# CIS 4.2 - Ensure MySQL Root Password is Set
root_password_set if {
    count([user | user := input.mysql_users[_]; user.user == "root"; user.password != ""; user.authentication_string != ""]) > 0
}

# CIS 4.3 - Ensure 'test' Database is Removed
mysql_test_db_removed if {
    mysql_test_db_not_installed # Already covered in 1.2
}

# CIS 4.4 - Ensure Remote Root Login is Disabled
remote_root_login_disabled if {
    count([user | user := input.mysql_users[_]; user.user == "root"; user.host != "localhost"; user.host != "127.0.0.1"; user.host != "::1"]) == 0
}

# CIS 4.5 - Ensure MySQL Users Are Assigned Appropriate Privileges
users_appropriate_privileges if {
    count([user | user := input.mysql_users[_]; user.user != "root"; contains(user.privileges, "*.*")]) == 0
}

# CIS 4.6 - Ensure No Users Have Wildcard Hostnames
no_wildcard_hostnames if {
    count([user | user := input.mysql_users[_]; contains(user.host, "%")]) == 0
}

# CIS 4.7 - Ensure No Anonymous Users Exist
no_anonymous_users if {
    anonymous_accounts_removed # Already covered in 4.1
}

# CIS 5.1 - Ensure 'sql_mode' Contains 'STRICT_TRANS_TABLES'
sql_mode_strict if {
    contains(input.mysql_config.sql_mode, "STRICT_TRANS_TABLES")
}

# CIS 5.2 - Ensure 'log_error' is Configured
log_error_configured if {
    input.mysql_config.log_error != ""
    input.mysql_config.log_error != "OFF"
}

# CIS 5.3 - Ensure 'log-raw' is Set to 'OFF'
log_raw_disabled if {
    input.mysql_config.log_raw == "OFF"
}

# CIS 6.1 - Ensure 'log_error_verbosity' is Set to '2' or Higher
log_error_verbosity_appropriate if {
    input.mysql_config.log_error_verbosity >= 2
}

# CIS 6.2 - Ensure 'log_warnings' is Set to '2' or Higher (MySQL 5.7)
log_warnings_appropriate if {
    version_parts := split(input.mysql_info.version, ".")
    major := to_number(version_parts[0])
    minor := to_number(version_parts[1])
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
old_passwords_disabled if {
    input.mysql_config.old_passwords == "OFF"
}

# CIS 7.2 - Ensure 'secure_auth' is Enabled
secure_auth_enabled if {
    input.mysql_config.secure_auth == "ON"
}

# CIS 7.3 - Ensure Password Length is Configured
password_length_configured if {
    input.mysql_config.validate_password_length >= 14
}

# CIS 7.4 - Ensure Password Complexity is Configured
password_complexity_configured if {
    policy := input.mysql_config.validate_password_policy
    some valid_policy in ["MEDIUM", "STRONG"]
    policy == valid_policy
    input.mysql_config.validate_password_mixed_case_count >= 1
    input.mysql_config.validate_password_number_count >= 1
    input.mysql_config.validate_password_special_char_count >= 1
}

# CIS 8.1 - Ensure 'have_ssl' is Set to 'YES'
ssl_enabled if {
    input.mysql_config.have_ssl == "YES"
}

# CIS 8.2 - Ensure 'ssl_type' is Set for All Remote Users
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