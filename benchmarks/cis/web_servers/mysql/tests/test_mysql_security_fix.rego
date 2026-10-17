package cis.server.mysql_test

import rego.v1

# Validation fix pass 2026-10-17.

test_test_db_detected_in_array if {
	not data.cis.server.mysql.mysql_test_db_not_installed with input as {"mysql_databases": ["information_schema", "test"]}
}

test_test_db_absent_in_array_passes if {
	data.cis.server.mysql.mysql_test_db_not_installed with input as {"mysql_databases": ["information_schema", "app"]}
}

test_test_db_detected_in_string if {
	not data.cis.server.mysql.mysql_test_db_not_installed with input as {"mysql_databases": "information_schema\ntest\napp"}
}

test_missing_database_list_not_evidence if {
	not data.cis.server.mysql.mysql_test_db_not_installed with input as {}
}

test_startup_option_array_detected if {
	not data.cis.server.mysql.skip_grant_tables_not_used with input as {"mysql_startup_options": ["--skip-grant-tables"]}
	data.cis.server.mysql.skip_grant_tables_not_used with input as {"mysql_startup_options": ["--port=3306"]}
}

test_privileges_array_global_flagged if {
	not data.cis.server.mysql.users_appropriate_privileges with input as {"mysql_users": [{"user": "bob", "host": "10.0.0.1", "privileges": ["*.*"]}]}
	data.cis.server.mysql.users_appropriate_privileges with input as {"mysql_users": [{"user": "bob", "host": "10.0.0.1", "privileges": ["app.*"]}]}
}

test_privileges_string_global_flagged if {
	not data.cis.server.mysql.users_appropriate_privileges with input as {"mysql_users": [{"user": "bob", "host": "h", "privileges": "ALL ON *.*"}]}
}

test_missing_user_list_is_not_evidence if {
	not data.cis.server.mysql.anonymous_accounts_removed with input as {}
	not data.cis.server.mysql.no_wildcard_hostnames with input as {}
	not data.cis.server.mysql.remote_root_login_disabled with input as {}
	not data.cis.server.mysql.users_appropriate_privileges with input as {}
}

test_bind_address_ipv6_wildcards_flagged if {
	every a in ["::", "[::]", "0.0.0.0", "*", "", "10.0.0.5,::", "*,::1"] {
		not data.cis.server.mysql.bind_address_specific with input as {"mysql_config": {"bind_address": a}}
	}
	data.cis.server.mysql.bind_address_specific with input as {"mysql_config": {"bind_address": "10.0.0.5"}}
	data.cis.server.mysql.bind_address_specific with input as {"mysql_config": {"bind_address": "127.0.0.1,::1"}}
}

test_file_mode_forms if {
	inp := {"mysql_config": {"datadir": "/d"}, "file_permissions": {"/d": {"mode": "750"}}}
	data.cis.server.mysql.data_directory_permissions_restrictive with input as inp
	inp2 := {"mysql_config": {"datadir": "/d"}, "file_permissions": {"/d": {"mode": "0770"}}}
	not data.cis.server.mysql.data_directory_permissions_restrictive with input as inp2
}

test_report_populated_on_empty_input if {
	r := data.cis.server.mysql.mysql_server_compliance with input as {}
	r.overall_compliant == false
	count(r) == 34
}
