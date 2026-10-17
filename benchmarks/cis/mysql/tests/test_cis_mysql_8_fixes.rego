package cis.mysql_8_fixes_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

test_datadir_absolute_non_system_passes if {
	data.cis.mysql_8.databases_on_non_system_partitions with input as {"mysql": {"config": {"datadir": "/data/mysql"}}}
}

test_datadir_var_fails if {
	not data.cis.mysql_8.databases_on_non_system_partitions with input as {"mysql": {"config": {"datadir": "/var/lib/mysql"}}}
}

test_datadir_relative_fails if {
	not data.cis.mysql_8.databases_on_non_system_partitions with input as {"mysql": {"config": {"datadir": "mysql"}}}
}

test_logs_absolute_non_system_passes if {
	data.cis.mysql_8.logs_on_non_system_partitions with input as {"mysql": {"config": {
		"log_bin": "/data/binlog/mysql-bin",
		"general_log_file": "/logs/general.log",
		"slow_query_log_file": "/logs/slow.log",
	}}}
}

test_logs_binlog_under_var_fails if {
	not data.cis.mysql_8.logs_on_non_system_partitions with input as {"mysql": {"config": {
		"log_bin": "/var/lib/mysql/binlog",
		"general_log_file": "/logs/general.log",
		"slow_query_log_file": "/logs/slow.log",
	}}}
}

test_password_complexity_strong_passes if {
	data.cis.mysql_8.password_complexity_enabled with input as {"mysql": {"config": {"validate_password_policy": "STRONG"}}}
}

test_password_complexity_low_fails if {
	not data.cis.mysql_8.password_complexity_enabled with input as {"mysql": {"config": {"validate_password_policy": "LOW"}}}
}

test_tls_version_with_space_passes if {
	data.cis.mysql_8.tls_version_secure with input as {"mysql": {"config": {"tls_version": "TLSv1.1, TLSv1.2"}}}
}

test_tls_version_insecure_only_fails if {
	not data.cis.mysql_8.tls_version_secure with input as {"mysql": {"config": {"tls_version": "TLSv1, TLSv1.1"}}}
}

test_replication_absent_fails_closed if {
	not data.cis.mysql_8.master_ssl_ca_set with input as {"mysql": {"config": {}}}
	not data.cis.mysql_8.slave_ssl_verify_server_cert_on with input as {"mysql": {"config": {}}}
}

test_replication_not_slave_passes if {
	data.cis.mysql_8.master_ssl_ca_set with input as {"mysql": {"replication": {"is_slave": false}}}
}

test_replication_slave_requires_config if {
	not data.cis.mysql_8.master_ssl_ca_set with input as {"mysql": {"replication": {"is_slave": true}, "config": {"master_ssl_ca": ""}}}
	data.cis.mysql_8.master_ssl_ca_set with input as {"mysql": {"replication": {"is_slave": true}, "config": {"master_ssl_ca": "/ca.pem"}}}
}
