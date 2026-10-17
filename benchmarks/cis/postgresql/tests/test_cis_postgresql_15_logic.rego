package cis.postgresql_15_test

import rego.v1

# Validation fix 2026-10-17: inverted data-directory check, pgaudit "all"/spacing, size units,
# first-sudo-rule-only, substring database names.

pkg := data.cis.postgresql_15

test_absolute_data_dir_outside_system_ok if {
	pkg.subdirs_outside_system with input as {"postgresql": {"directories": {"data_directory": "/var/lib/postgresql/15/main"}}}
}

test_system_data_dir_fails if {
	not pkg.subdirs_outside_system with input as {"postgresql": {"directories": {"data_directory": "/usr/lib/pg"}}}
	not pkg.subdirs_outside_system with input as {"postgresql": {"directories": {"data_directory": "/etc/pg"}}}
}

test_relative_data_dir_fails if {
	not pkg.subdirs_outside_system with input as {"postgresql": {"directories": {"data_directory": "data/pgdata"}}}
}

test_pgaudit_all_ok if {
	pkg.pgaudit_log_correct with input as {"postgresql": {"pgaudit": {"log": "all"}}}
}

test_pgaudit_spaced_ok if {
	pkg.pgaudit_log_correct with input as {"postgresql": {"pgaudit": {"log": "ddl, write"}}}
}

test_pgaudit_ddl_only_fails if {
	not pkg.pgaudit_log_correct with input as {"postgresql": {"pgaudit": {"log": "ddl"}}}
}

test_rotation_size_units if {
	pkg.log_rotation_size_correct with input as {"postgresql": {"logging": {"log_rotation_size": "1GB"}}}
	pkg.log_rotation_size_correct with input as {"postgresql": {"logging": {"log_rotation_size": "10MB"}}}
	not pkg.log_rotation_size_correct with input as {"postgresql": {"logging": {"log_rotation_size": "2GB"}}}
	not pkg.log_rotation_size_correct with input as {"postgresql": {"logging": {"log_rotation_size": "0"}}}
	not pkg.log_rotation_size_correct with input as {"postgresql": {"logging": {"log_rotation_size": "lots"}}}
}

test_every_postgres_sudo_rule_checked if {
	not pkg.sudo_configured_correctly with input as {"postgresql": {"system": {"sudo_config": [{"user": "postgres", "allow_all_commands": false}, {"user": "postgres", "allow_all_commands": true}]}}}
	pkg.sudo_configured_correctly with input as {"postgresql": {"system": {"sudo_config": [{"user": "postgres", "allow_all_commands": false}]}}}
}

test_database_names_tokens if {
	pkg.database_names_appropriate with input as {"postgresql": {"databases": [{"name": "product_catalog"}, {"name": "latest_orders"}]}}
	not pkg.database_names_appropriate with input as {"postgresql": {"databases": [{"name": "app_prod"}]}}
	not pkg.database_names_appropriate with input as {"postgresql": {"databases": [{"name": "dev-db"}]}}
}

test_passphrase_locate_not_flagged if {
	pkg.ssl_passphrase_command_secure with input as {"postgresql": {"ssl": {"ssl_passphrase_command": "vault-locate-pass"}}}
}

test_passphrase_cat_flagged if {
	not pkg.ssl_passphrase_command_secure with input as {"postgresql": {"ssl": {"ssl_passphrase_command": "/bin/cat /etc/key"}}}
}

test_passphrase_echo_flagged if {
	not pkg.ssl_passphrase_command_secure with input as {"postgresql": {"ssl": {"ssl_passphrase_command": "echo secret"}}}
}

