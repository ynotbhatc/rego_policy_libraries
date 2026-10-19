package cis.oracle_19c_test

import rego.v1

p := data.cis.oracle_19c

test_absolute_oracle_home_ok if {
	p.software_not_on_system_partitions with input as {"oracle": {"directories": {"oracle_home": {"path": "/u01/app/oracle/product/19c"}}}}
}

test_oracle_home_under_usr_fails if {
	not p.software_not_on_system_partitions with input as {"oracle": {"directories": {"oracle_home": {"path": "/usr/local/oracle"}}}}
}

test_oracle_home_at_root_fails if {
	not p.software_not_on_system_partitions with input as {"oracle": {"directories": {"oracle_home": {"path": "/"}}}}
}

test_data_files_on_u01_ok if {
	p.data_files_non_system_partitions with input as {"oracle": {"data_files": [{"path": "/u01/oradata/orcl/users01.dbf"}]}}
}

test_data_files_under_var_fail if {
	not p.data_files_non_system_partitions with input as {"oracle": {"data_files": [{"path": "/var/lib/oradata/users01.dbf"}]}}
}

test_audit_trail_with_space_ok if {
	p.audit_trail_appropriate with input as {"oracle": {"init_parameters": {"audit_trail": "DB, EXTENDED"}}}
}

test_audit_trail_none_fails if {
	not p.audit_trail_appropriate with input as {"oracle": {"init_parameters": {"audit_trail": "NONE"}}}
}

test_audit_file_dest_custom_dir_ok if {
	p.audit_file_dest_dedicated with input as {"oracle": {"init_parameters": {"audit_file_dest": "/u01/app/oracle/audit_dedicated"}}}
}

test_audit_file_dest_default_adump_fails if {
	not p.audit_file_dest_dedicated with input as {"oracle": {"init_parameters": {"audit_file_dest": "/oracle/admin/orcl/adump"}}}
}

test_names_directory_path_string_ok if {
	p.names_directory_path_correct with input as {"oracle": {"sqlnet_config": {"names_directory_path": "TNSNAMES, EZCONNECT"}}}
}

test_names_directory_path_array_ok if {
	p.names_directory_path_correct with input as {"oracle": {"sqlnet_config": {"names_directory_path": ["TNSNAMES", "EZCONNECT"]}}}
}

test_names_directory_path_hostname_fails if {
	not p.names_directory_path_correct with input as {"oracle": {"sqlnet_config": {"names_directory_path": "TNSNAMES,HOSTNAME"}}}
}

test_no_sensitive_tables_declared_fails if {
	not p.sensitive_data_access_auditing with input as {"oracle": {"fga_policies": [], "sensitive_tables": []}}
}

test_sensitive_tables_audited_ok if {
	p.sensitive_data_access_auditing with input as {"oracle": {"fga_policies": [{"table_name": "HR.SALARY"}], "sensitive_tables": ["HR.SALARY"]}}
}

test_single_grant_any_role_fails if {
	not p.grant_any_role_restricted with input as {"oracle": {"system_privileges": [{"privilege": "GRANT ANY ROLE", "grantee": "APP"}]}}
}

test_no_grant_any_role_ok if {
	p.grant_any_role_restricted with input as {"oracle": {"system_privileges": [{"privilege": "CREATE SESSION", "grantee": "APP"}]}}
}

# Decisions 2026-10-19: file modes compared as octal bit sets, not exact strings.
dir_inp(m) := {"oracle": {"directories": {"oracle_home": {"owner": "oracle", "group": "oinstall", "mode": m}}}}

test_oracle_home_mode_exact_ok if {
	p.oracle_home_permissions_restricted with input as dir_inp("755")
}

test_oracle_home_stricter_mode_ok if {
	p.oracle_home_permissions_restricted with input as dir_inp("0750")
}

test_oracle_home_group_writable_fails if {
	not p.oracle_home_permissions_restricted with input as dir_inp("775")
}

test_oracle_home_unparsable_mode_fails if {
	not p.oracle_home_permissions_restricted with input as dir_inp("rwxr-xr-x")
}

test_tnsnames_mode_640_ok_664_fails if {
	n := {"oracle": {"network_config": {"tnsnames_ora": {"owner": "oracle", "group": "oinstall", "mode": "640"}}}}
	p.tnsnames_secured with input as n
	not p.tnsnames_secured with input as {"oracle": {"network_config": {"tnsnames_ora": {"owner": "oracle", "group": "oinstall", "mode": "664"}}}}
}

test_audit_files_mode_600_ok_644_fails if {
	p.audit_files_protected with input as {"oracle": {"audit_files": {"owner": "oracle", "group": "oinstall", "mode": "600"}}}
	not p.audit_files_protected with input as {"oracle": {"audit_files": {"owner": "oracle", "group": "oinstall", "mode": "644"}}}
}

# Conditional attestation (documented, kept): required == false passes; absent does not.
test_database_vault_attested_not_required_passes if {
	p.database_vault_configured with input as {"oracle": {"database_vault": {"required": false}}}
}

test_database_vault_without_attestation_fails if {
	not p.database_vault_configured with input as {"oracle": {"database_vault": {"enabled": false}}}
}
