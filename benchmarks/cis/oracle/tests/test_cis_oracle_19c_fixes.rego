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
