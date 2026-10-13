package stig.oracle_database_19c_test

import rego.v1
import data.stig.oracle_database_19c

test_report_wellformed_on_empty_input if {
	report := oracle_database_19c.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "oracle": {
	  "profiles": {
	   "ORA_STIG_PROFILE": {
	    "SESSIONS_PER_USER": "10",
	    "PASSWORD_LOCK_TIME": "UNLIMITED",
	    "FAILED_LOGIN_ATTEMPTS": "3",
	    "INACTIVE_ACCOUNT_TIME": "35",
	    "PASSWORD_VERIFY_FUNCTION": "ORA12C_STIG_VERIFY_FUNCTION",
	    "PASSWORD_LIFE_TIME": "60",
	    "PASSWORD_GRACE_TIME": "5"
	   }
	  },
	  "listener": {
	   "rate_limit_configured": true,
	   "admin_authentication_required": true,
	   "extproc_configured": false
	  },
	  "parameters": {
	   "max_idle_time": "15",
	   "audit_trail": "DB",
	   "remote_os_roles": "FALSE",
	   "sql92_security": "TRUE",
	   "remote_login_passwordfile": "EXCLUSIVE",
	   "audit_sys_operations": "TRUE",
	   "dbfips_140": "TRUE"
	  },
	  "attest": {
	   "security_labeling_implemented_or_not_required": true,
	   "org_level_auth_integrated": true,
	   "authorizations_enforced": true,
	   "shared_account_users_individually_identified": true,
	   "audit_event_selection_by_designated_personnel": true,
	   "dod_auditable_events_configured": true,
	   "additional_audit_information_configured": true,
	   "audit_storage_capacity_allocated": true,
	   "audit_offloaded_continuously": true,
	   "audit_storage_warning_at_75_percent": true,
	   "audit_failure_realtime_alert": true,
	   "audit_data_access_restricted": true,
	   "audit_tools_access_restricted": true,
	   "vendor_supported_version": true,
	   "software_change_monitoring_in_place": true,
	   "software_library_access_restricted": true,
	   "install_account_restricted": true,
	   "software_directories_dedicated": true,
	   "configured_per_dod_guidance": true,
	   "developers_excluded_from_dba_group": true,
	   "install_account_use_logged": true,
	   "data_log_audit_files_in_dedicated_directories": true,
	   "dba_os_accounts_least_privilege": true,
	   "temporary_accounts_identified": true,
	   "temporary_accounts_expire_within_72h": true,
	   "developers_no_elevated_privileges_on_shared_hosts": true,
	   "extproc_os_accounts_least_privilege": true,
	   "external_executables_authorized": true,
	   "ppsm_functions_ports_protocols_approved": true,
	   "shared_accounts_require_individual_authentication": true,
	   "organizational_users_uniquely_identified": true,
	   "temporary_password_procedures_documented": true,
	   "pki_private_key_access_restricted": true,
	   "pki_identity_mapped_to_accounts": true,
	   "cli_plaintext_password_tools_mitigated_and_approved": true,
	   "nonorganizational_users_uniquely_identified": true,
	   "admin_functionality_separated_from_users": true,
	   "security_functions_isolated": true,
	   "production_data_transfer_controlled": true,
	   "input_validation_implemented": true,
	   "dynamic_code_execution_justified": true,
	   "dynamic_code_injection_protected": true,
	   "error_messages_minimal": true,
	   "error_messages_restricted_to_authorized_personnel": true,
	   "compromised_password_list_checked": true,
	   "password_change_required_on_account_recovery": true,
	   "trust_store_contains_only_approved_anchors": true
	  },
	  "unified_audit_policies_enabled": [
	   "ORA_SECURECONFIG"
	  ],
	  "filesystem": {
	   "oracle_home_world_accessible": false,
	   "archive_log_dirs_world_accessible": false,
	   "diag_dir_world_accessible": false,
	   "database_files_world_accessible": false
	  },
	  "unauthorized_object_owners": [],
	  "direct_admin_privilege_grantees": [],
	  "instance_name": "PRODDB",
	  "version": "19.0.0.0.0",
	  "unauthorized_db_links": [],
	  "grantable_privileges_non_dba": [],
	  "unauthorized_admin_option_system_privileges": [],
	  "public_system_privileges": [],
	  "unauthorized_admin_option_roles": [],
	  "unauthorized_public_object_privileges": [],
	  "public_granted_roles": [],
	  "unauthorized_default_admin_roles": [],
	  "network": {
	   "access_restriction_enforced": true,
	   "tls_or_native_encryption_required": true
	  },
	  "cman": {
	   "present": false
	  },
	  "sqlnet": {
	   "allowed_logon_version_server": "12"
	  },
	  "os": {
	   "root_in_dba_group": false
	  },
	  "users_with_default_password": [],
	  "sample_schemas_present": [],
	  "unused_components_installed": [],
	  "unused_integrated_options_enabled": [],
	  "users_with_10g_password_verifier": [],
	  "log_mode": "ARCHIVELOG",
	  "tde": {
	   "enabled": true
	  },
	  "patches": {
	   "latest_cpu_applied": true
	  },
	  "control_files": [
	   "/u01/oradata/control01.ctl",
	   "/u02/oradata/control02.ctl",
	   "/u03/oradata/control03.ctl"
	  ],
	  "redo_log_groups": [
	   {
	    "group": 1,
	    "members": [
	     "/u01/redo01a.log",
	     "/u02/redo01b.log"
	    ]
	   },
	   {
	    "group": 2,
	    "members": [
	     "/u01/redo02a.log",
	     "/u02/redo02b.log"
	    ]
	   },
	   {
	    "group": 3,
	    "members": [
	     "/u01/redo03a.log",
	     "/u02/redo03b.log"
	    ]
	   }
	  ]
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := oracle_database_19c.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.oracle_database_19c.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}

test_single_bad_fact_opens_a_finding if {
	report := oracle_database_19c.stig_assessment with input as object.union(green_fixture, {"oracle": {"parameters": {"remote_os_roles": "TRUE"}}})
	some f in report.findings
	f.stig_id == "O19C-00-009200"
	f.status == "Open"
}
