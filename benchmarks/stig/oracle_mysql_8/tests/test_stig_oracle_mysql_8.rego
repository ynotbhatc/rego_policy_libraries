package stig.oracle_mysql_8_test

import rego.v1
import data.stig.oracle_mysql_8

test_report_wellformed_on_empty_input if {
	report := oracle_mysql_8.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "mysql": {
	  "plugins": {
	   "authentication_ldap_simple": "ACTIVE",
	   "audit_log": "ACTIVE",
	   "validate_password": "ACTIVE"
	  },
	  "variables": {
	   "max_user_connections": "50",
	   "validate_password.length": "15",
	   "validate_password.policy": "STRONG",
	   "require_secure_transport": "ON",
	   "ssl_fips_mode": "ON",
	   "audit_log_rotate_on_size": "1073741824"
	  },
	  "audit": {
	   "filters": [
	    "log_all"
	   ],
	   "force_plus_permanent": true
	  },
	  "filesystem": {
	   "audit_log_permissions_restricted": true,
	   "ssl_key_permissions_restricted": true,
	   "datadir_permissions_restricted": true
	  },
	  "attest": {
	   "no_shared_accounts_or_individually_identified": true,
	   "pki_certificate_path_and_revocation_validated": true,
	   "pki_identity_mapped_to_accounts": true,
	   "authentication_feedback_obscured": true,
	   "authorizations_enforced": true,
	   "configured_per_dod_guidance": true,
	   "ppsm_functions_ports_protocols_approved": true,
	   "organizational_users_uniquely_identified": true,
	   "nonorganizational_users_uniquely_identified": true,
	   "admin_functionality_separated_from_users": true,
	   "security_functions_isolated": true,
	   "production_data_transfer_controlled": true,
	   "input_validation_implemented": true,
	   "dynamic_code_execution_justified": true,
	   "dynamic_code_injection_protected": true,
	   "software_module_change_privileges_restricted": true,
	   "install_account_restricted": true,
	   "software_directories_dedicated": true,
	   "network_ports_protocols_approved": true,
	   "configuration_change_access_restricted": true,
	   "audit_storage_capacity_allocated": true,
	   "audit_offloaded_continuously": true,
	   "audit_storage_warning_at_75_percent": true,
	   "audit_failure_realtime_alert": true,
	   "cached_authenticator_lifetime_limited": true,
	   "reauthentication_circumstances_enforced": true,
	   "discretionary_access_control_enforced": true,
	   "security_labeling_implemented_or_not_required": true,
	   "session_termination_conditions_enforced": true,
	   "nsa_approved_cryptography_for_classified_or_not_required": true,
	   "server_certificate_issued_by_dod_pki": true,
	   "security_updates_applied_within_policy": true,
	   "invalid_input_handling_documented": true,
	   "vendor_supported_version": true
	  },
	  "unauthorized_audit_admins": [],
	  "users": [
	   {
	    "user": "app",
	    "host": "%",
	    "plugin": "caching_sha2_password"
	   }
	  ],
	  "sample_schemas_present": [],
	  "unused_plugins_installed": [],
	  "unused_integrated_components_enabled": [],
	  "encryption": {
	   "all_tablespaces_encrypted": true
	  },
	  "unauthorized_ddl_grantees": [],
	  "unauthorized_create_routine_grantees": [],
	  "unauthorized_definer_routines": []
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := oracle_mysql_8.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.oracle_mysql_8.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}

test_single_bad_fact_opens_a_finding if {
	report := oracle_mysql_8.stig_assessment with input as object.union(green_fixture, {"mysql": {"variables": {"require_secure_transport": "OFF"}}})
	some f in report.findings
	f.stig_id == "MYS8-00-005200"
	f.status == "Open"
}
