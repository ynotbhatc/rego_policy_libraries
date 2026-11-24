package iec_62443_evidence_rule_test

import rego.v1

# IEC 62443 (parts 2-1, 2-3, 2-4, 3-2 and 3-3 FR 1-7), target SL 4, two systems (one with remote and wireless access, one without), three zones, two conduits.
#
# Evidence rule, data-driven over an all-pass fixture: only the boolean true (or,
# for a "does this apply" fact, a stated boolean) is evidence. Every boolean leaf
# is replaced by "false", "true", "no", null, 0 and 1 and removed; every number
# leaf is replaced by its string form and null and removed. None of the mutated
# inputs may be reported compliant.

all_pass := {
	"authentication": {
		"audit_trail_for_privileged_access": true,
		"centralized_identity_management": true,
		"certificate_revocation_checking": true,
		"dual_approval_for_critical_actions": true,
		"hardware_token_authentication": true,
		"identifier_reuse_prevented": true,
		"initial_authenticator_secure_distribution": true,
		"pki_or_certificate_based": true,
		"portable_device_central_mgmt": true,
		"role_based_access_control": true,
		"strong_cryptography": true,
		"unified_account_policy": true,
	},
	"backups": {
		"backup_frequency_days": 1,
		"encryption_at_rest": true,
		"offsite_storage": true,
		"restoration_tested": true,
	},
	"conduits": [
		{
			"dest_zone": "ics_control",
			"encrypted": true,
			"firewall_or_dmz": true,
			"source_zone": "corporate_it",
			"traffic_filtered": true,
			"unidirectional_gateway": true,
		},
		{
			"dest_zone": "ics_control",
			"encrypted": true,
			"firewall_or_dmz": true,
			"source_zone": "dmz",
			"traffic_filtered": true,
		},
	],
	"ics_systems": [
		{
			"account_lockout_enabled": true,
			"account_lockout_threshold": 3,
			"account_review_process": true,
			"application_partitioning": true,
			"application_whitelisting": true,
			"approved_cryptographic_algorithms": true,
			"audit_log_includes_required_fields": true,
			"audit_log_tamper_protection": true,
			"audit_logging_enabled": true,
			"authenticator_feedback_obscured": true,
			"authenticator_lifecycle_managed": true,
			"automated_integrity_checking": true,
			"backup_configured": true,
			"communication_integrity": true,
			"concurrent_session_limit": 1,
			"configuration_baseline_documented": true,
			"criticality": "high",
			"cryptographic_integrity_protection": true,
			"cryptographic_key_management": true,
			"data_at_rest_protected": true,
			"data_encrypted_in_transit": true,
			"dedicated_hardware": true,
			"default_credentials_unchanged": false,
			"deterministic_output_verification": true,
			"device_authentication": true,
			"device_unique_id": true,
			"emergency_power_backup": true,
			"emergency_power_tested": true,
			"error_handling_implemented": true,
			"error_messages_expose_sensitive_data": false,
			"fips_140_2_compliant": true,
			"firmware_integrity_checking": true,
			"firmware_version_current": true,
			"input_validation": true,
			"inventory_documented": true,
			"key_rotation_policy": true,
			"least_privilege_enforced": true,
			"malware_definitions_current": true,
			"malware_protection": true,
			"media_sanitization_procedure": true,
			"memory_scrubbing_on_deallocation": true,
			"mfa_enabled": true,
			"mobile_code_controlled": true,
			"name": "plc-01",
			"non_repudiation_enabled": true,
			"ntp_configured": true,
			"os_hardened": true,
			"os_version_current": true,
			"password_complexity": true,
			"password_min_length": 16,
			"patch_status_documented": true,
			"portable_device_policy": true,
			"rate_limiting_enabled": true,
			"recovery_procedure_documented": true,
			"recovery_time_objective_hours": 1,
			"remote_access_controlled": true,
			"remote_access_enabled": true,
			"remote_access_mfa": true,
			"remote_session_termination": true,
			"removable_media_controlled": true,
			"resource_limits_configured": true,
			"resource_monitoring_enabled": true,
			"secure_deletion_capability": true,
			"security_function_testing": true,
			"sensitive_data_transmitted": true,
			"session_integrity": true,
			"session_invalidated_on_privilege_change": true,
			"session_lock_enabled": true,
			"session_lock_timeout_minutes": 5,
			"software_integrity_verification": true,
			"system_use_notification": true,
			"tls_version_current": true,
			"unique_identification": true,
			"unnecessary_services_disabled": true,
			"uses_deprecated_ciphers": false,
			"uses_shared_platform": true,
			"virtualization_isolation": true,
			"wireless_access": true,
			"wireless_authentication": true,
			"wireless_encrypted": true,
			"wireless_monitored": true,
			"wireless_use_authorized": true,
		},
		{
			"account_lockout_enabled": true,
			"account_lockout_threshold": 3,
			"account_review_process": true,
			"application_partitioning": true,
			"application_whitelisting": true,
			"approved_cryptographic_algorithms": true,
			"audit_log_includes_required_fields": true,
			"audit_log_tamper_protection": true,
			"audit_logging_enabled": true,
			"authenticator_feedback_obscured": true,
			"authenticator_lifecycle_managed": true,
			"automated_integrity_checking": true,
			"backup_configured": true,
			"communication_integrity": true,
			"concurrent_session_limit": 1,
			"configuration_baseline_documented": true,
			"criticality": "low",
			"cryptographic_integrity_protection": true,
			"cryptographic_key_management": true,
			"data_at_rest_protected": true,
			"data_encrypted_in_transit": true,
			"default_credentials_unchanged": false,
			"deterministic_output_verification": true,
			"device_authentication": true,
			"device_unique_id": true,
			"emergency_power_backup": true,
			"emergency_power_tested": true,
			"error_handling_implemented": true,
			"error_messages_expose_sensitive_data": false,
			"fips_140_2_compliant": true,
			"firmware_integrity_checking": true,
			"firmware_version_current": true,
			"input_validation": true,
			"inventory_documented": true,
			"key_rotation_policy": true,
			"least_privilege_enforced": true,
			"malware_definitions_current": true,
			"malware_protection": true,
			"media_sanitization_procedure": true,
			"memory_scrubbing_on_deallocation": true,
			"mfa_enabled": true,
			"mobile_code_controlled": true,
			"name": "hmi-02",
			"non_repudiation_enabled": true,
			"ntp_configured": true,
			"os_hardened": true,
			"os_version_current": true,
			"password_complexity": true,
			"password_min_length": 16,
			"patch_status_documented": true,
			"portable_device_policy": true,
			"rate_limiting_enabled": true,
			"recovery_procedure_documented": true,
			"remote_access_enabled": false,
			"removable_media_controlled": true,
			"resource_limits_configured": true,
			"resource_monitoring_enabled": true,
			"secure_deletion_capability": true,
			"security_function_testing": true,
			"sensitive_data_transmitted": false,
			"session_integrity": true,
			"session_invalidated_on_privilege_change": true,
			"session_lock_enabled": true,
			"session_lock_timeout_minutes": 5,
			"software_integrity_verification": true,
			"system_use_notification": true,
			"tls_version_current": true,
			"unique_identification": true,
			"unnecessary_services_disabled": true,
			"uses_deprecated_ciphers": false,
			"uses_shared_platform": false,
			"wireless_access": false,
		},
	],
	"is_iacs_service_provider": true,
	"monitoring": {
		"anomaly_detection_enabled": true,
		"audit_failure_response_defined": true,
		"audit_processing_failure_alerts": true,
		"audit_storage_adequate": true,
		"automated_alerts_configured": true,
		"centralized_log_collection": true,
		"continuous_monitoring": true,
		"dos_protection": true,
		"ics_log_retention_days": 400,
		"ics_specific_soc_capability": true,
		"incident_response_plan_for_ics": true,
		"log_access_controlled": true,
		"logs_sent_to_immutable_store": true,
		"mean_time_to_detect_hours": 1,
		"mean_time_to_respond_hours": 1,
		"security_event_monitoring": true,
		"threat_intelligence_integrated": true,
		"timestamps_synchronized": true,
	},
	"network": {
		"direct_internet_connectivity_to_ics": false,
		"dmz_implemented": true,
		"dos_traffic_management": true,
		"general_purpose_comms_policy": true,
		"it_ot_segmentation": true,
		"malware_protection_at_boundaries": true,
		"network_inventory_documented": true,
		"redundant_paths": true,
		"wireless_policy_documented": true,
	},
	"patch_management": {
		"change_management_integrated": true,
		"compensating_controls_for_unpatched": true,
		"emergency_patch_procedure": true,
		"max_patch_delay_days": 7,
		"patch_deployment_schedule_documented": true,
		"patch_inventory_tracked": true,
		"patch_testing_environment": true,
		"process_documented": true,
		"rollback_capability": true,
		"tested_before_deployment": true,
		"vendor_notification_subscriptions": true,
	},
	"risk_assessment": {
		"asset_inventory_complete": true,
		"conducted": true,
		"consequence_analysis_performed": true,
		"cyber_risk_identified": true,
		"high_level_security_requirements": true,
		"residual_risk_accepted": true,
		"review_frequency_months": 6,
		"target_sl_assigned_per_zone": true,
		"third_party_review": true,
		"threat_modeling_performed": true,
		"vulnerability_assessment_performed": true,
		"zones_and_conduits_defined": true,
	},
	"security_management": {
		"configuration_change_management": true,
		"csms_audit_conducted": true,
		"csms_audit_frequency_months": 6,
		"csms_documented": true,
		"functionality_review_schedule": true,
		"incident_response_capability": true,
		"inventory_auto_discovery": true,
		"policy_approved": true,
		"policy_review_cycle_months": 6,
		"recovery_plan_tested": true,
		"risk_management_process": true,
		"roles_responsibilities_defined": true,
		"security_awareness_training": true,
		"security_metrics_tracked": true,
		"security_testing_schedule_documented": true,
		"supply_chain_security": true,
		"third_party_security_requirements": true,
		"training_frequency_months": 6,
	},
	"service_provider": {
		"customer_security_requirements_reviewed": true,
		"incident_notification_sla_hours": 4,
		"installation_protection_measures": true,
		"malware_protection_on_tools": true,
		"patch_qualification_for_supplied_systems": true,
		"personnel_background_checks": true,
		"portable_tool_security_policy": true,
		"remote_access_mfa_enforced": true,
		"remote_access_security_controlled": true,
		"remote_session_audit_logged": true,
		"security_documentation_provided": true,
		"security_event_notification": true,
		"security_program_documented": true,
		"security_training_for_field_staff": true,
		"temporary_connection_policy": true,
		"vulnerability_disclosure_process": true,
	},
	"target_sl": 4,
	"zones": [
		{
			"criticality": "low",
			"general_purpose_comms_unrestricted": false,
			"name": "corporate_it",
			"risk_assessment_documented": true,
			"security_level": 3,
			"security_level_defined": true,
			"type": "it",
		},
		{
			"criticality": "medium",
			"general_purpose_comms_unrestricted": false,
			"name": "dmz",
			"risk_assessment_documented": true,
			"security_level": 3,
			"security_level_defined": true,
			"type": "dmz",
		},
		{
			"criticality": "high",
			"general_purpose_comms_unrestricted": false,
			"name": "ics_control",
			"risk_assessment_documented": true,
			"security_level": 3,
			"security_level_defined": true,
			"type": "ot",
		},
	],
}

_bool_leaves := [p | walk(all_pass, [p, v]); is_boolean(v)]

_number_leaves := [p | walk(all_pass, [p, v]); is_number(v)]

_bad_booleans := ["false", "true", "no", null, 0, 1]

_label(p) := concat(".", [sprintf("%v", [s]) | some s in p])

_mutations contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "input": inp} if {
	some p in _bool_leaves
	some bad in _bad_booleans
	inp := json.patch(all_pass, [{"op": "replace", "path": p, "value": bad}])
}

_mutations contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "input": inp} if {
	some p in _number_leaves
	some bad in [sprintf("%v", [object.get(all_pass, p, null)]), null]
	inp := json.patch(all_pass, [{"op": "replace", "path": p, "value": bad}])
}

_mutations contains {"case": sprintf("%s removed", [_label(p)]), "input": inp} if {
	some p in array.concat(_bool_leaves, _number_leaves)
	inp := json.patch(all_pass, [{"op": "remove", "path": p}])
}

# The mutated inputs that still pass (empty when the evidence rule holds).
escapes contains m.case if {
	some m in _mutations
	data.iec_62443.main.compliance_report.compliant == true with input as m.input
}

test_fixture_passes if {
	r := data.iec_62443.main.compliance_report with input as all_pass
	r.compliant == true
	count(r.violations) == 0
}

test_empty_input_fails if {
	r := data.iec_62443.main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_no_bad_evidence_passes if {
	count(_mutations) > 500
	count(escapes) == 0
}
