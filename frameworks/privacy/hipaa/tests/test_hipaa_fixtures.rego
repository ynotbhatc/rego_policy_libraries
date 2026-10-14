# Shared test fixtures for the CFR-keyed HIPAA modules: a scope that opens every gate and fact inputs on which
# every fact check passes. Test-only package.
package hipaa.test_fixtures

import rego.v1

scope_all := {
	"health_plan": true,
	"health_care_provider": true,
	"health_care_clearinghouse": true,
	"business_associate": true,
	"de_identifies_phi": true,
	"conducts_fundraising": true,
}

scope_none := {
	"health_plan": false,
	"health_care_provider": false,
	"health_care_clearinghouse": false,
	"business_associate": false,
	"de_identifies_phi": false,
	"conducts_fundraising": false,
}

administrative := {
	"security_management": {
		"risk_analysis": {"conducted": true, "documented": true, "frequency_months": 12},
		"risk_management": {"implemented": true},
		"sanction_policy": {"established": true},
		"activity_review": {"conducted": true},
	},
	"security_officer": {"designated": true, "documented": true, "responsibilities": {"defined": true}},
	"workforce": {
		"authorization_supervision": {"implemented": true},
		"clearance_procedure": {"implemented": true},
		"termination_procedures": {"implemented": true},
		"access_removed_on_termination": true,
	},
	"access_management": {
		"isolating_clearinghouse_functions": {"addressed": true},
		"access_authorization": {"implemented": true},
		"access_establishment": {"implemented": true},
		"least_privilege": {"enforced": true},
	},
	"training": {
		"program": {"implemented": true},
		"frequency_months": 12,
		"new_hires": {"required": true},
		"malicious_software": {"covered": true},
		"log_in_monitoring": {"covered": true},
		"password_management": {"covered": true},
	},
	"incident_response": {
		"response_procedures": {"implemented": true},
		"reporting": {"implemented": true},
		"breach_notification": {"procedures_defined": true},
		"forensic_capability": {"available": true},
	},
	"contingency": {
		"data_backup": {"plan_implemented": true},
		"disaster_recovery": {"plan_implemented": true},
		"emergency_mode": {"plan_implemented": true},
		"testing": {"performed": true, "frequency_months": 12},
		"applications": {"criticality_analysis_performed": true},
	},
	"evaluation": {
		"periodic_technical": {"performed": true},
		"frequency_months": 12,
		"environmental_operations_changes": {"trigger_review": true},
	},
	"business_associates": {
		"contracts": {"required": true, "phi_safeguards": {"required": true}},
		"inventory": {"maintained": true},
		"compliance": {"monitored": true},
	},
}

physical := {
	"facility_access": {
		"contingency_operations": {"addressed": true},
		"facility_security_plan": {"implemented": true},
		"access_control": {"implemented": true},
		"maintenance_records": {"tracked": true},
	},
	"workstation_use": {"policies": {"implemented": true}, "physical_access": {"restricted": true}, "screen_lock": {"configured": true}},
	"workstation_security": {"physical_safeguards": {"implemented": true}, "ephi_access": {"restricted": true}},
	"device_media": {
		"disposal": {"procedures_implemented": true, "ephi_wiped": true},
		"media_reuse": {"sanitization_implemented": true},
		"accountability": {"tracked": true},
		"data_backup": {"copy_made_before_movement": true},
	},
}

# Facts on which all five §164.312 data-activity modules report compliant (same shape as
# test_hipaa_security_rule.rego's _compliant_technical_input).
technical := {
	"phi_systems": [{
		"name": "ehr-db",
		"audit_logging_enabled": true,
		"audited_events": [
			"login_success", "login_failure", "logout", "phi_access", "phi_create",
			"phi_modify", "phi_delete", "phi_export", "permission_change",
			"account_creation", "account_deletion", "password_change",
		],
		"data_at_rest_encrypted": true,
		"encryption_algorithm": "AES-256",
		"integrity_checking_enabled": true,
		"integrity_check_frequency_hours": 12,
		"transmission_encrypted": true,
		"protocols_in_use": ["TLSv1.3"],
		"api_endpoint": "https://ehr.internal/api",
		"request_signing_enabled": true,
	}],
	"audit_logs": [{"event": "phi_access", "user_id": "u1", "timestamp": "2026-07-31T00:00:00Z"}],
	"audit_logging": {
		"centralized": true, "includes_user_id": true, "includes_timestamp": true,
		"includes_action_type": true, "includes_source_ip": true, "offsite_backup_enabled": true,
		"retention_days": 2555, "tamper_evident": true,
	},
	"monitoring": {
		"after_hours_access_alerts": true, "audit_review_frequency_days": 7,
		"automated_alerting_enabled": true, "unauthorized_access_alerts": true,
	},
	"users": [{"username": "alice", "shared_account": false, "phi_access_disabled": false}],
	"access_controls": {
		"emergency_access_procedure_documented": true, "emergency_access_tested": true,
		"emergency_accounts_reviewed_days": 30, "role_based_access_implemented": true,
	},
	"session": {"automatic_logoff_enabled": true, "inactivity_timeout_minutes": 10, "screen_lock_enabled": true},
	"encryption": {"key_management_policy_documented": true, "key_rotation_days": 90},
	"integrity": {
		"change_management_process": true, "checksum_or_hash_enabled": true,
		"digital_signatures_for_phi_export": true, "hash_algorithm": "SHA-256",
		"media_reuse_without_sanitization": false, "secure_deletion_policy": true,
		"write_protection_on_archived_phi": true,
	},
	"backup": {
		"regular_backups_enabled": true, "backup_frequency_hours": 24,
		"offsite_or_cloud_backup": true, "restore_tested": true, "restore_test_days": 90,
	},
	"mfa": {
		"enabled_for_phi_access": true, "required_for_remote_access": true,
		"required_for_privileged_accounts": true, "methods_allowed": ["totp", "fido2"],
		"stronger_method_also_available": true,
	},
	"password_policy": {
		"complexity_required": true, "history_count": 12, "lockout_enabled": true,
		"lockout_threshold": 5, "max_age_days": 90, "minimum_length": 14,
	},
	"authentication": {"concurrent_sessions_unlimited": false, "re_authentication_for_sensitive_ops": true},
	"privileged_accounts": [],
	"network": {"message_authentication_enabled": true, "phi_network_segmented": true, "remote_phi_access_enabled": false},
	"tls": {
		"minimum_version": "1.3", "enabled_ciphers": ["TLS_AES_256_GCM_SHA384"],
		"certificate_expiry_days": 200, "certificate_expiry_monitoring": true, "mutual_tls_for_phi_apis": true,
	},
	"vpn": {"required_for_remote_phi_access": true, "protocol": "IKEv2", "split_tunneling_enabled": false},
	"email": {"phi_sent_via_email": false, "dlp_enabled": true, "encrypted_email_required": true},
	"transmission": {},
	"api": {},
}

privacy := {
	"npp": {
		"documented": true, "plain_language": true, "provided_at_first_service": true, "posted_in_facility": true,
		"available_on_website": true, "includes_uses_and_disclosures": true, "includes_individual_rights": true,
		"includes_complaint_process": true, "includes_contact_info": true, "reviewed_and_updated_as_needed": true,
	},
	"tpo": {
		"treatment": {"uses_defined": true}, "payment": {"uses_defined": true}, "operations": {"uses_defined": true},
		"minimum_necessary": {"applied": true},
	},
	"authorization": {
		"required_for_non_tpo": true,
		"elements": {"all_required_elements": true, "expiration_date": true, "revocation_right": true},
		"records": {"retained_six_years": true},
		"copies_provided_to_individual": true,
	},
	"prohibited": {
		"sale_of_phi": {"not_permitted_without_auth": true},
		"marketing": {"not_without_auth": true},
		"fundraising": {"opt_out_provided": true},
	},
	"minimum_necessary": {
		"policies": {"documented": true}, "routine_disclosures": {"limited": true}, "requests": {"limited_to_needed": true},
		"role_based_access": {"implemented": true}, "workforce_access": {"limited_to_job_function": true},
	},
	"rights": {
		"access": {
			"process_defined": true, "response_within_30_days": true, "extension_allowed_30_days": true,
			"fee_limited_to_cost": true, "electronic_format_available": true, "third_party_directed_allowed": true,
			"denials": {"documented": true},
		},
		"amendment": {
			"process_defined": true, "response_within_60_days": true,
			"denials": {"basis_documented": true}, "accepted": {"propagated_to_relevant_parties": true},
		},
		"accounting": {
			"tracking_implemented": true, "six_years_retained": true, "provided_within_60_days": true,
			"first_request_free": true, "excludes_tpo": true,
		},
		"restrictions": {"process_defined": true, "out_of_pocket_payment": {"must_honor": true}},
		"confidential_communications": {"process_defined": true, "reasonable_requests_accommodated": true},
		"opt_out": {"facility_directory": true, "fundraising": true},
	},
	"de_identification": {
		"method": {"documented": true},
		"safe_harbor": {
			"names": {"removed": true}, "geographic": {"zip_to_3digits_or_less": true},
			"dates": {"age_over_89_obscured": true}, "phone_numbers": {"removed": true}, "ssn": {"removed": true},
			"mrn": {"removed": true}, "health_plan_numbers": {"removed": true}, "account_numbers": {"removed": true},
			"certificate_numbers": {"removed": true}, "device_identifiers": {"removed": true}, "urls": {"removed": true},
			"ip_addresses": {"removed": true}, "biometric_identifiers": {"removed": true},
			"full_face_photos": {"removed": true}, "unique_identifiers": {"removed": true},
			"no_re_identification_knowledge": true,
		},
	},
	"workforce": {"training": {
		"documented": true, "all_staff": {"completed": true}, "new_hires": {"within_30_days": true},
		"frequency": {"annual": true}, "role_specific": {"implemented": true}, "records": {"maintained": true},
	}},
	"sanctions": {
		"policy": {"documented": true}, "applied_to_all_workforce": true,
		"violations": {"investigated": true}, "consistent_application": true,
	},
	"privacy_officer": {"designated": true, "contact_info": {"published": true}, "responsibilities": {"documented": true}},
	"complaints": {
		"process": {"documented": true}, "contact_info": {"published": true},
		"hhs_complaint_right": {"communicated": true}, "log": {"maintained": true},
		"investigation": {"conducted": true}, "retaliation": {"prohibited": true},
	},
	"baa": {
		"required_for_all_bas": true, "uses_and_disclosures": {"limited": true}, "safeguards": {"required": true},
		"subcontractors": {"covered": true}, "phi_return_or_destruction": {"required": true},
		"breach_reporting": {"required": true}, "inventory": {"maintained": true},
	},
	"documentation": {
		"policies_and_procedures": {"maintained": true}, "retention_years": 6, "accessible": true,
		"communications": {"retained": true},
	},
}

hitech := {
	"breach_assessment": {
		"nature_and_extent": {"evaluated": true}, "who_accessed_phi": {"evaluated": true},
		"whether_phi_acquired": {"evaluated": true}, "mitigation_extent": {"evaluated": true},
		"documented": true, "result": {"low_probability_exception": {"documented_when_applied": true}},
	},
	"breach_notification": {
		"individuals": {
			"within_60_days": true, "written_notice": true, "includes_description": true,
			"includes_types_of_phi": true, "includes_steps_to_protect": true,
			"includes_investigation_steps": true, "includes_contact_info": true,
		},
		"hhs": {
			"small_breaches": {"annual_log": {"submitted": true}},
			"large_breaches": {"within_60_days": true},
			"large_breaches_500_plus": {"media_notice": true},
		},
		"media": {
			"required_threshold_500": true, "within_60_days": true,
			"state_or_jurisdiction": {"prominent_media_outlets": true},
		},
	},
	"breach_log": {
		"maintained": true, "all_breaches": {"documented": true}, "sub_500_breaches": {"included": true},
		"retention_years": 6,
	},
	"business_associates": {
		"directly_liable": true, "security_rule": {"applies_directly": true},
		"privacy_rule": {"applies_to_use_disclosure": true}, "subcontractors": {"baa_required": true},
	},
	"baa": {
		"hitech_provisions": {"included": true},
		"breach_notification": {"ba_notifies_ce_without_unreasonable_delay": true, "within_60_days_max": true},
		"individual_rights": {"access_honored": true}, "electronic_access": {"provided_when_requested": true},
	},
	"enforcement": {
		"cap_template": {"available": true}, "compliance_monitoring": {"internal": true},
		"audit_response": {"procedures_defined": true}, "hhs_ocr_cooperation": {"policy": true},
	},
	"patient_access": {
		"electronic_format": {"available": true}, "ehr": {"access_provided": true},
		"third_party_directed": {"honored": true}, "fee": {"reasonable_cost_based": true},
		"response_time": {"within_30_days": true},
	},
	"patient_rights": {"out_of_pocket": {"restriction_honored": true, "health_plan_disclosure": {"prohibited_when_restricted": true}}},
	"ehr": {
		"access_controls": {"unique_user_id": true, "emergency_access": {"procedure": true}, "automatic_logoff": {"configured": true}},
		"encryption": {"at_rest": true, "in_transit": true},
		"audit_log": {"enabled": true, "tamper_evident": true},
		"integrity": {"data_authentication": true},
	},
	"meaningful_use": {
		"security_risk_analysis": {"conducted": true, "annually": true},
		"security_updates": {"implemented": true}, "security_deficiencies": {"corrected": true},
	},
}

all_true(ids) := {id: true | some id, _ in ids}

# Everything green across all HIPAA modules.
full_input := object.union(technical, {
	"hipaa": {
		"scope": scope_all,
		"administrative": administrative,
		"physical": physical,
		"privacy": privacy,
		"specifications": all_true(data.hipaa.security_rule.specifications),
		"subpart_d": all_true(data.hipaa.hitech.breach_notification_rule),
		"subpart_e": all_true(data.hipaa.privacy_rule.requirements),
		"part_160": all_true(data.hipaa.part160.obligations),
		"part_162": all_true(data.hipaa.part162.obligations),
	},
	"hitech": hitech,
})
