package nist.sp800_53.main_test

import rego.v1

import data.nist.sp800_53.main

# Minimal "everything-passes" input — every required key set to true.
fully_compliant_input := {
    "assessment_date": "2026-06-26",
    "ac_controls": {
        "policy": {"documented": true, "disseminated": true, "reviewed_updated": true},
        "procedures": {"implementation_documented": true},
        "account_management": {"automated_tools": true, "approval_process": true, "regular_reviews": true, "timely_removal": true},
        "access_enforcement": {"mandatory_access_control": true, "discretionary_access_control": true, "role_based_access_control": true},
        "information_flow": {"security_labels": true, "flow_control_policies": true, "automated_enforcement": true},
        "separation_duties": {"critical_functions_divided": true, "documented_assignments": true, "monitored_compliance": true},
        "least_privilege": {"minimum_access_granted": true, "privileged_functions_authorized": true, "non_privileged_access_default": true},
        "logon_attempts": {"lockout_configured": true, "maximum_attempts": 3, "lockout_duration": 30},
        "use_notification": {"banner_displayed": true, "acknowledgment_required": true, "monitoring_consent": true},
        "logon_notification": {"timestamp_displayed": true, "location_displayed": true, "unsuccessful_attempts_displayed": true},
        "session_control": {"limits_configured": true, "per_account_limits": true, "per_device_limits": true},
        "session_lock": {"inactivity_timeout": 600, "pattern_hiding": true, "authentication_required": true},
        "session_termination": {"automatic_termination": true, "user_initiated": true, "administrative_termination": true},
        "permitted_actions": {"unauthenticated_functions": ["system_status"]},
        "automated_marking": {"security_labels": true, "classification_marking": true, "handling_caveats": true},
        "security_attributes": {"attribute_binding": true, "attribute_association": true, "transmission_preservation": true},
        "remote_access": {"authorized_only": true, "encrypted_connections": true, "monitored_controlled": true},
        "wireless_access": {"authorized_only": true, "encrypted_authentication": true, "monitored_usage": true},
        "mobile_devices": {"usage_restrictions": true, "connection_requirements": true, "configuration_requirements": true},
        "external_systems": {"authorized_only": true, "security_requirements": true, "user_agreements": true},
        "information_sharing": {"user_discretion_limited": true, "automated_guidance": true, "security_attributes_preserved": true},
        "public_content": {"authorized_personnel_only": true, "review_process": true, "removal_procedures": true},
        "data_mining": {"detection_techniques": true, "warning_notifications": true, "response_procedures": true},
        "decisions": {"security_attributes_used": true, "consistent_enforcement": true, "documented_criteria": true},
        "reference_monitor": {"tamper_proof": true, "always_invoked": true, "small_verifiable": true},
    },
    "au_controls": {
        "policy": {"documented": true},
        "event_logging": {"enabled": true},
        "content_of_records": {"adequate": true},
        "storage_capacity": {"adequate": true},
        "response_to_failures": {"alerting": true},
        "review_and_analysis": {"regular": true},
        "reduction_and_reporting": {"tools_available": true},
        "time_stamps": {"synchronized": true},
        "protection_of_records": {"tamper_resistant": true},
        "non_repudiation": {"implemented": true},
        "retention_period_days": 365,
        "generation": {"required_events_captured": true},
    },
    "cm_controls": {
        "policy": {"documented": true},
        "baseline_config": {"maintained": true},
        "change_control": {"process_exists": true},
        "security_impact_analysis": {"performed": true},
        "access_restrictions_for_change": {"enforced": true},
        "configuration_settings": {"documented": true},
        "least_functionality": {"enforced": true},
        "system_component_inventory": {"maintained": true},
        "config_management_plan": {"documented": true},
        "software_usage_restrictions": {"enforced": true},
        "user_installed_software": {"restricted": true},
    },
    "ia_controls": {
        "policy": {"documented": true},
        "user_id_auth": {"uniquely_identified": true, "mfa_for_privileged": true, "mfa_for_non_privileged": true},
        "device_identification": {"implemented": true},
        "identifier_management": {"unique_per_user": true},
        "authenticator_management": {"complexity_enforced": true, "encrypted_in_transit": true, "encrypted_at_rest": true},
        "authenticator_feedback": {"obscured": true},
        "cryptographic_module_auth": {"fips_validated": true},
        "non_organizational_users": {"identified": true},
    },
    "ir_controls": {
        "policy": {"documented": true},
        "training": {"completed_within_year": true},
        "testing": {"exercised_within_year": true},
        "handling": {"process_defined": true},
        "monitoring": {"continuous": true},
        "reporting": {"timely": true},
        "assistance": {"available": true},
        "plan": {"documented": true},
        "information_spillage": {"process_defined": true},
    },
    "sc_controls": {
        "policy": {"documented": true},
        "app_partitioning": {"separated": true},
        "security_function_isolation": {"implemented": true},
        "denial_of_service": {"protections": true},
        "boundary_protection": {"deployed": true},
        "transmission_confidentiality": {"encrypted": true},
        "transmission_integrity": {"protected": true},
        "network_disconnect": {"timeout_configured": true},
        "cryptographic_key_mgmt": {"documented": true},
        "cryptographic_protection": {"fips_validated": true},
        "collaborative_devices": {"disabled_when_unused": true},
        "public_key_infrastructure": {"certificates_managed": true},
        "mobile_code": {"controls_enforced": true},
        "voip": {"controls_enforced": true},
        "secure_dns": {"dnssec_enforced": true},
        "session_authenticity": {"protected": true},
        "protection_of_info_at_rest": {"encrypted": true},
    },
    "si_controls": {
        "policy": {"documented": true},
        "flaw_remediation": {"timely": true},
        "malicious_code_protection": {"deployed": true},
        "system_monitoring": {"continuous": true},
        "security_alerts": {"acted_upon": true},
        "security_function_verification": {"tested": true},
        "software_firmware_integrity": {"verified": true},
        "spam_protection": {"enabled": true},
        "input_validation": {"enforced": true},
        "error_handling": {"no_info_disclosure": true},
        "information_management_retention": {"policy_enforced": true},
        "memory_protection": {"enabled": true},
    },
}

test_compliance_report_returns_object if {
    r := main.compliance_report with input as fully_compliant_input
    r.framework == "NIST SP 800-53 Rev 5"
    is_number(r.total_controls)
}

test_compliant_when_all_inputs_pass if {
    main.compliant with input as fully_compliant_input
}

test_violations_empty_when_compliant if {
    count(main.violations) == 0 with input as fully_compliant_input
}

test_non_compliant_with_empty_input if {
    not main.compliant with input as {}
}

test_violations_non_empty_with_empty_input if {
    count(main.violations) > 0 with input as {}
}

test_family_summary_present if {
    r := main.compliance_report with input as fully_compliant_input
    r.family_summary.AC.compliant == true
    r.family_summary.SI.compliant == true
}
