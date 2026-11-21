# Evidence missing vs fail for PCI DSS v4.0.1 (Tim, 2026-11-21). Every requirement starts from an all-pass
# configuration (_all_pass: only facts that gate a requirement, CDE scope or program management) and breaks one
# fact two ways: set to false, the requirement fails (the fact is present and non-compliant); set to null or a
# string, it is evidence missing and the finding names the input path. Requirement numbers are cited; PCI DSS
# text is not quoted.
package pci_dss.main_evidence_test

import rego.v1

_all_pass := {"pci": {"audit_logs": {"data": {"user_identification": true, "event_type": true, "date_and_time": true, "success_or_failure": true, "origination_of_event": true, "identity_of_affected_data": true}, "protection": {"write_access_limited": true, "backup": {"promptly_backed_up": true}, "centralized": {"implemented": true}, "immutable_storage": {"enabled": true}, "integrity": {"checksums_or_hashing": true}}, "external_server": {"implemented": true, "separate_from_cde": true, "write_only_from_cde": true}, "events": {"user_access_to_chd": true, "privileged_user_actions": true, "invalid_logical_access_attempts": true, "use_of_identification_mechanisms": true, "initialization_of_audit_logs": true, "deletion_of_audit_logs": true, "system_object_creation_deletion": true}}, "log_review": {"automated": {"enabled": true}, "daily": {"performed": true, "all_security_events": true, "privileged_component_logs": true, "critical_system_logs": true, "security_controls_logs": true}, "exceptions": {"tracked": true, "investigation": {"timely": true}, "remediation": {"documented": true}}, "periodic": {"performed": true, "documented": true, "frequency_days": 1, "tra_defined_frequency_days": 1}}, "log_retention": {"policy": {"documented": true}, "total_months": 12, "online_months": 3}, "logging": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "failure_detection": {"security_controls_monitored": true, "ids_ips": {"monitoring": true}, "fim": {"monitoring": true}, "antivirus": {"monitoring": true}, "physical_access": {"monitoring": true}, "logical_access": {"monitoring": true}, "audit_log": {"monitoring": true}, "network_security_controls": {"monitoring": true}}, "failure_response": {"alert": {"immediate": true}, "restore": {"timely": true}, "compensating_controls": {"during_failure": true}, "root_cause": {"documented": true}}, "time_data": {"receiving": {"only_from_designated_central_servers": true}, "changes": {"logged": true, "alerts": {"configured": true}}}, "time_sync": {"ntp": {"implemented": true}, "authoritative_time_source": {"used": true}, "internal_servers": {"synced_from_authoritative": true}, "cde_systems": {"synchronized": true}}, "vuln_scanning": {"internal": {"authenticated": {"performed": true, "non_credentialed_systems_documented": true, "sufficient_privileges": true, "scan_accounts": {"managed_per_8_2_2": true}}, "performed": true, "qualified_personnel": true, "after_significant_changes": true, "high_and_critical": {"remediated": true}, "rescans": {"performed": true}, "frequency_days": 1}, "external": {"performed": true, "asv": {"approved": true}, "passing_scan": {"achieved": true}, "after_significant_changes": true, "frequency_days": 1}}, "fim": {"deployed": true, "critical_files": {"covered": true}, "os_files": {"covered": true}, "application_files": {"covered": true}, "configuration_files": {"covered": true}, "alerts": {"immediate": true}, "comparison": {"against_baseline": true}, "frequency_days": 1}, "ids_ips": {"deployed": true, "coverage": {"all_cde_network_traffic": true}, "signatures": {"current": true}, "alerts": {"configured": true}, "personnel": {"responds_to_alerts": true}}, "ecommerce": {"payment_pages": {"in_scope": true, "integrity_monitoring": true, "change_detection": {"implemented": true, "frequency_days": 1}, "script_inventory": {"maintained": true}, "alerts": {"configured": true}, "tls_enforced": true, "https_only": true, "hsts_enabled": true, "mixed_content": {"blocked": true}}, "in_scope": true}, "pen_testing": {"exploitable_vulnerabilities": {"corrected": true}, "retesting": {"performed_after_fixes": true}, "results": {"retained": true}, "performed": true, "after_significant_infrastructure_changes": true, "qualified": {"independent_tester": true}, "scope": {"network_layer": true, "application_layer": true, "includes_cde_perimeter": true, "includes_critical_systems": true}, "frequency_months": 1}, "security_testing": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "segmentation_testing": {"performed": true, "penetration_testing_method": true, "confirms_isolation": true, "after_segmentation_changes": true, "frequency_months": 1}, "vuln_remediation": {"critical": {"resolved": true}, "high": {"resolved": true}, "medium": {"risk_based_timeline": true}, "tracking": {"implemented": true}, "verification": {"rescan_after_fix": true}}, "wireless": {"authorized_access_points": {"inventoried": true}, "rogue_detection": {"implemented": true, "frequency_days": 1}, "unauthorized_access_points": {"alerts": {"configured": true}, "response": {"documented": true}}, "in_scope_for_cde": true, "default_settings": {"changed": true}, "wpa3_or_wpa2": {"enabled": true}, "wep": {"disabled": true}, "ssid": {"default_changed": true, "cde_ssid_not_broadcast": true}, "transmits_pan": true, "pan_transmission": {"strong_cryptography": true, "wpa3_or_wpa2_enterprise": true, "aes_encryption": true}}, "aup": {"documented": true, "approved": true, "explicit_approval_required": true, "updated_annually": true, "covers": {"technologies": true, "cardholder_data": true, "internet_usage": true, "removable_media": true}}, "forensic_readiness": {"evidence_preservation": {"procedures": true}, "forensic_firm": {"on_retainer": true}, "chain_of_custody": {"procedures": true}}, "incident_response": {"communication": {"card_brands": {"notification_procedures": true}, "acquirer": {"notification_procedures": true}, "legal": {"counsel_included": true}, "pr": {"procedures_defined": true}}, "plan": {"documented": true, "approved": true, "tested": {"annual": true}}, "roles": {"designated": true}, "training": {"conducted": true}, "monitoring": {"for_alerts": true}, "alerts": {"addressed_timely": true}, "scenarios": {"chd_compromise": true, "system_compromise": true, "phishing_attack": true, "insider_threat": true, "ransomware": true}}, "security_policy": {"documented": true, "approved_by_management": true, "published": true, "communicated_to_all_users": true, "reviewed_annually": true, "updated_when_environment_changes": true}, "pan_locations": {"all_identified": true, "storage": {"verified_limited": true}, "review": {"annual": true}}, "compliance_management": {"executive_responsibility": {"established": true}, "charter": {"defined": true}, "quarterly_review": {"performed": true}, "review": {"operational_security_controls": true, "failures_reviewed": true}}, "responsibilities": {"all_activities": {"assigned": true}, "documented": true, "communicated": true}, "scope": {"cde": {"documented": true}, "all_system_components": {"identified": true}, "connected_systems": {"identified": true}, "network_diagrams": {"current": true}, "data_flow_diagrams": {"current": true}, "validation": {"annual": true, "after_significant_changes": true}}, "personnel_screening": {"background_checks": {"conducted": true}, "before_access": {"to_cde": true}, "local_laws": {"complied_with": true}}, "risk_management": {"annual_risk_assessment": {"performed": true}, "methodology": {"documented": true}, "risk_register": {"maintained": true}, "treatment_plans": {"documented": true}, "management_review": {"conducted": true}, "threats_vulnerabilities": {"considered": true}, "residual_risk": {"accepted_by_management": true}}, "security_awareness": {"program": {"implemented": true}, "new_hires": {"training_upon_hire": true}, "frequency": {"at_least_annually": true}, "topics": {"security_policies": true, "phishing": true, "cardholder_data_handling": true}, "completion": {"tracked": true}, "acknowledgment": {"required": true}}, "security_roles": {"ciso_or_equivalent": {"assigned": true}, "responsibilities": {"documented": true}, "accountability": {"established": true}, "executive_management": {"accountability": true}}, "targeted_risk_analysis": {"performed": true, "frequency": {"defined": true}, "documents": {"what_is_being_protected": true, "threat_actors": true, "likelihood_and_impact": true}}, "targeted_training": {"high_risk_roles": {"identified": true}, "additional_training": {"provided": true}, "completion": {"tracked": true}}, "technology_review": {"hardware": {"annual": true}, "software": {"annual": true}, "end_of_life": {"identified": true, "plan": {"documented": true}}}, "third_party": {"acknowledgment": {"pci_compliance_responsibility": true, "documented": true}, "inventory": {"maintained": true, "pci_impact": {"documented": true}}, "due_diligence": {"conducted": true}, "agreements": {"include_pci_compliance": true, "security_requirements": true}, "monitoring": {"program": true}, "compliance_status": {"tracked": true}}, "tpsp": {"list": {"maintained": true}, "compliance": {"pci_dss_compliant": true}, "responsibilities": {"documented": true}, "aoc": {"obtained": true}}, "cde": {"direct_internet_access": {"prohibited": true}, "dmz": {"implemented": true}, "proxy_services": {"configured": true}, "internet_isolation": {"enforced": true}, "inbound_traffic": {"restricted": true, "necessary_only": true, "documented": true, "authorized": true}, "outbound_traffic": {"restricted": true, "necessary_only": true, "documented": true, "authorized": true}, "boundaries": {"documented": true}, "systems": {"inventoried": true}, "data_flows": {"mapped": true}, "network_diagram": {"current": true}}, "dmz": {"implemented": true, "separates_untrusted_from_cde": true, "controls_traffic_flow": true, "monitored": true}, "firewalls": {"configuration_standards": {"documented": true, "approved": true, "implemented": true}, "default_deny": {"configured": true}, "rules": {"documented": true, "business_justification": true, "reviewed_regularly": true, "approved_before_implementation": true}}, "multi_tenant": {"applicable": true, "each_entity_isolated": true, "cannot_access_others": true, "documented": true}, "network": {"nat": {"implemented": true, "hides_internal_addresses": true, "documented": true, "configured_securely": true}, "trusted_untrusted": {"identified": true, "controlled": true}, "connections": {"documented": true, "justified": true}}, "network_logging": {"firewall_logs": {"comprehensive": true}, "access_attempts": {"logged": true}, "denied_connections": {"logged": true}, "centralized": {"implemented": true}}, "network_security": {"maintenance": {"scheduled": true, "documented": true}, "change_management": {"implemented": true}, "review_process": {"established": true}, "event_correlation": {"enabled": true}, "siem_integration": {"configured": true}, "threat_detection": {"automated": true}, "incident_response": {"integrated": true}, "policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true, "documented": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "network_segmentation": {"implemented": true, "cde_isolated": true, "documented": true, "validated": true}, "network_monitoring": {"traffic_analysis": {"enabled": true}, "intrusion_detection": {"deployed": true}, "anomaly_detection": {"configured": true}, "real_time_alerts": {"enabled": true}}, "system_hardening": {"configuration_standards": {"documented": true, "applied_to_all_systems": true, "reviewed_after_vendor_updates": true}, "policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "hardening": {"database": {"default_accounts_disabled": true, "unnecessary_procedures_removed": true, "access_restricted": true, "audit_logging_enabled": true}, "default_credentials": {"changed": true, "verified_on_new_systems": true, "vendor_supplied_removed": true}, "standards": {"industry_accepted": true, "cis_benchmarks_referenced": true, "applied_to_all_component_types": true, "regularly_reviewed": true}, "security_patches": {"current": true, "applied_within_one_month": true}, "vulnerability_management": {"implemented": true}, "network_devices": {"default_passwords_changed": true, "unnecessary_services_disabled": true, "management_access_restricted": true, "snmp_v3_configured": true, "firmware_current": true}, "os": {"unnecessary_services_disabled": true, "host_based_firewall_enabled": true, "unnecessary_users_removed": true, "file_permissions_restricted": true, "logging_enabled": true}, "server_roles": {"single_primary_function": true, "documented": true, "justified": true}, "unnecessary_services": {"removed": true}, "unnecessary_protocols": {"disabled": true}, "unnecessary_ports": {"closed": true}, "unnecessary_functions": {"disabled": true}, "unnecessary_scripts": {"removed": true}}, "admin_access": {"non_console": {"encrypted": true, "strong_cryptography": true, "telnet_disabled": true, "ftp_disabled": true, "ssh_v2_only": true, "tls_enforced": true}}, "data_inventory": {"cardholder_data": {"documented": true}, "sensitive_auth_data": {"documented": true}, "locations": {"identified": true}, "data_flows": {"mapped": true}}, "data_protection": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true, "documented": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "data_purging": {"automated": {"implemented": true}, "schedule": {"defined": true}, "verification": {"conducted": true}, "secure_deletion": {"implemented": true}}, "cryptography": {"architecture": {"documented": true}, "algorithms": {"approved": true}, "protocols": {"secure": true}, "implementation": {"validated": true}, "tls": {"minimum_version": "1.2", "tls_1_0": {"disabled": true}, "tls_1_1": {"disabled": true}, "weak_cipher_suites": {"disabled": true}, "strong_cipher_suites": {"configured": true}}}, "crypto_admin": {"procedures": {"documented": true}, "access_controls": {"implemented": true}, "change_management": {"enforced": true}, "monitoring": {"comprehensive": true}}, "sad_storage": {"cvc": {"prohibited": true}, "cvc2": {"prohibited": true}, "cvv2": {"prohibited": true}, "cid": {"prohibited": true}, "magnetic_stripe": {"prohibited": true}, "track_data": {"prohibited": true}, "track_equivalent": {"prohibited": true}, "pin": {"prohibited": true}, "pin_blocks": {"prohibited": true}, "pin_verification": {"prohibited": true}}, "data_retention": {"policy": {"documented": true, "business_justified": true, "legal_requirements_met": true, "regularly_reviewed": true}}, "database_encryption": {"tablespace": {"encrypted": true}, "column_level": {"implemented": true}, "transparent_data_encryption": {"enabled": true}, "application_level": {"implemented": true}}, "filesystem_encryption": {"full_disk": {"enabled": true}, "file_level": {"implemented": true}, "removable_media": {"required": true}, "backup_media": {"encrypted": true}}, "key_distribution": {"secure_channels": {"used": true}, "split_knowledge": {"implemented": true}, "dual_control": {"enforced": true}, "authorization": {"required": true}}, "key_generation": {"strong_methods": {"used": true}, "random_sources": {"cryptographically_strong": true}, "key_strength": {"adequate": true}, "algorithm_compliance": {"verified": true}}, "key_lifecycle": {"generation": {"secure": true}, "distribution": {"controlled": true}, "rotation": {"scheduled": true}, "destruction": {"secure": true}}, "key_management": {"policies": {"documented": true, "approved": true}, "procedures": {"defined": true}, "lifecycle": {"managed": true}, "pan_transmission": {"inventory_maintained": true, "trusted_issuers_only": true, "key_rotation": {"documented": true}, "compromise_procedures": {"defined": true}}}, "key_storage": {"hsm": {"used": true}, "encrypted": {"always": true}, "access_controls": {"strict": true}, "separation": {"from_data": true}}, "pan_display": {"restriction": {"implemented": true}, "business_need": {"documented": true}, "authorization": {"required": true}, "logging": {"comprehensive": true}}, "pan_encryption": {"strong_cryptography": {"used": true}, "aes_minimum": {"compliant": true}, "algorithm_approved": {"implemented": true}, "key_strength": {"adequate": true}}, "pan_masking": {"default": {"enabled": true}, "first_six_last_four": {"maximum": true}, "applications": {"compliant": true}, "reports": {"implemented": true}}, "data_discovery": {"quarterly": {"conducted": true}, "automated_tools": {"used": true}, "results": {"documented": true}, "remediation": {"tracked": true}}, "sad_deletion": {"post_authorization": {"automated": true}, "verification": {"implemented": true}, "logs": {"maintained": true}, "exceptions": {"documented": true}}, "screen_protection": {"automatic_timeout": {"enabled": true}, "shoulder_surfing": {"prevented": true}, "viewing_restrictions": {"implemented": true}}, "api": {"tls_required": true, "minimum_tls_version": "1.2", "certificate_pinning": {"implemented": true}, "payload": {"pan_not_in_url": true, "pan_not_in_logs": true}}, "certificates": {"trusted_ca": {"used": true}, "validity": {"monitored": true}, "expiry": {"alerts_configured": true}, "revocation": {"checked": true}, "wildcard": {"usage_justified": true}}, "messaging": {"pan_transmission": {"prohibited": true, "dlp_controls": {"implemented": true}, "policy": {"documented": true}}}, "pos": {"in_scope": true, "terminals": {"point_to_point_encryption": true, "p2pe_solution": {"validated": true}, "terminal_management": {"secure": true}}}, "transmission": {"pan": {"strong_cryptography": true, "trusted_keys_certificates": true, "open_public_networks_encrypted": true}}, "transmission_security": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "weak_protocols": {"inventory": {"maintained": true}, "ssl": {"disabled": true}, "tls_1_0": {"disabled": true}, "tls_1_1": {"disabled": true}, "early_tls": {"migration_plan": {"completed": true}}}, "antimalware": {"scheduled_scans": {"configured": true}, "realtime_scanning": {"enabled": true}, "automatic_updates": {"enabled": true}, "deployed": true, "coverage": {"all_cde_systems": true, "servers": true, "workstations": true, "mobile_devices": true}, "logging": {"enabled": true, "retention_days": 365}, "signatures": {"current": true}, "definitions": {"automatic_updates": true}, "engine": {"up_to_date": true}, "tamper_protection": {"enabled": true, "admin_only": true}, "user_disabling": {"prevented": true}, "configuration": {"centrally_managed": true}}, "antiphishing": {"email_filtering": {"enabled": true}, "user_training": {"conducted": true}}, "malware_protection": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}, "risk_evaluation": {"documented": true, "methodology": {"defined": true}, "frequency_days": 1, "tra_defined_frequency_days": 1}}, "secure_coding": {"authentication": {"techniques_defined_and_in_use": true}, "injection": {"techniques_defined_and_in_use": true}, "cryptography": {"techniques_defined_and_in_use": true}, "memory": {"techniques_defined_and_in_use": true}, "xss": {"techniques_defined_and_in_use": true}}, "public_web_apps": {"in_scope": true}, "waf": {"implemented": true, "mode": {"blocking": true}}, "automated_detection": {"logging": {"configured": true}}, "code_review": {"performed": true, "by_security_aware_personnel": true, "all_code_changes_reviewed": true, "vulnerabilities_corrected_before_release": true}, "developer_training": {"secure_coding": {"conducted": true}, "records": {"maintained": true}, "frequency_months": 1}, "testing": {"preproduction": {"performed": true}, "production_data_not_used": true, "test_accounts": {"removed_before_production": true}, "custom_application_accounts": {"reviewed": true}}, "secure_development": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "sdlc": {"documented": true, "security_requirements": {"defined": true}, "security_integrated_at_all_phases": true, "security_training": {"required_for_developers": true}}, "patch_management": {"process": {"documented": true}, "critical_patches": {"applied_within_30_days": true}, "high_patches": {"applied_within_30_days": true}, "testing": {"required_before_deployment": true}, "rollback": {"procedures_defined": true}}, "software_inventory": {"bespoke": {"documented": true}, "third_party": {"documented": true}}, "vulnerability_management": {"industry_sources": {"monitored": true}, "risk_ranking": {"assigned": true}}, "access_control": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "acs": {"implemented": true, "all_cde_system_components": {"covered": true}, "default_deny": {"configured": true}, "settings": {"restriction_unless_specifically_allowed": true}}, "system_accounts": {"inventory": {"maintained": true}, "access": {"limited_to_functions_needed": true}, "interactive_login": {"disabled_unless_needed": true}, "review": {"annually": true, "performed_periodically": true}, "interactive_use": {"prohibited_unless_exceptional": true}, "authentication": {"managed": true}, "credentials": {"in_vault": true, "rotation": {"automated": true}}}, "access_assignment": {"job_functions": {"documented": true}, "access_required": {"justified": true}, "approval_required": true, "manager_approval": true}, "access_model": {"least_privilege": {"implemented": true}, "need_to_know": {"enforced": true}, "default_deny": {"configured": true}, "access_rules": {"documented": true}}, "privileged_access": {"inventory": {"maintained": true}, "assignment": {"approved": true}, "separation_from_normal": {"enforced": true}, "just_in_time": {"available": true}, "monitoring": {"enabled": true}}, "rbac": {"enabled": true, "roles": {"defined": true, "cde_access": {"restricted": true}}, "privilege_assignment": {"approved": true}, "conflicting_duties": {"prevented": true}}, "third_party_access": {"inventory": {"maintained": true}, "need_to_know": {"enforced": true}, "time_limited": true, "mfa": {"required": true}, "monitoring": {"enabled": true}}, "access_review": {"performed": true, "all_accounts": {"included": true}, "results": {"documented": true}, "inappropriate_access": {"removed": true}, "frequency_months": 1}, "account_lifecycle": {"provisioning": {"approval_required": true}, "modification": {"approval_required": true}, "termination": {"immediate_revocation": true}, "inactive_accounts": {"disabled_after_90_days": true}}, "auth_factors": {"stored": {"encrypted": true}, "transmission": {"encrypted": true}, "service_providers": {"different_from_customers": true}}, "authentication": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "passwords": {"first_use": {"change_required": true}, "reset": {"immediate_change_required": true}, "temporary": {"single_use": true}, "numeric_and_alpha": {"required": true}, "customer_accounts": {"single_factor_only": true, "max_age_days": 1}, "single_factor_only": true, "minimum_length": 12, "history": {"count": 4}, "lockout": {"after_attempts": 1, "duration_minutes": 30}, "max_age_days": 1}, "sessions": {"reauthentication_required": true, "idle_timeout_minutes": 1}, "mfa": {"all_cde_access": {"required": true}, "user_cde_access": {"enforced": true}, "cde_admin_access": {"required": true}, "non_console_admin": {"required": true}, "factors": {"at_least_two": true, "different_categories": true, "cannot_be_same_type": true}, "remote_access": {"required": true}, "vpn": {"mfa_enforced": true}, "remote_desktop": {"mfa_enforced": true}, "replay_attacks": {"prevented": true}, "all_factors_required": true, "bypass": {"not_possible_by_any_single_admin": true}}, "entity": {"service_provider": true}, "user_ids": {"unique_per_user": true, "shared_accounts": {"prohibited": true}, "generic_accounts": {"prohibited_in_cde": true}, "group_accounts": {"prohibited": true}}, "vendor_accounts": {"disabled_when_not_in_use": true, "monitored_when_active": true, "time_limited": true}, "badge_system": {"implemented": true, "unique_per_individual": true, "lost_badges": {"revoked_immediately": true}, "terminated_employees": {"revoked_immediately": true}}, "disk": {"destruction": {"dod_or_nist_wipe": true, "cryptographic_erasure_acceptable": true, "physical_destruction": {"when_cryptographic_not_possible": true}, "documented": true}}, "media": {"destruction": {"secure_process": true, "certificates_obtained": true, "cross_cut_shredding_or_equivalent": true, "log": {"maintained": true}, "third_party": {"verified": true}}, "distribution": {"tracking_implemented": true, "secured_courier": true, "management_approval_required": true, "encrypted": true}, "inventory": {"maintained": true}, "storage": {"physically_secured": true}, "access": {"restricted_to_authorized": true}, "external_distribution": {"management_approval": true, "logged": true}}, "physical_access": {"authorization": {"documented": true, "approval_required": true, "regularly_reviewed": true, "access_list": {"current": true}}, "sensitive_areas": {"access_controls_implemented": true, "entry_logs": {"maintained": true}, "cameras": {"installed": true, "footage_retained_days": 90}}}, "physical_security": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "poi_devices": {"in_scope": true, "inventory": {"maintained": true}, "inspection": {"periodic": true, "frequency_days": 1, "tra_defined_frequency_days": 1}, "tampering": {"training_for_personnel": true}, "serial_numbers": {"verified": true}, "substitution": {"procedures_for_detecting": true}}, "network_access": {"public_area_jacks": {"disabled": true}, "public_area_wireless": {"restricted": true}}, "visitors": {"identification": {"required": true}, "badge": {"temporary_issued": true, "visually_distinguishable": true, "surrendered_on_departure": true}, "escort": {"required_in_sensitive_areas": true}, "log": {"maintained": true, "retention_months": 3}}, "program": {"policies": {"established": true}, "roles": {"defined": true}, "training": {"conducted": true}, "documentation": {"maintained": true}, "risk_assessment": {"performed_annually": true}}}, "cloud": {"security_groups": {"cde_specific": true, "least_privilege": true, "regularly_reviewed": true, "documented": true}, "waf": {"enabled": true, "rules": {"pci_specific": true}, "logging": {"comprehensive": true}, "monitoring": {"real_time": true}}, "vpc": {"cde_dedicated": true, "private_subnets": {"cde_isolated": true}, "nat_gateways": {"configured": true}, "flow_logs": {"enabled": true}}, "databases": {"encryption_at_rest": {"enabled": true}, "transparent_data_encryption": {"configured": true}, "backup_encryption": {"enabled": true}, "key_management": {"integrated": true}}, "encryption": {"kms": {"integrated": true}, "customer_managed_keys": {"used": true}, "hsm": {"available": true}, "key_rotation": {"automated": true}}, "storage": {"server_side_encryption": {"enabled": true}, "client_side_encryption": {"implemented": true}, "bucket_encryption": {"default": true}, "access_logging": {"comprehensive": true}}}, "openshift": {"containers": {"network_isolation": {"enabled": true}, "pod_security": {"network_restricted": true}, "namespace_isolation": {"cde_separated": true}, "data_encryption": {"persistent_volumes": true, "ephemeral_storage": true, "container_images": true, "application_layer": true}}, "network_policies": {"cde_isolation": {"enabled": true}, "default_deny": {"configured": true}, "ingress_rules": {"restrictive": true}, "egress_rules": {"restrictive": true}}, "sdn": {"network_policy": {"enabled": true}, "multitenant": {"configured": true}, "subnet_isolation": {"enabled": true}, "ingress_controllers": {"secured": true}}, "service_mesh": {"enabled": true, "mutual_tls": {"enforced": true}, "traffic_policies": {"pci_compliant": true}, "access_control": {"implemented": true}}, "registry": {"image_encryption": {"enabled": true}, "vulnerability_scanning": {"comprehensive": true}, "image_signing": {"required": true}, "access_controls": {"strict": true}}, "secrets": {"external_vault": {"integrated": true}, "encryption_at_rest": {"enabled": true}, "rotation": {"automated": true}, "access_control": {"rbac": true}}, "storage": {"csi_encryption": {"enabled": true}, "storage_classes": {"encrypted": true}, "volume_encryption": {"automatic": true}, "backup_encryption": {"enabled": true}}}}

test_all_pass_fixture_is_compliant if {
	r := data.pci_dss.main.compliance_report with input as _all_pass
	r.compliant == true
	r.violation_count == 0
	r.requirement_result_counts == {"pass": 12, "fail": 0, "evidence_missing": 0}
}

test_empty_input_is_evidence_missing_everywhere if {
	r := data.pci_dss.main.compliance_report with input as {}
	r.compliant == false
	r.requirement_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 12}
	every v in r.violations {
		v.status == "evidence_missing"
		contains(v.title, "evidence missing")
	}
}

# Requirement 10 (audit_log_data_elements)
test_req_10_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"audit_logs": {"data": {"user_identification": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_10_logging_monitoring"
	r.status == "fail"
	r.failing_checks == ["audit_log_data_elements"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_10_logging_monitoring", "status": "fail", "title": "PCI DSS v4.0.1 req_10_logging_monitoring is not compliant (failing checks: audit_log_data_elements)"}]
}

test_req_10_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"audit_logs": {"data": {"user_identification": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_10_logging_monitoring"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["audit_log_data_elements"]
	r.evidence_missing == ["input.pci.audit_logs.data.user_identification"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_10_logging_monitoring: evidence missing")
	contains(vs[0].title, "input.pci.audit_logs.data.user_identification")
}

test_req_10_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"audit_logs": {"data": {"user_identification": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_10_logging_monitoring"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.audit_logs.data.user_identification"]
}

# Requirement 11 (ids_ips_deployed)
test_req_11_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"ids_ips": {"deployed": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_11_security_testing"
	r.status == "fail"
	r.failing_checks == ["ids_ips_deployed"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_11_security_testing", "status": "fail", "title": "PCI DSS v4.0.1 req_11_security_testing is not compliant (failing checks: ids_ips_deployed)"}]
}

test_req_11_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"ids_ips": {"deployed": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_11_security_testing"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["ids_ips_deployed"]
	r.evidence_missing == ["input.pci.ids_ips.deployed"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_11_security_testing: evidence missing")
	contains(vs[0].title, "input.pci.ids_ips.deployed")
}

test_req_11_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"ids_ips": {"deployed": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_11_security_testing"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.ids_ips.deployed"]
}

# Requirement 12 (acceptable_use_policy)
test_req_12_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"aup": {"documented": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_12_governance"
	r.status == "fail"
	r.failing_checks == ["acceptable_use_policy"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_12_governance", "status": "fail", "title": "PCI DSS v4.0.1 req_12_governance is not compliant (failing checks: acceptable_use_policy)"}]
}

test_req_12_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"aup": {"documented": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_12_governance"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["acceptable_use_policy"]
	r.evidence_missing == ["input.pci.aup.documented"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_12_governance: evidence missing")
	contains(vs[0].title, "input.pci.aup.documented")
}

test_req_12_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"aup": {"documented": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_12_governance"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.aup.documented"]
}

# Requirement 1 (cloud_security_groups_configured)
test_req_1_fact_false_is_fail if {
	fx := object.union(_all_pass, {"cloud": {"security_groups": {"cde_specific": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_1_network_security"
	r.status == "fail"
	r.failing_checks == ["cloud_security_groups_configured"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_1_network_security", "status": "fail", "title": "PCI DSS v4.0.1 req_1_network_security is not compliant (failing checks: cloud_security_groups_configured)"}]
}

test_req_1_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"cloud": {"security_groups": {"cde_specific": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_1_network_security"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["cloud_security_groups_configured"]
	r.evidence_missing == ["input.cloud.security_groups.cde_specific"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_1_network_security: evidence missing")
	contains(vs[0].title, "input.cloud.security_groups.cde_specific")
}

test_req_1_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"cloud": {"security_groups": {"cde_specific": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_1_network_security"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.cloud.security_groups.cde_specific"]
}

# Requirement 2 (configuration_standards_maintained)
test_req_2_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"system_hardening": {"configuration_standards": {"documented": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_2_system_hardening"
	r.status == "fail"
	r.failing_checks == ["configuration_standards_maintained"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_2_system_hardening", "status": "fail", "title": "PCI DSS v4.0.1 req_2_system_hardening is not compliant (failing checks: configuration_standards_maintained)"}]
}

test_req_2_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"system_hardening": {"configuration_standards": {"documented": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_2_system_hardening"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["configuration_standards_maintained"]
	r.evidence_missing == ["input.pci.system_hardening.configuration_standards.documented"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_2_system_hardening: evidence missing")
	contains(vs[0].title, "input.pci.system_hardening.configuration_standards.documented")
}

test_req_2_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"system_hardening": {"configuration_standards": {"documented": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_2_system_hardening"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.system_hardening.configuration_standards.documented"]
}

# Requirement 3 (account_data_inventory_maintained)
test_req_3_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"data_inventory": {"cardholder_data": {"documented": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_3_stored_data"
	r.status == "fail"
	r.failing_checks == ["account_data_inventory_maintained"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_3_stored_data", "status": "fail", "title": "PCI DSS v4.0.1 req_3_stored_data is not compliant (failing checks: account_data_inventory_maintained)"}]
}

test_req_3_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"data_inventory": {"cardholder_data": {"documented": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_3_stored_data"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["account_data_inventory_maintained"]
	r.evidence_missing == ["input.pci.data_inventory.cardholder_data.documented"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_3_stored_data: evidence missing")
	contains(vs[0].title, "input.pci.data_inventory.cardholder_data.documented")
}

test_req_3_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"data_inventory": {"cardholder_data": {"documented": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_3_stored_data"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.data_inventory.cardholder_data.documented"]
}

# Requirement 4 (certificate_management_secure)
test_req_4_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"certificates": {"trusted_ca": {"used": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_4_transmission_security"
	r.status == "fail"
	r.failing_checks == ["certificate_management_secure"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_4_transmission_security", "status": "fail", "title": "PCI DSS v4.0.1 req_4_transmission_security is not compliant (failing checks: certificate_management_secure)"}]
}

test_req_4_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"certificates": {"trusted_ca": {"used": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_4_transmission_security"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["certificate_management_secure"]
	r.evidence_missing == ["input.pci.certificates.trusted_ca.used"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_4_transmission_security: evidence missing")
	contains(vs[0].title, "input.pci.certificates.trusted_ca.used")
}

test_req_4_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"certificates": {"trusted_ca": {"used": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_4_transmission_security"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.certificates.trusted_ca.used"]
}

# Requirement 5 (antimalware_deployed)
test_req_5_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"antimalware": {"deployed": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_5_malware_protection"
	r.status == "fail"
	r.failing_checks == ["antimalware_deployed"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_5_malware_protection", "status": "fail", "title": "PCI DSS v4.0.1 req_5_malware_protection is not compliant (failing checks: antimalware_deployed)"}]
}

test_req_5_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"antimalware": {"deployed": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_5_malware_protection"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["antimalware_deployed"]
	r.evidence_missing == ["input.pci.antimalware.deployed"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_5_malware_protection: evidence missing")
	contains(vs[0].title, "input.pci.antimalware.deployed")
}

test_req_5_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"antimalware": {"deployed": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_5_malware_protection"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.antimalware.deployed"]
}

# Requirement 6 (bespoke_code_review)
test_req_6_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"code_review": {"performed": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_6_secure_development"
	r.status == "fail"
	r.failing_checks == ["bespoke_code_review"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_6_secure_development", "status": "fail", "title": "PCI DSS v4.0.1 req_6_secure_development is not compliant (failing checks: bespoke_code_review)"}]
}

test_req_6_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"code_review": {"performed": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["bespoke_code_review"]
	r.evidence_missing == ["input.pci.code_review.performed"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_6_secure_development: evidence missing")
	contains(vs[0].title, "input.pci.code_review.performed")
}

test_req_6_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"code_review": {"performed": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.code_review.performed"]
}

# Requirement 7 (access_control_policies_established)
test_req_7_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"access_control": {"policies": {"documented": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_7_access_restriction"
	r.status == "fail"
	r.failing_checks == ["access_control_policies_established"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_7_access_restriction", "status": "fail", "title": "PCI DSS v4.0.1 req_7_access_restriction is not compliant (failing checks: access_control_policies_established)"}]
}

test_req_7_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"access_control": {"policies": {"documented": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_7_access_restriction"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["access_control_policies_established"]
	r.evidence_missing == ["input.pci.access_control.policies.documented"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_7_access_restriction: evidence missing")
	contains(vs[0].title, "input.pci.access_control.policies.documented")
}

test_req_7_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"access_control": {"policies": {"documented": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_7_access_restriction"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.access_control.policies.documented"]
}

# Requirement 8 (account_lifecycle_managed)
test_req_8_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"account_lifecycle": {"provisioning": {"approval_required": false}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_8_authentication"
	r.status == "fail"
	r.failing_checks == ["account_lifecycle_managed"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_8_authentication", "status": "fail", "title": "PCI DSS v4.0.1 req_8_authentication is not compliant (failing checks: account_lifecycle_managed)"}]
}

test_req_8_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"account_lifecycle": {"provisioning": {"approval_required": null}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_8_authentication"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["account_lifecycle_managed"]
	r.evidence_missing == ["input.pci.account_lifecycle.provisioning.approval_required"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_8_authentication: evidence missing")
	contains(vs[0].title, "input.pci.account_lifecycle.provisioning.approval_required")
}

test_req_8_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"account_lifecycle": {"provisioning": {"approval_required": "true"}}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_8_authentication"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.account_lifecycle.provisioning.approval_required"]
}

# Requirement 9 (badge_system)
test_req_9_fact_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"badge_system": {"implemented": false}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_9_physical_access"
	r.status == "fail"
	r.failing_checks == ["badge_system"]
	r.evidence_missing == []
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "req_9_physical_access", "status": "fail", "title": "PCI DSS v4.0.1 req_9_physical_access is not compliant (failing checks: badge_system)"}]
}

test_req_9_fact_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"badge_system": {"implemented": null}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_9_physical_access"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["badge_system"]
	r.evidence_missing == ["input.pci.badge_system.implemented"]
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "evidence_missing"
	startswith(vs[0].title, "PCI DSS v4.0.1 req_9_physical_access: evidence missing")
	contains(vs[0].title, "input.pci.badge_system.implemented")
}

test_req_9_fact_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"badge_system": {"implemented": "true"}}})
	rs := data.pci_dss.main.requirement_results with input as fx
	some r in rs
	r.id == "req_9_physical_access"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.badge_system.implemented"]
}

# 6.4.2: public-facing web applications need the WAF (implemented, blocking or alerting, logging).
test_req_6_4_2_waf_absent_is_evidence_missing if {
	fx := json.remove(_all_pass, ["pci/waf"])
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	r.evidence_missing_checks == ["automated_attack_detection"]
	"input.pci.waf.implemented" in r.evidence_missing
	data.pci_dss.main.requirement_6_compliant == false with input as fx
}

test_req_6_4_2_waf_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"waf": {"implemented": false}}})
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "fail"
	r.failing_checks == ["automated_attack_detection"]
}

test_req_6_4_2_waf_or_vapt_does_not_replace_the_waf if {
	fx := object.union(json.remove(_all_pass, ["pci/waf"]), {"pci": {"automated_detection": {"waf_or_vapt": {"implemented": true}, "active_blocking": {"enabled": true}}}})
	data.pci_dss.main.requirement_6_compliant == false with input as fx
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.waf.implemented"]
}

test_req_6_4_2_alerting_with_immediate_investigation_passes if {
	fx := object.union(_all_pass, {"pci": {"waf": {"mode": {"blocking": false}}, "automated_detection": {"alerts": {"immediately_investigated": true}}}})
	data.pci_dss.main.requirement_6_compliant == true with input as fx
}

test_req_6_4_2_scope_flag_string_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"public_web_apps": {"in_scope": "true"}}})
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	"input.pci.public_web_apps.in_scope" in r.evidence_missing
}

test_req_6_4_2_out_of_scope_passes_without_waf if {
	fx := object.union(json.remove(_all_pass, ["pci/waf"]), {"pci": {"public_web_apps": {"in_scope": false}}})
	data.pci_dss.main.requirement_6_compliant == true with input as fx
}

test_cde_scope_null_is_evidence_missing if {
	fx := object.union(_all_pass, {"pci": {"cde": {"boundaries": {"documented": null}}}})
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "cde_scope", "status": "evidence_missing", "title": "PCI DSS v4.0.1 CDE scope is not defined and documented (cde_scope): evidence missing — not collected or not of the expected type: input.pci.cde.boundaries.documented"}]
}

test_program_management_false_is_fail if {
	fx := object.union(_all_pass, {"pci": {"program": {"training": {"conducted": false}}}})
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	vs == [{"control": "program_management", "status": "fail", "title": "PCI DSS v4.0.1 program management is not established (program_management)"}]
}

# A failing check with a present non-compliant fact makes the requirement fail; another check in the same
# requirement that lacks evidence is still named.
test_mixed_fail_and_missing_is_fail_and_names_the_missing_fact if {
	fx := object.union(_all_pass, {"pci": {"waf": {"implemented": false}, "code_review": {"performed": null}}})
	vs := data.pci_dss.main.compliance_report.violations with input as fx
	count(vs) == 1
	vs[0].status == "fail"
	vs[0].title == "PCI DSS v4.0.1 req_6_secure_development is not compliant (failing checks: automated_attack_detection); evidence missing for bespoke_code_review: input.pci.code_review.performed"
}

# A route the entity does not use failing (no active blocking) does not turn a missing WAF fact into a fail:
# the alerting route is still open and lacks only input.pci.waf.implemented.
test_req_6_4_2_waf_absent_with_alerting_route_is_evidence_missing if {
	fx := object.union(json.remove(_all_pass, ["pci/waf"]), {"pci": {"automated_detection": {"active_blocking": {"enabled": false}, "alerts": {"immediately_investigated": true}}}})
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "evidence_missing"
	r.evidence_missing == ["input.pci.waf.implemented"]
}

# Every route closed (blocking off, no alerting, WAF present) is a fail, though the alerting fact is absent.
test_req_6_4_2_all_routes_closed_is_fail if {
	fx := object.union(_all_pass, {"pci": {"waf": {"mode": {"blocking": false}}, "automated_detection": {"active_blocking": {"enabled": false}, "alerts": {"immediately_investigated": false}}}})
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "fail"
}

# 6.2.4: the detailed techniques all present with one false is a fail although the summary flag is absent.
test_req_6_2_4_detailed_route_false_is_fail if {
	fx := object.union(json.remove(_all_pass, ["pci/secure_coding/injection"]), {"pci": {"secure_coding": {
		"sql_injection": {"input_validation": true, "parameterized_queries": false},
		"command_injection": {"input_sanitization": true},
		"ldap_injection": {"prevented": true},
	}}})
	some r in data.pci_dss.main.requirement_results with input as fx
	r.id == "req_6_secure_development"
	r.status == "fail"
	r.failing_checks == ["injection_attacks_prevented"]
}
