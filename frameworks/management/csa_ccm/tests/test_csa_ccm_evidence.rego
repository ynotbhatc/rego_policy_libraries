package csa_ccm.evidence_test

import rego.v1

# Evidence rule (audit 2026-11-24): only the boolean true passes a CSA CCM check. Before the fix the
# string "false" on every fact cleared every finding in every domain and the report said compliant.
# The fixture holds the 549 facts the 16 domain modules read, all true.

all_pass := {
	"csa_ccm": {
		"application_security": {
			"appsec_policy": {
				"policy_established": true,
				"policy_reviewed_annually": true,
				"developer_acknowledgement": true,
				"cloud_app_scope_included": true,
			},
			"sdlc": {
				"lifecycle_implemented": true,
				"security_requirements_defined": true,
				"threat_modeling_performed": true,
				"security_training_for_developers": true,
				"security_gates_in_cicd": true,
			},
			"testing": {
				"sast_conducted": true,
				"dast_conducted": true,
				"pentest_conducted": true,
				"findings_remediated": true,
				"pre_release_testing_required": true,
			},
			"input_validation": {
				"input_validation_implemented": true,
				"output_encoding_implemented": true,
				"sql_injection_prevented": true,
				"xss_prevented": true,
			},
			"api_security": {
				"authentication_required": true,
				"authorization_enforced": true,
				"rate_limiting_implemented": true,
				"api_inventory_maintained": true,
				"transport_encryption_enforced": true,
			},
			"dependencies": {
				"inventory_maintained": true,
				"vulnerability_scanning": true,
				"sca_tool_in_use": true,
				"outdated_components_remediated": true,
			},
			"code_review": {
				"review_process_established": true,
				"peer_review_required": true,
				"security_focused_review": true,
				"automated_review_integrated": true,
			},
		},
		"audit_assurance": {
			"independent_audit": {
				"program_established": true,
				"auditor_independence_confirmed": true,
				"cloud_scope_included": true,
			},
			"audit_scope": {
				"scope_documented": true,
				"frequency_defined": true,
				"methodology_documented": true,
				"risk_based_approach": true,
			},
			"findings_tracking": {
				"remediation_tracked": true,
				"owners_assigned": true,
				"due_dates_set": true,
				"overdue_escalation_process": true,
			},
			"reporting": {
				"reports_communicated": true,
				"executive_distribution": true,
				"board_notification": true,
				"timely_issuance": true,
			},
			"internal_audit": {
				"function_exists": true,
				"charter_documented": true,
				"independence_maintained": true,
			},
			"evidence_retention": {
				"retention_policy_defined": true,
				"evidence_stored_securely": true,
				"retention_period_met": true,
				"disposal_process_defined": true,
			},
			"continuous_monitoring": {
				"monitoring_program_exists": true,
				"automated_controls_monitored": true,
				"alerts_configured": true,
				"results_reviewed_regularly": true,
			},
		},
		"business_continuity": {
			"bcm_policy": {
				"policy_established": true,
				"executive_approved": true,
				"cloud_services_included": true,
				"reviewed_annually": true,
			},
			"bia": {
				"bia_conducted": true,
				"critical_processes_identified": true,
				"cloud_dependency_mapped": true,
				"reviewed_after_significant_change": true,
			},
			"bcp": {
				"plans_documented": true,
				"plans_maintained": true,
				"roles_assigned": true,
				"contact_lists_current": true,
				"activation_criteria_defined": true,
			},
			"bcp_testing": {
				"plans_tested": true,
				"test_frequency_met": true,
				"test_results_documented": true,
				"deficiencies_remediated": true,
			},
			"drp": {
				"plans_documented": true,
				"recovery_procedures_defined": true,
				"alternate_site_defined": true,
				"data_recovery_procedures_included": true,
			},
			"drp_testing": {
				"drp_tested_annually": true,
				"failover_tested": true,
				"test_results_documented": true,
			},
			"dependencies": {
				"critical_dependencies_identified": true,
				"third_party_dependencies_mapped": true,
				"single_points_of_failure_addressed": true,
			},
			"rto_rpo": {
				"rto_defined": true,
				"rpo_defined": true,
				"rto_rpo_validated": true,
				"business_approved": true,
			},
			"backup": {
				"procedures_implemented": true,
				"backup_frequency_meets_rpo": true,
				"backups_tested": true,
				"offsite_or_cloud_storage": true,
				"encryption_applied": true,
			},
			"crisis_communication": {
				"plan_established": true,
				"stakeholder_notifications_defined": true,
				"media_response_defined": true,
				"regulatory_notification_included": true,
			},
			"lessons_learned": {
				"process_defined": true,
				"findings_incorporated_into_plans": true,
				"review_conducted_after_events": true,
			},
		},
		"change_control": {
			"change_policy": {
				"policy_established": true,
				"cloud_changes_in_scope": true,
				"policy_reviewed_annually": true,
				"roles_defined": true,
			},
			"change_approval": {
				"documentation_required": true,
				"review_required": true,
				"approval_required": true,
				"change_records_maintained": true,
				"impact_assessment_required": true,
			},
			"emergency_change": {
				"procedure_defined": true,
				"post_approval_required": true,
				"emergency_changes_tracked": true,
				"retrospective_review_conducted": true,
			},
			"config_baseline": {
				"baseline_established": true,
				"baseline_documented": true,
				"baseline_reviewed_regularly": true,
				"security_hardening_included": true,
			},
			"config_tracking": {
				"changes_tracked": true,
				"audit_trail_maintained": true,
				"version_control_used": true,
			},
			"unauthorized_change_detection": {
				"detection_controls_exist": true,
				"alerts_configured": true,
				"drift_detection_automated": true,
				"response_procedure_defined": true,
			},
			"rollback": {
				"rollback_procedure_defined": true,
				"success_criteria_defined": true,
				"rollback_tested": true,
			},
			"separation_of_duties": {
				"sod_enforced": true,
				"developer_prod_access_restricted": true,
				"approvals_auditable": true,
			},
			"post_implementation_review": {
				"review_conducted": true,
				"objectives_validated": true,
				"unintended_effects_assessed": true,
				"lessons_captured": true,
			},
		},
		"cryptography": {
			"crypto_policy": {
				"policy_established": true,
				"approved_algorithms_listed": true,
				"key_management_procedures_defined": true,
				"policy_reviewed_annually": true,
			},
			"encryption_at_rest": {
				"sensitive_data_encrypted": true,
				"database_encryption_enabled": true,
				"storage_encryption_enabled": true,
				"backup_encryption_enabled": true,
			},
			"encryption_in_transit": {
				"tls_enforced": true,
				"minimum_tls_version_met": true,
				"weak_ciphers_disabled": true,
				"certificate_validity_enforced": true,
			},
			"key_generation": {
				"approved_algorithms_used": true,
				"key_length_meets_standard": true,
				"random_number_generator_validated": true,
				"weak_keys_prohibited": true,
			},
			"key_storage": {
				"hsm_or_equivalent_used": true,
				"keys_never_stored_in_plaintext": true,
				"key_access_restricted": true,
				"key_access_logged": true,
			},
			"key_rotation": {
				"rotation_schedule_defined": true,
				"rotation_enforced": true,
				"emergency_rotation_procedure": true,
				"rotation_logged": true,
			},
			"key_destruction": {
				"destruction_procedure_defined": true,
				"destroyed_keys_irrecoverable": true,
				"revocation_timely": true,
			},
			"certificate_management": {
				"lifecycle_management_implemented": true,
				"expiry_monitoring_enabled": true,
				"certificate_inventory_maintained": true,
				"crl_or_ocsp_implemented": true,
			},
			"crypto_review": {
				"standards_review_process": true,
				"deprecated_crypto_identified": true,
				"migration_plan_when_deprecated": true,
			},
		},
		"data_security": {
			"classification": {
				"policy_established": true,
				"classification_scheme_defined": true,
				"cloud_data_in_scope": true,
				"policy_reviewed_annually": true,
			},
			"labeling": {
				"labeling_implemented": true,
				"sensitive_data_labeled": true,
				"labeling_enforced_at_creation": true,
			},
			"retention": {
				"retention_policy_defined": true,
				"retention_schedules_documented": true,
				"retention_enforced_technically": true,
				"legal_hold_process_defined": true,
			},
			"disposal": {
				"disposal_procedures_defined": true,
				"secure_deletion_used": true,
				"cloud_data_deletion_verified": true,
				"disposal_records_maintained": true,
			},
			"dlp": {
				"dlp_controls_implemented": true,
				"egress_monitoring_enabled": true,
				"dlp_policies_cover_cloud": true,
				"dlp_alerts_reviewed": true,
			},
			"privacy": {
				"privacy_notice_provided": true,
				"consent_mechanism_implemented": true,
				"data_subject_rights_honored": true,
				"privacy_impact_assessments_conducted": true,
			},
			"data_flows": {
				"data_flows_mapped": true,
				"data_flow_diagrams_maintained": true,
				"unauthorized_flows_detected": true,
			},
			"cross_border": {
				"transfer_restrictions_assessed": true,
				"transfer_mechanisms_documented": true,
				"cloud_region_data_residency_enforced": true,
			},
			"data_inventory": {
				"inventory_maintained": true,
				"data_owners_assigned": true,
				"inventory_reviewed_regularly": true,
			},
			"access_to_data": {
				"access_based_on_classification": true,
				"least_privilege_enforced": true,
				"privileged_data_access_logged": true,
			},
		},
		"endpoint_management": {
			"uem_policy": {
				"policy_established": true,
				"byod_policy_defined": true,
				"policy_reviewed_annually": true,
				"all_device_types_in_scope": true,
			},
			"mdm_deployment": {
				"mdm_uem_solution_deployed": true,
				"all_managed_devices_enrolled": true,
				"compliance_policies_enforced": true,
				"device_inventory_maintained": true,
			},
			"device_encryption": {
				"encryption_enforced": true,
				"encryption_compliance_monitored": true,
				"mobile_device_encryption_enforced": true,
			},
			"remote_wipe": {
				"remote_wipe_capability_enabled": true,
				"remote_wipe_procedure_defined": true,
				"selective_wipe_for_byod": true,
			},
			"byod": {
				"byod_policy_enforced": true,
				"containerization_or_mam_implemented": true,
				"jailbroken_rooted_devices_blocked": true,
				"minimum_os_version_enforced": true,
			},
			"edr": {
				"edr_solution_deployed": true,
				"edr_coverage_complete": true,
				"edr_alerts_monitored": true,
				"automated_response_enabled": true,
			},
			"endpoint_patching": {
				"patch_management_implemented": true,
				"critical_patches_applied_timely": true,
				"patch_compliance_monitored": true,
				"patch_testing_before_deployment": true,
			},
			"removable_media": {
				"removable_media_policy_defined": true,
				"unauthorized_media_blocked": true,
				"media_scanning_enforced": true,
			},
			"screen_lock": {
				"screen_lock_enforced": true,
				"screen_lock_timeout_appropriate": true,
			},
			"application_control": {
				"application_allowlisting_implemented": true,
				"unauthorized_apps_blocked": true,
			},
			"configuration_baseline": {
				"endpoint_hardening_standards_applied": true,
				"baseline_drift_detected": true,
				"new_devices_hardened_before_deployment": true,
			},
			"network_access_control": {
				"nac_implemented": true,
				"non_compliant_devices_quarantined": true,
				"guest_network_segregated": true,
			},
		},
		"governance": {
			"security_framework": {
				"framework_established": true,
				"cloud_governance_included": true,
				"framework_aligned_to_standard": true,
				"framework_documented": true,
				"reviewed_annually": true,
			},
			"roles_responsibilities": {
				"ciso_or_equivalent_defined": true,
				"cloud_security_roles_documented": true,
				"accountability_assigned": true,
				"raci_or_equivalent_defined": true,
			},
			"risk_management": {
				"risk_program_exists": true,
				"risk_register_maintained": true,
				"risk_treatment_plans_defined": true,
				"risk_review_cadence": true,
				"risk_aligned_to_business_objectives": true,
			},
			"compliance_obligations": {
				"obligations_inventoried": true,
				"obligations_tracked": true,
				"gaps_identified_and_remediated": true,
				"regulatory_change_monitoring": true,
			},
			"executive_approval": {
				"policies_executive_approved": true,
				"cloud_strategy_approved": true,
				"security_budget_allocated": true,
				"board_oversight_exists": true,
			},
			"metrics": {
				"metrics_defined": true,
				"metrics_reported_to_leadership": true,
				"metrics_actionable": true,
				"metrics_reviewed_regularly": true,
			},
		},
		"human_resources": {
			"background_checks": {
				"policy_established": true,
				"checks_conducted_pre_hire": true,
				"checks_commensurate_with_access": true,
				"contractors_included": true,
			},
			"security_awareness": {
				"training_program_established": true,
				"training_conducted_at_hire": true,
				"annual_training_required": true,
				"cloud_security_topics_included": true,
				"completion_tracked": true,
			},
			"acceptable_use": {
				"policy_established": true,
				"employees_acknowledged": true,
				"policy_reviewed_annually": true,
				"violations_enforced": true,
			},
			"nda": {
				"nda_required": true,
				"nda_signed_before_access": true,
				"nda_covers_cloud_data": true,
				"nda_records_maintained": true,
			},
			"termination": {
				"termination_procedure_defined": true,
				"access_revoked_timely": true,
				"privileged_access_revoked_immediately": true,
				"asset_return_verified": true,
				"exit_process_documented": true,
			},
			"role_based_access_removal": {
				"access_tied_to_role": true,
				"access_updated_on_role_change": true,
				"periodic_access_reviews_conducted": true,
				"orphaned_accounts_removed": true,
			},
			"insider_threat": {
				"program_exists": true,
				"monitoring_implemented": true,
				"reporting_mechanism_exists": true,
				"high_risk_personnel_controls": true,
			},
			"security_roles": {
				"specialized_training_provided": true,
				"certifications_encouraged": true,
				"security_responsibilities_documented": true,
			},
			"third_party_personnel": {
				"security_requirements_communicated": true,
				"access_limited_to_required": true,
				"access_reviewed_regularly": true,
			},
		},
		"identity_access": {
			"iam_policy": {
				"policy_established": true,
				"cloud_identities_in_scope": true,
				"policy_reviewed_annually": true,
				"least_privilege_principle_adopted": true,
			},
			"identity_lifecycle": {
				"provisioning_process_defined": true,
				"deprovisioning_process_defined": true,
				"unique_identities_enforced": true,
				"identity_verified_before_provisioning": true,
			},
			"mfa": {
				"mfa_enforced": true,
				"mfa_on_privileged_accounts": true,
				"mfa_on_remote_access": true,
				"phishing_resistant_mfa_for_admins": true,
			},
			"privileged_access": {
				"pam_solution_deployed": true,
				"privileged_accounts_inventoried": true,
				"privileged_sessions_recorded": true,
				"standing_privilege_minimized": true,
				"break_glass_procedure_defined": true,
			},
			"sso": {
				"sso_implemented": true,
				"sso_uses_federated_identity": true,
				"sso_session_timeout_configured": true,
			},
			"service_accounts": {
				"service_accounts_inventoried": true,
				"service_account_credentials_rotated": true,
				"service_account_permissions_minimal": true,
				"managed_identities_preferred": true,
			},
			"access_reviews": {
				"reviews_conducted": true,
				"privileged_access_reviewed_frequently": true,
				"inappropriate_access_revoked": true,
				"review_results_documented": true,
			},
			"jit_access": {
				"jit_implemented_for_privileged": true,
				"access_requests_approved": true,
				"jit_access_time_limited": true,
			},
			"rbac": {
				"rbac_implemented": true,
				"roles_defined_per_job_function": true,
				"excessive_role_assignments_detected": true,
			},
			"zero_trust": {
				"network_implicit_trust_eliminated": true,
				"continuous_verification_implemented": true,
				"microsegmentation_applied": true,
			},
			"password_policy": {
				"password_policy_enforced": true,
				"minimum_length_enforced": true,
				"breached_password_detection": true,
			},
			"account_lockout": {
				"lockout_policy_configured": true,
				"lockout_threshold_appropriate": true,
			},
			"federated_identity": {
				"federation_implemented": true,
				"directory_sync_operational": true,
				"terminated_users_deprovisioned_automatically": true,
			},
			"privileged_identity": {
				"privileged_identity_governance_defined": true,
				"admin_accounts_separate_from_user_accounts": true,
				"global_admin_accounts_minimized": true,
			},
		},
		"incident_management": {
			"ir_policy": {
				"policy_established": true,
				"cloud_incidents_in_scope": true,
				"roles_defined": true,
				"policy_reviewed_annually": true,
				"ir_plan_exists": true,
			},
			"classification": {
				"classification_scheme_defined": true,
				"severity_levels_documented": true,
				"triage_procedure_defined": true,
				"cloud_specific_classification_included": true,
			},
			"escalation": {
				"escalation_procedures_defined": true,
				"escalation_contacts_maintained": true,
				"management_notification_thresholds": true,
				"on_call_rotation_established": true,
			},
			"notification": {
				"customer_notification_procedure": true,
				"regulatory_notification_timeframes": true,
				"notification_templates_prepared": true,
				"notifications_sent_within_sla": true,
			},
			"forensic_readiness": {
				"forensic_readiness_plan_exists": true,
				"cloud_forensics_capability": true,
				"evidence_preservation_procedure": true,
				"legal_hold_integrated_with_ir": true,
				"log_retention_sufficient_for_forensics": true,
			},
			"post_incident_review": {
				"review_conducted": true,
				"root_cause_analysis_performed": true,
				"lessons_learned_documented": true,
				"process_improvements_tracked": true,
			},
			"ir_testing": {
				"ir_plan_tested": true,
			},
			"ediscovery": {
				"ediscovery_capability_defined": true,
				"cloud_data_searchable": true,
				"legal_team_engaged_in_planning": true,
			},
			"metrics": {
				"incident_metrics_tracked": true,
				"metrics_reported_to_management": true,
				"trend_analysis_conducted": true,
			},
		},
		"infrastructure": {
			"network_segmentation": {
				"segmentation_implemented": true,
				"micro_segmentation_applied": true,
				"dmz_implemented": true,
				"segmentation_validated": true,
			},
			"hypervisor": {
				"hypervisor_hardened": true,
				"hypervisor_patched_regularly": true,
				"hypervisor_access_restricted": true,
			},
			"vm_isolation": {
				"vm_isolation_enforced": true,
				"vm_breakout_controls_implemented": true,
				"multi_tenant_isolation_verified": true,
			},
			"network_security_groups": {
				"security_groups_configured": true,
				"default_deny_implemented": true,
				"overly_permissive_rules_detected": true,
				"security_group_review_conducted": true,
			},
			"container_security": {
				"container_images_scanned": true,
				"trusted_registries_enforced": true,
				"containers_run_as_non_root": true,
				"runtime_security_monitoring": true,
				"image_signing_enforced": true,
			},
			"workload_protection": {
				"workload_protection_deployed": true,
				"cloud_security_posture_managed": true,
				"cloud_workload_protection_active": true,
			},
			"vulnerability_scanning": {
				"infrastructure_scanned": true,
				"scan_frequency_defined": true,
				"findings_tracked_to_remediation": true,
				"authenticated_scans_used": true,
			},
			"host_hardening": {
				"hardening_standards_applied": true,
				"cis_benchmark_or_stig_followed": true,
				"hardening_compliance_verified": true,
			},
			"network_monitoring": {
				"network_traffic_monitored": true,
				"flow_logs_enabled": true,
				"ids_ips_deployed": true,
			},
			"patch_management": {
				"infrastructure_patches_applied": true,
				"critical_patches_applied_timely": true,
				"patch_compliance_monitored": true,
			},
			"resource_management": {
				"unused_resources_identified": true,
				"resource_inventory_maintained": true,
				"resource_tagging_enforced": true,
			},
		},
		"interoperability": {
			"data_portability": {
				"requirements_documented": true,
				"export_capability_verified": true,
				"portability_sla_in_contracts": true,
				"data_formats_documented": true,
			},
			"api_standards": {
				"apis_documented": true,
				"standard_protocols_used": true,
				"api_versioning_managed": true,
				"api_dependency_inventory": true,
			},
			"exit_plan": {
				"exit_plan_established": true,
				"data_migration_procedure_defined": true,
				"business_continuity_during_migration": true,
				"exit_plan_reviewed_regularly": true,
				"transition_timelines_defined": true,
			},
			"data_format_standards": {
				"open_standards_preferred": true,
				"vendor_lock_in_assessed": true,
				"format_standards_documented": true,
			},
			"portability_testing": {
				"portability_tested": true,
				"test_results_documented": true,
				"deficiencies_remediated": true,
			},
		},
		"logging_monitoring": {
			"audit_logging": {
				"logging_policy_established": true,
				"audit_logging_enabled": true,
				"cloud_api_logging_enabled": true,
				"log_coverage_verified": true,
			},
			"log_retention": {
				"retention_policy_defined": true,
				"retention_period_enforced": true,
				"minimum_retention_met": true,
				"archived_logs_protected": true,
			},
			"centralized_logging": {
				"siem_deployed": true,
				"cloud_logs_forwarded": true,
				"all_critical_sources_onboarded": true,
				"log_parsing_configured": true,
			},
			"real_time_alerting": {
				"alerting_configured": true,
				"alert_rules_defined": true,
				"alert_response_times_defined": true,
				"alerts_reviewed_and_actioned": true,
			},
			"anomaly_detection": {
				"anomaly_detection_implemented": true,
				"ueba_or_equivalent": true,
				"cloud_anomalies_detected": true,
			},
			"privileged_access_logging": {
				"privileged_actions_logged": true,
				"privileged_session_content_captured": true,
				"privileged_log_tampering_prevented": true,
			},
			"ntp": {
				"time_synchronization_configured": true,
				"single_time_source_used": true,
				"time_drift_monitored": true,
			},
			"log_integrity": {
				"logs_protected_from_tampering": true,
				"immutable_log_storage_used": true,
				"log_integrity_verified": true,
				"log_access_controlled": true,
			},
			"monitoring_coverage": {
				"all_environments_monitored": true,
				"network_monitoring_active": true,
				"application_logging_enabled": true,
			},
			"incident_detection": {
				"detection_use_cases_defined": true,
				"detection_rules_tuned": true,
			},
			"monitoring_program": {
				"program_reviewed_annually": true,
				"coverage_gaps_identified": true,
			},
			"data_access_logging": {
				"sensitive_data_access_logged": true,
				"bulk_data_access_alerted": true,
			},
			"metrics_dashboards": {
				"security_dashboards_operational": true,
				"kpi_metrics_tracked": true,
			},
		},
		"supply_chain": {
			"supplier_policy": {
				"policy_established": true,
				"cloud_suppliers_in_scope": true,
				"policy_reviewed_annually": true,
			},
			"supplier_assessments": {
				"assessments_conducted": true,
				"risk_tiering_applied": true,
				"reassessments_conducted_periodically": true,
				"questionnaires_or_audits_used": true,
				"certifications_reviewed": true,
			},
			"third_party_risk": {
				"risk_management_program_exists": true,
				"risk_register_includes_vendors": true,
				"critical_vendors_identified": true,
				"vendor_risk_monitoring_ongoing": true,
			},
			"subprocessor_inventory": {
				"inventory_maintained": true,
				"data_sharing_documented": true,
				"subprocessor_changes_managed": true,
				"subprocessors_assessed": true,
			},
			"contract_requirements": {
				"security_requirements_in_contracts": true,
				"right_to_audit_included": true,
				"incident_notification_sla_included": true,
				"data_handling_requirements_specified": true,
				"termination_provisions_included": true,
			},
			"transparency": {
				"csp_transparency_report_reviewed": true,
				"csp_shared_responsibility_understood": true,
				"csp_security_posture_reviewed": true,
			},
			"software_supply_chain": {
				"sbom_maintained": true,
				"build_pipeline_integrity": true,
				"third_party_code_reviewed": true,
			},
			"offboarding": {
				"vendor_offboarding_procedure_defined": true,
				"data_retrieved_or_deleted_on_exit": true,
				"access_revoked_on_termination": true,
			},
			"incident_response": {
				"vendor_ir_coordination_defined": true,
				"vendor_notification_requirements_enforced": true,
			},
		},
		"threat_vulnerability": {
			"tvm_policy": {
				"policy_established": true,
				"cloud_assets_in_scope": true,
				"remediation_slas_defined": true,
				"policy_reviewed_annually": true,
			},
			"internal_scanning": {
				"internal_scans_conducted": true,
				"scan_frequency_defined": true,
				"authenticated_scans_used": true,
				"all_assets_covered": true,
			},
			"external_scanning": {
				"external_scans_conducted": true,
				"external_scan_frequency_defined": true,
				"external_attack_surface_inventoried": true,
			},
			"patch_critical": {
				"critical_patches_applied_within_sla": true,
				"zero_day_response_process_defined": true,
				"patch_exemption_process_defined": true,
			},
			"patch_high": {
				"high_patches_applied_within_sla": true,
				"patch_compliance_rate_monitored": true,
			},
			"penetration_testing": {
				"pentest_conducted": true,
				"pentest_frequency_met": true,
				"cloud_specific_testing_performed": true,
				"findings_remediated": true,
				"qualified_testers_used": true,
			},
			"threat_intel": {
				"threat_intel_feeds_subscribed": true,
				"threat_intel_operationalized": true,
				"cloud_specific_threat_intel_consumed": true,
			},
			"cvss_scoring": {
				"cvss_scoring_used": true,
				"exploitability_considered": true,
				"business_context_applied": true,
			},
			"remediation_tracking": {
				"all_findings_tracked": true,
				"overdue_vulns_escalated": true,
				"remediation_effectiveness_verified": true,
				"metrics_reported_to_management": true,
			},
			"zero_day_response": {
				"process_defined": true,
				"emergency_patching_capability": true,
				"workarounds_applied_when_patch_unavailable": true,
				"csp_advisories_monitored": true,
			},
		},
	},
}

# Every boolean leaf of the fixture, as a path.
_leaves := [path |
	walk(all_pass, [path, value])
	is_boolean(value)
]

_pointer(path) := concat("/", array.concat([""], path))

_field(path) := concat(".", array.concat(["input"], path))

_set(path, value) := json.patch(all_pass, [{"op": "replace", "path": _pointer(path), "value": value}])

_drop(path) := json.remove(all_pass, [_pointer(path)])

# The whole fixture with every boolean leaf replaced by one value.
_all_set(value) := json.patch(all_pass, [op |
	some path in _leaves
	op := {"op": "replace", "path": _pointer(path), "value": value}
])

# Values that are not the boolean true or false: each is a collection error, never a pass.
_wrong_types := ["false", "true", "no", "yes", 0, 1]

_named(violations, path, problem) if {
	some msg in violations
	contains(msg, _field(path))
	contains(msg, problem)
}

# Per domain: checks, control ids carried, and checks that only apply once another fact is true
# (they are silent when that fact is not true, and the fact's own check reports instead).
_domains := {
	"application_security": {
		"checks": 31,
		"controls": 7,
		"conditional": 0,
	},
	"audit_assurance": {
		"checks": 26,
		"controls": 7,
		"conditional": 4,
	},
	"business_continuity": {
		"checks": 43,
		"controls": 11,
		"conditional": 0,
	},
	"change_control": {
		"checks": 34,
		"controls": 9,
		"conditional": 0,
	},
	"cryptography": {
		"checks": 34,
		"controls": 9,
		"conditional": 1,
	},
	"data_security": {
		"checks": 35,
		"controls": 10,
		"conditional": 0,
	},
	"endpoint_management": {
		"checks": 39,
		"controls": 12,
		"conditional": 0,
	},
	"governance": {
		"checks": 26,
		"controls": 6,
		"conditional": 0,
	},
	"human_resources": {
		"checks": 36,
		"controls": 9,
		"conditional": 0,
	},
	"identity_access": {
		"checks": 48,
		"controls": 14,
		"conditional": 1,
	},
	"incident_management": {
		"checks": 33,
		"controls": 8,
		"conditional": 0,
	},
	"infrastructure": {
		"checks": 38,
		"controls": 11,
		"conditional": 0,
	},
	"interoperability": {
		"checks": 19,
		"controls": 5,
		"conditional": 0,
	},
	"logging_monitoring": {
		"checks": 40,
		"controls": 13,
		"conditional": 0,
	},
	"supply_chain": {
		"checks": 32,
		"controls": 9,
		"conditional": 0,
	},
	"threat_vulnerability": {
		"checks": 35,
		"controls": 10,
		"conditional": 0,
	},
}

_domain_leaves(domain) := [path |
	some path in _leaves
	path[1] == domain
]

_report(domain, inp) := r if {
	r := data.csa_ccm[domain].compliance_report with input as inp
}

test_fixture_has_549_facts if {
	count(_leaves) == 549
	every domain, spec in _domains {
		count(_domain_leaves(domain)) == spec.checks
	}
}

test_all_true_passes_every_domain if {
	every domain, spec in _domains {
		r := _report(domain, all_pass)
		r.compliant == true
		r.violation_count == 0
		r.failed_controls == 0
		r.passed_controls == spec.controls
		r.controls_checked == spec.controls
		r.checks_total == spec.checks
	}
}

test_empty_input_fails_every_domain_as_missing_evidence if {
	every domain, spec in _domains {
		r := _report(domain, {})
		r.compliant == false
		r.violation_count == spec.checks - spec.conditional
		r.failed_controls == spec.controls
		r.passed_controls == 0
		every msg in r.violations {
			contains(msg, sprintf("evidence missing: input.csa_ccm.%s.", [domain]))
		}
	}
}

test_boolean_false_everywhere_keeps_plain_findings if {
	inp := _all_set(false)
	every domain, spec in _domains {
		r := _report(domain, inp)
		r.compliant == false
		r.violation_count == spec.checks - spec.conditional
		every msg in r.violations {
			not contains(msg, " — evidence missing: ")
			not contains(msg, " — evidence invalid: ")
		}
	}
}

test_wrong_type_everywhere_fails_every_domain if {
	every value in _wrong_types {
		inp := _all_set(value)
		every domain, spec in _domains {
			r := _report(domain, inp)
			r.compliant == false
			r.violation_count == spec.checks - spec.conditional
			r.failed_controls == spec.controls
			every msg in r.violations {
				contains(msg, sprintf("is not a boolean (got %s)", [type_name(value)]))
			}
		}
	}
}

test_null_everywhere_fails_every_domain if {
	inp := _all_set(null)
	every domain, spec in _domains {
		r := _report(domain, inp)
		r.compliant == false
		r.violation_count == spec.checks - spec.conditional
		every msg in r.violations {
			contains(msg, "evidence missing: input.csa_ccm.")
		}
	}
}

# One fact at a time, all 549: the wrong type fails the fact's own check and the finding names the field.
test_each_fact_with_wrong_type_fails_and_is_named if {
	every path in _leaves {
		every value in ["false", "true", 1] {
			r := _report(path[1], _set(path, value))
			r.compliant == false
			r.violation_count >= 1
			r.failed_controls == 1
			_named(r.violations, path, "evidence invalid")
		}
	}
}

test_each_fact_null_or_removed_fails_and_is_named if {
	every path in _leaves {
		r1 := _report(path[1], _set(path, null))
		r1.compliant == false
		r1.failed_controls == 1
		_named(r1.violations, path, "evidence missing")
		r2 := _report(path[1], _drop(path))
		r2.compliant == false
		r2.failed_controls == 1
		_named(r2.violations, path, "evidence missing")
	}
}

test_each_fact_false_fails if {
	every path in _leaves {
		r := _report(path[1], _set(path, false))
		r.compliant == false
		r.failed_controls == 1
		r.violation_count >= 1
	}
}

# A domain section sent as a string, null, a boolean or a list is missing evidence for the whole domain.
test_domain_section_of_the_wrong_type_fails if {
	every value in ["false", null, true, []] {
		every domain, spec in _domains {
			r := _report(domain, {"csa_ccm": object.union(all_pass.csa_ccm, {domain: value})})
			r.compliant == false
			r.failed_controls == spec.controls
		}
	}
}

test_input_that_is_not_an_object_fails if {
	r := data.csa_ccm.main.compliance_report with input as "true"
	r.compliant == false
	r.failed_controls == 150
}

# ── Main report ──────────────────────────────────────────────────────────────

test_main_all_true_passes if {
	r := data.csa_ccm.main.compliance_report with input as all_pass
	r.compliant == true
	r.overall_compliant == true
	r.domains_passing == 16
	r.violation_count == 0
	r.failed_controls == 0
	r.passed_controls == 150
	r.total_controls == 197
}

# Controls and findings are counted separately, and the control counts add up to the declared total.
test_main_counts_are_consistent if {
	every inp in [{}, all_pass, _all_set(false), _all_set("false"), _all_set("true"), _all_set(null)] {
		r := data.csa_ccm.main.compliance_report with input as inp
		r.total_controls == 197
		r.controls_checked == 150
		r.checks_total == 549
		(r.passed_controls + r.failed_controls) + r.controls_not_checked == r.total_controls
		r.failed_controls <= r.total_controls
		r.failed_controls == count(r.failed_control_ids)
		r.violation_count == count(r.violations)
		r.violation_count <= r.checks_total
	}
}

test_main_bad_evidence_everywhere_fails_all_150_checked_controls if {
	every inp in [{}, _all_set(false), _all_set("false"), _all_set("true"), _all_set(null), _all_set(0)] {
		r := data.csa_ccm.main.compliance_report with input as inp
		r.compliant == false
		r.domains_passing == 0
		r.failed_controls == 150
		r.passed_controls == 0
		r.violation_count == 543
	}
}

# One bad fact fails one control and one domain in the main report.
test_main_one_string_fact_fails_one_control if {
	inp := _set(["csa_ccm", "identity_access", "mfa", "mfa_enforced"], "true")
	r := data.csa_ccm.main.compliance_report with input as inp
	r.compliant == false
	r.domains_passing == 15
	r.failed_control_ids == ["IAM-03"]
	r.passed_controls == 149
	r.violations == ["IAM-03: Multi-factor authentication (MFA) not enforced for access to cloud management consoles and sensitive systems — evidence invalid: input.csa_ccm.identity_access.mfa.mfa_enforced is not a boolean (got string)"]
}

# A check that depends on another fact stays silent unless that fact is the boolean true.
test_conditional_check_needs_boolean_true if {
	path := ["csa_ccm", "identity_access", "sso", "sso_uses_federated_identity"]
	federated := "IAM-05: SSO not federated with enterprise identity provider — applications must authenticate through central IdP"
	r1 := _report("identity_access", _set(path, false))
	federated in r1.violations
	inp := json.patch(all_pass, [
		{"op": "replace", "path": _pointer(path), "value": false},
		{"op": "replace", "path": "/csa_ccm/identity_access/sso/sso_implemented", "value": "true"},
	])
	r2 := _report("identity_access", inp)
	not federated in r2.violations
	_named(r2.violations, ["csa_ccm", "identity_access", "sso", "sso_implemented"], "evidence invalid")
}
