package iso27001_annex_a_test

import rego.v1

import data.iso27001

# ISO/IEC 27001:2022 Annex A (= ISO/IEC 27002:2022 clauses 5-8): table shape, the iso27002 view, fail-closed
# evaluation, fact-evaluated vs attested basis, and the input contract (unknown and 2013-era ids).

# Facts that satisfy every check of the five fact modules (generated from the modules' own comparisons).
_facts := {
	"acceptance_testing": {
		"criteria_defined": true,
		"documentation_complete": true,
		"formal_sign_off": true,
		"security_criteria_included": true,
		"stakeholders_signed_off": true,
	},
	"access_control": {
		"access_rules": {
			"defined": true,
			"enforced": true,
		},
		"policy": {
			"approved": true,
			"communicated": true,
			"documented": true,
		},
	},
	"access_removal": {
		"automated_process": true,
		"immediate_termination": true,
		"role_change_adjustment": true,
		"verification_required": true,
	},
	"access_review": {
		"documented_results": true,
		"frequency_days": 120,
		"management_approval": true,
		"regular_schedule": true,
		"remediation_tracked": true,
	},
	"admin_logging": {
		"configuration_changes_logged": true,
		"logs_reviewed_regularly": true,
		"privileged_commands_logged": true,
		"root_access_logged": true,
		"service_account_activity_logged": true,
		"sudo_usage_logged": true,
	},
	"api": {
		"certificate_pinning": true,
		"payload_encryption": true,
		"tls_required": true,
		"token_encryption": true,
	},
	"audit_controls": {
		"audit_access_restricted": true,
		"audit_tools_protected": true,
		"logging": {
			"audit_activities_logged": true,
			"audit_log_protected": true,
		},
		"production_disruption_minimized": true,
		"requirements_agreed": true,
		"scheduling": {
			"maintenance_window_preferred": true,
			"planned_in_advance": true,
			"stakeholders_notified": true,
		},
		"scope_controlled": true,
	},
	"authentication": {
		"mfa": {
			"enabled": true,
			"required_for_admin": true,
			"required_for_remote": true,
		},
		"password_policy": {
			"complexity_required": true,
			"expiry_enabled": true,
			"history_count": 12,
			"lockout_enabled": true,
			"min_length": 8,
		},
		"secrets": {
			"access_controlled": true,
			"encrypted_storage": true,
			"regular_rotation": true,
			"secure_transmission": true,
		},
	},
	"backup": {
		"coverage": {
			"application_data": true,
			"configuration_files": true,
			"critical_systems": true,
			"databases": true,
		},
		"encryption": {
			"enabled": true,
			"integrity_verification": true,
			"key_escrow": true,
			"separate_keys": true,
		},
		"frequency": {
			"daily_incremental": true,
			"weekly_full": true,
		},
		"policy": {
			"approved": true,
			"documented": true,
			"regularly_tested": true,
		},
		"retention": {
			"defined": true,
			"minimum_days": 30,
		},
		"security": {
			"access_controlled": true,
			"encrypted": true,
			"integrity_verified": true,
			"offsite_copy": true,
		},
		"testing": {
			"frequency_days": 90,
			"restore_tests_performed": true,
		},
	},
	"capacity_management": {
		"alerts_configured": true,
		"forecasting_performed": true,
		"monitoring_enabled": true,
		"resources": {
			"cpu_monitored": true,
			"memory_monitored": true,
			"network_monitored": true,
			"storage_monitored": true,
		},
		"thresholds_defined": true,
		"tuning_performed": true,
	},
	"certificates": {
		"lifecycle": {
			"automated_renewal": true,
			"expiry_monitoring": true,
			"secure_generation": true,
		},
		"regular_renewal": true,
		"revocation_checking": true,
		"secure_storage": true,
		"trusted_ca_only": true,
	},
	"change_control": {
		"approval_required": true,
		"documentation_required": true,
		"formal_process": true,
		"impact_assessment": true,
		"post_change_review": true,
		"rollback_plan": true,
		"testing_required": true,
		"version_control": {
			"all_changes_tracked": true,
			"branch_protection": true,
			"mandatory": true,
		},
	},
	"change_management": {
		"approval_required": true,
		"cab": {
			"exists": true,
			"regular_meetings": true,
			"security_represented": true,
		},
		"documentation_required": true,
		"emergency": {
			"defined": true,
			"post_implementation_review": true,
		},
		"formal_process": true,
		"impact_assessment": true,
		"rollback_procedures": true,
		"testing_required": true,
	},
	"cicd": {
		"access_controlled": true,
		"artifact_signing": true,
		"container_scanning": true,
		"gates": {
			"approval_required_for_production": true,
			"quality_checks_required": true,
			"security_scan_required": true,
		},
		"infrastructure_as_code_scanning": true,
		"pipeline_as_code": true,
		"secrets_management": {
			"no_plaintext_secrets": true,
			"vault_used": true,
		},
	},
	"clock_sync": {
		"all_systems_synchronized": true,
		"authoritative_source": true,
		"drift_monitored": true,
		"max_drift_seconds": 1,
		"ntp_configured": true,
	},
	"cryptography": {
		"algorithms_in_use": ["AES"],
		"approved_algorithms": ["AES"],
		"policy": {
			"approved": true,
			"approved_algorithms": ["AES"],
			"communicated": true,
			"documented": true,
			"encryption_requirements": true,
			"key_management_addressed": true,
			"regularly_reviewed": true,
		},
		"quantum_resistance": {
			"assessment_completed": true,
			"migration_plan": true,
			"timeline_defined": true,
		},
	},
	"database": {
		"connections": {
			"certificate_validation": true,
			"ssl_required": true,
		},
		"encryption": {
			"at_rest": true,
			"in_transit": true,
			"key_rotation": true,
			"transparent_encryption": true,
		},
	},
	"dev_environment": {
		"access_restricted": true,
		"code_repository_protected": true,
		"secrets_management_implemented": true,
		"security_controls_applied": true,
		"separated_from_production": true,
		"workstations": {
			"antivirus_deployed": true,
			"full_disk_encryption": true,
			"patching_current": true,
			"screen_lock_configured": true,
		},
	},
	"development": {"policy": {
		"approved": true,
		"communicated": true,
		"covers": {
			"coding_standards": true,
			"peer_code_review": true,
			"secure_coding_guidelines": true,
			"security_training": true,
			"vulnerability_testing": true,
		},
		"documented": true,
		"enforced": true,
	}},
	"digital_signatures": {
		"code_signing": true,
		"document_signing": true,
		"non_repudiation": true,
		"timestamp_verification": true,
	},
	"dns_security": {
		"dnssec_enabled": true,
		"internal_external_separated": true,
		"monitoring_enabled": true,
		"recursive_queries_restricted": true,
		"response_rate_limiting": true,
	},
	"electronic_messaging": {
		"anti_malware": {
			"attachment_filtering": true,
			"email_scanning": true,
		},
		"anti_spam": {"enabled": true},
		"authentication": {
			"dkim_enabled": true,
			"dmarc_configured": true,
			"spf_configured": true,
		},
		"dlp": {
			"enabled": true,
			"sensitive_data_blocked": true,
		},
		"encryption": {
			"emails_encrypted": true,
			"sensitive_content_protected": true,
		},
	},
	"encryption": {
		"application_data": {
			"configuration_files": true,
			"sensitive_fields": true,
		},
		"data_at_rest": {
			"enabled": true,
			"key_management_integrated": true,
			"strong_algorithms": true,
		},
		"data_in_transit": {
			"certificate_validation": true,
			"perfect_forward_secrecy": true,
			"tls_enforced": true,
			"minimum_tls_version": "1.3",
		},
		"filesystem": {
			"full_disk_encryption": true,
			"secure_boot": true,
		},
	},
	"environments": {
		"access_controls_different": true,
		"compilers_restricted_in_production": true,
		"data_not_copied_without_authorization": true,
		"development_separated": true,
		"production_separated": true,
		"testing_separated": true,
	},
	"hsm": {
		"available": true,
		"cryptographic_operations": true,
		"fips_140_2_level": 2,
		"key_generation": true,
		"key_storage": true,
		"tamper_protection": true,
	},
	"information_transfer": {
		"agreements": {
			"classification_labeling_required": true,
			"formal_agreements_required": true,
			"responsibilities_defined": true,
			"security_requirements_defined": true,
			"third_party": {
				"audit_rights_reserved": true,
				"breach_notification_required": true,
				"data_handling_procedures": true,
				"nda_required": true,
			},
		},
		"controls": {
			"data_classification_applied": true,
			"encryption_required": true,
			"integrity_checking": true,
			"unauthorized_interception_prevented": true,
		},
		"policy": {
			"acceptable_use_defined": true,
			"approved": true,
			"communicated": true,
			"documented": true,
		},
	},
	"key_management": {
		"destruction": {
			"audit_logged": true,
			"documented_process": true,
			"secure_deletion": true,
			"verification_required": true,
		},
		"distribution": {
			"authentication_required": true,
			"encrypted_channels": true,
			"integrity_protected": true,
		},
		"generation": {
			"approved_algorithms": true,
			"documented_process": true,
			"random_source_secure": true,
			"sufficient_entropy": true,
		},
		"key_specifications": ["AES"],
		"rotation": {
			"automated_process": true,
			"emergency_procedures": true,
			"max_lifetime_days": 365,
			"regular_schedule": true,
		},
		"storage": {
			"access_controlled": true,
			"audit_logged": true,
			"backup_encrypted": true,
			"hardware_security_modules": true,
		},
		"usage": {
			"access_restricted": true,
			"audit_logged": true,
			"purpose_specific": true,
		},
	},
	"log_protection": {
		"access_restricted": true,
		"backup_enabled": true,
		"centralized_storage": true,
		"deletion_prevention": true,
		"encryption_enabled": true,
		"siem_integrated": true,
	},
	"logging": {
		"events": {
			"authentication_attempts": true,
			"exceptions": true,
			"faults": true,
			"privileged_operations": true,
			"security_events": true,
			"system_access": true,
			"user_activities": true,
		},
		"integrity": {
			"checksum_verification": true,
			"immutable_storage": true,
			"tamper_protection": true,
		},
		"retention": {
			"enabled": true,
			"minimum_days": 90,
		},
	},
	"logon": {
		"authentication_required": true,
		"failed_attempt_lockout": true,
		"max_failed_attempts": 5,
		"session_timeout_configured": true,
		"session_timeout_minutes": 30,
		"user_identification_required": true,
		"warning_message_displayed": true,
	},
	"malware_protection": {
		"antivirus": {
			"coverage_percentage": 95,
			"deployed": true,
			"real_time_enabled": true,
			"scheduled_scans": true,
			"signature_age_days": 3,
			"signatures_current": true,
		},
		"application_whitelisting": true,
		"email_scanning": true,
		"phishing_training": true,
		"removable_media_scanning": true,
		"user_awareness_training": true,
		"web_filtering": true,
	},
	"nda": {
		"enforcement": {
			"expiry_tracked": true,
			"records_maintained": true,
			"renewal_process": true,
		},
		"legally_reviewed": true,
		"regularly_reviewed": true,
		"required_for_contractors": true,
		"required_for_partners": true,
		"required_for_staff": true,
		"signed_before_access": true,
	},
	"network": {
		"https": {
			"enforced": true,
			"hsts_enabled": true,
			"secure_cookies": true,
		},
		"ssh": {
			"key_based_auth": true,
			"protocol_version": 2,
			"strong_ciphers": true,
		},
		"vpn": {
			"certificate_based": true,
			"strong_encryption": true,
		},
	},
	"network_management": {
		"change_management_applied": true,
		"configuration_backups": true,
		"management_access_restricted": true,
		"management_vlan_separate": true,
		"out_of_band_management": true,
		"snmp_v3_only": true,
	},
	"network_monitoring": {
		"alert_thresholds_configured": true,
		"anomaly_detection": true,
		"ids_ips_deployed": true,
		"log_retention_days": 90,
		"siem_integrated": true,
		"traffic_analysis": true,
	},
	"network_security": {"controls": {
		"access_control_lists": true,
		"firewalls_deployed": true,
		"intrusion_detection": true,
		"network_monitoring": true,
		"policy_documented": true,
		"responsibility_assigned": true,
	}},
	"network_segregation": {
		"dmz_implemented": true,
		"internal_external_separated": true,
		"perimeter": {
			"egress_filtering": true,
			"firewall_rules_documented": true,
			"ingress_filtering": true,
		},
		"vlans_configured": true,
		"wireless": {
			"corporate_separate": true,
			"guest_network_isolated": true,
		},
		"zones_defined": true,
	},
	"network_services": {
		"managed_security_services": true,
		"security_features_identified": true,
		"service_agreements_documented": true,
		"service_levels_monitored": true,
		"third_party": {
			"compliance_monitored": true,
			"contracts_include_security": true,
			"security_requirements_defined": true,
		},
	},
	"operational_procedures": {
		"accessible_to_staff": true,
		"approved": true,
		"covers": {
			"backup_procedures": true,
			"error_handling": true,
			"escalation_paths": true,
			"incident_management": true,
			"system_startup_shutdown": true,
		},
		"documented": true,
		"regularly_reviewed": true,
		"version_controlled": true,
	},
	"os_change_review": {
		"applications_tested_after_os_change": true,
		"change_management_notified": true,
		"compatibility_verified": true,
		"procedure_defined": true,
		"security_posture_validated": true,
	},
	"password_system": {
		"centralized_management": true,
		"change_notification": true,
		"policy_enforcement": true,
		"secure_storage": true,
		"temporary_passwords_controlled": true,
	},
	"pki": {
		"certificate_authority": {
			"audited": true,
			"trusted": true,
		},
		"certificate_policies": {"documented": true},
		"certificate_revocation": {
			"crl_available": true,
			"ocsp_enabled": true,
		},
	},
	"privileged_access": {
		"allocation_restricted": true,
		"monitoring_enabled": true,
		"multi_factor_auth": true,
		"regular_review": true,
		"shared_accounts": [],
	},
	"privileged_utilities": {
		"approval_required": true,
		"logging_enabled": true,
		"monitoring_active": true,
		"restricted_access": true,
	},
	"public_services": {
		"authentication": {
			"multi_factor_enabled": true,
			"strong_auth_required": true,
		},
		"encryption": {
			"tls_enforced": true,
			"minimum_tls_version": "1.3",
		},
		"fraud_prevention": {"controls_implemented": true},
		"input_validation": {
			"enabled": true,
			"parameterized_queries": true,
			"sanitization": true,
		},
		"integrity": {
			"message_signing": true,
			"transaction_verification": true,
		},
	},
	"remote_access": {
		"endpoints": {
			"antivirus_required": true,
			"compliance_check": true,
			"patch_level_verified": true,
		},
		"sessions": {
			"activity_monitored": true,
			"idle_timeout_minutes": 30,
			"logging_enabled": true,
		},
		"vpn": {
			"multi_factor_auth": true,
			"required": true,
			"session_timeout_configured": true,
			"strong_encryption": true,
		},
	},
	"sca": {
		"enabled": true,
		"known_vulnerabilities_flagged": true,
		"license_compliance_checked": true,
		"policy_enforcement": true,
		"sbom_generated": true,
	},
	"secure_engineering": {
		"authentication_centralized": true,
		"defense_in_depth": true,
		"fail_secure": true,
		"input_validation_implemented": true,
		"least_privilege": true,
		"output_encoding_implemented": true,
		"owasp_top10_mitigated": true,
		"security_architecture_review": true,
		"separation_of_duties": true,
		"session_management_secure": true,
		"threat_modeling": true,
	},
	"security_testing": {
		"dast": {"enabled": true},
		"dependency_scanning": {
			"blocking_on_critical": true,
			"enabled": true,
		},
		"penetration_testing": {"frequency_days": 365},
		"policy": {"defined": true},
		"sast": {
			"enabled": true,
			"integrated_in_pipeline": true,
		},
		"types": {
			"integration_testing": true,
			"penetration_testing": true,
			"static_analysis": true,
			"unit_testing": true,
			"vulnerability_scanning": true,
		},
	},
	"software_control": {
		"installation": {
			"admin_rights_required": true,
			"approval_process": true,
			"approved_software_list": true,
			"policy_defined": true,
			"unauthorized_installation_prevented": true,
		},
		"inventory": {
			"maintained": true,
			"regularly_reviewed": true,
			"unauthorized_software_detected": true,
		},
	},
	"software_packages": {
		"modification_restricted": true,
		"modifications_documented": true,
		"modifications_tested": true,
		"vendor_notification_when_modified": true,
		"vendor_packages_preferred": true,
	},
	"software_restriction": {
		"application_whitelisting": true,
		"code_signing_required": true,
		"exceptions_documented": true,
		"standard_builds_enforced": true,
		"unapproved_software_blocked": true,
	},
	"source_code": {
		"access_restricted": true,
		"audit_trail": true,
		"backup_protected": true,
		"change_approval": true,
		"version_control": true,
	},
	"system_access": {
		"data_classification_enforced": true,
		"need_to_know": true,
		"role_based_control": true,
		"segregation_of_duties": true,
	},
	"system_requirements": {
		"categorization": {
			"data_classification_considered": true,
			"regulatory_requirements_mapped": true,
			"risk_assessment_performed": true,
		},
		"security_requirements": {
			"documented": true,
			"included_in_specifications": true,
			"reviewed_before_procurement": true,
			"stakeholders_approved": true,
		},
	},
	"test_data": {
		"generators": {"approved_tools": true},
		"production_data_not_used_for_testing": true,
		"synthetic_data": {
			"available": true,
			"realistic_for_testing": true,
		},
	},
	"transactions": {
		"audit_trail": true,
		"confidentiality_protected": true,
		"error_handling_secure": true,
		"integrity_verification": true,
		"non_repudiation": true,
		"routing_security": true,
		"timeout_configured": true,
	},
	"user_management": {
		"provisioning": {
			"approval_required": true,
			"automated_tools": true,
			"least_privilege": true,
			"role_based": true,
		},
		"registration": {
			"authorization_required": true,
			"documented": true,
			"formal_process": true,
		},
		"unauthorized_users": [],
	},
	"user_responsibilities": {
		"clear_desk_policy": true,
		"password_protection": true,
		"training_completed": true,
		"unattended_sessions": true,
	},
	"vulnerability_management": {
		"patching": {
			"automated_where_possible": true,
			"critical_patch_sla_days": 7,
			"high_patch_sla_days": 30,
			"policy_defined": true,
			"testing_required": true,
		},
		"scanning": {
			"authenticated_scans": true,
			"covers_all_systems": true,
			"frequency_days": 30,
			"regular_scans": true,
		},
		"tracking": {
			"management_reporting": true,
			"remediation_tracked": true,
			"risk_register": true,
		},
	},
}

_all := {id: true | some id, _ in iso27001.annex_a}

_attest_only := {id: true | some id, _ in iso27001.annex_a; not iso27001.fact_checks[id]}

_green := object.union(_facts, {"iso27001": {"annex_a": _all}})

_has(r, s) if {
	some v in r.violations
	contains(v, s)
}

# --- table -----------------------------------------------------------------

test_annex_a_has_93_controls if {
	count(iso27001.annex_a) == 93
	r := iso27001.compliance_report with input as {}
	r.total_controls == 93
	r.standard_total == 93
}

test_annex_a_theme_counts_37_8_14_34 if {
	count({id | some id, c in iso27001.annex_a; c.theme == "Organizational"}) == 37
	count({id | some id, c in iso27001.annex_a; c.theme == "People"}) == 8
	count({id | some id, c in iso27001.annex_a; c.theme == "Physical"}) == 14
	count({id | some id, c in iso27001.annex_a; c.theme == "Technological"}) == 34
	r := iso27001.compliance_report with input as {}
	r.themes.Organizational.controls == 37
	r.themes.People.controls == 8
	r.themes.Physical.controls == 14
	r.themes.Technological.controls == 34
}

test_ids_are_2022_annex_a_numbers_and_contiguous if {
	expected := {sprintf("A.%v.%v", [t, n]) |
		some t, max in {"5": 37, "6": 8, "7": 14, "8": 34}
		some n in numbers.range(1, max)
	}
	{id | some id, _ in iso27001.annex_a} == expected
}

test_theme_matches_clause if {
	every id, c in iso27001.annex_a {
		c.theme == iso27001.themes[split(id, ".")[1]]
	}
}

test_every_row_is_title_and_attribute_values_only if {
	every _, c in iso27001.annex_a {
		object.keys(c) == {"theme", "title", "control_type", "properties", "concepts", "capabilities", "domains"}
		is_string(c.title)
		count(c.title) > 0
		every k in ["control_type", "properties", "concepts", "capabilities", "domains"] {
			count(c[k]) > 0
			every v in c[k] {
				v in iso27001.attribute_values[k]
			}
		}
	}
}

test_spot_titles if {
	iso27001.annex_a["A.5.1"].title == "Policies for information security"
	iso27001.annex_a["A.5.23"].title == "Information security for use of cloud services"
	iso27001.annex_a["A.6.3"].title == "Information security awareness, education and training"
	iso27001.annex_a["A.7.4"].title == "Physical security monitoring"
	iso27001.annex_a["A.8.34"].title == "Protection of information systems during audit testing"
}

# --- iso27002 view ---------------------------------------------------------

test_iso27002_view_is_the_same_93_rows if {
	count(iso27001.iso27002_controls) == 93
	every cid, row in iso27001.iso27002_controls {
		row.annex_a == concat("", ["A.", cid])
		row.title == iso27001.annex_a[row.annex_a].title
		row.capabilities == iso27001.annex_a[row.annex_a].capabilities
	}
	iso27001.iso27002_controls["5.1"].annex_a == "A.5.1"
	iso27001.iso27002_controls["8.34"].theme == "Technological"
}

test_report_carries_iso27002_view if {
	r := iso27001.compliance_report with input as _green
	count(r.iso27002) == 93
	r.iso27002["8.24"].annex_a == "A.8.24"
	r.iso27002["8.24"].satisfied == r.annex_a["A.8.24"].satisfied
}

# --- fact wiring -----------------------------------------------------------

test_fact_and_attestation_counts if {
	count(iso27001.fact_checks) == 35
	r := iso27001.compliance_report with input as {}
	r.controls_fact_evaluated == 35
	r.controls_attested == 58
}

test_fact_checks_point_at_annex_a_ids_and_real_rules if {
	every id, checks in iso27001.fact_checks {
		iso27001.annex_a[id]
		every c in checks {
			is_boolean(data.iso27001[c.pkg][c.rule]) with input as {}
		}
	}
}

test_fact_checks_keep_2013_ids if {
	some c in iso27001.fact_checks["A.8.4"]
	c.iso2013 == "A.9.4.5"
	some d in iso27001.fact_checks["A.5.14"]
	d.iso2013 == "A.13.2.1"
}

# --- evaluation ------------------------------------------------------------

test_empty_input_fails_closed if {
	r := iso27001.compliance_report with input as {}
	r.compliant == false
	_has(r, "FAIL-CLOSED")
	r.controls_satisfied < 93
	not iso27001.compliant with input as {}
}

test_non_object_attestations_fail_closed if {
	r := iso27001.compliance_report with input as object.union(_facts, {"iso27001": {"annex_a": ["A.5.1"]}})
	r.compliant == false
	_has(r, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := iso27001.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.controls_satisfied == 93
	r.themes_passing == 4
	every _, t in r.themes {
		t.gaps == []
	}
	a := iso27001.iso27001_assessment with input as _green
	a.compliant == true
	a.annex_a_controls == {"organizational_controls": 37, "people_controls": 8, "physical_controls": 14, "technological_controls": 34}
}

test_one_attested_control_false_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/iso27001/annex_a/A.7.4", "value": false}])
	r := iso27001.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	_has(r, "A.7.4 Physical security monitoring (Physical): not attested")
	r.themes.Physical.gaps == ["A.7.4"]
	r.annex_a["A.7.4"].satisfied == false
}

test_one_fact_check_false_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/source_code/version_control", "value": false}])
	r := iso27001.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	_has(r, "A.8.4 Access to source code: fact check failed — data.iso27001.access_control.source_code_access_control (2013 A.9.4.5)")
	r.annex_a["A.8.4"].basis == "facts"
	r.annex_a["A.8.4"].fact_checks_failed == ["access_control.source_code_access_control"]
}

test_attestations_alone_satisfy_only_attested_controls if {
	r := iso27001.compliance_report with input as {"iso27001": {"annex_a": _all}}
	r.compliant == false
	not _has(r, "FAIL-CLOSED")

	# A.8.30 (outsourced development) passes with no facts: the module treats absent outsourcing as satisfied
	r.controls_satisfied == 59
}

test_facts_alone_fail_closed if {
	r := iso27001.compliance_report with input as _facts
	r.compliant == false
	_has(r, "FAIL-CLOSED")
	r.controls_satisfied == 35
}

test_attesting_a_fact_evaluated_control_does_not_decide_it if {
	inp := json.patch(_green, [{"op": "replace", "path": "/cryptography/policy/documented", "value": false}])
	r := iso27001.compliance_report with input as inp
	r.annex_a["A.8.24"].attested == true
	r.annex_a["A.8.24"].satisfied == false
	_has(r, "A.8.24 Use of cryptography: fact check failed")
}

test_unknown_id_is_a_violation if {
	inp := json.patch(_green, [{"op": "add", "path": "/iso27001/annex_a/A.5.38", "value": true}])
	r := iso27001.compliance_report with input as inp
	r.compliant == false
	_has(r, "unknown Annex A control id A.5.38")
}

test_27002_number_as_attestation_key_is_unknown if {
	inp := json.patch(_green, [{"op": "add", "path": "/iso27001/annex_a/5.1", "value": true}])
	r := iso27001.compliance_report with input as inp
	r.compliant == false
	_has(r, "unknown Annex A control id 5.1")
}

test_2013_era_ids_are_violations if {
	inp := json.patch(_green, [
		{"op": "add", "path": "/iso27001/annex_a/A.9.1.1", "value": true},
		{"op": "add", "path": "/iso27001/annex_a/A.12", "value": true},
	])
	r := iso27001.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 2
	_has(r, "A.9.1.1 is an ISO/IEC 27001:2013 Annex A id")
	_has(r, "A.12 is an ISO/IEC 27001:2013 Annex A id")
}
