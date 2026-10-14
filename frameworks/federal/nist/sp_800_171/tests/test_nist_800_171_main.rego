# Tests for nist_800_171.main — NIST SP 800-171 Rev 3 (CPRT ids). Generated alongside the module from the
# CPRT export (sha256 19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa); the green fixture sets every fact the family modules read.
package nist_800_171.main_test

import rego.v1

import data.nist_800_171.main

_all := {id: true | some id, _ in main.requirements}

_facts := {
	"cui_access": {
		"user_authorization": {
			"all_users_authorized": true,
			"process_authorization": true,
			"device_authorization": true,
		},
		"transaction_limits": {
			"role_based_restrictions": true,
			"function_authorization": true,
			"documented_permissions": true,
		},
		"flow_control": {
			"approved_authorizations": true,
			"automated_enforcement": true,
			"monitoring_implemented": true,
		},
		"separation_duties": {
			"critical_functions_separated": true,
			"documented_assignments": true,
			"collusion_prevention": true,
		},
		"least_privilege": {
			"minimum_necessary_access": true,
			"privileged_account_restrictions": true,
			"security_function_limits": true,
		},
		"non_privileged": {
			"separate_accounts": true,
			"role_segregation": true,
			"privilege_escalation_controlled": true,
		},
		"privileged_prevention": {
			"execution_controls": true,
			"authorization_required": true,
			"monitoring_implemented": true,
		},
		"logon_limits": {
			"maximum_attempts": 3,
			"lockout_implemented": true,
			"lockout_duration": 15,
		},
		"notices": {
			"privacy_notice_displayed": true,
			"security_notice_displayed": true,
			"cui_rules_referenced": true,
		},
		"session_lock": {
			"inactivity_timeout": 900,
			"pattern_hiding": true,
			"authentication_required": true,
		},
		"session_termination": {
			"defined_conditions": true,
			"automatic_termination": true,
			"user_notification": true,
		},
		"remote_access": {
			"session_monitoring": true,
			"access_control": true,
			"encrypted_connections": true,
		},
		"remote_encryption": {
			"cryptographic_protection": true,
			"approved_algorithms": true,
			"end_to_end_encryption": true,
		},
		"managed_access": {
			"designated_control_points": true,
			"centralized_management": true,
			"monitoring_capability": true,
		},
		"remote_privileged": {
			"explicit_authorization": true,
			"strong_authentication": true,
			"logging_monitoring": true,
		},
		"wireless": {
			"pre_authorization_required": true,
			"configuration_management": true,
			"security_controls": true,
		},
		"wireless_protection": {
			"authentication_required": true,
			"encryption_implemented": true,
			"approved_protocols": true,
		},
		"mobile_devices": {
			"connection_controls": true,
			"device_registration": true,
			"security_requirements": true,
		},
		"mobile_encryption": {
			"cui_encrypted": true,
			"approved_encryption": true,
			"key_management": true,
		},
		"external_systems": {
			"connection_verification": true,
			"usage_limitations": true,
			"security_assessments": true,
		},
		"portable_storage": {
			"usage_restrictions": true,
			"authorization_required": true,
			"security_controls": true,
		},
		"public_systems": {
			"cui_restrictions": true,
			"review_procedures": true,
			"removal_capability": true,
		},
	},
	"nist_800_171": {
		"awareness_training": {
			"awareness": {
				"program_established": true,
				"all_personnel_covered": true,
				"risk_topics_included": true,
				"periodic_refreshes": true,
			},
			"role_training": {
				"role_specific_content": true,
				"completion_tracked": true,
				"before_access_granted": true,
			},
			"threat_training": {
				"phishing_covered": true,
				"social_engineering_covered": true,
				"insider_threat_covered": true,
				"reporting_procedures_covered": true,
			},
		},
		"audit_accountability": {
			"audit_logs": {
				"logging_enabled": true,
				"retention_period_days": 90,
				"covers_all_systems": true,
			},
			"user_tracing": {
				"unique_user_ids": true,
				"shared_accounts_prohibited": true,
				"audit_trail_complete": true,
			},
			"event_review": {
				"events_defined": true,
				"periodic_review_performed": true,
				"updates_documented": true,
			},
			"failure_alerting": {
				"alerts_configured": true,
				"responsible_personnel_notified": true,
				"response_procedures_documented": true,
			},
			"correlation": {
				"correlation_capability": true,
				"cross_system_analysis": true,
				"reporting_integrated": true,
			},
			"reduction": {
				"reduction_capability": true,
				"report_generation": true,
				"on_demand_analysis": true,
			},
			"time_sync": {
				"ntp_configured": true,
				"authoritative_source": true,
				"all_systems_synchronized": true,
			},
			"audit_protection": {
				"access_restricted": true,
				"integrity_protected": true,
				"deletion_prevented": true,
			},
			"audit_management": {
				"restricted_to_privileged": true,
				"access_list_documented": true,
				"separation_of_duties": true,
			},
		},
		"configuration_management": {
			"baselines": {
				"documented": true,
				"inventory_maintained": true,
				"includes_all_components": true,
				"reviewed_periodically": true,
			},
			"security_settings": {
				"settings_defined": true,
				"enforcement_automated": true,
				"deviations_approved": true,
			},
			"change_control": {
				"change_tracking": true,
				"review_process": true,
				"approval_required": true,
				"changes_logged": true,
			},
			"impact_analysis": {
				"performed_before_implementation": true,
				"security_team_involved": true,
				"results_documented": true,
			},
			"change_access": {
				"physical_restrictions_defined": true,
				"logical_restrictions_defined": true,
				"approval_documented": true,
				"enforcement_implemented": true,
			},
			"least_functionality": {
				"unnecessary_functions_disabled": true,
				"reviewed_periodically": true,
				"documented_rationale": true,
			},
			"nonessential": {
				"ports_restricted": true,
				"protocols_restricted": true,
				"services_restricted": true,
				"programs_restricted": true,
			},
			"software_policy": {
				"deny_by_exception_implemented": true,
				"authorized_software_list": true,
				"enforcement_automated": true,
			},
			"user_software": {
				"installation_restricted": true,
				"monitoring_implemented": true,
				"policy_documented": true,
			},
		},
		"identification_authentication": {
			"identification": {
				"users_identified": true,
				"processes_identified": true,
				"devices_identified": true,
			},
			"authentication": {
				"required_before_access": true,
				"all_entry_points_covered": true,
				"mechanism_documented": true,
			},
			"mfa": {
				"privileged_local_mfa": true,
				"privileged_network_mfa": true,
				"non_privileged_network_mfa": true,
			},
			"replay_resistant": {
				"mechanism_implemented": true,
				"covers_privileged": true,
				"covers_non_privileged": true,
			},
			"identifier_mgmt": {
				"inactivity_period_days": 35,
				"disable_on_inactivity": true,
				"unique_identifiers": true,
			},
			"inactivity_disable": {
				"policy_defined": true,
				"automated_enforcement": true,
				"period_documented": true,
			},
			"password_complexity": {
				"minimum_length": 12,
				"complexity_enforced": true,
				"change_requirements_defined": true,
			},
			"password_reuse": {
				"generations_remembered": 5,
				"enforcement_automated": true,
			},
			"temp_password": {
				"immediate_change_required": true,
				"secure_delivery": true,
				"expiry_enforced": true,
			},
			"password_crypto": {
				"storage_hashed": true,
				"transmission_encrypted": true,
				"approved_algorithms": true,
			},
			"feedback": {
				"password_masked": true,
				"no_hint_displayed": true,
				"all_interfaces_covered": true,
			},
		},
		"incident_response": {
			"handling": {
				"plan_documented": true,
				"preparation_phase": true,
				"detection_procedures": true,
				"analysis_procedures": true,
				"containment_procedures": true,
				"recovery_procedures": true,
				"user_response_procedures": true,
			},
			"tracking": {
				"incident_tracking_system": true,
				"documentation_required": true,
				"designated_officials_identified": true,
				"reporting_timelines_defined": true,
			},
			"testing": {
				"tested_annually": true,
				"test_type_documented": true,
				"results_reviewed": true,
				"lessons_incorporated": true,
			},
		},
		"maintenance": {
			"maintenance_schedule": {
				"schedule_documented": true,
				"performed_regularly": true,
				"records_maintained": true,
			},
			"controls": {
				"approved_tools": true,
				"approved_techniques": true,
				"authorized_personnel_only": true,
				"controls_documented": true,
			},
			"sanitization": {
				"removed_equipment_sanitized": true,
				"sanitization_verified": true,
				"process_documented": true,
			},
			"diagnostic_media": {
				"scanned_before_use": true,
				"approved_scanning_tool": true,
				"results_documented": true,
			},
			"remote_maintenance": {
				"mfa_required": true,
				"session_terminated_after": true,
				"connections_monitored": true,
			},
			"supervision": {
				"unauthorized_personnel_supervised": true,
				"supervisor_has_required_access": true,
				"supervision_documented": true,
			},
		},
		"media_protection": {
			"physical": {
				"paper_media_secured": true,
				"digital_media_secured": true,
				"access_controlled": true,
			},
			"access": {
				"authorized_users_only": true,
				"access_list_documented": true,
				"access_enforcement_implemented": true,
			},
			"sanitization": {
				"sanitized_before_disposal": true,
				"sanitized_before_reuse": true,
				"method_documented": true,
				"verification_performed": true,
			},
			"marking": {
				"cui_markings_applied": true,
				"distribution_limitations_marked": true,
				"marking_policy_documented": true,
			},
			"transport": {
				"access_controlled_during_transport": true,
				"accountability_maintained": true,
				"chain_of_custody_documented": true,
			},
			"transport_crypto": {
				"encryption_implemented": true,
				"approved_algorithms": true,
				"covers_all_cui_transport": true,
			},
			"removable": {
				"usage_policy_defined": true,
				"technical_controls_implemented": true,
				"approval_required": true,
			},
			"portable_storage": {
				"owner_identification_required": true,
				"unidentified_devices_prohibited": true,
				"enforcement_implemented": true,
			},
			"backup": {
				"backups_encrypted": true,
				"storage_location_secured": true,
				"access_restricted": true,
			},
		},
		"personnel_security": {
			"screening": {
				"background_checks_performed": true,
				"criteria_documented": true,
				"rescreening_policy": true,
			},
			"personnel_actions": {
				"termination_procedures": true,
				"transfer_procedures": true,
				"access_revocation_timely": true,
				"property_return_required": true,
			},
		},
		"physical_protection": {
			"access": {
				"authorized_individuals_only": true,
				"access_controls_implemented": true,
				"access_list_maintained": true,
			},
			"monitoring": {
				"facility_monitored": true,
				"support_infrastructure_monitored": true,
				"monitoring_continuous": true,
			},
			"visitors": {
				"escort_required": true,
				"activity_monitored": true,
				"visitor_log_maintained": true,
			},
			"access_logs": {
				"logs_maintained": true,
				"covers_all_entry_points": true,
				"retention_period_days": 90,
				"reviewed_periodically": true,
			},
			"access_devices": {
				"inventory_maintained": true,
				"issuance_tracked": true,
				"revocation_procedures": true,
				"periodic_audit": true,
			},
			"alternate_sites": {
				"safeguards_defined": true,
				"safeguards_enforced": true,
				"includes_remote_work": true,
			},
		},
		"risk_assessment": {
			"assessment": {
				"performed_annually": true,
				"covers_operations": true,
				"covers_assets": true,
				"covers_individuals": true,
				"results_documented": true,
			},
			"vulnerability_scanning": {
				"periodic_scans_performed": true,
				"triggered_on_new_vulnerabilities": true,
				"covers_all_systems": true,
				"results_documented": true,
			},
			"remediation": {
				"risk_based_prioritization": true,
				"critical_days": 15,
				"high_days": 30,
				"tracking_system": true,
			},
		},
		"security_assessment": {
			"controls_assessment": {
				"periodic_assessments": true,
				"effectiveness_determined": true,
				"results_documented": true,
				"independent_assessor": true,
			},
			"plans_of_action": {
				"poam_documented": true,
				"deficiencies_tracked": true,
				"milestones_defined": true,
				"progress_monitored": true,
			},
			"continuous_monitoring": {
				"monitoring_implemented": true,
				"ongoing_not_just_periodic": true,
				"automated_where_possible": true,
			},
			"ssp": {
				"plan_documented": true,
				"system_boundary_defined": true,
				"environment_described": true,
				"requirements_implementation_described": true,
				"interconnections_documented": true,
				"updated_periodically": true,
			},
		},
		"system_communications": {
			"boundary": {
				"external_boundaries_monitored": true,
				"key_internal_boundaries_monitored": true,
				"communications_controlled": true,
			},
			"engineering": {
				"security_by_design": true,
				"secure_sdlc": true,
				"principles_documented": true,
			},
			"separation": {
				"user_mgmt_separated": true,
				"technical_controls_implemented": true,
				"admin_interfaces_distinct": true,
			},
			"shared_resources": {
				"unauthorized_transfer_prevented": true,
				"resource_isolation": true,
				"controls_documented": true,
			},
			"dmz": {
				"public_components_separated": true,
				"physical_or_logical_separation": true,
				"internal_network_protected": true,
			},
			"deny_all": {
				"default_deny_implemented": true,
				"permit_by_exception": true,
				"exceptions_documented": true,
			},
			"split_tunneling": {
				"prevention_implemented": true,
				"vpn_configured_correctly": true,
				"policy_enforced": true,
			},
			"transmission": {
				"encryption_implemented": true,
				"approved_algorithms": true,
				"covers_all_cui_transmission": true,
			},
			"session_timeout": {
				"inactivity_timeout_defined": true,
				"automatic_termination": true,
				"all_connection_types_covered": true,
			},
			"key_management": {
				"key_generation_documented": true,
				"key_distribution_secured": true,
				"key_rotation_policy": true,
				"key_destruction_procedures": true,
			},
			"fips": {
				"fips_validated_modules": true,
				"covers_cui_protection": true,
				"inventory_maintained": true,
			},
			"collaborative_devices": {
				"remote_activation_prohibited": true,
				"presence_indicator": true,
				"policy_documented": true,
			},
			"mobile_code": {
				"usage_policy_defined": true,
				"technical_controls": true,
				"monitoring_implemented": true,
			},
			"voip": {
				"usage_policy_defined": true,
				"technical_controls": true,
				"monitoring_implemented": true,
			},
			"authenticity": {
				"session_authentication": true,
				"replay_protection": true,
				"mechanisms_documented": true,
			},
			"data_at_rest": {
				"encryption_implemented": true,
				"approved_algorithms": true,
				"covers_all_cui_storage": true,
			},
		},
		"system_information": {
			"flaws": {
				"identification_process": true,
				"reporting_process": true,
				"timely_correction": true,
				"tracking_system": true,
			},
			"malicious_code": {
				"protection_at_entry_exit": true,
				"workstation_protection": true,
				"server_protection": true,
				"approved_solution": true,
			},
			"alerts": {
				"monitoring_implemented": true,
				"advisories_tracked": true,
				"response_procedures_defined": true,
				"subscribed_to_threat_feeds": true,
			},
			"malicious_code_updates": {
				"automatic_updates": true,
				"update_frequency_defined": true,
				"all_systems_covered": true,
			},
			"scanning": {
				"periodic_scans_performed": true,
				"real_time_scanning": true,
				"external_source_files_scanned": true,
				"scan_schedule_defined": true,
			},
			"attack_detection": {
				"system_monitoring": true,
				"inbound_traffic_monitored": true,
				"outbound_traffic_monitored": true,
				"ioc_detection": true,
			},
			"unauthorized_use": {
				"detection_mechanisms": true,
				"baseline_established": true,
				"anomaly_detection": true,
				"response_procedures": true,
			},
		},
	},
}

_attest_only := {id: true | some id, _ in main.requirements; not main.fact_checks[id]}

_green := object.union(_facts, {"nist_sp_800_171": {"requirements": _attest_only}})

test_table_counts_match_cprt if {
	count(main.requirements) == 97
	count(main.withdrawn) == 33
	count(main.families) == 17
	sum([count(r.statements) | some r in main.requirements]) == 349
	count(main.fact_checks) == 79
	count(main.retired_rev2_checks) == 11
}

test_no_withdrawn_id_is_a_control if {
	count({id | some id, _ in main.withdrawn; main.requirements[id]}) == 0
}

test_every_requirement_keyed_under_its_family if {
	count({id | some id, r in main.requirements; not startswith(id, concat("", [r.family, "."]))}) == 0
	count({id | some id, r in main.requirements; not main.families[r.family]}) == 0
	count({s | some id, r in main.requirements; some s, _ in r.statements; not startswith(s, concat("", ["SR-", id]))}) == 0
}

test_fact_checks_point_at_active_requirements_and_real_rules if {
	count({id | some id, _ in main.fact_checks; not main.requirements[id]}) == 0
	count({c.rule | some _, cs in main.fact_checks; some c in cs; not data.nist.sp800_171[c.pkg][c.rule] == false}) == 0 with input as {}
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.requirements_satisfied == 0
	r.violation_count > 18
}

test_non_object_attestations_fail_closed if {
	r := main.compliance_report with input as object.union(_facts, {"nist_sp_800_171": {"requirements": ["03.01.01"]}})
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.requirements_satisfied == 97
	r.families_passing == 17
}

test_attestations_alone_satisfy_only_the_attested_requirements if {
	r := main.compliance_report with input as {"nist_sp_800_171": {"requirements": _all}}
	r.compliant == false
	r.requirements_satisfied == 18
	r.requirements["03.01.01"].basis == "facts"
	r.requirements["03.01.01"].attested == true
	r.requirements["03.01.01"].satisfied == false
	r.requirements["03.17.01"].basis == "attestation"
	r.requirements["03.17.01"].satisfied == true
}

test_facts_alone_satisfy_only_the_fact_evaluated_requirements_and_fail_closed if {
	r := main.compliance_report with input as _facts
	r.compliant == false
	r.requirements_satisfied == 79
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_attesting_a_fact_evaluated_id_is_accepted_but_does_not_decide_it if {
	main.compliant with input as object.union(_facts, {"nist_sp_800_171": {"requirements": _all}})
	r := main.compliance_report with input as json.patch(_green, [
		{"op": "add", "path": "/nist_sp_800_171/requirements/03.01.12", "value": true},
		{"op": "replace", "path": "/cui_access/managed_access/designated_control_points", "value": false},
	])
	r.requirements["03.01.12"].satisfied == false
}

test_one_requirement_per_family_resolves if {
	r := main.compliance_report with input as _green
	main.requirements["03.01.01"].family == "03.01"
	main.requirements["03.01.01"].title == "Account Management"
	r.requirements["03.01.01"].satisfied == true
	main.requirements["03.02.01"].family == "03.02"
	main.requirements["03.02.01"].title == "Literacy Training and Awareness"
	r.requirements["03.02.01"].satisfied == true
	main.requirements["03.03.01"].family == "03.03"
	main.requirements["03.03.01"].title == "Event Logging"
	r.requirements["03.03.01"].satisfied == true
	main.requirements["03.04.01"].family == "03.04"
	main.requirements["03.04.01"].title == "Baseline Configuration"
	r.requirements["03.04.01"].satisfied == true
	main.requirements["03.05.01"].family == "03.05"
	main.requirements["03.05.01"].title == "User Identification and Authentication"
	r.requirements["03.05.01"].satisfied == true
	main.requirements["03.06.01"].family == "03.06"
	main.requirements["03.06.01"].title == "Incident Handling"
	r.requirements["03.06.01"].satisfied == true
	main.requirements["03.07.04"].family == "03.07"
	main.requirements["03.07.04"].title == "Maintenance Tools"
	r.requirements["03.07.04"].satisfied == true
	main.requirements["03.08.01"].family == "03.08"
	main.requirements["03.08.01"].title == "Media Storage"
	r.requirements["03.08.01"].satisfied == true
	main.requirements["03.09.01"].family == "03.09"
	main.requirements["03.09.01"].title == "Personnel Screening"
	r.requirements["03.09.01"].satisfied == true
	main.requirements["03.10.01"].family == "03.10"
	main.requirements["03.10.01"].title == "Physical Access Authorizations"
	r.requirements["03.10.01"].satisfied == true
	main.requirements["03.11.01"].family == "03.11"
	main.requirements["03.11.01"].title == "Risk Assessment"
	r.requirements["03.11.01"].satisfied == true
	main.requirements["03.12.01"].family == "03.12"
	main.requirements["03.12.01"].title == "Security Assessment"
	r.requirements["03.12.01"].satisfied == true
	main.requirements["03.13.01"].family == "03.13"
	main.requirements["03.13.01"].title == "Boundary Protection"
	r.requirements["03.13.01"].satisfied == true
	main.requirements["03.14.01"].family == "03.14"
	main.requirements["03.14.01"].title == "Flaw Remediation"
	r.requirements["03.14.01"].satisfied == true
	main.requirements["03.15.01"].family == "03.15"
	main.requirements["03.15.01"].title == "Policy and Procedures"
	r.requirements["03.15.01"].satisfied == true
	main.requirements["03.16.01"].family == "03.16"
	main.requirements["03.16.01"].title == "Security Engineering Principles"
	r.requirements["03.16.01"].satisfied == true
	main.requirements["03.17.01"].family == "03.17"
	main.requirements["03.17.01"].title == "Supply Chain Risk Management Plan"
	r.requirements["03.17.01"].satisfied == true
}

test_folded_rev2_fact_gates_its_incorporating_requirement if {
	# Rev 2 3.1.14 (managed access control points) is withdrawn in Rev 3, "Incorporated into 03.01.12."
	inp := json.patch(_green, [{"op": "replace", "path": "/cui_access/managed_access/designated_control_points", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.requirements["03.01.12"].satisfied == false
	r.requirements["03.01.12"].fact_checks_failed == ["3.1.14"]
	r.families["03.01"].gaps == ["03.01.12"]
	r.requirements_satisfied == 96
}

test_retired_rev2_fact_gates_nothing if {
	# Rev 2 3.13.14 (VoIP) is withdrawn in Rev 3 as "Technology-specific."
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_800_171/system_communications/voip/usage_policy_defined", "value": false}])
	main.compliant with input as inp
}

test_attested_only_requirement_gap if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_sp_800_171/requirements/03.17.02", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.families["03.17"].gaps == ["03.17.02"]
	r.violation_count == 1
}

test_withdrawn_id_attestation_is_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_sp_800_171/requirements/03.01.13", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	some v in r.violations
	contains(v, "03.01.13 is withdrawn in Rev 3")
}

test_unknown_and_rev2_style_ids_are_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_sp_800_171/requirements/3.1.1", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	some v in r.violations
	contains(v, "unknown requirement id 3.1.1")
}
