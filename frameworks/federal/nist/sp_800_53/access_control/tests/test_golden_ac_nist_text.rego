# Golden cases for NIST SP 800-53 Rev 5 Access Control, built from the control statements in the NIST OSCAL
# catalog (SP 800-53 Rev 5.2.0, public domain). Each case cites the control and statement item and quotes one
# short phrase of it. A fail case starts from a configuration that meets every AC control evaluated here and
# breaks only the element the quoted statement item requires: exactly that control is reported, as a finding
# rather than missing evidence, and the family aggregate is no longer compliant. A pass case puts a value at or
# inside the organization-defined parameter (ODP) and expects no finding for that control.
#
# Issue #305 (golden test cases from the standards' own text); these cases also kill the body-line mutants that
# scripts/mutation_test.py found surviving in ac_controls.rego (#306).
package nist.sp800_53.access_control_golden_test

import data.nist.sp800_53.access_control as ac
import rego.v1

_green := {"ac_controls": {
	"policy": {"documented": true, "disseminated": true, "reviewed_updated": true},
	"procedures": {"implementation_documented": true},
	"account_management": {
		"approval_process": true, "regular_reviews": true, "timely_removal": true, "automated_tools": true,
		"temporary_accounts": {"automated_expiry_enforced": true, "max_lifetime_hours": 72, "odp": {"max_lifetime_hours": 72}},
		"disable_accounts": {"inactivity_threshold_days": 35, "max_days_to_disable": 1, "odp": {"inactivity_days": 35, "disable_within_days": 1}},
		"automated_audit": {"creation": true, "modification": true, "enabling": true, "disabling": true, "removal": true},
		"inactivity_logout": {"enforced": true, "logout_after_minutes": 15, "odp": {"logout_after_minutes": 30}},
		"high_risk_individuals": {"max_hours_to_disable": 0, "odp": {"disable_within_hours": 1, "significant_risks": ["termination for cause"]}},
		"privileged_user_accounts": {
			"administered_per_scheme": true, "assignments_monitored": true, "changes_monitored": true,
			"inappropriate_assignments_not_revoked": 0, "odp": {"scheme": "role-based"},
		},
		"shared_accounts": {"accounts_not_meeting_conditions": 0, "odp": {"conditions": ["break-glass only, checked out from the vault"]}},
		"usage_conditions": {"accounts_without_enforced_conditions": 0, "odp": {"conditions": ["business hours"], "accounts": ["batch-*"]}},
		"atypical_usage": {"monitoring_enabled": true, "detections_not_reported": 0, "odp": {"atypical_usage": ["off-hours logon"], "report_to": ["soc"]}},
	},
	"access_enforcement": {"role_based_access_control": true},
	"information_flow": {
		"flow_control_policies": true, "automated_enforcement": true, "security_labels": true,
		"encrypted_information": {"action_enforced": true, "uninspected_encrypted_flows": 0, "odp": {"mechanisms": ["egress proxy"], "action": "decrypt"}},
		"separation": {"separations_not_enforced": 0, "odp": {"mechanisms": ["vlans"], "required_separations": ["management from user traffic"]}},
	},
	"separation_duties": {"critical_functions_divided": true, "documented_assignments": true},
	"least_privilege": {
		"minimum_access_granted": true, "privileged_functions_authorized": true, "non_privileged_access_default": true,
		"privileged_functions_logged": true, "non_privileged_execution_prevented": true,
		"privileged_accounts": {"accounts_outside_authorized_roles": 0, "odp": {"authorized_roles": ["sysadmin"]}},
		"privilege_review": {"days_since_last": 30, "unremediated_findings": 0, "odp": {"frequency_days": 90}},
		"network_privileged_commands": {"accounts_without_documented_need": 0, "rationale_in_security_plan": true, "odp": {"commands": ["sudo"], "needs": ["on-call recovery"]}},
		"code_execution": {"software_above_user_privilege": 0, "odp": {"software": ["office suite", "browsers"]}},
	},
	"logon_attempts": {"lockout_configured": true, "maximum_attempts": 3, "odp": {"max_attempts": 3}},
	"use_notification": {"banner_displayed": true, "acknowledgment_required": true, "monitoring_consent": true},
	"logon_notification": {"timestamp_displayed": true, "unsuccessful_attempts_displayed": true, "location_displayed": true},
	"session_control": {"limits_configured": true, "per_account_limits": true},
	"session_lock": {"inactivity_timeout": 900, "authentication_required": true, "pattern_hiding": true, "odp": {"inactivity_timeout": 900}},
	"session_termination": {"automatic_termination": true, "user_initiated": true},
	"permitted_actions": {"unauthenticated_functions": [], "organization_approved_functions": [], "rationale_documented": true},
	"security_attributes": {"attribute_binding": true, "attribute_association": true, "transmission_preservation": true},
	"remote_access": {
		"authorized_only": true, "monitored_controlled": true, "encrypted_connections": true, "unmanaged_access_points": 0,
		"privileged_commands": {"restricted_to_defined_needs": true, "assessable_evidence_produced": true, "rationale_in_security_plan": true, "odp": {"needs": ["break-glass recovery"]}},
	},
	"wireless_access": {
		"authorized_only": true, "encrypted_authentication": true, "components_with_unused_wireless_enabled": 0,
		"user_configuration": {"authorized_users_identified": true, "unauthorized_users_able_to_configure": 0},
		"signal_containment": {"power_levels_calibrated": true, "access_points_detected_outside_boundary": 0},
	},
	"mobile_devices": {
		"usage_restrictions": true, "connection_requirements": true, "configuration_requirements": true,
		"encryption": {"devices_without_required_encryption": 0, "odp": {"method": "full-device"}},
	},
	"external_systems": {
		"authorized_only": true, "security_requirements": true, "user_agreements": true,
		"limits_on_authorized_use": {"systems_without_verification_or_agreement": 0},
		"portable_storage": {"restrictions_enforced": true, "odp": {"restrictions": ["encrypted devices only"]}},
	},
	"information_sharing": {"user_discretion_limited": true, "automated_guidance": true},
	"public_content": {"authorized_personnel_only": true, "review_process": true, "removal_procedures": true},
	"data_mining": {"detection_techniques": true, "warning_notifications": true, "response_procedures": true},
	"decisions": {"security_attributes_used": true, "consistent_enforcement": true, "documented_criteria": true},
	"reference_monitor": {"tamper_proof": true, "always_invoked": true, "small_verifiable": true},
}}

_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

test_golden_green_configuration_meets_every_ac_control if {
	r := ac.compliance_report with input as _green
	r.violation_count == 0
	ac.nist_sp800_53_ac_compliant with input as _green
}

# AC-1 item a: "Develop, document, and disseminate"
test_golden_ac_1_policy_not_documented_fails if {
	fx := object.union(_green, {"ac_controls": {"policy": {"documented": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-1"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-1 item a: "Develop, document, and disseminate"
test_golden_ac_1_policy_not_disseminated_fails if {
	fx := object.union(_green, {"ac_controls": {"policy": {"disseminated": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-1"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-1 item c.1: "Review and update"
test_golden_ac_1_policy_not_reviewed_fails if {
	fx := object.union(_green, {"ac_controls": {"policy": {"reviewed_updated": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-1"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-1 item a.2: "Procedures to facilitate the implementation"
test_golden_ac_1_procedures_missing_fails if {
	fx := object.union(_green, {"ac_controls": {"procedures": {"implementation_documented": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-1"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-2 item e: "Require approvals"
test_golden_ac_2_no_approval_for_new_accounts_fails if {
	fx := object.union(_green, {"ac_controls": {"account_management": {"approval_process": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-2 item j: "Review accounts for compliance"
test_golden_ac_2_accounts_not_reviewed_fails if {
	fx := object.union(_green, {"ac_controls": {"account_management": {"regular_reviews": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-2 item f: "disable, and remove accounts"
test_golden_ac_2_accounts_not_removed_fails if {
	fx := object.union(_green, {"ac_controls": {"account_management": {"timely_removal": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-2(1): "Support the management of system accounts"
test_golden_ac_2_1_no_automated_account_management_fails if {
	fx := object.union(_green, {"ac_controls": {"account_management": {"automated_tools": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-3: "Enforce approved authorizations for logical access"
test_golden_ac_3_no_access_model_enforced_fails if {
	fx := object.union(_green, {"ac_controls": {"access_enforcement": {"role_based_access_control": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-3"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-4: "controlling the flow of information"
test_golden_ac_4_no_flow_control_policy_fails if {
	fx := object.union(_green, {"ac_controls": {"information_flow": {"flow_control_policies": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-4"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-4: "Enforce approved authorizations"
test_golden_ac_4_flow_policy_not_enforced_fails if {
	fx := object.union(_green, {"ac_controls": {"information_flow": {"automated_enforcement": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-4"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-4(1): "as a basis for flow control decisions"
test_golden_ac_4_1_no_flow_attributes_fails if {
	fx := object.union(_green, {"ac_controls": {"information_flow": {"security_labels": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-4(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-5 item a: "Identify and document"
test_golden_ac_5_duties_not_divided_fails if {
	fx := object.union(_green, {"ac_controls": {"separation_duties": {"critical_functions_divided": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-5"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-5 item b: "support separation of duties"
test_golden_ac_5_assignments_not_documented_fails if {
	fx := object.union(_green, {"ac_controls": {"separation_duties": {"documented_assignments": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-5"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-6: "only authorized accesses"
test_golden_ac_6_excess_access_granted_fails if {
	fx := object.union(_green, {"ac_controls": {"least_privilege": {"minimum_access_granted": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-6"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-6(1): "Authorize access for"
test_golden_ac_6_1_security_functions_unauthorized_fails if {
	fx := object.union(_green, {"ac_controls": {"least_privilege": {"privileged_functions_authorized": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-6(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-6(2): "use non-privileged accounts or roles"
test_golden_ac_6_2_privileged_account_for_nonsecurity_work_fails if {
	fx := object.union(_green, {"ac_controls": {"least_privilege": {"non_privileged_access_default": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-6(2)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-7 item a: "Enforce a limit of"
test_golden_ac_7_attempts_above_org_limit_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"maximum_attempts": 4}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-7"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-7 item b: "when the maximum number of unsuccessful attempts is exceeded"
test_golden_ac_7_no_lockout_action_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"lockout_configured": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-7"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-8 item a: "before granting access to the system"
test_golden_ac_8_no_banner_fails if {
	fx := object.union(_green, {"ac_controls": {"use_notification": {"banner_displayed": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-8"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-8 item b: "until users acknowledge the usage conditions"
test_golden_ac_8_banner_not_retained_until_acknowledged_fails if {
	fx := object.union(_green, {"ac_controls": {"use_notification": {"acknowledgment_required": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-8"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-8 item a.4: "consent to monitoring and recording"
test_golden_ac_8_no_monitoring_consent_fails if {
	fx := object.union(_green, {"ac_controls": {"use_notification": {"monitoring_consent": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-8"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-9: "the date and time of the last logon"
test_golden_ac_9_last_logon_not_shown_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_notification": {"timestamp_displayed": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-9"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-9(1): "the number of unsuccessful logon attempts"
test_golden_ac_9_1_failed_attempts_not_shown_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_notification": {"unsuccessful_attempts_displayed": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-9(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-9(4): "additional information"
test_golden_ac_9_4_additional_info_not_shown_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_notification": {"location_displayed": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-9(4)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-10: "Limit the number of concurrent sessions"
test_golden_ac_10_no_session_limit_fails if {
	fx := object.union(_green, {"ac_controls": {"session_control": {"limits_configured": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-10"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-10: "for each"
test_golden_ac_10_limit_not_per_account_fails if {
	fx := object.union(_green, {"ac_controls": {"session_control": {"per_account_limits": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-10"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-11 item a: "Prevent further access to the system"
test_golden_ac_11_lock_later_than_org_period_fails if {
	fx := object.union(_green, {"ac_controls": {"session_lock": {"inactivity_timeout": 901}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-11"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-11 item b: "Retain the device lock until the user reestablishes access"
test_golden_ac_11_lock_released_without_reauth_fails if {
	fx := object.union(_green, {"ac_controls": {"session_lock": {"authentication_required": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-11"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-11(1): "Conceal, via the device lock"
test_golden_ac_11_1_lock_screen_shows_content_fails if {
	fx := object.union(_green, {"ac_controls": {"session_lock": {"pattern_hiding": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-11(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-12: "Automatically terminate a user session"
test_golden_ac_12_no_automatic_termination_fails if {
	fx := object.union(_green, {"ac_controls": {"session_termination": {"automatic_termination": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-12"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-12(1): "Provide a logout capability"
test_golden_ac_12_1_no_user_logout_fails if {
	fx := object.union(_green, {"ac_controls": {"session_termination": {"user_initiated": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-12(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-14 item a: "without identification or authentication"
test_golden_ac_14_unidentified_action_not_approved_fails if {
	fx := object.union(_green, {"ac_controls": {"permitted_actions": {"unauthenticated_functions": ["admin_console"]}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-14"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-14 item b: "supporting rationale in the security plan"
test_golden_ac_14_no_rationale_fails if {
	fx := object.union(_green, {"ac_controls": {"permitted_actions": {"rationale_documented": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-14"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-16 item a: "Provide the means to associate"
test_golden_ac_16_attributes_not_bound_fails if {
	fx := object.union(_green, {"ac_controls": {"security_attributes": {"attribute_binding": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-16"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-16 item b: "made and retained with the information"
test_golden_ac_16_associations_not_retained_fails if {
	fx := object.union(_green, {"ac_controls": {"security_attributes": {"attribute_association": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-16"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-16 item a: "in transmission"
test_golden_ac_16_attributes_lost_in_transmission_fails if {
	fx := object.union(_green, {"ac_controls": {"security_attributes": {"transmission_preservation": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-16"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-17 item b: "Authorize each type of remote access"
test_golden_ac_17_remote_access_unauthorized_fails if {
	fx := object.union(_green, {"ac_controls": {"remote_access": {"authorized_only": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-17"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-17(1): "monitor and control remote access methods"
test_golden_ac_17_1_remote_access_unmonitored_fails if {
	fx := object.union(_green, {"ac_controls": {"remote_access": {"monitored_controlled": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-17(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-17(2): "confidentiality and integrity of remote access sessions"
test_golden_ac_17_2_remote_access_unencrypted_fails if {
	fx := object.union(_green, {"ac_controls": {"remote_access": {"encrypted_connections": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-17(2)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-18 item b: "Authorize each type of wireless access"
test_golden_ac_18_wireless_unauthorized_fails if {
	fx := object.union(_green, {"ac_controls": {"wireless_access": {"authorized_only": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-18"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-18(1): "using authentication of"
test_golden_ac_18_1_wireless_without_auth_encryption_fails if {
	fx := object.union(_green, {"ac_controls": {"wireless_access": {"encrypted_authentication": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-18(1)"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-19 item a: "Establish configuration requirements"
test_golden_ac_19_mobile_no_configuration_requirements_fails if {
	fx := object.union(_green, {"ac_controls": {"mobile_devices": {"configuration_requirements": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-19"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-19 item a: "connection requirements"
test_golden_ac_19_mobile_no_connection_requirements_fails if {
	fx := object.union(_green, {"ac_controls": {"mobile_devices": {"connection_requirements": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-19"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-19 item a: "implementation guidance"
test_golden_ac_19_mobile_no_usage_restrictions_fails if {
	fx := object.union(_green, {"ac_controls": {"mobile_devices": {"usage_restrictions": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-19"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-20 item a: "allowing authorized individuals to"
test_golden_ac_20_external_systems_not_authorized_fails if {
	fx := object.union(_green, {"ac_controls": {"external_systems": {"authorized_only": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-20"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-20 item a: "consistent with the trust relationships"
test_golden_ac_20_external_systems_no_security_requirements_fails if {
	fx := object.union(_green, {"ac_controls": {"external_systems": {"security_requirements": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-20"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-20 item a: "trust relationships established with other organizations"
test_golden_ac_20_external_systems_no_agreements_fails if {
	fx := object.union(_green, {"ac_controls": {"external_systems": {"user_agreements": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-20"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-21 item a: "Enable authorized users to determine"
test_golden_ac_21_sharing_left_to_user_discretion_fails if {
	fx := object.union(_green, {"ac_controls": {"information_sharing": {"user_discretion_limited": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-21"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-21 item b: "assist users in making information sharing"
test_golden_ac_21_no_sharing_decision_aid_fails if {
	fx := object.union(_green, {"ac_controls": {"information_sharing": {"automated_guidance": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-21"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-22 item a: "Designate individuals authorized"
test_golden_ac_22_anyone_can_publish_fails if {
	fx := object.union(_green, {"ac_controls": {"public_content": {"authorized_personnel_only": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-22"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-22 item c: "Review the proposed content"
test_golden_ac_22_content_not_reviewed_fails if {
	fx := object.union(_green, {"ac_controls": {"public_content": {"review_process": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-22"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-22 item d: "remove such information, if discovered"
test_golden_ac_22_nonpublic_content_not_removed_fails if {
	fx := object.union(_green, {"ac_controls": {"public_content": {"removal_procedures": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-22"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-23: "to detect and protect against unauthorized data mining"
test_golden_ac_23_no_mining_detection_fails if {
	fx := object.union(_green, {"ac_controls": {"data_mining": {"detection_techniques": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-23"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-23: "detect and protect"
test_golden_ac_23_no_mining_warning_fails if {
	fx := object.union(_green, {"ac_controls": {"data_mining": {"warning_notifications": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-23"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-23: "protect against unauthorized data mining"
test_golden_ac_23_no_mining_response_fails if {
	fx := object.union(_green, {"ac_controls": {"data_mining": {"response_procedures": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-23"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-24: "applied to each access request"
test_golden_ac_24_decisions_ignore_attributes_fails if {
	fx := object.union(_green, {"ac_controls": {"decisions": {"security_attributes_used": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-24"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-24: "prior to access enforcement"
test_golden_ac_24_decisions_inconsistent_fails if {
	fx := object.union(_green, {"ac_controls": {"decisions": {"consistent_enforcement": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-24"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-24: "to ensure"
test_golden_ac_24_decision_criteria_undocumented_fails if {
	fx := object.union(_green, {"ac_controls": {"decisions": {"documented_criteria": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-24"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-25: "tamperproof"
test_golden_ac_25_monitor_not_tamperproof_fails if {
	fx := object.union(_green, {"ac_controls": {"reference_monitor": {"tamper_proof": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-25"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-25: "always invoked"
test_golden_ac_25_monitor_bypassable_fails if {
	fx := object.union(_green, {"ac_controls": {"reference_monitor": {"always_invoked": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-25"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-25: "small enough to be subject to analysis and testing"
test_golden_ac_25_monitor_not_verifiable_fails if {
	fx := object.union(_green, {"ac_controls": {"reference_monitor": {"small_verifiable": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-25"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-7 item b: "Automatically"
test_golden_ac_7_lockout_shorter_than_org_period_fails if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"lockout_duration": 29, "odp": {"lockout_duration": 30}}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-7"}
	not contains(concat("", r.violations), "evidence missing")
	not ac.nist_sp800_53_ac_compliant with input as fx
}

# AC-7 item a: "Enforce a limit of" (the value is organization-defined)
test_golden_ac_7_attempts_equal_to_org_limit_passes if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"maximum_attempts": 3, "odp": {"max_attempts": 3}}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-7 item a: "Enforce a limit of" (the value is organization-defined)
test_golden_ac_7_attempts_below_org_limit_passes if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"maximum_attempts": 2, "odp": {"max_attempts": 3}}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-7 item b: "Automatically" (the value is organization-defined)
test_golden_ac_7_lockout_period_equal_to_org_period_passes if {
	fx := object.union(_green, {"ac_controls": {"logon_attempts": {"lockout_duration": 30, "odp": {"lockout_duration": 30}}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-11 item a: "Prevent further access to the system" (the value is organization-defined)
test_golden_ac_11_lock_at_org_period_passes if {
	fx := object.union(_green, {"ac_controls": {"session_lock": {"inactivity_timeout": 900, "odp": {"inactivity_timeout": 900}}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-11 item a: "Prevent further access to the system" (the value is organization-defined)
test_golden_ac_11_lock_before_org_period_passes if {
	fx := object.union(_green, {"ac_controls": {"session_lock": {"inactivity_timeout": 300, "odp": {"inactivity_timeout": 900}}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-14 item a: "Identify" (the value is organization-defined)
test_golden_ac_14_approved_unidentified_action_passes if {
	fx := object.union(_green, {"ac_controls": {"permitted_actions": {"unauthenticated_functions": ["status_page"], "organization_approved_functions": ["status_page"]}}})
	r := ac.compliance_report with input as fx
	r.violation_count == 0
}

# AC-14 item a: "Identify" -- the identified actions must be a list; a string in its place is missing evidence
test_golden_ac_14_actions_as_string_is_evidence_missing if {
	fx := object.union(_green, {"ac_controls": {"permitted_actions": {"unauthenticated_functions": "status_page"}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-14"}
	contains(concat("", r.violations), "evidence missing")
}
