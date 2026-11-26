# METADATA
# title: "NIST SP 800-53 Rev 5 - Access Control (AC) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 98
#     cited: 61
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.access_control

import rego.v1

# NIST SP 800-53 Rev 5 - Access Control (AC) Family
# Security controls for managing access to information systems.
#
# Control ids and titles checked against the NIST OSCAL catalog, SP 800-53 Rev 5 release 5.2.0
# (usnistgov/oscal-content, nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json).
# Evaluated here: AC-1..AC-12, AC-14, AC-16..AC-25 and the enhancements AC-2(1), AC-4(1), AC-6(1), AC-6(2),
# AC-9(1), AC-9(4), AC-11(1), AC-12(1), AC-17(1), AC-17(2), AC-18(1), and the further NIST SP 800-53B Moderate
# enhancements AC-2(2), AC-2(3), AC-2(4), AC-2(5), AC-2(13), AC-6(5), AC-6(7), AC-6(9), AC-6(10), AC-17(3),
# AC-17(4), AC-18(3), AC-19(5), AC-20(1), AC-20(2), and the NIST / FedRAMP High enhancements AC-2(7), AC-2(9),
# AC-2(11), AC-2(12), AC-4(4), AC-4(21), AC-6(3), AC-6(8), AC-18(4), AC-18(5), and the Privacy-baseline enhancement
# AC-3(14), and AC-17(9) (TX-RAMP Level 2 selects it; in no NIST or FedRAMP baseline) (61 ids).
# A base control never fails on an enhancement's requirement; each enhancement is its own finding. Not evaluated: AC-13 (withdrawn,
# incorporated into AC-2 and AU-6) and AC-15 (withdrawn, "incorporated into MP-3" Media Marking; this
# library has no MP family module, so AC-15 is not assessed and never produces a finding).
#
# Organization-defined parameters (ODPs) are not fixed by the base control. Where a check compares a
# configured value with an ODP (AC-7, AC-11, AC-14) the organisation supplies the ODP value under
# `.odp` / `organization_approved_functions`; a missing ODP is reported as missing evidence, never a pass.

# AC-1: Access Control Policy and Procedures
access_control_policy if {
	input.ac_controls.policy.documented == true
	input.ac_controls.policy.disseminated == true
	input.ac_controls.policy.reviewed_updated == true
	input.ac_controls.procedures.implementation_documented == true
}

# AC-2(1): Automated System Account Management
automated_account_management if input.ac_controls.account_management.automated_tools == true

# AC-2: Account Management — approval, review and timely removal; automated tooling is AC-2(1).
account_management if {
	input.ac_controls.account_management.approval_process == true
	input.ac_controls.account_management.regular_reviews == true
	input.ac_controls.account_management.timely_removal == true
}

# AC-3: Access Enforcement — "Enforce approved authorizations for logical access ... in accordance with
# applicable access control policies." The base control does not name a model: MAC, DAC, RBAC and ABAC are
# the separate enhancements AC-3(3), AC-3(4), AC-3(7) and AC-3(13). The check passes when at least one
# access control policy model the organisation chose is evidenced as enforced; none evidenced is a finding.
_ac3_model_fields := [
	"mandatory_access_control",
	"discretionary_access_control",
	"role_based_access_control",
	"attribute_based_access_control",
]

ac3_enforced_models contains m if {
	some m in _ac3_model_fields
	object.get(input, ["ac_controls", "access_enforcement", m], false) == true
}

access_enforcement if count(ac3_enforced_models) > 0

# AC-4(1): Object Security and Privacy Attributes
flow_object_attributes if input.ac_controls.information_flow.security_labels == true

# AC-4: Information Flow Enforcement — approved flow-control policies enforced; labels are AC-4(1).
information_flow_enforcement if {
	input.ac_controls.information_flow.flow_control_policies == true
	input.ac_controls.information_flow.automated_enforcement == true
}

# AC-5: Separation of Duties
separation_of_duties if {
	input.ac_controls.separation_duties.critical_functions_divided == true
	input.ac_controls.separation_duties.documented_assignments == true
}

# AC-6: Least Privilege
# AC-6 base: only the accesses necessary for assigned tasks. AC-6(1) and AC-6(2) are evaluated separately.
least_privilege if input.ac_controls.least_privilege.minimum_access_granted == true

# AC-6(1) Authorize Access to Security Functions
authorize_security_functions if input.ac_controls.least_privilege.privileged_functions_authorized == true

# AC-6(2) Non-privileged Access for Nonsecurity Functions
non_privileged_access_for_nonsecurity if input.ac_controls.least_privilege.non_privileged_access_default == true

# AC-7: Unsuccessful Logon Attempts — "Enforce a limit of [ODP number] consecutive invalid logon attempts
# ... and automatically [ODP action] when the maximum number of unsuccessful attempts is exceeded."
# The limit and the lockout period are organization-defined, not fixed by NIST. The organisation supplies
# them under input.ac_controls.logon_attempts.odp: max_attempts (required) and lockout_duration in minutes
# (only when the chosen action is a timed lock).
_ac7 := object.get(input, ["ac_controls", "logon_attempts"], {})

_ac7_odp_max := object.get(_ac7, ["odp", "max_attempts"], null)

_ac7_odp_lock := object.get(_ac7, ["odp", "lockout_duration"], null)

ac7_evidence_missing contains "input.ac_controls.logon_attempts.odp.max_attempts (organization-defined limit)" if {
	not is_number(_ac7_odp_max)
}

ac7_evidence_missing contains "input.ac_controls.logon_attempts.maximum_attempts" if {
	not is_number(object.get(_ac7, "maximum_attempts", null))
}

ac7_evidence_missing contains "input.ac_controls.logon_attempts.lockout_configured" if {
	not is_boolean(object.get(_ac7, "lockout_configured", null))
}

ac7_evidence_missing contains "input.ac_controls.logon_attempts.lockout_duration" if {
	is_number(_ac7_odp_lock)
	not is_number(object.get(_ac7, "lockout_duration", null))
}

_ac7_lock_ok if not is_number(_ac7_odp_lock)

_ac7_lock_ok if {
	is_number(_ac7_odp_lock)
	_ac7.lockout_duration >= _ac7_odp_lock
}

unsuccessful_logon_attempts if {
	count(ac7_evidence_missing) == 0
	_ac7.lockout_configured == true
	_ac7.maximum_attempts <= _ac7_odp_max
	_ac7_lock_ok
}

# AC-8: System Use Notification
system_use_notification if {
	input.ac_controls.use_notification.banner_displayed == true
	input.ac_controls.use_notification.acknowledgment_required == true
	input.ac_controls.use_notification.monitoring_consent == true
}

# AC-9: Previous Logon Notification
# AC-9 base: date and time of the last logon. AC-9(1) unsuccessful logons; AC-9(4) additional information (location).
previous_logon_notification if input.ac_controls.logon_notification.timestamp_displayed == true

previous_logon_unsuccessful_count if input.ac_controls.logon_notification.unsuccessful_attempts_displayed == true

previous_logon_additional_info if input.ac_controls.logon_notification.location_displayed == true

# AC-10: Concurrent Session Control
concurrent_session_control if {
	input.ac_controls.session_control.limits_configured == true
	input.ac_controls.session_control.per_account_limits == true
}

# AC-11: Device Lock (Rev 5 title; "Session Lock" was the Rev 4 title) — lock after an organization-defined
# period of inactivity and retain the lock until the user re-authenticates. The period is an ODP supplied
# as input.ac_controls.session_lock.odp.inactivity_timeout (seconds, same unit as inactivity_timeout).
# Pattern hiding is the enhancement AC-11(1), evaluated separately.
_ac11 := object.get(input, ["ac_controls", "session_lock"], {})

_ac11_odp := object.get(_ac11, ["odp", "inactivity_timeout"], null)

ac11_evidence_missing contains "input.ac_controls.session_lock.odp.inactivity_timeout (organization-defined period)" if {
	not is_number(_ac11_odp)
}

ac11_evidence_missing contains "input.ac_controls.session_lock.inactivity_timeout" if {
	not is_number(object.get(_ac11, "inactivity_timeout", null))
}

ac11_evidence_missing contains "input.ac_controls.session_lock.authentication_required" if {
	not is_boolean(object.get(_ac11, "authentication_required", null))
}

session_lock if {
	count(ac11_evidence_missing) == 0
	_ac11.inactivity_timeout <= _ac11_odp
	_ac11.authentication_required == true
}

# AC-11(1): Pattern-hiding Displays
pattern_hiding_display if _ac11.pattern_hiding == true

# AC-12: Session Termination
# AC-12 base: automatic termination after defined conditions. User-initiated logout is AC-12(1).
session_termination if input.ac_controls.session_termination.automatic_termination == true

user_initiated_logout if input.ac_controls.session_termination.user_initiated == true

# AC-14: Permitted Actions Without Identification or Authentication — the organisation identifies the
# permitted user actions (ODP) and documents the rationale in the security plan. The approved list is
# supplied as organization_approved_functions; every observed unauthenticated function must be on it.
_ac14 := object.get(input, ["ac_controls", "permitted_actions"], {})

ac14_evidence_missing contains "input.ac_controls.permitted_actions.unauthenticated_functions" if {
	not is_array(object.get(_ac14, "unauthenticated_functions", null))
}

ac14_evidence_missing contains "input.ac_controls.permitted_actions.organization_approved_functions (organization-defined)" if {
	not is_array(object.get(_ac14, "organization_approved_functions", null))
}

ac14_evidence_missing contains "input.ac_controls.permitted_actions.rationale_documented" if {
	not is_boolean(object.get(_ac14, "rationale_documented", null))
}

ac14_unapproved_functions contains f if {
	count(ac14_evidence_missing) == 0
	some f in _ac14.unauthenticated_functions
	not f in _ac14.organization_approved_functions
}

permitted_actions_restricted if {
	count(ac14_evidence_missing) == 0
	count(ac14_unapproved_functions) == 0
	_ac14.rationale_documented == true
}

# AC-16: Security Attributes
security_attributes if {
	input.ac_controls.security_attributes.attribute_binding == true
	input.ac_controls.security_attributes.attribute_association == true
	input.ac_controls.security_attributes.transmission_preservation == true
}

# AC-17: Remote Access
# AC-17 base: each type of remote access authorized. Monitoring is AC-17(1), encryption AC-17(2).
remote_access_control if input.ac_controls.remote_access.authorized_only == true

remote_access_monitoring if input.ac_controls.remote_access.monitored_controlled == true

remote_access_encryption if input.ac_controls.remote_access.encrypted_connections == true

# AC-18: Wireless Access
# AC-18 base: each type of wireless access authorized. Authentication and encryption is AC-18(1).
# (Rev 5 AC-18 has no monitoring requirement; monitored_usage is not read.)
wireless_access_control if input.ac_controls.wireless_access.authorized_only == true

wireless_auth_encryption if input.ac_controls.wireless_access.encrypted_authentication == true

# AC-19: Access Control for Mobile Devices
mobile_device_access_control if {
	input.ac_controls.mobile_devices.usage_restrictions == true
	input.ac_controls.mobile_devices.connection_requirements == true
	input.ac_controls.mobile_devices.configuration_requirements == true
}

# AC-20: Use of External Systems
external_systems_control if {
	input.ac_controls.external_systems.authorized_only == true
	input.ac_controls.external_systems.security_requirements == true
	input.ac_controls.external_systems.user_agreements == true
}

# AC-21: Information Sharing
information_sharing_control if {
	input.ac_controls.information_sharing.user_discretion_limited == true
	input.ac_controls.information_sharing.automated_guidance == true
}

# AC-22: Publicly Accessible Content
publicly_accessible_content if {
	input.ac_controls.public_content.authorized_personnel_only == true
	input.ac_controls.public_content.review_process == true
	input.ac_controls.public_content.removal_procedures == true
}

# AC-23: Data Mining Protection
data_mining_protection if {
	input.ac_controls.data_mining.detection_techniques == true
	input.ac_controls.data_mining.warning_notifications == true
	input.ac_controls.data_mining.response_procedures == true
}

# AC-24: Access Control Decisions
access_control_decisions if {
	input.ac_controls.decisions.security_attributes_used == true
	input.ac_controls.decisions.consistent_enforcement == true
	input.ac_controls.decisions.documented_criteria == true
}

# AC-25: Reference Monitor
reference_monitor if {
	input.ac_controls.reference_monitor.tamper_proof == true
	input.ac_controls.reference_monitor.always_invoked == true
	input.ac_controls.reference_monitor.small_verifiable == true
}

# Aggregate NIST SP 800-53 Access Control compliance: true exactly when every evaluated AC id passes (no
# violation at all), not only the 34 legacy boolean rules (Tim, 2026-11-21). Facts must be supplied as an object
# under input.ac_controls, so {} is never compliant.
default nist_sp800_53_ac_compliant := false

nist_sp800_53_ac_compliant if {
	is_object(input.ac_controls)
	count(violation) == 0
}

# Detailed NIST SP 800-53 Access Control compliance report
nist_sp800_53_ac_compliance := {
	"access_control_policy": access_control_policy,
	"account_management": account_management,
	"access_enforcement": access_enforcement,
	"information_flow_enforcement": information_flow_enforcement,
	"separation_of_duties": separation_of_duties,
	"least_privilege": least_privilege,
	"unsuccessful_logon_attempts": unsuccessful_logon_attempts,
	"system_use_notification": system_use_notification,
	"previous_logon_notification": previous_logon_notification,
	"concurrent_session_control": concurrent_session_control,
	"session_lock": session_lock,
	"pattern_hiding_display": pattern_hiding_display,
	"session_termination": session_termination,
	"permitted_actions_restricted": permitted_actions_restricted,
	"security_attributes": security_attributes,
	"remote_access_control": remote_access_control,
	"wireless_access_control": wireless_access_control,
	"mobile_device_access_control": mobile_device_access_control,
	"external_systems_control": external_systems_control,
	"information_sharing_control": information_sharing_control,
	"publicly_accessible_content": publicly_accessible_content,
	"data_mining_protection": data_mining_protection,
	"access_control_decisions": access_control_decisions,
	"reference_monitor": reference_monitor,
	"automated_account_management": automated_account_management,
	"flow_object_attributes": flow_object_attributes,
	"authorize_security_functions": authorize_security_functions,
	"non_privileged_access_for_nonsecurity": non_privileged_access_for_nonsecurity,
	"previous_logon_unsuccessful_count": previous_logon_unsuccessful_count,
	"previous_logon_additional_info": previous_logon_additional_info,
	"user_initiated_logout": user_initiated_logout,
	"remote_access_monitoring": remote_access_monitoring,
	"remote_access_encryption": remote_access_encryption,
	"wireless_auth_encryption": wireless_auth_encryption,
	"overall_compliant": nist_sp800_53_ac_compliant,
}

# ── Violation set (for nist_800_53.main orchestrator) ─────────────────────
# Boolean rules above are kept for compatibility with existing
# comprehensive_test_suite.rego; this set turns them into the
# violation-message shape required by the framework master.

violation contains msg if {
	not access_control_policy
	msg := sprintf("NIST AC-1: %s", [_ac_detail(["policy.documented", "policy.disseminated", "policy.reviewed_updated", "procedures.implementation_documented"], "Access control policy/procedures not documented, disseminated, or reviewed")])
}

violation contains msg if {
	not account_management
	msg := sprintf("NIST AC-2: %s", [_ac_detail(["account_management.approval_process", "account_management.regular_reviews", "account_management.timely_removal"], "Account management lacks approval, regular review, or timely removal")])
}

_ac3_any_collected if {
	some m in _ac3_model_fields
	is_boolean(object.get(input, ["ac_controls", "access_enforcement", m], null))
}

violation contains msg if {
	not access_enforcement
	not _ac3_any_collected
	msg := "NIST AC-3: evidence missing — no approved access control policy is evidenced as enforced (input.ac_controls.access_enforcement: none of mandatory_access_control, discretionary_access_control, role_based_access_control, attribute_based_access_control collected)"
}

violation contains msg if {
	not access_enforcement
	_ac3_any_collected
	msg := "NIST AC-3: No approved access control policy is enforced (input.ac_controls.access_enforcement: none of mandatory_access_control, discretionary_access_control, role_based_access_control, attribute_based_access_control is true)"
}

violation contains msg if {
	not information_flow_enforcement
	msg := sprintf("NIST AC-4: %s", [_ac_detail(["information_flow.flow_control_policies", "information_flow.automated_enforcement"], "Information flow not enforced according to approved flow control policies")])
}

violation contains msg if {
	not separation_of_duties
	msg := sprintf("NIST AC-5: %s", [_ac_detail(["separation_duties.critical_functions_divided", "separation_duties.documented_assignments"], "Duties not identified and documented or access authorizations not defined to support separation of duties")])
}

violation contains msg if {
	not least_privilege
	msg := sprintf("NIST AC-6: %s", [_ac_detail(["least_privilege.minimum_access_granted"], "Least privilege not employed (input.ac_controls.least_privilege.minimum_access_granted)")])
}

violation contains msg if {
	count(ac7_evidence_missing) > 0
	msg := sprintf("NIST AC-7: evidence missing — %s not collected", [concat(", ", sort(ac7_evidence_missing))])
}

violation contains msg if {
	count(ac7_evidence_missing) == 0
	not unsuccessful_logon_attempts
	msg := sprintf(
		"NIST AC-7: Unsuccessful logon attempts not limited as the organization defined (limit %v, configured %v; lockout action configured: %v; lockout %v min, organization-defined %v)",
		[_ac7_odp_max, _ac7.maximum_attempts, _ac7.lockout_configured, object.get(_ac7, "lockout_duration", "n/a"), object.get(_ac7, ["odp", "lockout_duration"], "n/a")],
	)
}

violation contains msg if {
	not system_use_notification
	msg := sprintf("NIST AC-8: %s", [_ac_detail(["use_notification.banner_displayed", "use_notification.acknowledgment_required", "use_notification.monitoring_consent"], "System use notification banner/acknowledgment/consent missing")])
}

violation contains msg if {
	not previous_logon_notification
	msg := sprintf("NIST AC-9: %s", [_ac_detail(["logon_notification.timestamp_displayed"], "Date and time of the last logon not displayed to the user upon successful logon")])
}

violation contains msg if {
	not concurrent_session_control
	msg := sprintf("NIST AC-10: %s", [_ac_detail(["session_control.limits_configured", "session_control.per_account_limits"], "Concurrent sessions not limited per account or account type")])
}

violation contains msg if {
	count(ac11_evidence_missing) > 0
	msg := sprintf("NIST AC-11: evidence missing — %s not collected", [concat(", ", sort(ac11_evidence_missing))])
}

violation contains msg if {
	count(ac11_evidence_missing) == 0
	not session_lock
	msg := sprintf(
		"NIST AC-11: Device lock not initiated within the organization-defined inactivity period or not retained until re-authentication (timeout %vs, organization-defined %vs)",
		[_ac11.inactivity_timeout, _ac11_odp],
	)
}

violation contains msg if {
	not pattern_hiding_display
	msg := sprintf("NIST AC-11(1): %s", [_ac_detail(["session_lock.pattern_hiding"], "Device lock does not conceal previously visible information (input.ac_controls.session_lock.pattern_hiding is not true)")])
}

violation contains msg if {
	not session_termination
	msg := sprintf("NIST AC-12: %s", [_ac_detail(["session_termination.automatic_termination"], "User sessions not automatically terminated after the defined conditions")])
}

violation contains msg if {
	count(ac14_evidence_missing) > 0
	msg := sprintf("NIST AC-14: evidence missing — %s not collected", [concat(", ", sort(ac14_evidence_missing))])
}

violation contains msg if {
	count(ac14_evidence_missing) == 0
	not permitted_actions_restricted
	msg := sprintf(
		"NIST AC-14: Unauthenticated actions not limited to the organization-approved list or rationale not documented (unapproved: %v; rationale documented: %v)",
		[sort(ac14_unapproved_functions), _ac14.rationale_documented],
	)
}

violation contains msg if {
	not remote_access_control
	msg := sprintf("NIST AC-17: %s", [_ac_detail(["remote_access.authorized_only"], "Remote access types not authorized before connections are allowed")])
}

violation contains msg if {
	not wireless_access_control
	msg := sprintf("NIST AC-18: %s", [_ac_detail(["wireless_access.authorized_only"], "Wireless access types not authorized before connections are allowed")])
}

violation contains msg if {
	not mobile_device_access_control
	msg := sprintf("NIST AC-19: %s", [_ac_detail(["mobile_devices.usage_restrictions", "mobile_devices.connection_requirements", "mobile_devices.configuration_requirements"], "Mobile device access control missing usage restrictions or config requirements")])
}

violation contains msg if {
	not external_systems_control
	msg := sprintf("NIST AC-20: %s", [_ac_detail(["external_systems.authorized_only", "external_systems.security_requirements", "external_systems.user_agreements"], "External system use not authorized or governed by user agreements")])
}

violation contains msg if {
	not publicly_accessible_content
	msg := sprintf("NIST AC-22: %s", [_ac_detail(["public_content.authorized_personnel_only", "public_content.review_process", "public_content.removal_procedures"], "Publicly accessible content lacks review/removal process")])
}

violation contains msg if {
	not security_attributes
	msg := sprintf("NIST AC-16: %s", [_ac_detail(["security_attributes.attribute_binding", "security_attributes.attribute_association", "security_attributes.transmission_preservation"], "Security and privacy attributes not bound, associated, and preserved in transmission")])
}

violation contains msg if {
	not information_sharing_control
	msg := sprintf("NIST AC-21: %s", [_ac_detail(["information_sharing.user_discretion_limited", "information_sharing.automated_guidance"], "Information sharing lacks partner-authorization checks or automated decision support")])
}

violation contains msg if {
	not data_mining_protection
	msg := sprintf("NIST AC-23: %s", [_ac_detail(["data_mining.detection_techniques", "data_mining.warning_notifications", "data_mining.response_procedures"], "Data mining protection lacks detection techniques, warnings, or response procedures")])
}

violation contains msg if {
	not access_control_decisions
	msg := sprintf("NIST AC-24: %s", [_ac_detail(["decisions.security_attributes_used", "decisions.consistent_enforcement", "decisions.documented_criteria"], "Access control decisions not based on security attributes, consistently enforced, or documented")])
}

violation contains msg if {
	not reference_monitor
	msg := sprintf("NIST AC-25: %s", [_ac_detail(["reference_monitor.tamper_proof", "reference_monitor.always_invoked", "reference_monitor.small_verifiable"], "Reference monitor not tamper-proof, always-invoked, and small enough to verify")])
}

violation contains msg if {
	not automated_account_management
	msg := sprintf("NIST AC-2(1): %s", [_ac_detail(["account_management.automated_tools"], "Automated system account management not supported (input.ac_controls.account_management.automated_tools)")])
}

violation contains msg if {
	not flow_object_attributes
	msg := sprintf("NIST AC-4(1): %s", [_ac_detail(["information_flow.security_labels"], "Security and privacy attributes not used for flow control decisions (input.ac_controls.information_flow.security_labels)")])
}

violation contains msg if {
	not authorize_security_functions
	msg := sprintf("NIST AC-6(1): %s", [_ac_detail(["least_privilege.privileged_functions_authorized"], "Access to security functions not explicitly authorized (input.ac_controls.least_privilege.privileged_functions_authorized)")])
}

violation contains msg if {
	not non_privileged_access_for_nonsecurity
	msg := sprintf("NIST AC-6(2): %s", [_ac_detail(["least_privilege.non_privileged_access_default"], "Privileged users not required to use non-privileged accounts for nonsecurity functions (input.ac_controls.least_privilege.non_privileged_access_default)")])
}

violation contains msg if {
	not previous_logon_unsuccessful_count
	msg := sprintf("NIST AC-9(1): %s", [_ac_detail(["logon_notification.unsuccessful_attempts_displayed"], "Number of unsuccessful logon attempts not shown upon successful logon (input.ac_controls.logon_notification.unsuccessful_attempts_displayed)")])
}

violation contains msg if {
	not previous_logon_additional_info
	msg := sprintf("NIST AC-9(4): %s", [_ac_detail(["logon_notification.location_displayed"], "Additional logon information (location) not shown upon successful logon (input.ac_controls.logon_notification.location_displayed)")])
}

violation contains msg if {
	not user_initiated_logout
	msg := sprintf("NIST AC-12(1): %s", [_ac_detail(["session_termination.user_initiated"], "No user-initiated logout capability (input.ac_controls.session_termination.user_initiated)")])
}

violation contains msg if {
	not remote_access_monitoring
	msg := sprintf("NIST AC-17(1): %s", [_ac_detail(["remote_access.monitored_controlled"], "Remote access methods not monitored and controlled by automated mechanisms (input.ac_controls.remote_access.monitored_controlled)")])
}

violation contains msg if {
	not remote_access_encryption
	msg := sprintf("NIST AC-17(2): %s", [_ac_detail(["remote_access.encrypted_connections"], "Remote access sessions not cryptographically protected (input.ac_controls.remote_access.encrypted_connections)")])
}

violation contains msg if {
	not wireless_auth_encryption
	msg := sprintf("NIST AC-18(1): %s", [_ac_detail(["wireless_access.encrypted_authentication"], "Wireless access not protected by authentication and encryption (input.ac_controls.wireless_access.encrypted_authentication)")])
}

# ── Evidence helpers ─────────────────────────────────────────────────────
# A fact path is dotted below input.ac_controls. A fact that is absent, null or of the wrong type is missing
# evidence, never a pass.
_ac_get(p) := object.get(input, array.concat(["ac_controls"], split(p, ".")), null)

_ac_path(p) := concat(".", ["input.ac_controls", p])

# The boolean facts in `ps` that are absent or not a boolean.
_ac_bool_missing(ps) := {_ac_path(p) | some p in ps; not is_boolean(_ac_get(p))}

# Finding text for an existing boolean rule that fired: evidence missing when one of the facts it reads is absent
# or not a boolean, otherwise the rule's own text. The rule's pass condition is unchanged.
_ac_detail(ps, text) := sprintf("evidence missing — %s not collected", [concat(", ", sort(m))]) if {
	m := _ac_bool_missing(ps)
	count(m) > 0
} else := text

# Finding text for an enhancement: the missing evidence when any, otherwise the unmet elements.
_ac_enh_detail(missing, failed) := sprintf("evidence missing — %s not collected", [concat(", ", sort(missing))]) if {
	count(missing) > 0
} else := concat("; ", sort(failed))

_ac_bool_false(ps) := {sprintf("%s is not true", [_ac_path(p)]) | some p in ps; _ac_get(p) == false}

# A count: a non-negative whole number; anything else is evidence missing.
_ac_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_ac_count_missing(ps) := {_ac_path(p) | some p in ps; not _ac_count_ok(_ac_get(p))}

_ac_num_missing(ps) := {_ac_path(p) | some p in ps; not is_number(_ac_get(p))}

_ac_nonempty_array(v) if {
	is_array(v)
	count(v) > 0
}

_ac_list_missing(ps) := {concat("", [_ac_path(p), " (non-empty list)"]) | some p in ps; not _ac_nonempty_array(_ac_get(p))}

# A count that must be zero: `what` names what was counted.
_ac_nonzero(p, what) := {sprintf("%v %s (%s)", [v, what, _ac_path(p)]) |
	v := _ac_get(p)
	is_number(v)
	_ac_count_ok(v)
	v > 0
}

# The observed value may not exceed the organization-defined value.
_ac_over(obs, odp, fmt) := {sprintf(fmt, [o, l]) |
	o := _ac_get(obs)
	l := _ac_get(odp)
	is_number(o)
	is_number(l)
	o > l
}

# ── Moderate-baseline enhancements (NIST SP 800-53B) ─────────────────────
# Each id has a set of missing evidence paths and a set of unmet elements; one finding per id: the missing
# evidence when any, otherwise the unmet elements.

# AC-2(2) Automated Temporary and Emergency Account Management: temporary and emergency accounts are removed or
# disabled automatically after the organization-defined period.
# Facts (input.ac_controls.account_management.temporary_accounts): automated_expiry_enforced (boolean);
# max_lifetime_hours (longest lifetime configured for a temporary or emergency account) +
# odp.max_lifetime_hours (organization-defined period).
_ac2_2 := "account_management.temporary_accounts"

_ac2_2_missing := _ac_bool_missing([concat(".", [_ac2_2, "automated_expiry_enforced"])]) | _ac_num_missing([concat(".", [_ac2_2, "max_lifetime_hours"]), concat(".", [_ac2_2, "odp.max_lifetime_hours"])])

_ac2_2_failed := _ac_bool_false([concat(".", [_ac2_2, "automated_expiry_enforced"])]) | _ac_over(concat(".", [_ac2_2, "max_lifetime_hours"]), concat(".", [_ac2_2, "odp.max_lifetime_hours"]), "temporary or emergency accounts live up to %v hours; the organization-defined period is %v hours")

# AC-2(3) Disable Accounts: accounts that have expired, are no longer associated with a user, violate policy or
# have been inactive for the organization-defined period are disabled within the organization-defined period.
# Facts (input.ac_controls.account_management.disable_accounts): inactivity_threshold_days (configured) +
# odp.inactivity_days; max_days_to_disable (longest observed time from an account meeting a disable condition to
# its disabling) + odp.disable_within_days.
_ac2_3 := "account_management.disable_accounts"

_ac2_3_missing := _ac_num_missing([concat(".", [_ac2_3, f]) | some f in ["inactivity_threshold_days", "odp.inactivity_days", "max_days_to_disable", "odp.disable_within_days"]])

_ac2_3_failed := _ac_over(concat(".", [_ac2_3, "inactivity_threshold_days"]), concat(".", [_ac2_3, "odp.inactivity_days"]), "inactive accounts disabled after %v days of inactivity; the organization-defined period is %v days") | _ac_over(concat(".", [_ac2_3, "max_days_to_disable"]), concat(".", [_ac2_3, "odp.disable_within_days"]), "accounts meeting a disable condition were disabled up to %v days later; the organization-defined period is %v days")

# AC-2(4) Automated Audit Actions: account creation, modification, enabling, disabling and removal are audited
# automatically.
# Facts (input.ac_controls.account_management.automated_audit): creation, modification, enabling, disabling,
# removal (booleans).
_ac2_4 := [concat(".", ["account_management.automated_audit", a]) | some a in ["creation", "modification", "enabling", "disabling", "removal"]]

_ac2_4_missing := _ac_bool_missing(_ac2_4)

_ac2_4_failed := _ac_bool_false(_ac2_4)

# AC-2(5) Inactivity Logout: users are logged out after the organization-defined period of expected inactivity.
# Facts (input.ac_controls.account_management.inactivity_logout): enforced (boolean); logout_after_minutes
# (configured) + odp.logout_after_minutes.
_ac2_5 := "account_management.inactivity_logout"

_ac2_5_missing := _ac_bool_missing([concat(".", [_ac2_5, "enforced"])]) | _ac_num_missing([concat(".", [_ac2_5, "logout_after_minutes"]), concat(".", [_ac2_5, "odp.logout_after_minutes"])])

_ac2_5_failed := _ac_bool_false([concat(".", [_ac2_5, "enforced"])]) | _ac_over(concat(".", [_ac2_5, "logout_after_minutes"]), concat(".", [_ac2_5, "odp.logout_after_minutes"]), "users logged out after %v minutes of inactivity; the organization-defined period is %v minutes")

# AC-2(13) Disable Accounts for High-risk Individuals: accounts of individuals are disabled within the
# organization-defined period of discovery of the organization-defined significant risks.
# Facts (input.ac_controls.account_management.high_risk_individuals): max_hours_to_disable (longest observed time
# from discovery to disabling in the assessment window; 0 when no case occurred) + odp.disable_within_hours;
# odp.significant_risks (non-empty list of the risks the organisation defined).
_ac2_13 := "account_management.high_risk_individuals"

_ac2_13_missing := _ac_num_missing([concat(".", [_ac2_13, "max_hours_to_disable"]), concat(".", [_ac2_13, "odp.disable_within_hours"])]) | _ac_list_missing([concat(".", [_ac2_13, "odp.significant_risks"])])

_ac2_13_failed := _ac_over(concat(".", [_ac2_13, "max_hours_to_disable"]), concat(".", [_ac2_13, "odp.disable_within_hours"]), "accounts of high-risk individuals disabled up to %v hours after discovery; the organization-defined period is %v hours")

# AC-6(5) Privileged Accounts: privileged accounts are restricted to the organization-defined personnel or roles.
# Facts (input.ac_controls.least_privilege.privileged_accounts): odp.authorized_roles (non-empty list);
# accounts_outside_authorized_roles (count of privileged accounts not held by those roles).
_ac6_5 := "least_privilege.privileged_accounts"

_ac6_5_missing := (_ac_list_missing([concat(".", [_ac6_5, "odp.authorized_roles"])]) | _ac_num_missing([concat(".", [_ac6_5, "accounts_outside_authorized_roles"])])) | _ac_count_missing([concat(".", [_ac6_5, "accounts_outside_authorized_roles"])])

_ac6_5_failed := _ac_nonzero(concat(".", [_ac6_5, "accounts_outside_authorized_roles"]), "privileged accounts held outside the organization-defined roles")

# AC-6(7) Review of User Privileges: privileges of the organization-defined roles are reviewed at the
# organization-defined frequency, and privileges are reassigned or removed where the review found them unneeded.
# Facts (input.ac_controls.least_privilege.privilege_review): days_since_last + odp.frequency_days;
# unremediated_findings (count of privileges the last review marked for removal or reassignment and still held).
_ac6_7 := "least_privilege.privilege_review"

_ac6_7_missing := _ac_num_missing([concat(".", [_ac6_7, f]) | some f in ["days_since_last", "odp.frequency_days", "unremediated_findings"]]) | _ac_count_missing([concat(".", [_ac6_7, "unremediated_findings"])])

_ac6_7_failed := _ac_over(concat(".", [_ac6_7, "days_since_last"]), concat(".", [_ac6_7, "odp.frequency_days"]), "user privileges last reviewed %v days ago; the organization-defined frequency is %v days") | _ac_nonzero(concat(".", [_ac6_7, "unremediated_findings"]), "privileges marked for removal or reassignment still held")

# AC-6(9) Log Use of Privileged Functions. Fact: input.ac_controls.least_privilege.privileged_functions_logged
# (boolean: execution of privileged functions is logged, e.g. audit rules on privileged commands).
_ac6_9 := ["least_privilege.privileged_functions_logged"]

_ac6_9_missing := _ac_bool_missing(_ac6_9)

_ac6_9_failed := _ac_bool_false(_ac6_9)

# AC-6(10) Prohibit Non-privileged Users from Executing Privileged Functions.
# Fact: input.ac_controls.least_privilege.non_privileged_execution_prevented (boolean).
_ac6_10 := ["least_privilege.non_privileged_execution_prevented"]

_ac6_10_missing := _ac_bool_missing(_ac6_10)

_ac6_10_failed := _ac_bool_false(_ac6_10)

# AC-17(3) Managed Access Control Points: remote access is routed through authorized, managed access control
# points. Fact: input.ac_controls.remote_access.unmanaged_access_points (count of remote access entry points that
# bypass the managed access control points).
_ac17_3_missing := _ac_num_missing(["remote_access.unmanaged_access_points"]) | _ac_count_missing(["remote_access.unmanaged_access_points"])

_ac17_3_failed := _ac_nonzero("remote_access.unmanaged_access_points", "remote access entry points not routed through a managed access control point")

# AC-17(4) Privileged Commands and Access: privileged commands and access to security-relevant information over
# remote access are authorized only for the organization-defined needs, in a format that provides assessable
# evidence, with the rationale documented in the security plan.
# Facts (input.ac_controls.remote_access.privileged_commands): odp.needs (non-empty list); restricted_to_defined_needs,
# assessable_evidence_produced (e.g. session recording or command logging), rationale_in_security_plan (booleans).
_ac17_4 := [concat(".", ["remote_access.privileged_commands", f]) | some f in ["restricted_to_defined_needs", "assessable_evidence_produced", "rationale_in_security_plan"]]

_ac17_4_missing := _ac_bool_missing(_ac17_4) | _ac_list_missing(["remote_access.privileged_commands.odp.needs"])

_ac17_4_failed := _ac_bool_false(_ac17_4)

# AC-17(9) Disconnect or Disable Access (NIST SP 800-53 Rev 5, OSCAL catalog release 5.2.0, public domain):
# "Provide the capability to disconnect or disable remote access to the system within [organization-defined time
# period]." One organization-defined parameter, the time period. Facts (input.ac_controls.remote_access.disconnect):
# capability_provided (boolean: the capability exists), odp.time_period_minutes (number > 0, the organization-defined
# period) and measured_minutes (number: the time a test took to disconnect or disable remote access to the system;
# it may not exceed the period).
_ac17_9 := "remote_access.disconnect"

_ac17_9_odp := concat(".", [_ac17_9, "odp.time_period_minutes"])

_ac17_9_missing := (_ac_bool_missing([concat(".", [_ac17_9, "capability_provided"])]) | _ac_num_missing([concat(".", [_ac17_9, "measured_minutes"]), _ac17_9_odp])) | {concat("", [_ac_path(_ac17_9_odp), " (a number greater than 0)"]) |
	is_number(_ac_get(_ac17_9_odp))
	_ac_get(_ac17_9_odp) <= 0
}

_ac17_9_failed := _ac_bool_false([concat(".", [_ac17_9, "capability_provided"])]) | _ac_over(concat(".", [_ac17_9, "measured_minutes"]), _ac17_9_odp, "remote access took %v minutes to disconnect or disable; the organization-defined time period is %v minutes")

# AC-18(3) Disable Wireless Networking: embedded wireless capabilities not intended for use are disabled before
# issuance and deployment. Fact: input.ac_controls.wireless_access.components_with_unused_wireless_enabled (count).
_ac18_3_missing := _ac_num_missing(["wireless_access.components_with_unused_wireless_enabled"]) | _ac_count_missing(["wireless_access.components_with_unused_wireless_enabled"])

_ac18_3_failed := _ac_nonzero("wireless_access.components_with_unused_wireless_enabled", "deployed components with wireless networking enabled but not intended for use")

# AC-19(5) Full Device or Container-based Encryption: the organization-defined encryption is employed on the
# organization-defined mobile devices.
# Facts (input.ac_controls.mobile_devices.encryption): odp.method ("full-device" or "container-based");
# devices_without_required_encryption (count of in-scope mobile devices without it).
_ac19_5 := "mobile_devices.encryption"

_ac19_5_methods := {"full-device", "container-based"}

_ac19_5_missing contains concat(".", [_ac_path(_ac19_5), "odp.method (full-device or container-based)"]) if {
	not _ac_get(concat(".", [_ac19_5, "odp.method"])) in _ac19_5_methods
}

_ac19_5_missing contains m if {
	some m in _ac_num_missing([concat(".", [_ac19_5, "devices_without_required_encryption"])])
}

_ac19_5_missing contains m if {
	some m in _ac_count_missing([concat(".", [_ac19_5, "devices_without_required_encryption"])])
}

_ac19_5_failed := _ac_nonzero(concat(".", [_ac19_5, "devices_without_required_encryption"]), "mobile devices without the organization-defined encryption")

# AC-20(1) Limits on Authorized Use: an external system is used only after its controls are verified or an
# approved connection or processing agreement is retained.
# Fact: input.ac_controls.external_systems.limits_on_authorized_use.systems_without_verification_or_agreement
# (count of external systems in use with neither).
_ac20_1 := "external_systems.limits_on_authorized_use.systems_without_verification_or_agreement"

_ac20_1_missing := _ac_num_missing([_ac20_1]) | _ac_count_missing([_ac20_1])

_ac20_1_failed := _ac_nonzero(_ac20_1, "external systems in use without verified controls or a retained agreement")

# AC-20(2) Portable Storage Devices — Restricted Use: use of organization-controlled portable storage devices on
# external systems is restricted with the organization-defined restrictions.
# Facts (input.ac_controls.external_systems.portable_storage): odp.restrictions (non-empty list);
# restrictions_enforced (boolean).
_ac20_2 := ["external_systems.portable_storage.restrictions_enforced"]

_ac20_2_missing := _ac_bool_missing(_ac20_2) | _ac_list_missing(["external_systems.portable_storage.odp.restrictions"])

_ac20_2_failed := _ac_bool_false(_ac20_2)

violation contains sprintf("NIST AC-2(2): %s", [_ac_enh_detail(_ac2_2_missing, _ac2_2_failed)]) if count(_ac2_2_missing | _ac2_2_failed) > 0

violation contains sprintf("NIST AC-2(3): %s", [_ac_enh_detail(_ac2_3_missing, _ac2_3_failed)]) if count(_ac2_3_missing | _ac2_3_failed) > 0

violation contains sprintf("NIST AC-2(4): %s", [_ac_enh_detail(_ac2_4_missing, _ac2_4_failed)]) if count(_ac2_4_missing | _ac2_4_failed) > 0

violation contains sprintf("NIST AC-2(5): %s", [_ac_enh_detail(_ac2_5_missing, _ac2_5_failed)]) if count(_ac2_5_missing | _ac2_5_failed) > 0

violation contains sprintf("NIST AC-2(13): %s", [_ac_enh_detail(_ac2_13_missing, _ac2_13_failed)]) if count(_ac2_13_missing | _ac2_13_failed) > 0

violation contains sprintf("NIST AC-6(5): %s", [_ac_enh_detail(_ac6_5_missing, _ac6_5_failed)]) if count(_ac6_5_missing | _ac6_5_failed) > 0

violation contains sprintf("NIST AC-6(7): %s", [_ac_enh_detail(_ac6_7_missing, _ac6_7_failed)]) if count(_ac6_7_missing | _ac6_7_failed) > 0

violation contains sprintf("NIST AC-6(9): %s", [_ac_enh_detail(_ac6_9_missing, _ac6_9_failed)]) if count(_ac6_9_missing | _ac6_9_failed) > 0

violation contains sprintf("NIST AC-6(10): %s", [_ac_enh_detail(_ac6_10_missing, _ac6_10_failed)]) if count(_ac6_10_missing | _ac6_10_failed) > 0

violation contains sprintf("NIST AC-17(3): %s", [_ac_enh_detail(_ac17_3_missing, _ac17_3_failed)]) if count(_ac17_3_missing | _ac17_3_failed) > 0

violation contains sprintf("NIST AC-17(4): %s", [_ac_enh_detail(_ac17_4_missing, _ac17_4_failed)]) if count(_ac17_4_missing | _ac17_4_failed) > 0

violation contains sprintf("NIST AC-17(9): %s", [_ac_enh_detail(_ac17_9_missing, _ac17_9_failed)]) if count(_ac17_9_missing | _ac17_9_failed) > 0

violation contains sprintf("NIST AC-18(3): %s", [_ac_enh_detail(_ac18_3_missing, _ac18_3_failed)]) if count(_ac18_3_missing | _ac18_3_failed) > 0

violation contains sprintf("NIST AC-19(5): %s", [_ac_enh_detail(_ac19_5_missing, _ac19_5_failed)]) if count(_ac19_5_missing | _ac19_5_failed) > 0

violation contains sprintf("NIST AC-20(1): %s", [_ac_enh_detail(_ac20_1_missing, _ac20_1_failed)]) if count(_ac20_1_missing | _ac20_1_failed) > 0

violation contains sprintf("NIST AC-20(2): %s", [_ac_enh_detail(_ac20_2_missing, _ac20_2_failed)]) if count(_ac20_2_missing | _ac20_2_failed) > 0

# ── NIST and FedRAMP High-baseline enhancements ──────────────────────────
# Same shape as the Moderate enhancements: missing evidence and unmet elements per id, one finding per id.

_ac_f(base, f) := concat(".", [base, f])

# A selection ODP: the organisation's choice must be one of the values the statement allows.
_ac_choice_missing(p, allowed) := {sprintf("%s (one of %s)", [_ac_path(p), concat(", ", sort(allowed))]) | not _ac_get(p) in allowed}

# AC-2(7) Privileged User Accounts: privileged user accounts are administered under the organization-defined
# role-based or attribute-based scheme; privileged role or attribute assignments and changes to them are
# monitored; access is revoked when an assignment is no longer appropriate.
# Facts (input.ac_controls.account_management.privileged_user_accounts): odp.scheme ("role-based" or
# "attribute-based"); administered_per_scheme, assignments_monitored, changes_monitored (booleans);
# inappropriate_assignments_not_revoked (count of privileged assignments found inappropriate and still held).
_ac2_7 := "account_management.privileged_user_accounts"

_ac2_7_bools := [_ac_f(_ac2_7, f) | some f in ["administered_per_scheme", "assignments_monitored", "changes_monitored"]]

_ac2_7_missing := ((_ac_bool_missing(_ac2_7_bools) | _ac_num_missing([_ac_f(_ac2_7, "inappropriate_assignments_not_revoked")])) | _ac_choice_missing(_ac_f(_ac2_7, "odp.scheme"), {"role-based", "attribute-based"})) | _ac_count_missing([_ac_f(_ac2_7, "inappropriate_assignments_not_revoked")])

_ac2_7_failed := _ac_bool_false(_ac2_7_bools) | _ac_nonzero(_ac_f(_ac2_7, "inappropriate_assignments_not_revoked"), "privileged role or attribute assignments no longer appropriate and not revoked")

# AC-2(9) Restrictions on Use of Shared and Group Accounts: only shared and group accounts that meet the
# organization-defined conditions are permitted.
# Facts (input.ac_controls.account_management.shared_accounts): odp.conditions (non-empty list);
# accounts_not_meeting_conditions (count of enabled shared or group accounts that do not meet them).
_ac2_9 := "account_management.shared_accounts"

_ac2_9_missing := (_ac_list_missing([_ac_f(_ac2_9, "odp.conditions")]) | _ac_num_missing([_ac_f(_ac2_9, "accounts_not_meeting_conditions")])) | _ac_count_missing([_ac_f(_ac2_9, "accounts_not_meeting_conditions")])

_ac2_9_failed := _ac_nonzero(_ac_f(_ac2_9, "accounts_not_meeting_conditions"), "shared or group accounts enabled that do not meet the organization-defined conditions")

# AC-2(11) Usage Conditions: the organization-defined circumstances or usage conditions (time of day, location,
# source network) are enforced for the organization-defined system accounts.
# Facts (input.ac_controls.account_management.usage_conditions): odp.conditions, odp.accounts (non-empty lists);
# accounts_without_enforced_conditions (count of those accounts on which the conditions are not enforced).
_ac2_11 := "account_management.usage_conditions"

_ac2_11_missing := (_ac_list_missing([_ac_f(_ac2_11, "odp.conditions"), _ac_f(_ac2_11, "odp.accounts")]) | _ac_num_missing([_ac_f(_ac2_11, "accounts_without_enforced_conditions")])) | _ac_count_missing([_ac_f(_ac2_11, "accounts_without_enforced_conditions")])

_ac2_11_failed := _ac_nonzero(_ac_f(_ac2_11, "accounts_without_enforced_conditions"), "organization-defined accounts without the usage conditions enforced")

# AC-2(12) Account Monitoring for Atypical Usage: system accounts are monitored for the organization-defined
# atypical usage, which is reported to the organization-defined personnel or roles.
# Facts (input.ac_controls.account_management.atypical_usage): odp.atypical_usage, odp.report_to (non-empty
# lists); monitoring_enabled (boolean, e.g. UEBA or SIEM rules on account use); detections_not_reported (count of
# atypical-usage detections in the review period not reported to those personnel or roles).
_ac2_12 := "account_management.atypical_usage"

_ac2_12_missing := ((_ac_list_missing([_ac_f(_ac2_12, "odp.atypical_usage"), _ac_f(_ac2_12, "odp.report_to")]) | _ac_bool_missing([_ac_f(_ac2_12, "monitoring_enabled")])) | _ac_num_missing([_ac_f(_ac2_12, "detections_not_reported")])) | _ac_count_missing([_ac_f(_ac2_12, "detections_not_reported")])

_ac2_12_failed := _ac_bool_false([_ac_f(_ac2_12, "monitoring_enabled")]) | _ac_nonzero(_ac_f(_ac2_12, "detections_not_reported"), "atypical account usage detections not reported")

# AC-4(4) Flow Control of Encrypted Information: encrypted information is prevented from bypassing the
# organization-defined flow control mechanisms by decrypting it, blocking it, terminating the session, or an
# organization-defined method.
# Facts (input.ac_controls.information_flow.encrypted_information): odp.mechanisms (non-empty list); odp.action
# ("decrypt", "block", "terminate" or "other"); action_enforced (boolean: e.g. TLS inspection or a block rule is
# active); uninspected_encrypted_flows (count of encrypted flows observed passing the mechanisms uninspected).
_ac4_4 := "information_flow.encrypted_information"

_ac4_4_missing := (((_ac_list_missing([_ac_f(_ac4_4, "odp.mechanisms")]) | _ac_choice_missing(_ac_f(_ac4_4, "odp.action"), {"decrypt", "block", "terminate", "other"})) | _ac_bool_missing([_ac_f(_ac4_4, "action_enforced")])) | _ac_num_missing([_ac_f(_ac4_4, "uninspected_encrypted_flows")])) | _ac_count_missing([_ac_f(_ac4_4, "uninspected_encrypted_flows")])

_ac4_4_failed := _ac_bool_false([_ac_f(_ac4_4, "action_enforced")]) | _ac_nonzero(_ac_f(_ac4_4, "uninspected_encrypted_flows"), "encrypted flows bypassing the organization-defined flow control mechanisms")

# AC-4(21) Physical or Logical Separation of Information Flows: information flows are separated logically or
# physically with the organization-defined mechanisms to accomplish the organization-defined separations.
# Facts (input.ac_controls.information_flow.separation): odp.mechanisms, odp.required_separations (non-empty
# lists); separations_not_enforced (count of required separations not in place, e.g. from network segmentation
# tests).
_ac4_21 := "information_flow.separation"

_ac4_21_missing := (_ac_list_missing([_ac_f(_ac4_21, "odp.mechanisms"), _ac_f(_ac4_21, "odp.required_separations")]) | _ac_num_missing([_ac_f(_ac4_21, "separations_not_enforced")])) | _ac_count_missing([_ac_f(_ac4_21, "separations_not_enforced")])

_ac4_21_failed := _ac_nonzero(_ac_f(_ac4_21, "separations_not_enforced"), "organization-defined information flow separations not enforced")

# AC-6(3) Network Access to Privileged Commands: network access to the organization-defined privileged commands is
# authorized only for the organization-defined compelling operational needs, with the rationale in the security
# plan. Facts (input.ac_controls.least_privilege.network_privileged_commands): odp.commands, odp.needs (non-empty
# lists); accounts_without_documented_need (count of accounts with network access to those commands and no
# documented compelling need); rationale_in_security_plan (boolean).
_ac6_3 := "least_privilege.network_privileged_commands"

_ac6_3_missing := ((_ac_list_missing([_ac_f(_ac6_3, "odp.commands"), _ac_f(_ac6_3, "odp.needs")]) | _ac_num_missing([_ac_f(_ac6_3, "accounts_without_documented_need")])) | _ac_bool_missing([_ac_f(_ac6_3, "rationale_in_security_plan")])) | _ac_count_missing([_ac_f(_ac6_3, "accounts_without_documented_need")])

_ac6_3_failed := _ac_bool_false([_ac_f(_ac6_3, "rationale_in_security_plan")]) | _ac_nonzero(_ac_f(_ac6_3, "accounts_without_documented_need"), "accounts with network access to privileged commands and no documented compelling operational need")

# AC-6(8) Privilege Levels for Code Execution: the organization-defined software cannot execute at a higher
# privilege level than the user running it.
# Facts (input.ac_controls.least_privilege.code_execution): odp.software (non-empty list);
# software_above_user_privilege (count of those programs found able to run with elevated privilege, e.g. setuid
# bits, elevated service accounts).
_ac6_8 := "least_privilege.code_execution"

_ac6_8_missing := (_ac_list_missing([_ac_f(_ac6_8, "odp.software")]) | _ac_num_missing([_ac_f(_ac6_8, "software_above_user_privilege")])) | _ac_count_missing([_ac_f(_ac6_8, "software_above_user_privilege")])

_ac6_8_failed := _ac_nonzero(_ac_f(_ac6_8, "software_above_user_privilege"), "organization-defined programs able to execute above the invoking user's privilege level")

# AC-18(4) Restrict Configurations by Users: users allowed to configure wireless networking independently are
# identified and explicitly authorized.
# Facts (input.ac_controls.wireless_access.user_configuration): authorized_users_identified (boolean: an explicit
# list of authorized users exists); unauthorized_users_able_to_configure (count of users able to change wireless
# settings who are not on it).
_ac18_4 := "wireless_access.user_configuration"

_ac18_4_missing := (_ac_bool_missing([_ac_f(_ac18_4, "authorized_users_identified")]) | _ac_num_missing([_ac_f(_ac18_4, "unauthorized_users_able_to_configure")])) | _ac_count_missing([_ac_f(_ac18_4, "unauthorized_users_able_to_configure")])

_ac18_4_failed := _ac_bool_false([_ac_f(_ac18_4, "authorized_users_identified")]) | _ac_nonzero(_ac_f(_ac18_4, "unauthorized_users_able_to_configure"), "users able to configure wireless networking without explicit authorization")

# AC-18(5) Antennas and Transmission Power Levels: antennas are selected and transmission power calibrated so that
# signals are unlikely to be received outside organization-controlled boundaries.
# Facts (input.ac_controls.wireless_access.signal_containment): power_levels_calibrated (boolean: access point
# power settings set from a site survey); access_points_detected_outside_boundary (count of organizational access
# points whose signal the last site survey detected outside the controlled boundary).
_ac18_5 := "wireless_access.signal_containment"

_ac18_5_missing := (_ac_bool_missing([_ac_f(_ac18_5, "power_levels_calibrated")]) | _ac_num_missing([_ac_f(_ac18_5, "access_points_detected_outside_boundary")])) | _ac_count_missing([_ac_f(_ac18_5, "access_points_detected_outside_boundary")])

_ac18_5_failed := _ac_bool_false([_ac_f(_ac18_5, "power_levels_calibrated")]) | _ac_nonzero(_ac_f(_ac18_5, "access_points_detected_outside_boundary"), "access points whose signal is received outside the organization-controlled boundary")

violation contains sprintf("NIST AC-2(7): %s", [_ac_enh_detail(_ac2_7_missing, _ac2_7_failed)]) if count(_ac2_7_missing | _ac2_7_failed) > 0

violation contains sprintf("NIST AC-2(9): %s", [_ac_enh_detail(_ac2_9_missing, _ac2_9_failed)]) if count(_ac2_9_missing | _ac2_9_failed) > 0

violation contains sprintf("NIST AC-2(11): %s", [_ac_enh_detail(_ac2_11_missing, _ac2_11_failed)]) if count(_ac2_11_missing | _ac2_11_failed) > 0

violation contains sprintf("NIST AC-2(12): %s", [_ac_enh_detail(_ac2_12_missing, _ac2_12_failed)]) if count(_ac2_12_missing | _ac2_12_failed) > 0

violation contains sprintf("NIST AC-4(4): %s", [_ac_enh_detail(_ac4_4_missing, _ac4_4_failed)]) if count(_ac4_4_missing | _ac4_4_failed) > 0

violation contains sprintf("NIST AC-4(21): %s", [_ac_enh_detail(_ac4_21_missing, _ac4_21_failed)]) if count(_ac4_21_missing | _ac4_21_failed) > 0

violation contains sprintf("NIST AC-6(3): %s", [_ac_enh_detail(_ac6_3_missing, _ac6_3_failed)]) if count(_ac6_3_missing | _ac6_3_failed) > 0

violation contains sprintf("NIST AC-6(8): %s", [_ac_enh_detail(_ac6_8_missing, _ac6_8_failed)]) if count(_ac6_8_missing | _ac6_8_failed) > 0

violation contains sprintf("NIST AC-18(4): %s", [_ac_enh_detail(_ac18_4_missing, _ac18_4_failed)]) if count(_ac18_4_missing | _ac18_4_failed) > 0

violation contains sprintf("NIST AC-18(5): %s", [_ac_enh_detail(_ac18_5_missing, _ac18_5_failed)]) if count(_ac18_5_missing | _ac18_5_failed) > 0

default compliant := false

compliant if count(violation) == 0

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# AC-3(14) Individual Access: the organization-defined mechanisms let individuals access the organization-defined
# elements of their PII.
# Facts (input.ac_controls.access_enforcement.individual_access): mechanisms_implemented (boolean);
# odp.elements (non-empty list of the organization-defined PII elements); elements_accessible (list of the elements
# the mechanisms let an individual retrieve).
_ac3_14 := "access_enforcement.individual_access"

_ac3_14_missing := (_ac_bool_missing([_ac_f(_ac3_14, "mechanisms_implemented")]) | _ac_list_missing([_ac_f(_ac3_14, "odp.elements")])) | {concat("", [_ac_path(_ac_f(_ac3_14, "elements_accessible")), " (list)"]) | not is_array(_ac_get(_ac_f(_ac3_14, "elements_accessible")))}

_ac3_14_failed := _ac_bool_false([_ac_f(_ac3_14, "mechanisms_implemented")]) | {sprintf("PII elements individuals cannot access: %v (%s)", [sort(lack), _ac_path(_ac_f(_ac3_14, "elements_accessible"))]) |
	o := _ac_get(_ac_f(_ac3_14, "elements_accessible"))
	l := _ac_get(_ac_f(_ac3_14, "odp.elements"))
	is_array(o)
	is_array(l)
	lack := {x | some x in l; not x in o}
	count(lack) > 0
}

violation contains sprintf("NIST AC-3(14): %s", [_ac_enh_detail(_ac3_14_missing, _ac3_14_failed)]) if count(_ac3_14_missing | _ac3_14_failed) > 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"AC-1", "AC-2", "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)", "AC-2(5)", "AC-2(7)", "AC-2(9)", "AC-2(11)",
	"AC-2(12)", "AC-2(13)", "AC-3", "AC-4", "AC-4(1)", "AC-4(4)", "AC-4(21)", "AC-5", "AC-6", "AC-6(1)", "AC-6(2)",
	"AC-6(3)", "AC-6(5)", "AC-6(7)", "AC-6(8)", "AC-6(9)", "AC-6(10)", "AC-7", "AC-8", "AC-9", "AC-9(1)", "AC-9(4)",
	"AC-10", "AC-11", "AC-11(1)", "AC-12", "AC-12(1)", "AC-14", "AC-16", "AC-17", "AC-17(1)", "AC-17(2)", "AC-17(3)",
	"AC-17(4)", "AC-17(9)", "AC-18", "AC-18(1)", "AC-18(3)", "AC-18(4)", "AC-18(5)", "AC-19", "AC-19(5)", "AC-20", "AC-20(1)",
	"AC-20(2)", "AC-21", "AC-22", "AC-23", "AC-24", "AC-25",
	"AC-3(14)",
}

compliance_report := {
	"family": "AC",
	"name": "Access Control",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
