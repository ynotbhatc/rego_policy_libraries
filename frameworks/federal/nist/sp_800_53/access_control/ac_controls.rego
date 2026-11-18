# METADATA
# title: "NIST SP 800-53 Rev 5 - Access Control (AC) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 71
#     cited: 34
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
# AC-9(1), AC-9(4), AC-11(1), AC-12(1), AC-17(1), AC-17(2), AC-18(1) (34 ids). A base control never fails on
# an enhancement's requirement; each enhancement is its own finding. Not evaluated: AC-13 (withdrawn,
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

# Aggregate NIST SP 800-53 Access Control compliance
nist_sp800_53_ac_compliant if {
	access_control_policy
	account_management
	access_enforcement
	information_flow_enforcement
	separation_of_duties
	least_privilege
	unsuccessful_logon_attempts
	system_use_notification
	previous_logon_notification
	concurrent_session_control
	session_lock
	pattern_hiding_display
	session_termination
	permitted_actions_restricted
	security_attributes
	remote_access_control
	wireless_access_control
	mobile_device_access_control
	external_systems_control
	information_sharing_control
	publicly_accessible_content
	data_mining_protection
	access_control_decisions
	reference_monitor
	automated_account_management
	flow_object_attributes
	authorize_security_functions
	non_privileged_access_for_nonsecurity
	previous_logon_unsuccessful_count
	previous_logon_additional_info
	user_initiated_logout
	remote_access_monitoring
	remote_access_encryption
	wireless_auth_encryption
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
	msg := "NIST AC-1: Access control policy/procedures not documented, disseminated, or reviewed"
}

violation contains msg if {
	not account_management
	msg := "NIST AC-2: Account management lacks approval, regular review, or timely removal"
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
	msg := "NIST AC-4: Information flow not enforced according to approved flow control policies"
}

violation contains msg if {
	not separation_of_duties
	msg := "NIST AC-5: Duties not identified and documented or access authorizations not defined to support separation of duties"
}

violation contains msg if {
	not least_privilege
	msg := "NIST AC-6: Least privilege not employed (input.ac_controls.least_privilege.minimum_access_granted)"
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
	msg := "NIST AC-8: System use notification banner/acknowledgment/consent missing"
}

violation contains msg if {
	not previous_logon_notification
	msg := "NIST AC-9: Date and time of the last logon not displayed to the user upon successful logon"
}

violation contains msg if {
	not concurrent_session_control
	msg := "NIST AC-10: Concurrent sessions not limited per account or account type"
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
	msg := "NIST AC-11(1): Device lock does not conceal previously visible information (input.ac_controls.session_lock.pattern_hiding is not true)"
}

violation contains msg if {
	not session_termination
	msg := "NIST AC-12: User sessions not automatically terminated after the defined conditions"
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
	msg := "NIST AC-17: Remote access types not authorized before connections are allowed"
}

violation contains msg if {
	not wireless_access_control
	msg := "NIST AC-18: Wireless access types not authorized before connections are allowed"
}

violation contains msg if {
	not mobile_device_access_control
	msg := "NIST AC-19: Mobile device access control missing usage restrictions or config requirements"
}

violation contains msg if {
	not external_systems_control
	msg := "NIST AC-20: External system use not authorized or governed by user agreements"
}

violation contains msg if {
	not publicly_accessible_content
	msg := "NIST AC-22: Publicly accessible content lacks review/removal process"
}

violation contains msg if {
	not security_attributes
	msg := "NIST AC-16: Security and privacy attributes not bound, associated, and preserved in transmission"
}

violation contains msg if {
	not information_sharing_control
	msg := "NIST AC-21: Information sharing lacks partner-authorization checks or automated decision support"
}

violation contains msg if {
	not data_mining_protection
	msg := "NIST AC-23: Data mining protection lacks detection techniques, warnings, or response procedures"
}

violation contains msg if {
	not access_control_decisions
	msg := "NIST AC-24: Access control decisions not based on security attributes, consistently enforced, or documented"
}

violation contains msg if {
	not reference_monitor
	msg := "NIST AC-25: Reference monitor not tamper-proof, always-invoked, and small enough to verify"
}

violation contains msg if {
	not automated_account_management
	msg := "NIST AC-2(1): Automated system account management not supported (input.ac_controls.account_management.automated_tools)"
}

violation contains msg if {
	not flow_object_attributes
	msg := "NIST AC-4(1): Security and privacy attributes not used for flow control decisions (input.ac_controls.information_flow.security_labels)"
}

violation contains msg if {
	not authorize_security_functions
	msg := "NIST AC-6(1): Access to security functions not explicitly authorized (input.ac_controls.least_privilege.privileged_functions_authorized)"
}

violation contains msg if {
	not non_privileged_access_for_nonsecurity
	msg := "NIST AC-6(2): Privileged users not required to use non-privileged accounts for nonsecurity functions (input.ac_controls.least_privilege.non_privileged_access_default)"
}

violation contains msg if {
	not previous_logon_unsuccessful_count
	msg := "NIST AC-9(1): Number of unsuccessful logon attempts not shown upon successful logon (input.ac_controls.logon_notification.unsuccessful_attempts_displayed)"
}

violation contains msg if {
	not previous_logon_additional_info
	msg := "NIST AC-9(4): Additional logon information (location) not shown upon successful logon (input.ac_controls.logon_notification.location_displayed)"
}

violation contains msg if {
	not user_initiated_logout
	msg := "NIST AC-12(1): No user-initiated logout capability (input.ac_controls.session_termination.user_initiated)"
}

violation contains msg if {
	not remote_access_monitoring
	msg := "NIST AC-17(1): Remote access methods not monitored and controlled by automated mechanisms (input.ac_controls.remote_access.monitored_controlled)"
}

violation contains msg if {
	not remote_access_encryption
	msg := "NIST AC-17(2): Remote access sessions not cryptographically protected (input.ac_controls.remote_access.encrypted_connections)"
}

violation contains msg if {
	not wireless_auth_encryption
	msg := "NIST AC-18(1): Wireless access not protected by authentication and encryption (input.ac_controls.wireless_access.encrypted_authentication)"
}

default compliant := false

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"AC-1", "AC-2", "AC-2(1)", "AC-3", "AC-4", "AC-4(1)", "AC-5", "AC-6", "AC-6(1)", "AC-6(2)", "AC-7", "AC-8",
	"AC-9", "AC-9(1)", "AC-9(4)", "AC-10", "AC-11", "AC-11(1)", "AC-12", "AC-12(1)", "AC-14", "AC-16", "AC-17",
	"AC-17(1)", "AC-17(2)", "AC-18", "AC-18(1)", "AC-19", "AC-20", "AC-21", "AC-22", "AC-23", "AC-24", "AC-25",
}

compliance_report := {
	"family": "AC",
	"name": "Access Control",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
