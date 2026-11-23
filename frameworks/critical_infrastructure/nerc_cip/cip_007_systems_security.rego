# METADATA
# title: "CIP-007-6: Systems Security Management"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 32
#     cited: 16
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_007

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default default_passwords_changed := false

default login_attempt_limiting := false

default malicious_code_prevention_implemented := false

default malicious_code_response_documented := false

default password_policy_enforced := false

default patch_tracking_process := false

default physical_io_ports_protected := false

default ports_and_services_minimized := false

default ports_and_services_policy := false

default security_event_alerting := false

default security_event_logging_enabled := false

default security_log_review_current := false

default security_patch_evaluation_timely := false

default security_patches_applied := false

default shared_accounts_minimized := false

default unique_authentication_credentials := false

# -----------------------------------------------------------------------------
# Dated evidence
# -----------------------------------------------------------------------------

# Date normaliser: RFC 3339 strings or epoch nanoseconds; anything else is
# undefined, so the caller fails closed.
date_ns(v) := n if {
	is_string(v)
	n := time.parse_rfc3339_ns(v)
}

date_ns(v) := v if is_number(v)

# Evaluation clock. Tests pin it with `with time.now_ns as <ns>`.
now_ns := time.now_ns()

ns_per_day := 86400000000000

# Age in days of a dated record. Undefined when the date is absent, not a date,
# or later than the evaluation time: an activity dated in the future has not
# happened yet and is not evidence that it was done.
age_days(v) := (now_ns - date_ns(v)) / ns_per_day if date_ns(v) <= now_ns

# Days from start to end. Undefined when either date is absent or not a date,
# or when the end date is later than the evaluation time.
days_between(start, end) := (date_ns(end) - date_ns(start)) / ns_per_day if date_ns(end) <= now_ns

# Why a dated record cannot be used: "future", or "missing" when it is absent,
# of the wrong type or not RFC 3339. Undefined for a usable date.
date_problem(v) := "future" if date_ns(v) > now_ns

date_problem(v) := "missing" if not date_ns(v)

# Per-system requirements need the BES Cyber System inventory to have been collected.
bes_inventory_present if is_array(input.bes_cyber_systems)

# CIP-007-6: Systems Security Management
# Requirement: Manage system security by specifying select technical, operational,
# and procedural requirements in support of protecting BES Cyber Systems against
# compromise that could lead to misoperation or instability.
#
# NERC Standards Reference: CIP-007-6 (mandatory and enforceable in the United
# States; CIP-007-7.1 is approved with an effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-007-6.pdf
#
# Requirement parts of CIP-007-6 and the check that reads each:
#   R1  Ports and Services            1.1 logical ports, 1.2 physical ports
#   R2  Security Patch Management     2.1 tracking, 2.2 evaluation every 35 days,
#                                     2.3 apply or mitigation plan, 2.4 (not implemented)
#   R3  Malicious Code Prevention     3.1 deter/detect/prevent, 3.2 mitigate,
#                                     3.3 signature updates (inside the 3.1 check)
#   R4  Security Event Monitoring     4.1 logging, 4.2 alerting, 4.3 90-day
#                                     retention (inside the 4.1 check), 4.4 review
#                                     every 15 calendar days
#   R5  System Access Control         5.1 authentication, 5.2 (not implemented),
#                                     5.3 shared accounts, 5.4 default passwords,
#                                     5.5 password length/complexity, 5.6 password
#                                     change (inside the 5.5 check), 5.7 attempt limits

# =============================================================================
# R1: Ports and Services
# =============================================================================

# R1 - Documented process to authorize and document only needed ports and services
ports_and_services_policy if {
	input.ports_and_services.policy_documented == true
	input.ports_and_services.authorization_required == true
	input.ports_and_services.review_process_defined == true
}

# R1.1 - Enable only logical network accessible ports determined to be needed
ports_and_services_minimized if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not ports_minimized(system)
	]
	count(violations) == 0
}

ports_minimized(system) if {
	port_mgmt := input.network_port_management[system.system_id]
	port_mgmt.ports_documented == true
	port_mgmt.unnecessary_ports_disabled == true
	port_mgmt.port_review_current == true
	port_mgmt.authorization_documented == true
}

# R1.2 - Protect against the use of unnecessary physical input/output ports
physical_io_ports_protected if {
	bes_inventory_present

	# Judge only high/medium systems: a low impact system is out of scope and must
	# not make the whole requirement false.
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		not physical_io_unprotected(system)
	}
}

# Missing port-management evidence is a finding, not a pass.
physical_io_unprotected(system) if {
	not input.network_port_management[system.system_id].physical_ports.unused_disabled == true
}

# =============================================================================
# R2: Security Patch Management
# =============================================================================

# R2.1 - Track security patches and vulnerability notifications for BES Cyber Systems
patch_tracking_process if {
	input.patch_management.tracking_process_documented == true
	input.patch_management.vulnerability_sources_identified == true
	input.patch_management.ics_cert_monitoring == true
	input.patch_management.vendor_notifications_monitored == true
}

# R2.2 - Evaluate security patches for applicability at least once every 35
# calendar days (read here as: evaluated within 35 days of availability)
security_patch_evaluation_timely if {
	violations := [patch |
		patch := input.security_patches[_]
		patch.applicable == true
		not patch_evaluated_timely(patch)
	]
	count(violations) == 0
}

patch_evaluated_timely(patch) if {
	patch.evaluation.completed == true

	# An evaluation dated after the evaluation time has not been completed.
	days_between(patch.availability_date, patch.evaluation.completion_date) <= 35
}

# R2.3 - Within 35 calendar days of the evaluation, apply the patch or create or
# revise a dated mitigation plan
security_patches_applied if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not patch_management_adequate(system)
	]
	count(violations) == 0
}

patch_management_adequate(system) if {
	patch_mgmt := input.patch_management[system.system_id]
	patch_mgmt.process_documented == true
	patch_mgmt.vulnerability_assessment_performed == true
	patch_mgmt.patch_installation_tracking == true
	patch_mgmt.emergency_procedures_defined == true
}

# =============================================================================
# R3: Malicious Code Prevention
# =============================================================================

# R3.1 - Implement methods to deter, detect, or prevent malicious code
malicious_code_prevention_implemented if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not malicious_code_protection_adequate(system)
	]
	count(violations) == 0
}

malicious_code_protection_adequate(system) if {
	protection := input.malicious_code_protection[system.system_id]
	protection.method_implemented == true # AV, application whitelisting, etc.
	protection.signatures_current == true
	protection.scanning_enabled == true
}

# R3.2 - Mitigate the threat of detected malicious code
malicious_code_response_documented if {
	input.malicious_code_response.procedures_documented == true
	input.malicious_code_response.escalation_procedures == true
	input.malicious_code_response.eradication_procedures == true
}

# R3.2 (not evaluated) - alternate mitigation where anti-malware is not available.
# Part 3.3 (signature and pattern updates) is read by signatures_current in the 3.1 check.
malicious_code_mitigation_documented if {
	input.malicious_code_protection.mitigation_procedures_documented == true
	input.malicious_code_protection.alternate_controls_when_av_not_available == true
}

# =============================================================================
# R4: Security Event Monitoring
# =============================================================================

# R4.1 - Log events (4.1.1-4.1.3); the same per-system record carries Part 4.3,
# retention of the logs for at least the last 90 consecutive calendar days
security_event_logging_enabled if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not security_monitoring_adequate(system)
	]
	count(violations) == 0
}

security_monitoring_adequate(system) if {
	monitoring := input.security_monitoring[system.system_id]
	monitoring.logging_enabled == true
	monitoring.log_retention_adequate == true
	is_number(monitoring.log_retention_days)
	monitoring.log_retention_days >= 90
	monitoring.event_correlation == true
	monitoring.alerting_configured == true
}

# R4.2 - Generate alerts for security events
security_event_alerting if {
	input.security_event_alerting.enabled == true
	input.security_event_alerting.failed_login_alert == true
	input.security_event_alerting.account_lockout_alert == true
	input.security_event_alerting.privilege_escalation_alert == true
	input.security_event_alerting.alert_review_process_documented == true
}

# R4.4 - Review a summarization or sampling of logged events at intervals no
# greater than 15 calendar days. (Earlier releases labelled this R4.3 and allowed
# 15 calendar months; Part 4.3 is log retention.) Part 4.4 applies to high impact
# BES Cyber Systems: with an inventory that holds none, it is not applicable.
log_review_applicable if not bes_inventory_present

log_review_applicable if {
	some system in input.bes_cyber_systems
	system.impact_categorization == "high"
}

security_log_review_current if {
	not log_review_applicable
} else if {
	age_days(input.security_event_alerting.last_review_date) <= 15
}

dated_evidence contains {
	"requirement": "R4.4",
	"path": "security_event_alerting.last_review_date",
	"value": object.get(input, ["security_event_alerting", "last_review_date"], null),
} if {
	log_review_applicable
}

# Per-patch dates behind Part 2.2.
dated_evidence contains {
	"requirement": "R2.2",
	"path": sprintf("security_patches[%d].%s", [i, field.name]),
	"value": field.value,
} if {
	some i, patch in input.security_patches
	patch.applicable == true
	patch.evaluation.completed == true
	some field in [
		{"name": "availability_date", "value": object.get(patch, "availability_date", null)},
		{"name": "evaluation.completion_date", "value": object.get(patch, ["evaluation", "completion_date"], null)},
	]
}

# =============================================================================
# R5: System Access Controls
# =============================================================================

# R5.1 - Enforce authentication of interactive user access
unique_authentication_credentials if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not access_controls_adequate(system)
	]
	count(violations) == 0
}

access_controls_adequate(system) if {
	access_ctrl := input.system_access_controls[system.system_id]
	access_ctrl.user_authentication == true
	access_ctrl.unique_account_per_user == true
	access_ctrl.account_management == true
	access_ctrl.password_policy_enforced == true
	access_ctrl.session_management == true
}

# R5.5 - Password length (5.5.1) and complexity (5.5.2) for password-only
# authentication; the same record carries Part 5.6 (password change) and Part 5.7
# (limit or alert on unsuccessful attempts)
password_policy_enforced if {
	is_number(input.password_policy.minimum_length)
	input.password_policy.minimum_length >= 8
	input.password_policy.complexity_required == true
	input.password_policy.expiration_configured == true
	input.password_policy.account_lockout_configured == true
	is_number(input.password_policy.lockout_threshold)
	input.password_policy.lockout_threshold <= 5
}

# R5.4 - Change known default passwords, per Cyber Asset capability
default_passwords_changed if {
	bes_inventory_present
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		not default_password_vulnerability(system)
	}
}

# Missing system_configurations evidence is a finding, not a pass.
default_password_vulnerability(system) if {
	not input.system_configurations[system.system_id].default_passwords.changed == true
}

# R5.3 - Shared accounts: individuals with authorized access are identified and
# the account is justified
shared_accounts_minimized if {
	violations := [account |
		account := input.user_accounts[_]
		account.shared == true
		not account.technical_necessity_documented == true
	]
	count(violations) == 0
}

# R5.7 - Limit the number of unsuccessful authentication attempts (or alert)
login_attempt_limiting if {
	bes_inventory_present
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		input.system_access_controls[system.system_id].account_lockout_configured == true
	}
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not ports_and_services_minimized
	v := {
		"standard": "CIP-007",
		"requirement": "R1.1",
		"severity": "high",
		"description": "Unnecessary ports or services enabled on one or more BES Cyber Systems",
		"remediation": "Disable all ports and services not required for system function; document authorized ports",
	}
}

violations contains v if {
	not patch_tracking_process
	v := {
		"standard": "CIP-007",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Security patch tracking process not documented or vulnerability sources not identified",
		"remediation": "Establish patch tracking process monitoring ICS-CERT, vendor advisories, and other sources",
	}
}

violations contains v if {
	not security_patch_evaluation_timely
	v := {
		"standard": "CIP-007",
		"requirement": "R2.2",
		"severity": "high",
		"description": "Security patches not evaluated within 35 days of availability",
		"remediation": "Establish 35-day evaluation process for all applicable security patches",
	}
}

violations contains v if {
	not security_patches_applied
	v := {
		"standard": "CIP-007",
		"requirement": "R2.3",
		"severity": "critical",
		"description": "Security patches not applied or missing documented mitigation for applicable BES Cyber Systems",
		"remediation": "Apply applicable patches or document technical mitigation for each applicable vulnerability",
	}
}

violations contains v if {
	not malicious_code_prevention_implemented
	v := {
		"standard": "CIP-007",
		"requirement": "R3.1",
		"severity": "critical",
		"description": "Malicious code prevention not implemented on one or more BES Cyber Systems",
		"remediation": "Implement anti-virus, application whitelisting, or equivalent controls on all applicable systems",
	}
}

violations contains v if {
	not security_event_logging_enabled
	v := {
		"standard": "CIP-007",
		"requirement": "R4.1",
		"severity": "high",
		"description": "Security event logging not enabled (Part 4.1) or log retention insufficient (Part 4.3, less than 90 days)",
		"remediation": "Enable security event logging with at least 90-day retention on all applicable systems",
	}
}

violations contains v if {
	not unique_authentication_credentials
	v := {
		"standard": "CIP-007",
		"requirement": "R5.1",
		"severity": "critical",
		"description": "Authentication of interactive user access not enforced with unique accounts",
		"remediation": "Ensure each user has a unique account; eliminate shared accounts unless technically necessary",
	}
}

violations contains v if {
	not password_policy_enforced
	v := {
		"standard": "CIP-007",
		"requirement": "R5.5",
		"severity": "high",
		"description": "Password policy does not meet minimum requirements (Parts 5.5-5.7)",
		"remediation": "Enforce password policy with minimum length, complexity, expiration, and lockout requirements",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not ports_and_services_policy
	v := {
		"standard": "CIP-007",
		"requirement": "R1",
		"severity": "medium",
		"description": "CIP-007 R1: ports and services policy requirement not met",
		"remediation": "Satisfy and evidence the ports and services policy requirement (CIP-007 R1)",
	}
}

violations contains v if {
	not physical_io_ports_protected
	v := {
		"standard": "CIP-007",
		"requirement": "R1.2",
		"severity": "medium",
		"description": "CIP-007 R1.2: physical io ports protected requirement not met",
		"remediation": "Satisfy and evidence the physical io ports protected requirement (CIP-007 R1.2)",
	}
}

violations contains v if {
	not malicious_code_response_documented
	v := {
		"standard": "CIP-007",
		"requirement": "R3.2",
		"severity": "medium",
		"description": "CIP-007 R3.2: malicious code response documented requirement not met",
		"remediation": "Satisfy and evidence the malicious code response documented requirement (CIP-007 R3.2)",
	}
}

violations contains v if {
	not security_event_alerting
	v := {
		"standard": "CIP-007",
		"requirement": "R4.2",
		"severity": "medium",
		"description": "CIP-007 R4.2: security event alerting requirement not met",
		"remediation": "Satisfy and evidence the security event alerting requirement (CIP-007 R4.2)",
	}
}

violations contains v if {
	not default_passwords_changed
	v := {
		"standard": "CIP-007",
		"requirement": "R5.4",
		"severity": "medium",
		"description": "CIP-007 R5.4: default passwords changed requirement not met",
		"remediation": "Satisfy and evidence the default passwords changed requirement (CIP-007 R5.4)",
	}
}

violations contains v if {
	not shared_accounts_minimized
	v := {
		"standard": "CIP-007",
		"requirement": "R5.3",
		"severity": "medium",
		"description": "CIP-007 R5.3: shared accounts minimized requirement not met",
		"remediation": "Satisfy and evidence the shared accounts minimized requirement (CIP-007 R5.3)",
	}
}

violations contains v if {
	not login_attempt_limiting
	v := {
		"standard": "CIP-007",
		"requirement": "R5.7",
		"severity": "medium",
		"description": "CIP-007 R5.7: login attempt limiting requirement not met",
		"remediation": "Satisfy and evidence the login attempt limiting requirement (CIP-007 R5.7)",
	}
}

violations contains v if {
	not security_log_review_current
	v := {
		"standard": "CIP-007",
		"requirement": "R4.4",
		"severity": "medium",
		"description": "Logged security events not reviewed within 15 calendar days (R4.4)",
		"remediation": "Review a summarization or sampling of logged events at intervals no greater than 15 calendar days",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-007",
		"requirement": e.requirement,
		"severity": "medium",
		"description": sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [e.path]),
		"remediation": sprintf("Collect input.%s as an RFC 3339 timestamp", [e.path]),
	}
}

violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "future"
	v := {
		"standard": "CIP-007",
		"requirement": e.requirement,
		"severity": "high",
		"description": sprintf("input.%s (%v) is later than the evaluation time — a future date is not evidence of a completed activity", [e.path, e.value]),
		"remediation": sprintf("Record in input.%s the date the activity was actually completed", [e.path]),
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	ports_and_services_policy
	ports_and_services_minimized
	physical_io_ports_protected
	patch_tracking_process
	security_patch_evaluation_timely
	security_patches_applied
	malicious_code_prevention_implemented
	malicious_code_response_documented
	security_event_logging_enabled
	security_event_alerting
	security_log_review_current
	unique_authentication_credentials
	password_policy_enforced
	default_passwords_changed
	shared_accounts_minimized
	login_attempt_limiting
}

report := {
	"standard": "CIP-007-6",
	"title": "Systems Security Management",
	"compliant": compliant,
	"requirements": {
		"R1_ports_policy": ports_and_services_policy,
		"R1_1_ports_minimized": ports_and_services_minimized,
		"R1_2_physical_ports": physical_io_ports_protected,
		"R2_1_patch_tracking": patch_tracking_process,
		"R2_2_patch_evaluation_timely": security_patch_evaluation_timely,
		"R2_3_patches_applied": security_patches_applied,
		"R3_1_malicious_code_prevention": malicious_code_prevention_implemented,
		"R3_2_malicious_code_response": malicious_code_response_documented,
		"R4_1_security_event_logging": security_event_logging_enabled,
		"R4_2_security_alerting": security_event_alerting,
		"R4_4_log_review_current": security_log_review_current,
		"R5_1_unique_credentials": unique_authentication_credentials,
		"R5_3_shared_accounts_minimized": shared_accounts_minimized,
		"R5_4_default_passwords_changed": default_passwords_changed,
		"R5_5_password_policy": password_policy_enforced,
		"R5_7_login_limiting": login_attempt_limiting,
	},
	"violations": violations,
	"violation_count": count(violations),
}
