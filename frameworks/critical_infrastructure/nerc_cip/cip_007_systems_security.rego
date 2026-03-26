package nerc_cip.cip_007

import rego.v1

# CIP-007-6: Systems Security Management
# Requirement: Manage system security by specifying select technical, operational,
# and procedural requirements in support of protecting BES Cyber Systems against
# compromise that could lead to misoperation or instability.
#
# NERC Standards Reference: CIP-007-6

# =============================================================================
# R1: Ports and Services
# =============================================================================

# R1.1 - Define a process to authorize and document only needed ports and services
ports_and_services_policy if {
	input.ports_and_services.policy_documented == true
	input.ports_and_services.authorization_required == true
	input.ports_and_services.review_process_defined == true
}

# R1.2 - Enable only authorized ports and services (disable all others)
ports_and_services_minimized if {
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

# R1.3 - Protect physical I/O ports
physical_io_ports_protected if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		not physical_io_unprotected(system)
	}
}

physical_io_unprotected(system) if {
	port_mgmt := input.network_port_management[system.system_id]
	port_mgmt.physical_ports.unused_disabled == false
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

# R2.2 - Evaluate security patches within 35 days of availability
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
	evaluation_age_days := (patch.evaluation.completion_date - patch.availability_date) / (24 * 60 * 60 * 1000000000)
	evaluation_age_days <= 35
}

# R2.3 - Install security patches or have documented mitigation if not installable
security_patches_applied if {
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

# R3.2 - Address response to malicious code
malicious_code_response_documented if {
	input.malicious_code_response.procedures_documented == true
	input.malicious_code_response.escalation_procedures == true
	input.malicious_code_response.eradication_procedures == true
}

# R3.3 - Mitigate threat of detected malicious code
malicious_code_mitigation_documented if {
	input.malicious_code_protection.mitigation_procedures_documented == true
	input.malicious_code_protection.alternate_controls_when_av_not_available == true
}

# =============================================================================
# R4: Security Event Monitoring
# =============================================================================

# R4.1 - Log events that might indicate compromise
security_event_logging_enabled if {
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
	monitoring.log_retention_days >= 90
	monitoring.event_correlation == true
	monitoring.alerting_configured == true
}

# R4.2 - Generate alerts for security events (failed access, account lockout)
security_event_alerting if {
	input.security_event_alerting.enabled == true
	input.security_event_alerting.failed_login_alert == true
	input.security_event_alerting.account_lockout_alert == true
	input.security_event_alerting.privilege_escalation_alert == true
	input.security_event_alerting.alert_review_process_documented == true
}

# R4.3 - Review security event logs at least every 15 calendar months
security_log_review_current if {
	last_review_ns := time.parse_rfc3339_ns(input.security_event_alerting.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# =============================================================================
# R5: System Access Controls
# =============================================================================

# R5.1 - Each account must have a unique authentication credential
unique_authentication_credentials if {
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

# R5.2 - Implement a policy for authenticating interactive user access
password_policy_enforced if {
	input.password_policy.minimum_length >= 8
	input.password_policy.complexity_required == true
	input.password_policy.expiration_configured == true
	input.password_policy.account_lockout_configured == true
	input.password_policy.lockout_threshold <= 5
}

# R5.3 - Change default or generic account passwords before deployment
default_passwords_changed if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		not default_password_vulnerability(system)
	}
}

default_password_vulnerability(system) if {
	sys_config := input.system_configurations[system.system_id]
	sys_config.default_passwords.changed == false
}

# R5.4 - Shared accounts prohibited except where technically necessary
shared_accounts_minimized if {
	violations := [account |
		account := input.user_accounts[_]
		account.shared == true
		not account.technical_necessity_documented == true
	]
	count(violations) == 0
}

# R5.5 - Limit number of unsuccessful authentication attempts
login_attempt_limiting if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		sys_config := input.system_access_controls[system.system_id]
		sys_config.account_lockout_configured == true
	}
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not ports_and_services_minimized
	v := {
		"standard": "CIP-007",
		"requirement": "R1",
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
		"requirement": "R3",
		"severity": "critical",
		"description": "Malicious code prevention not implemented on one or more BES Cyber Systems",
		"remediation": "Implement anti-virus, application whitelisting, or equivalent controls on all applicable systems",
	}
}

violations contains v if {
	not security_event_logging_enabled
	v := {
		"standard": "CIP-007",
		"requirement": "R4",
		"severity": "high",
		"description": "Security event logging not enabled or log retention insufficient (less than 90 days)",
		"remediation": "Enable security event logging with at least 90-day retention on all applicable systems",
	}
}

violations contains v if {
	not unique_authentication_credentials
	v := {
		"standard": "CIP-007",
		"requirement": "R5.1",
		"severity": "critical",
		"description": "Shared or non-unique authentication credentials in use",
		"remediation": "Ensure each user has a unique account; eliminate shared accounts unless technically necessary",
	}
}

violations contains v if {
	not password_policy_enforced
	v := {
		"standard": "CIP-007",
		"requirement": "R5.2",
		"severity": "high",
		"description": "Password policy does not meet minimum requirements",
		"remediation": "Enforce password policy with minimum length, complexity, expiration, and lockout requirements",
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
		"R1_1_ports_policy": ports_and_services_policy,
		"R1_2_ports_minimized": ports_and_services_minimized,
		"R1_3_physical_ports": physical_io_ports_protected,
		"R2_1_patch_tracking": patch_tracking_process,
		"R2_2_patch_evaluation_timely": security_patch_evaluation_timely,
		"R2_3_patches_applied": security_patches_applied,
		"R3_1_malicious_code_prevention": malicious_code_prevention_implemented,
		"R3_2_malicious_code_response": malicious_code_response_documented,
		"R4_1_security_event_logging": security_event_logging_enabled,
		"R4_2_security_alerting": security_event_alerting,
		"R4_3_log_review_current": security_log_review_current,
		"R5_1_unique_credentials": unique_authentication_credentials,
		"R5_2_password_policy": password_policy_enforced,
		"R5_3_default_passwords_changed": default_passwords_changed,
		"R5_4_shared_accounts_minimized": shared_accounts_minimized,
		"R5_5_login_limiting": login_attempt_limiting,
	},
	"violations": violations,
	"violation_count": count(violations),
}
