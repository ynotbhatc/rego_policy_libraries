# METADATA
# title: "CIP-005-7: Electronic Security Perimeters"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 24
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_005

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default access_attempt_logging := false

default all_applicable_systems_in_esp := false

default deny_by_default_implemented := false

default electronic_access_points_controlled := false

default electronic_security_perimeters_documented := false

default esp_monitoring_enabled := false

default remote_access_authentication_implemented := false

default remote_access_encrypted := false

default remote_access_monitored := false

default remote_access_session_timeout := false

default unused_ports_disabled := false

# CIP-005-7: Electronic Security Perimeters
# Requirement: Manage electronic access to BES Cyber Systems by specifying
# a controlled Electronic Security Perimeter in support of protecting
# BES Cyber Systems against compromise.
#
# NERC Standards Reference: CIP-005-7
# (mandatory and enforceable in the United States; CIP-005-8 is approved with an
# effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-005-7.pdf
#
# Requirement parts of CIP-005-7 and the checks that read them:
#   R1  1.1 Cyber Assets inside a defined ESP, 1.2 External Routable Connectivity
#       through an identified EAP, 1.3 inbound and outbound access permissions
#       with deny by default, 1.4 Dial-up Connectivity authentication (not
#       implemented), 1.5 detection of malicious communications
#   R2  2.1 Intermediate System, 2.2 encryption, 2.3 multi-factor authentication,
#       2.4 and 2.5 vendor remote access sessions (not implemented)
#   R3  vendor remote access to EACMS and PACS, 3.1 and 3.2 (not implemented)
#
# Unused ports, EAP access-attempt logging, idle session timeout and session
# monitoring are not numbered parts of CIP-005-7. They are kept as supporting
# checks under R1 or R2 and say so in the finding.

# =============================================================================
# R1: Electronic Security Perimeter (ESP)
# =============================================================================

# R1.1 - All applicable BES Cyber Systems must be within a defined ESP
all_applicable_systems_in_esp if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not system_in_esp(system)
	]
	count(violations) == 0
}

system_in_esp(system) if {
	esp := input.electronic_security_perimeters[system.system_id]
	esp.defined == true
	esp.boundary_documented == true
}

# R1.2 - External Routable Connectivity goes through an identified Electronic
# Access Point (EAP): each ESP has identified EAPs
electronic_security_perimeters_documented if {
	every esp_id in input.electronic_security_perimeter_ids {
		esp := input.electronic_security_perimeters[esp_id]
		esp.documented == true
		esp.boundary_defined == true
		esp.electronic_access_points_identified == true
		count(esp.electronic_access_points) > 0
	}
}

# R1.3 - Each EAP requires inbound and outbound access permissions
electronic_access_points_controlled if {
	# No EAP inventory is no evidence (an ESP with no EAPs is not "controlled").
	is_array(input.electronic_access_points)
	count(input.electronic_access_points) > 0
	violations := [eap |
		eap := input.electronic_access_points[_]
		not eap_controls_adequate(eap)
	]
	count(violations) == 0
}

eap_controls_adequate(eap) if {
	eap.access_control.enabled == true
	eap.access_control.inbound_filtering == true
	eap.access_control.outbound_filtering == true
	eap.access_control.authentication_required == true
	eap.access_control.authorization_verified == true
	eap.monitoring.enabled == true
	eap.logging.enabled == true
	eap.logging.retention_adequate == true
}

# R1.3 - ...and denies all other access by default. (Part 1.4 is Dial-up
# Connectivity authentication, which is not implemented.)
deny_by_default_implemented if {
	every eap in input.electronic_access_points {
		eap.access_control.default_deny == true
	}
}

# R1 (supporting) - Unused ports disabled. This is a CIP-007-6 R1 control, not a
# numbered part of CIP-005-7 (Part 1.5 is detection of malicious communications).
unused_ports_disabled if {
	is_array(input.bes_cyber_systems)

	# Judge only high/medium systems: an out-of-scope (low impact) system must not
	# make the whole requirement false.
	every system in [s | some s in input.bes_cyber_systems; s.impact_categorization in ["high", "medium"]] {
		not unused_io_ports_vulnerable(system)
	}
}

# Missing port-management evidence is a finding, not a pass.
unused_io_ports_vulnerable(system) if {
	not input.network_port_management[system.system_id].unused_ports_disabled == true
}

# =============================================================================
# R2: Remote Access Management
# =============================================================================

# R2.3 - Multi-factor authentication for all Interactive Remote Access sessions
remote_access_authentication_implemented if {
	input.remote_access.policy_documented == true
	input.remote_access.authentication.multi_factor == true
	input.remote_access.authentication.implemented == true
}

# R2.2 - Encryption for all Interactive Remote Access sessions
remote_access_encrypted if {
	# The session list must have been collected (an empty list means no sessions).
	is_array(input.remote_access_sessions)
	violations := [session |
		session := input.remote_access_sessions[_]
		not session.encryption_enabled == true
	]
	count(violations) == 0
}

# R2 (supporting) - Terminate remote access sessions that are inactive for 15
# minutes; not a numbered part of CIP-005-7
remote_access_session_timeout if {
	is_number(input.remote_access.session_management.idle_timeout_minutes)
	input.remote_access.session_management.idle_timeout_minutes <= 15
	input.remote_access.session_management.timeout_implemented == true
}

# R2.1 - Intermediate System for Interactive Remote Access
controlled_intermediary if {
	not input.remote_access.uses_intermediary_device
} else if {
	input.remote_access.uses_intermediary_device == true
	input.remote_access.intermediary_device.in_esp == true
	input.remote_access.intermediary_device.access_controlled == true
	input.remote_access.intermediary_device.monitored == true
}

# R2 (supporting) - Monitor remote access sessions; not a numbered part (Part 2.4
# is determining active vendor remote access sessions)
remote_access_monitored if {
	is_array(input.remote_access_sessions)
	violations := [session |
		session := input.remote_access_sessions[_]
		not session.session_monitoring == true
	]
	count(violations) == 0
}

remote_access_managed if {
	remote_access_authentication_implemented
	remote_access_encrypted
	remote_access_session_timeout
	controlled_intermediary
	remote_access_monitored
}

# =============================================================================
# R1 Part 1.5: Detection of malicious communications (ESP monitoring)
# =============================================================================

# R1.5 - Methods for detecting known or suspected malicious communications,
# inbound and outbound: every ESP is monitored with alerting
esp_monitoring_enabled if {
	every esp_id in input.electronic_security_perimeter_ids {
		esp := input.electronic_security_perimeters[esp_id]
		esp.monitoring.enabled == true
		esp.monitoring.logging_enabled == true
		esp.monitoring.alerting_configured == true
		esp.monitoring.review_process_documented == true
	}
}

# R1 (supporting) - Access attempts (successful and failed) logged at each EAP;
# not a numbered part of CIP-005-7
access_attempt_logging if {
	every eap in input.electronic_access_points {
		eap.logging.successful_access_logged == true
		eap.logging.failed_access_logged == true
	}
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not all_applicable_systems_in_esp
	v := {
		"standard": "CIP-005",
		"requirement": "R1.1",
		"severity": "critical",
		"description": "One or more High or Medium Impact BES Cyber Systems not within a defined ESP",
		"remediation": "Define and document Electronic Security Perimeters for all applicable BES Cyber Systems",
	}
}

violations contains v if {
	not electronic_security_perimeters_documented
	v := {
		"standard": "CIP-005",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Electronic Security Perimeters not properly documented with identified EAPs",
		"remediation": "Document all ESP boundaries and identify all Electronic Access Points",
	}
}

violations contains v if {
	not electronic_access_points_controlled
	v := {
		"standard": "CIP-005",
		"requirement": "R1.3",
		"severity": "critical",
		"description": "Electronic Access Points lack required inbound/outbound access controls",
		"remediation": "Implement access controls with authentication, authorization, and logging at all EAPs",
	}
}

violations contains v if {
	not deny_by_default_implemented
	v := {
		"standard": "CIP-005",
		"requirement": "R1.3",
		"severity": "high",
		"description": "Deny-by-default not implemented at one or more Electronic Access Points",
		"remediation": "Configure firewall/ACL rules to deny all access not explicitly permitted",
	}
}

violations contains v if {
	not remote_access_authentication_implemented
	v := {
		"standard": "CIP-005",
		"requirement": "R2.3",
		"severity": "critical",
		"description": "Multi-factor authentication not implemented for remote access",
		"remediation": "Implement multi-factor authentication for all remote access to BES Cyber Systems",
	}
}

violations contains v if {
	not remote_access_encrypted
	v := {
		"standard": "CIP-005",
		"requirement": "R2.2",
		"severity": "critical",
		"description": "Remote access sessions are not encrypted",
		"remediation": "Implement encryption for all remote access connections (TLS/VPN)",
	}
}

violations contains v if {
	not remote_access_session_timeout
	v := {
		"standard": "CIP-005",
		"requirement": "R2",
		"severity": "high",
		"description": "Remote access sessions do not terminate after 15 minutes of inactivity (R2 supporting check, not a numbered part of CIP-005-7)",
		"remediation": "Configure session timeout of 15 minutes or less for remote access",
	}
}

violations contains v if {
	not esp_monitoring_enabled
	v := {
		"standard": "CIP-005",
		"requirement": "R1.5",
		"severity": "high",
		"description": "ESP monitoring not enabled or alerting not configured",
		"remediation": "Enable monitoring, logging, and alerting for all ESP access attempts",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not unused_ports_disabled
	v := {
		"standard": "CIP-005",
		"requirement": "R1",
		"severity": "medium",
		"description": "CIP-005 R1: unused ports disabled requirement not met (supporting check; the control itself is CIP-007-6 R1)",
		"remediation": "Disable or protect unused ports on every high and medium impact BES Cyber System",
	}
}

violations contains v if {
	not remote_access_managed
	v := {
		"standard": "CIP-005",
		"requirement": "R2",
		"severity": "medium",
		"description": "CIP-005 R2: remote access managed requirement not met",
		"remediation": "Satisfy and evidence the remote access management requirement (CIP-005 R2)",
	}
}

violations contains v if {
	not access_attempt_logging
	v := {
		"standard": "CIP-005",
		"requirement": "R1",
		"severity": "medium",
		"description": "CIP-005 R1: access attempt logging requirement not met (supporting check, not a numbered part of CIP-005-7)",
		"remediation": "Log successful and failed access attempts at every Electronic Access Point",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	all_applicable_systems_in_esp
	electronic_security_perimeters_documented
	electronic_access_points_controlled
	deny_by_default_implemented
	unused_ports_disabled
	remote_access_managed
	esp_monitoring_enabled
	access_attempt_logging
}

report := {
	"standard": "CIP-005-7",
	"title": "Electronic Security Perimeters",
	"compliant": compliant,
	"requirements": {
		"R1_1_systems_in_esp": all_applicable_systems_in_esp,
		"R1_2_esps_documented": electronic_security_perimeters_documented,
		"R1_3_eap_controls": electronic_access_points_controlled,
		"R1_3_deny_by_default": deny_by_default_implemented,
		"R1_5_esp_monitoring": esp_monitoring_enabled,
		"R1_supporting_unused_ports_disabled": unused_ports_disabled,
		"R1_supporting_access_logging": access_attempt_logging,
		"R2_2_remote_access_encrypted": remote_access_encrypted,
		"R2_3_remote_access_mfa": remote_access_authentication_implemented,
		"R2_supporting_session_timeout": remote_access_session_timeout,
		"R2_supporting_session_monitoring": remote_access_monitored,
	},
	"esp_summary": {
		"total_esps": count(object.get(input, ["electronic_security_perimeter_ids"], [])),
		"total_eaps": count(object.get(input, ["electronic_access_points"], [])),
		"high_impact_systems": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "high"]),
		"medium_impact_systems": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "medium"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
