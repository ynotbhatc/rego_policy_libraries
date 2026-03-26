package nerc_cip.cip_005

import rego.v1

# CIP-005-7: Electronic Security Perimeters
# Requirement: Manage electronic access to BES Cyber Systems by specifying
# a controlled Electronic Security Perimeter in support of protecting
# BES Cyber Systems against compromise.
#
# NERC Standards Reference: CIP-005-7

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

# R1.2 - Each ESP must have identifiable Electronic Access Points (EAPs)
electronic_security_perimeters_documented if {
	every esp_id in input.electronic_security_perimeter_ids {
		esp := input.electronic_security_perimeters[esp_id]
		esp.documented == true
		esp.boundary_defined == true
		esp.electronic_access_points_identified == true
		count(esp.electronic_access_points) > 0
	}
}

# R1.3 - Each EAP must have controls for inbound and outbound access
electronic_access_points_controlled if {
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

# R1.4 - Deny by default all access that is not explicitly allowed
deny_by_default_implemented if {
	every eap in input.electronic_access_points {
		eap.access_control.default_deny == true
	}
}

# R1.5 - Physical I/O ports not used must be disabled or protected
unused_ports_disabled if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		not unused_io_ports_vulnerable(system)
	}
}

unused_io_ports_vulnerable(system) if {
	port_mgmt := input.network_port_management[system.system_id]
	port_mgmt.unused_ports_disabled == false
}

# =============================================================================
# R2: Remote Access Management
# =============================================================================

# R2.1 - Implement a process to authenticate remote access users/machines
remote_access_authentication_implemented if {
	input.remote_access.policy_documented == true
	input.remote_access.authentication.multi_factor == true
	input.remote_access.authentication.implemented == true
}

# R2.2 - Use encryption for all remote access connections
remote_access_encrypted if {
	violations := [session |
		session := input.remote_access_sessions[_]
		not session.encryption_enabled == true
	]
	count(violations) == 0
}

# R2.3 - Terminate remote access sessions that are inactive for 15 minutes
remote_access_session_timeout if {
	input.remote_access.session_management.idle_timeout_minutes <= 15
	input.remote_access.session_management.timeout_implemented == true
}

# Controlled intermediate systems (jump hosts)
controlled_intermediary if {
	not input.remote_access.uses_intermediary_device
} else if {
	input.remote_access.uses_intermediary_device == true
	input.remote_access.intermediary_device.in_esp == true
	input.remote_access.intermediary_device.access_controlled == true
	input.remote_access.intermediary_device.monitored == true
}

# R2.4 - Monitor remote access sessions
remote_access_monitored if {
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
# R3: ESP Monitoring
# =============================================================================

# All ESPs must have monitoring enabled for access attempts
esp_monitoring_enabled if {
	every esp_id in input.electronic_security_perimeter_ids {
		esp := input.electronic_security_perimeters[esp_id]
		esp.monitoring.enabled == true
		esp.monitoring.logging_enabled == true
		esp.monitoring.alerting_configured == true
		esp.monitoring.review_process_documented == true
	}
}

# Access attempts (successful and failed) must be logged
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
		"requirement": "R1.4",
		"severity": "high",
		"description": "Deny-by-default not implemented at one or more Electronic Access Points",
		"remediation": "Configure firewall/ACL rules to deny all access not explicitly permitted",
	}
}

violations contains v if {
	not remote_access_authentication_implemented
	v := {
		"standard": "CIP-005",
		"requirement": "R2.1",
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
		"requirement": "R2.3",
		"severity": "high",
		"description": "Remote access sessions do not terminate after 15 minutes of inactivity",
		"remediation": "Configure session timeout of 15 minutes or less for remote access",
	}
}

violations contains v if {
	not esp_monitoring_enabled
	v := {
		"standard": "CIP-005",
		"requirement": "R1",
		"severity": "high",
		"description": "ESP monitoring not enabled or alerting not configured",
		"remediation": "Enable monitoring, logging, and alerting for all ESP access attempts",
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
		"R1_4_deny_by_default": deny_by_default_implemented,
		"R1_5_unused_ports_disabled": unused_ports_disabled,
		"R2_1_remote_access_auth": remote_access_authentication_implemented,
		"R2_2_remote_access_encrypted": remote_access_encrypted,
		"R2_3_session_timeout": remote_access_session_timeout,
		"R2_4_session_monitoring": remote_access_monitored,
		"R3_esp_monitoring": esp_monitoring_enabled,
		"R3_access_logging": access_attempt_logging,
	},
	"esp_summary": {
		"total_esps": count(input.electronic_security_perimeter_ids),
		"total_eaps": count(input.electronic_access_points),
		"high_impact_systems": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "high"]),
		"medium_impact_systems": count([s | s := input.bes_cyber_systems[_]; s.impact_categorization == "medium"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
