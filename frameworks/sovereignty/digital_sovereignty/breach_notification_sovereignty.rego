package digital_sovereignty.breach_notification_sovereignty

import rego.v1

# Digital Sovereignty — Breach Notification Sovereignty
# Ensures breach notifications are handled in-jurisdiction and within
# regulatory timelines. Foreign-routed notifications violate GDPR Art. 33,
# NIS2 Art. 20, and ENISA digital sovereignty principles.
#
# Input schema:
#   input.breach_notification
#     .policy_documented                          — bool
#     .procedure_tested_date                      — ISO8601 string
#     .procedure_test_frequency_days              — int (max age of test)
#     .supervisory_authority_contact_in_jurisdiction — bool
#     .notification_timeline_hours                — int (GDPR: ≤72h)
#     .early_warning_timeline_hours               — int (NIS2: ≤24h)
#     .notification_channel_in_jurisdiction       — bool
#     .notification_vendor_hq_country             — string (country code)
#     .data_processor_notification_procedure      — bool (GDPR Art. 33(2))
#     .breach_register_maintained                 — bool (GDPR Art. 33(5))
#     .forensic_evidence_jurisdiction             — string (country code)
#     .breach_comms_encrypted                     — bool
#     .law_enforcement_disclosure_controlled      — bool
#   input.approved_jurisdictions[]

# =============================================================================
# REGULATORY TIMELINE COMPLIANCE
# =============================================================================

# GDPR Art. 33: supervisory authority must be notified within 72 hours
notification_timeline_compliant if {
	input.breach_notification.notification_timeline_hours <= 72
}

# NIS2 Art. 20: 24-hour early warning to competent authority
early_warning_timeline_compliant if {
	input.breach_notification.early_warning_timeline_hours <= 24
}

# =============================================================================
# PROCEDURE DOCUMENTATION AND TESTING
# =============================================================================

# Procedure must be documented and tested within the required frequency
notification_procedure_documented if {
	input.breach_notification.policy_documented == true
	tested_ns := time.parse_rfc3339_ns(input.breach_notification.procedure_tested_date)
	max_age_ns := input.breach_notification.procedure_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

# Supervisory authority contact must be in-jurisdiction (not a foreign DPA)
supervisory_authority_in_jurisdiction if {
	input.breach_notification.supervisory_authority_contact_in_jurisdiction == true
}

# =============================================================================
# NOTIFICATION CHANNEL SOVEREIGNTY
# =============================================================================

# Breach notification tooling (SIEM/SOAR/ticketing) must not route to foreign HQ
notification_channel_sovereign if {
	input.breach_notification.notification_channel_in_jurisdiction == true
} else if {
	input.breach_notification.notification_vendor_hq_country in input.approved_jurisdictions
}

# =============================================================================
# PROCESSOR AND REGISTER OBLIGATIONS
# =============================================================================

# GDPR Art. 33(2): processors must notify controller without undue delay
processor_notification_procedure_exists if {
	input.breach_notification.data_processor_notification_procedure == true
}

# GDPR Art. 33(5): maintain a register of all breaches regardless of notification
breach_register_maintained if {
	input.breach_notification.breach_register_maintained == true
}

# =============================================================================
# EVIDENCE AND COMMUNICATIONS SOVEREIGNTY
# =============================================================================

# Forensic evidence and incident artefacts must remain in-jurisdiction
forensic_evidence_in_jurisdiction if {
	input.breach_notification.forensic_evidence_jurisdiction in input.approved_jurisdictions
}

# All breach notification communications must be encrypted end-to-end
breach_comms_encrypted if {
	input.breach_notification.breach_comms_encrypted == true
}

# Organisation must have a documented right to refuse or delay disclosure
# to foreign law enforcement agencies
foreign_le_disclosure_controlled if {
	input.breach_notification.law_enforcement_disclosure_controlled == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not notification_timeline_compliant
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-001",
		"severity": "critical",
		"description": concat("", [
			"Breach notification timeline exceeds 72 hours: ",
			format_int(input.breach_notification.notification_timeline_hours, 10),
			"h (GDPR Art. 33 requires ≤72h)",
		]),
		"remediation": "Update incident response procedure to guarantee supervisory authority notification within 72 hours; assign a dedicated breach response role",
	}
}

violations contains v if {
	not early_warning_timeline_compliant
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-002",
		"severity": "high",
		"description": concat("", [
			"NIS2 early warning timeline exceeds 24 hours: ",
			format_int(input.breach_notification.early_warning_timeline_hours, 10),
			"h (NIS2 Art. 20 requires ≤24h early warning)",
		]),
		"remediation": "Implement 24-hour early warning process to competent authority for significant incidents",
	}
}

violations contains v if {
	not notification_procedure_documented
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-003",
		"severity": "high",
		"description": "Breach notification procedure not documented or not tested within required frequency",
		"remediation": "Document and regularly test breach notification procedure; record test date and outcomes",
	}
}

violations contains v if {
	not supervisory_authority_in_jurisdiction
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-004",
		"severity": "high",
		"description": "Supervisory authority contact is outside approved jurisdiction — breach notifications may route to foreign regulator",
		"remediation": "Register with in-jurisdiction supervisory authority (e.g., national DPA); update notification contacts",
	}
}

violations contains v if {
	not notification_channel_sovereign
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-005",
		"severity": "high",
		"description": concat("", [
			"Breach notification channel routes through foreign-HQ tooling: ",
			input.breach_notification.notification_vendor_hq_country,
		]),
		"remediation": "Replace SIEM/SOAR/ticketing with in-jurisdiction tooling, or ensure notification channel is fully in-jurisdiction",
	}
}

violations contains v if {
	not processor_notification_procedure_exists
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-006",
		"severity": "medium",
		"description": "No data processor-to-controller notification procedure (GDPR Art. 33(2)) — processors may not notify in time",
		"remediation": "Include breach notification obligations in all data processing agreements; establish processor notification SLA",
	}
}

violations contains v if {
	not breach_register_maintained
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-007",
		"severity": "medium",
		"description": "No breach register maintained (GDPR Art. 33(5) requires record of all breaches, including those not reported)",
		"remediation": "Implement breach register capturing date, nature, categories affected, and actions taken for all incidents",
	}
}

violations contains v if {
	not forensic_evidence_in_jurisdiction
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-008",
		"severity": "high",
		"description": concat("", [
			"Forensic evidence and incident artefacts stored outside approved jurisdiction: ",
			input.breach_notification.forensic_evidence_jurisdiction,
		]),
		"remediation": "Ensure all forensic captures, memory dumps, and incident logs are stored in-jurisdiction",
	}
}

violations contains v if {
	not breach_comms_encrypted
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-009",
		"severity": "medium",
		"description": "Breach notification communications are not encrypted — sensitive incident details exposed in transit",
		"remediation": "Implement end-to-end encryption for all breach notification communications (email, ticketing, regulator portal)",
	}
}

violations contains v if {
	not foreign_le_disclosure_controlled
	v := {
		"domain": "breach_notification_sovereignty",
		"control": "BN-010",
		"severity": "high",
		"description": "No documented right to refuse or delay foreign law enforcement disclosure requests related to breach",
		"remediation": "Document foreign LE disclosure response procedure with legal counsel review and data owner notification steps",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	notification_timeline_compliant
	early_warning_timeline_compliant
	notification_procedure_documented
	supervisory_authority_in_jurisdiction
	notification_channel_sovereign
	processor_notification_procedure_exists
	breach_register_maintained
	forensic_evidence_in_jurisdiction
	breach_comms_encrypted
	foreign_le_disclosure_controlled
}

report := {
	"domain": "Breach Notification Sovereignty",
	"compliant": compliant,
	"controls": {
		"BN-001_notification_timeline": notification_timeline_compliant,
		"BN-002_early_warning_timeline": early_warning_timeline_compliant,
		"BN-003_procedure_documented": notification_procedure_documented,
		"BN-004_supervisory_authority_jurisdiction": supervisory_authority_in_jurisdiction,
		"BN-005_notification_channel_sovereign": notification_channel_sovereign,
		"BN-006_processor_notification_procedure": processor_notification_procedure_exists,
		"BN-007_breach_register": breach_register_maintained,
		"BN-008_forensic_evidence_jurisdiction": forensic_evidence_in_jurisdiction,
		"BN-009_breach_comms_encrypted": breach_comms_encrypted,
		"BN-010_foreign_le_controlled": foreign_le_disclosure_controlled,
	},
	"violations": violations,
	"violation_count": count(violations),
}
