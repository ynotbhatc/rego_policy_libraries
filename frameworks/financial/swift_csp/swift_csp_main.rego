# METADATA
# title: "SWIFT Customer Security Programme (CSP)"
# custom:
#   class: compliance
#   framework: swift_csp
#   source: swift
#   domains: [financial, banking]
#   coverage:
#     checks: 45
#     cited: 23
#     expected: 32
#     found: 45
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package swift_csp.main

import rego.v1

# SWIFT Customer Security Programme (CSP)
# Customer Security Controls Framework (CSCF) v2024
#
# Required for all SWIFT network participants (banks, financial institutions,
# corporates, and market infrastructures using SWIFT messaging).
#
# Control architecture:
#   Mandatory controls (M) — must be implemented by all users
#   Advisory controls (A)  — strongly recommended best practices
#
# Three security objectives:
#   1. Secure your environment   (controls 1.x, 2.x)
#   2. Know and limit access     (controls 4.x, 5.x, 6.x)
#   3. Detect and respond        (controls 6.x, 7.x)
#
# OPA endpoint: POST http://<host>:8182/v1/data/swift_csp/main/compliance_report

default compliant := false

compliant if {
	count(mandatory_violations) == 0
}

# ── Objective 1: Secure Your Environment ─────────────────────────────────────

# Control 1.1 — SWIFT Environment Protection (M)
violations contains msg if {
	note := _unmet(_root, ["environment", "secure_zone", "defined"])
	text := "SWIFT CSP 1.1(M): SWIFT infrastructure not isolated in a secure zone separate from general IT"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["environment", "secure_zone", "network_segmentation"])
	text := "SWIFT CSP 1.1(M): Network segmentation not implemented between SWIFT zone and other networks"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["environment", "data_flow", "documented"])
	text := "SWIFT CSP 1.1(M): Data flows between SWIFT zone and other components not documented"
	msg := concat("", [text, note])
}

# Control 1.2 — Operating System Privilege Account Control (M)
violations contains msg if {
	note := _unmet(_root, ["os_security", "privileged_accounts", "restricted"])
	text := "SWIFT CSP 1.2(M): OS privileged accounts on SWIFT systems not restricted to minimum required"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["os_security", "admin_accounts", "not_used_for_daily_tasks"])
	text := "SWIFT CSP 1.2(M): Administrative accounts on SWIFT systems used for day-to-day tasks"
	msg := concat("", [text, note])
}

# Control 1.3 — Virtualisation Platform Security (M)
violations contains msg if {
	input.infrastructure.virtualised == true
	note := _unmet(_root, ["infrastructure", "virtualisation", "host_hardened"])
	text := "SWIFT CSP 1.3(M): Virtualisation platform hosting SWIFT components not hardened"
	msg := concat("", [text, note])
}

violations contains msg if {
	input.infrastructure.virtualised == true
	note := _unmet(_root, ["infrastructure", "virtualisation", "swift_vms_isolated"])
	text := "SWIFT CSP 1.3(M): SWIFT VMs not isolated from non-SWIFT VMs on shared infrastructure"
	msg := concat("", [text, note])
}

violations contains msg if {
	not is_boolean(object.get(_root, ["infrastructure", "virtualised"], null))
	msg := "SWIFT CSP 1.3(M): evidence missing — infrastructure.virtualised not collected; applicability of virtualisation platform security cannot be determined"
}

# Control 1.4 — Restriction of Internet Access (M)
violations contains msg if {
	note := _unmet(_root, ["network", "internet_access", "restricted_from_swift_zone"])
	text := "SWIFT CSP 1.4(M): Internet access not restricted from SWIFT infrastructure zone"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["network", "outbound_filtering", "enabled"])
	text := "SWIFT CSP 1.4(M): Outbound internet traffic from SWIFT environment not controlled and filtered"
	msg := concat("", [text, note])
}

# Control 2.1 — Internal Data Flow Security (M)
violations contains msg if {
	note := _unmet(_root, ["data_security", "internal_flows", "encrypted"])
	text := "SWIFT CSP 2.1(M): SWIFT data flows within internal network not protected with encryption"
	msg := concat("", [text, note])
}

# Control 2.2 — Security Updates (M)
violations contains msg if {
	note := _unmet(_root, ["patch_management", "swift_components", "current"])
	text := "SWIFT CSP 2.2(M): SWIFT software components not updated with latest security patches"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["patch_management", "os", "critical_patches_within_3_months"])
	text := "SWIFT CSP 2.2(M): Critical OS patches on SWIFT systems not applied within 3 months"
	msg := concat("", [text, note])
}

# Control 2.3 — System Hardening (M)
violations contains msg if {
	note := _unmet(_root, ["hardening", "swift_systems", "baseline_applied"])
	text := "SWIFT CSP 2.3(M): Security hardening baseline not applied to SWIFT infrastructure systems"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["hardening", "unnecessary_services", "disabled"])
	text := "SWIFT CSP 2.3(M): Unnecessary services, ports, and programs not disabled on SWIFT systems"
	msg := concat("", [text, note])
}

# Control 2.4 — Back Office Data Flow Security (M — for A4 and B user types)
violations contains msg if {
	note := _unmet(_root, ["back_office", "data_flows", "encrypted"])
	text := "SWIFT CSP 2.4(M): Data flows between SWIFT infrastructure and back-office systems not encrypted"
	msg := concat("", [text, note])
}

# Control 2.5 — External Transmission Data Protection (M)
violations contains msg if {
	note := _unmet(_root, ["transmission", "swift_messages", "integrity_protected"])
	text := "SWIFT CSP 2.5(M): SWIFT messages not integrity-protected for external transmission"
	msg := concat("", [text, note])
}

# Control 2.6 — Operator Session Confidentiality and Integrity (M)
violations contains msg if {
	note := _unmet(_root, ["sessions", "operator", "encrypted"])
	text := "SWIFT CSP 2.6(M): Operator sessions to SWIFT systems not encrypted"
	msg := concat("", [text, note])
}

# Control 2.7 — Vulnerability Scanning (M)
violations contains msg if {
	note := _unmet(_root, ["vulnerability_scanning", "swift_zone", "quarterly"])
	text := "SWIFT CSP 2.7(M): Vulnerability scanning of SWIFT infrastructure not conducted at least quarterly"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["vulnerability_scanning", "findings", "remediated_timely"])
	text := "SWIFT CSP 2.7(M): Critical and high vulnerabilities on SWIFT systems not remediated within defined timeframes"
	msg := concat("", [text, note])
}

# Control 2.8 — Outsourced Critical Activity Protection (M)
violations contains msg if {
	input.outsourcing.swift_activities == true
	note := _unmet(_root, ["outsourcing", "service_provider", "cscf_compliant"])
	text := "SWIFT CSP 2.8(M): Outsourced SWIFT service provider not confirmed as CSCF compliant"
	msg := concat("", [text, note])
}

violations contains msg if {
	not is_boolean(object.get(_root, ["outsourcing", "swift_activities"], null))
	msg := "SWIFT CSP 2.8(M): evidence missing — outsourcing.swift_activities not collected; applicability of outsourced activity protection cannot be determined"
}

# ── Objective 2: Know and Limit Access ───────────────────────────────────────

# Control 4.1 — Password Policy (M)
violations contains msg if {
	note := _unmet(_root, ["authentication", "passwords", "strong_policy"])
	text := "SWIFT CSP 4.1(M): Strong password policy not enforced for all SWIFT system accounts"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["authentication", "passwords", "change_on_compromise"])
	text := "SWIFT CSP 4.1(M): Process not in place to immediately change passwords on suspected compromise"
	msg := concat("", [text, note])
}

# Control 5.1 — Logical Access Controls (M)
violations contains msg if {
	note := _unmet(_root, ["access_control", "swift_systems", "least_privilege"])
	text := "SWIFT CSP 5.1(M): Least privilege not enforced for access to SWIFT systems"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "swift_systems", "role_based"])
	text := "SWIFT CSP 5.1(M): Role-based access controls not implemented for SWIFT systems"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "privileged_access", "mfa"])
	text := "SWIFT CSP 5.1(M): MFA not required for all privileged access to SWIFT infrastructure"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["access_control", "access_reviews", "periodic"])
	text := "SWIFT CSP 5.1(M): Periodic reviews of user access rights to SWIFT systems not conducted"
	msg := concat("", [text, note])
}

# Control 5.2 — Token Management (M)
violations contains msg if {
	note := _unmet(_root, ["token_management", "hardware_tokens", "used_for_swift"])
	text := "SWIFT CSP 5.2(M): Hardware authentication tokens not used for SWIFT Business Application access"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["token_management", "tokens", "secure_storage"])
	text := "SWIFT CSP 5.2(M): Authentication tokens not stored securely when not in use"
	msg := concat("", [text, note])
}

# Control 5.4 — Physical and Logical Password Storage (M)
violations contains msg if {
	note := _unmet(_root, ["credential_storage", "encrypted"])
	text := "SWIFT CSP 5.4(M): Stored credentials for SWIFT systems not encrypted"
	msg := concat("", [text, note])
}

# Control 6.1 — Malware Protection (M)
violations contains msg if {
	note := _unmet(_root, ["malware_protection", "swift_systems", "antimalware_deployed"])
	text := "SWIFT CSP 6.1(M): Anti-malware software not deployed on all SWIFT infrastructure components"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["malware_protection", "swift_systems", "signatures_current"])
	text := "SWIFT CSP 6.1(M): Anti-malware signatures on SWIFT systems not regularly updated"
	msg := concat("", [text, note])
}

# ── Objective 3: Detect and Respond ──────────────────────────────────────────

# Control 6.4 — Logging and Monitoring (M)
violations contains msg if {
	note := _unmet(_root, ["logging", "swift_systems", "all_events_captured"])
	text := "SWIFT CSP 6.4(M): All security events on SWIFT systems not captured in audit logs"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["logging", "swift_transactions", "logged"])
	text := "SWIFT CSP 6.4(M): SWIFT transaction logs not maintained for all processed messages"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["logging", "retention", "minimum_3_months_online"])
	text := "SWIFT CSP 6.4(M): Logs not retained for minimum 3 months in readily accessible form"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["logging", "retention", "minimum_2_5_years_archived"])
	text := "SWIFT CSP 6.4(M): Logs not archived for minimum 2.5 years total"
	msg := concat("", [text, note])
}

# Control 7.1 — Cyber Incident Response Planning (M)
violations contains msg if {
	note := _unmet(_root, ["incident_response", "plan", "swift_specific"])
	text := "SWIFT CSP 7.1(M): SWIFT-specific cyber incident response plan not established"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["incident_response", "plan", "swift_notification_included"])
	text := "SWIFT CSP 7.1(M): Incident response plan does not include SWIFT notification procedures"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["incident_response", "swift_notification", "process_exists"])
	text := "SWIFT CSP 7.1(M): Process not established to notify SWIFT of confirmed fraud or security incidents"
	msg := concat("", [text, note])
}

# Control 7.2 — Security Training and Awareness (M)
violations contains msg if {
	note := _unmet(_root, ["training", "swift_staff", "annual"])
	text := "SWIFT CSP 7.2(M): Annual security training not provided to personnel handling SWIFT systems"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["training", "social_engineering", "included"])
	text := "SWIFT CSP 7.2(M): Security training does not include social engineering and fraud awareness"
	msg := concat("", [text, note])
}

# ── Advisory Controls (non-blocking but tracked) ─────────────────────────────

advisory_violations contains msg if {
	note := _unmet(_root, ["network", "jump_server", "deployed"])
	text := "SWIFT CSP 2.9(A): Jump server not deployed for administrative access to SWIFT infrastructure"
	msg := concat("", [text, note])
}

advisory_violations contains msg if {
	note := _unmet(_root, ["environment", "transaction_business_controls", "implemented"])
	text := "SWIFT CSP 6.2(A): Transaction business controls not implemented to detect unusual payment patterns"
	msg := concat("", [text, note])
}

advisory_violations contains msg if {
	note := _unmet(_root, ["software_integrity", "swift_components", "verified"])
	text := "SWIFT CSP 6.3(A): Software integrity of SWIFT applications not verified after installation"
	msg := concat("", [text, note])
}

# Mandatory violations are the subset that block compliance
mandatory_violations := violations

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default next_attestation_due := "unknown"

next_attestation_due := input.next_attestation_due

default swift_bic := "unknown"

swift_bic := input.swift_bic

default user_type := "unknown"

user_type := input.user_type

compliance_report := {
	"framework": "SWIFT Customer Security Programme (CSP)",
	"version": "CSCF v2024",
	"entity_name": entity_name,
	"swift_bic": swift_bic,
	"user_type": user_type,
	"assessed_at": assessment_date,
	"next_attestation_due": next_attestation_due,
	"compliant": compliant,
	# Standard contract fields (mandatory + advisory rolled up into the
	# generic violations array so the universal report shape is satisfied).
	"violations": array.concat([v | some v in mandatory_violations], [v | some v in advisory_violations]),
	"violation_count": count(mandatory_violations) + count(advisory_violations),
	"failed_controls": min([32, count(mandatory_violations) + count(advisory_violations)]),
	"total_controls": 32,
	"mandatory_violations": mandatory_violations,
	"mandatory_violation_count": count(mandatory_violations),
	"advisory_violations": advisory_violations,
	"advisory_violation_count": count(advisory_violations),
	"objective_summary": {
		"secure_environment": array.concat([v | some v in mandatory_violations; contains(v, "CSP 1.")], [v | some v in mandatory_violations; contains(v, "CSP 2.")]),
		"know_limit_access": array.concat([v | some v in mandatory_violations; contains(v, "CSP 4.")], [v | some v in mandatory_violations; contains(v, "CSP 5.")]),
		"detect_respond": array.concat([v | some v in mandatory_violations; contains(v, "CSP 6.")], [v | some v in mandatory_violations; contains(v, "CSP 7.")]),
	},
}

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
