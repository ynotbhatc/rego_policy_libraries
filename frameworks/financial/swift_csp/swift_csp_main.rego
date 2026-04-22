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
    not input.environment.secure_zone.defined
    msg := "SWIFT CSP 1.1(M): SWIFT infrastructure not isolated in a secure zone separate from general IT"
}

violations contains msg if {
    not input.environment.secure_zone.network_segmentation
    msg := "SWIFT CSP 1.1(M): Network segmentation not implemented between SWIFT zone and other networks"
}

violations contains msg if {
    not input.environment.data_flow.documented
    msg := "SWIFT CSP 1.1(M): Data flows between SWIFT zone and other components not documented"
}

# Control 1.2 — Operating System Privilege Account Control (M)
violations contains msg if {
    not input.os_security.privileged_accounts.restricted
    msg := "SWIFT CSP 1.2(M): OS privileged accounts on SWIFT systems not restricted to minimum required"
}

violations contains msg if {
    not input.os_security.admin_accounts.not_used_for_daily_tasks
    msg := "SWIFT CSP 1.2(M): Administrative accounts on SWIFT systems used for day-to-day tasks"
}

# Control 1.3 — Virtualisation Platform Security (M)
violations contains msg if {
    input.infrastructure.virtualised == true
    not input.infrastructure.virtualisation.host_hardened
    msg := "SWIFT CSP 1.3(M): Virtualisation platform hosting SWIFT components not hardened"
}

violations contains msg if {
    input.infrastructure.virtualised == true
    not input.infrastructure.virtualisation.swift_vms_isolated
    msg := "SWIFT CSP 1.3(M): SWIFT VMs not isolated from non-SWIFT VMs on shared infrastructure"
}

# Control 1.4 — Restriction of Internet Access (M)
violations contains msg if {
    not input.network.internet_access.restricted_from_swift_zone
    msg := "SWIFT CSP 1.4(M): Internet access not restricted from SWIFT infrastructure zone"
}

violations contains msg if {
    not input.network.outbound_filtering.enabled
    msg := "SWIFT CSP 1.4(M): Outbound internet traffic from SWIFT environment not controlled and filtered"
}

# Control 2.1 — Internal Data Flow Security (M)
violations contains msg if {
    not input.data_security.internal_flows.encrypted
    msg := "SWIFT CSP 2.1(M): SWIFT data flows within internal network not protected with encryption"
}

# Control 2.2 — Security Updates (M)
violations contains msg if {
    not input.patch_management.swift_components.current
    msg := "SWIFT CSP 2.2(M): SWIFT software components not updated with latest security patches"
}

violations contains msg if {
    not input.patch_management.os.critical_patches_within_3_months
    msg := "SWIFT CSP 2.2(M): Critical OS patches on SWIFT systems not applied within 3 months"
}

# Control 2.3 — System Hardening (M)
violations contains msg if {
    not input.hardening.swift_systems.baseline_applied
    msg := "SWIFT CSP 2.3(M): Security hardening baseline not applied to SWIFT infrastructure systems"
}

violations contains msg if {
    not input.hardening.unnecessary_services.disabled
    msg := "SWIFT CSP 2.3(M): Unnecessary services, ports, and programs not disabled on SWIFT systems"
}

# Control 2.4 — Back Office Data Flow Security (M — for A4 and B user types)
violations contains msg if {
    not input.back_office.data_flows.encrypted
    msg := "SWIFT CSP 2.4(M): Data flows between SWIFT infrastructure and back-office systems not encrypted"
}

# Control 2.5 — External Transmission Data Protection (M)
violations contains msg if {
    not input.transmission.swift_messages.integrity_protected
    msg := "SWIFT CSP 2.5(M): SWIFT messages not integrity-protected for external transmission"
}

# Control 2.6 — Operator Session Confidentiality and Integrity (M)
violations contains msg if {
    not input.sessions.operator.encrypted
    msg := "SWIFT CSP 2.6(M): Operator sessions to SWIFT systems not encrypted"
}

# Control 2.7 — Vulnerability Scanning (M)
violations contains msg if {
    not input.vulnerability_scanning.swift_zone.quarterly
    msg := "SWIFT CSP 2.7(M): Vulnerability scanning of SWIFT infrastructure not conducted at least quarterly"
}

violations contains msg if {
    not input.vulnerability_scanning.findings.remediated_timely
    msg := "SWIFT CSP 2.7(M): Critical and high vulnerabilities on SWIFT systems not remediated within defined timeframes"
}

# Control 2.8 — Outsourced Critical Activity Protection (M)
violations contains msg if {
    input.outsourcing.swift_activities == true
    not input.outsourcing.service_provider.cscf_compliant
    msg := "SWIFT CSP 2.8(M): Outsourced SWIFT service provider not confirmed as CSCF compliant"
}

# ── Objective 2: Know and Limit Access ───────────────────────────────────────

# Control 4.1 — Password Policy (M)
violations contains msg if {
    not input.authentication.passwords.strong_policy
    msg := "SWIFT CSP 4.1(M): Strong password policy not enforced for all SWIFT system accounts"
}

violations contains msg if {
    not input.authentication.passwords.change_on_compromise
    msg := "SWIFT CSP 4.1(M): Process not in place to immediately change passwords on suspected compromise"
}

# Control 5.1 — Logical Access Controls (M)
violations contains msg if {
    not input.access_control.swift_systems.least_privilege
    msg := "SWIFT CSP 5.1(M): Least privilege not enforced for access to SWIFT systems"
}

violations contains msg if {
    not input.access_control.swift_systems.role_based
    msg := "SWIFT CSP 5.1(M): Role-based access controls not implemented for SWIFT systems"
}

violations contains msg if {
    not input.access_control.privileged_access.mfa
    msg := "SWIFT CSP 5.1(M): MFA not required for all privileged access to SWIFT infrastructure"
}

violations contains msg if {
    not input.access_control.access_reviews.periodic
    msg := "SWIFT CSP 5.1(M): Periodic reviews of user access rights to SWIFT systems not conducted"
}

# Control 5.2 — Token Management (M)
violations contains msg if {
    not input.token_management.hardware_tokens.used_for_swift
    msg := "SWIFT CSP 5.2(M): Hardware authentication tokens not used for SWIFT Business Application access"
}

violations contains msg if {
    not input.token_management.tokens.secure_storage
    msg := "SWIFT CSP 5.2(M): Authentication tokens not stored securely when not in use"
}

# Control 5.4 — Physical and Logical Password Storage (M)
violations contains msg if {
    not input.credential_storage.encrypted
    msg := "SWIFT CSP 5.4(M): Stored credentials for SWIFT systems not encrypted"
}

# Control 6.1 — Malware Protection (M)
violations contains msg if {
    not input.malware_protection.swift_systems.antimalware_deployed
    msg := "SWIFT CSP 6.1(M): Anti-malware software not deployed on all SWIFT infrastructure components"
}

violations contains msg if {
    not input.malware_protection.swift_systems.signatures_current
    msg := "SWIFT CSP 6.1(M): Anti-malware signatures on SWIFT systems not regularly updated"
}

# ── Objective 3: Detect and Respond ──────────────────────────────────────────

# Control 6.4 — Logging and Monitoring (M)
violations contains msg if {
    not input.logging.swift_systems.all_events_captured
    msg := "SWIFT CSP 6.4(M): All security events on SWIFT systems not captured in audit logs"
}

violations contains msg if {
    not input.logging.swift_transactions.logged
    msg := "SWIFT CSP 6.4(M): SWIFT transaction logs not maintained for all processed messages"
}

violations contains msg if {
    not input.logging.retention.minimum_3_months_online
    msg := "SWIFT CSP 6.4(M): Logs not retained for minimum 3 months in readily accessible form"
}

violations contains msg if {
    not input.logging.retention.minimum_2_5_years_archived
    msg := "SWIFT CSP 6.4(M): Logs not archived for minimum 2.5 years total"
}

# Control 7.1 — Cyber Incident Response Planning (M)
violations contains msg if {
    not input.incident_response.plan.swift_specific
    msg := "SWIFT CSP 7.1(M): SWIFT-specific cyber incident response plan not established"
}

violations contains msg if {
    not input.incident_response.plan.swift_notification_included
    msg := "SWIFT CSP 7.1(M): Incident response plan does not include SWIFT notification procedures"
}

violations contains msg if {
    not input.incident_response.swift_notification.process_exists
    msg := "SWIFT CSP 7.1(M): Process not established to notify SWIFT of confirmed fraud or security incidents"
}

# Control 7.2 — Security Training and Awareness (M)
violations contains msg if {
    not input.training.swift_staff.annual
    msg := "SWIFT CSP 7.2(M): Annual security training not provided to personnel handling SWIFT systems"
}

violations contains msg if {
    not input.training.social_engineering.included
    msg := "SWIFT CSP 7.2(M): Security training does not include social engineering and fraud awareness"
}

# ── Advisory Controls (non-blocking but tracked) ─────────────────────────────

advisory_violations contains msg if {
    not input.network.jump_server.deployed
    msg := "SWIFT CSP 2.9(A): Jump server not deployed for administrative access to SWIFT infrastructure"
}

advisory_violations contains msg if {
    not input.environment.transaction_business_controls.implemented
    msg := "SWIFT CSP 6.2(A): Transaction business controls not implemented to detect unusual payment patterns"
}

advisory_violations contains msg if {
    not input.software_integrity.swift_components.verified
    msg := "SWIFT CSP 6.3(A): Software integrity of SWIFT applications not verified after installation"
}

# Mandatory violations are the subset that block compliance
mandatory_violations := violations

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":               "SWIFT Customer Security Programme (CSP)",
    "version":                 "CSCF v2024",
    "entity_name":             input.entity_name,
    "swift_bic":               input.swift_bic,
    "user_type":               input.user_type,
    "assessed_at":             input.assessment_date,
    "next_attestation_due":    input.next_attestation_due,
    "compliant":               compliant,
    "mandatory_violations":    mandatory_violations,
    "mandatory_violation_count": count(mandatory_violations),
    "advisory_violations":     advisory_violations,
    "advisory_violation_count": count(advisory_violations),
    "objective_summary": {
        "secure_environment":  array.concat([v | some v in mandatory_violations; contains(v, "CSP 1.")], [v | some v in mandatory_violations; contains(v, "CSP 2.")]),
        "know_limit_access":   array.concat([v | some v in mandatory_violations; contains(v, "CSP 4.")], [v | some v in mandatory_violations; contains(v, "CSP 5.")]),
        "detect_respond":      array.concat([v | some v in mandatory_violations; contains(v, "CSP 6.")], [v | some v in mandatory_violations; contains(v, "CSP 7.")]),
    },
}
