package hitrust.main

import rego.v1

# HITRUST Common Security Framework (CSF) v11.3.0
# Published: 2023
#
# Applies to: Healthcare organizations, business associates, and
#             technology vendors handling protected health information (PHI)
#             or requiring HITRUST certification for healthcare customers.
#
# 19 Control Categories (mapped to HIPAA, NIST, ISO 27001, SOC 2):
#   00 — Information Security Management Program
#   01 — Access Control
#   02 — Human Resources Security
#   03 — Risk Management
#   04 — Security Policy
#   05 — Organization of Information Security
#   06 — Compliance
#   07 — Asset Management
#   08 — Physical and Environmental Security
#   09 — Communications and Operations Management
#   10 — Information Systems Acquisition, Development and Maintenance
#   11 — Information Access Management
#   12 — Audit Logging and Monitoring
#   13 — Education, Training and Awareness
#   14 — Third Party Assurance
#   15 — Incident Management
#   16 — Business Continuity Management
#   17 — Risk Management (specific)
#   18 — Privacy Practices
#
# OPA endpoint: POST http://<host>:8182/v1/data/hitrust/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── Category 00 — Information Security Management Program ───────────────────

violations contains msg if {
    not input.security_program.isms.established
    msg := "HITRUST CSF 00.a: Information Security Management System (ISMS) not formally established"
}

violations contains msg if {
    not input.security_program.policies.approved_by_management
    msg := "HITRUST CSF 00.b: Information security policies not approved by senior management"
}

violations contains msg if {
    not input.security_program.policies.annual_review
    msg := "HITRUST CSF 00.c: Information security policies not reviewed at least annually"
}

# ── Category 01 — Access Control ────────────────────────────────────────────

violations contains msg if {
    not input.access_control.policy.documented
    msg := "HITRUST CSF 01.a: Access control policy not established, documented, and implemented"
}

violations contains msg if {
    not input.access_control.user_access.formal_registration
    msg := "HITRUST CSF 01.b: Formal user access registration and de-registration process not established"
}

violations contains msg if {
    not input.access_control.privileged_access.controlled
    msg := "HITRUST CSF 01.c: Privileged access rights not managed through formal authorization process"
}

violations contains msg if {
    not input.access_control.password_policy.strong
    msg := "HITRUST CSF 01.d: Strong password/authentication policy not enforced"
}

violations contains msg if {
    not input.access_control.mfa.critical_systems
    msg := "HITRUST CSF 01.e: Multi-factor authentication not enforced for critical system access"
}

violations contains msg if {
    not input.access_control.access_review.periodic
    msg := "HITRUST CSF 01.f: Periodic review of user access rights not conducted (at minimum annually)"
}

violations contains msg if {
    not input.access_control.termination.prompt_revocation
    msg := "HITRUST CSF 01.g: Access rights not promptly revoked upon termination or role change"
}

# ── Category 02 — Human Resources Security ──────────────────────────────────

violations contains msg if {
    not input.hr_security.background_checks.performed
    msg := "HITRUST CSF 02.a: Pre-employment background checks not performed for personnel with PHI access"
}

violations contains msg if {
    not input.hr_security.confidentiality.agreements_signed
    msg := "HITRUST CSF 02.b: Confidentiality/non-disclosure agreements not signed by employees with PHI access"
}

violations contains msg if {
    not input.hr_security.sanctions.policy_documented
    msg := "HITRUST CSF 02.c: Sanction policy for workforce members who fail to comply with security policies not documented"
}

# ── Category 03 — Risk Management ────────────────────────────────────────────

violations contains msg if {
    not input.risk_management.assessment.conducted
    msg := "HITRUST CSF 03.a: Formal risk assessment not conducted"
}

violations contains msg if {
    not input.risk_management.assessment.phi_scope
    msg := "HITRUST CSF 03.b: Risk assessment does not include PHI confidentiality, integrity, and availability"
}

violations contains msg if {
    not input.risk_management.treatment.plan_documented
    msg := "HITRUST CSF 03.c: Risk treatment plan not documented with accepted residual risks"
}

violations contains msg if {
    not input.risk_management.assessment.periodic_review
    msg := "HITRUST CSF 03.d: Risk assessment not reviewed and updated periodically or after significant changes"
}

# ── Category 04 — Security Policy ────────────────────────────────────────────

violations contains msg if {
    not input.security_policy.phi_specific.documented
    msg := "HITRUST CSF 04.a: PHI-specific security policies and procedures not documented"
}

violations contains msg if {
    not input.security_policy.dissemination.to_workforce
    msg := "HITRUST CSF 04.b: Security policies not disseminated to all relevant workforce members"
}

# ── Category 06 — Compliance ─────────────────────────────────────────────────

violations contains msg if {
    not input.compliance.hipaa.privacy_rule.policies
    msg := "HITRUST CSF 06.a: HIPAA Privacy Rule compliance policies not implemented"
}

violations contains msg if {
    not input.compliance.hipaa.security_rule.policies
    msg := "HITRUST CSF 06.b: HIPAA Security Rule compliance policies not implemented"
}

violations contains msg if {
    not input.compliance.hipaa.breach_notification.plan
    msg := "HITRUST CSF 06.c: HIPAA Breach Notification Rule compliance plan not established"
}

violations contains msg if {
    not input.compliance.legal.periodic_review
    msg := "HITRUST CSF 06.d: Periodic compliance review not conducted to identify legal/regulatory changes"
}

# ── Category 07 — Asset Management ────────────────────────────────────────────

violations contains msg if {
    not input.asset_management.inventory.maintained
    msg := "HITRUST CSF 07.a: Asset inventory not maintained for systems and media containing PHI"
}

violations contains msg if {
    not input.asset_management.classification.phi_labeled
    msg := "HITRUST CSF 07.b: PHI assets not classified and labeled according to sensitivity"
}

violations contains msg if {
    not input.asset_management.disposal.secure_media_sanitization
    msg := "HITRUST CSF 07.c: Secure media sanitization procedures not established for PHI disposal"
}

# ── Category 08 — Physical and Environmental Security ───────────────────────

violations contains msg if {
    not input.physical_security.perimeter.controlled_access
    msg := "HITRUST CSF 08.a: Physical access to facilities containing PHI systems not controlled"
}

violations contains msg if {
    not input.physical_security.equipment.secured
    msg := "HITRUST CSF 08.b: Equipment containing PHI not secured against physical threats"
}

violations contains msg if {
    not input.physical_security.visitor_access.logged
    msg := "HITRUST CSF 08.c: Visitor access to secure areas not logged and controlled"
}

# ── Category 09 — Communications and Operations Management ──────────────────

violations contains msg if {
    not input.operations.change_management.formal_process
    msg := "HITRUST CSF 09.a: Formal change management process not established for PHI systems"
}

violations contains msg if {
    not input.operations.malware.protection_deployed
    msg := "HITRUST CSF 09.b: Malware protection not deployed on all systems processing PHI"
}

violations contains msg if {
    not input.operations.backup.phi_backed_up
    msg := "HITRUST CSF 09.c: PHI not backed up with tested recovery procedures"
}

violations contains msg if {
    not input.operations.vulnerability_management.scanning
    msg := "HITRUST CSF 09.d: Regular vulnerability scanning not performed on systems processing PHI"
}

violations contains msg if {
    not input.operations.patch_management.timely
    msg := "HITRUST CSF 09.e: Timely patch management process not established for PHI systems"
}

violations contains msg if {
    not input.operations.network_monitoring.enabled
    msg := "HITRUST CSF 09.f: Network monitoring not implemented to detect anomalous activity involving PHI"
}

# ── Category 10 — Information Systems Acquisition, Development ──────────────

violations contains msg if {
    not input.secure_development.requirements.security_included
    msg := "HITRUST CSF 10.a: Security requirements not included in information system development/acquisition"
}

violations contains msg if {
    not input.secure_development.testing.security_testing
    msg := "HITRUST CSF 10.b: Security testing not performed before PHI systems are placed into production"
}

violations contains msg if {
    not input.secure_development.phi.no_phi_in_test
    msg := "HITRUST CSF 10.c: PHI used in development or test environments — must use de-identified data"
}

# ── Category 11 — Information Access Management ──────────────────────────────

violations contains msg if {
    not input.access_management.phi.minimum_necessary
    msg := "HITRUST CSF 11.a: Access to PHI not restricted to minimum necessary for job function"
}

violations contains msg if {
    not input.access_management.remote_access.controlled
    msg := "HITRUST CSF 11.b: Remote access to PHI systems not controlled and monitored"
}

violations contains msg if {
    not input.access_management.wireless.secured
    msg := "HITRUST CSF 11.c: Wireless access transmitting PHI not properly secured and encrypted"
}

# ── Category 12 — Audit Logging and Monitoring ──────────────────────────────

violations contains msg if {
    not input.audit.phi_access.logged
    msg := "HITRUST CSF 12.a: All access to PHI (create, read, update, delete) not logged"
}

violations contains msg if {
    not input.audit.logs.protected_from_tampering
    msg := "HITRUST CSF 12.b: Audit logs not protected from unauthorized modification or deletion"
}

violations contains msg if {
    not input.audit.logs.retention_6_years
    msg := "HITRUST CSF 12.c: Audit logs for PHI not retained for minimum 6 years (HIPAA requirement)"
}

violations contains msg if {
    not input.audit.review.regular
    msg := "HITRUST CSF 12.d: Audit logs not reviewed regularly for suspicious activity"
}

# ── Category 13 — Education, Training and Awareness ─────────────────────────

violations contains msg if {
    not input.training.hipaa.all_workforce_annual
    msg := "HITRUST CSF 13.a: Annual HIPAA security and privacy training not provided to all workforce members"
}

violations contains msg if {
    not input.training.phi_handling.included
    msg := "HITRUST CSF 13.b: PHI handling procedures not included in security awareness training"
}

violations contains msg if {
    not input.training.completion.tracked
    msg := "HITRUST CSF 13.c: Security training completion not tracked for all workforce members"
}

# ── Category 14 — Third Party Assurance ─────────────────────────────────────

violations contains msg if {
    not input.third_party.baa.executed
    msg := "HITRUST CSF 14.a: Business Associate Agreements (BAA) not executed with all vendors accessing PHI"
}

violations contains msg if {
    not input.third_party.assessment.security_evaluation
    msg := "HITRUST CSF 14.b: Security evaluation of third parties with PHI access not performed"
}

violations contains msg if {
    not input.third_party.contracts.security_requirements
    msg := "HITRUST CSF 14.c: Contracts with PHI-handling vendors do not include security requirements"
}

# ── Category 15 — Incident Management ────────────────────────────────────────

violations contains msg if {
    not input.incident_response.plan.documented
    msg := "HITRUST CSF 15.a: Security incident response plan not documented"
}

violations contains msg if {
    not input.incident_response.phi_breach.procedures
    msg := "HITRUST CSF 15.b: PHI breach response procedures not established (including HIPAA notification timelines)"
}

violations contains msg if {
    not input.incident_response.plan.tested_annually
    msg := "HITRUST CSF 15.c: Incident response plan not tested at least annually"
}

violations contains msg if {
    not input.incident_response.reporting.hhs_60_days
    msg := "HITRUST CSF 15.d: Process not established to report breaches affecting 500+ individuals to HHS within 60 days"
}

# ── Category 16 — Business Continuity Management ─────────────────────────────

violations contains msg if {
    not input.business_continuity.bcp.documented
    msg := "HITRUST CSF 16.a: Business continuity plan not documented for critical PHI systems"
}

violations contains msg if {
    not input.business_continuity.drp.phi_systems
    msg := "HITRUST CSF 16.b: Disaster recovery plan not established for PHI system restoration"
}

violations contains msg if {
    not input.business_continuity.bcp.tested
    msg := "HITRUST CSF 16.c: Business continuity/disaster recovery plan not tested periodically"
}

# ── Category 17 — Risk Management Specific ────────────────────────────────────

violations contains msg if {
    not input.risk_management.encryption.phi_at_rest
    msg := "HITRUST CSF 17.a: PHI not encrypted at rest on storage systems"
}

violations contains msg if {
    not input.risk_management.encryption.phi_in_transit
    msg := "HITRUST CSF 17.b: PHI not encrypted in transit over networks (TLS 1.2+ required)"
}

# ── Category 18 — Privacy Practices ──────────────────────────────────────────

violations contains msg if {
    not input.privacy.notice.provided_to_patients
    msg := "HITRUST CSF 18.a: Notice of Privacy Practices not provided to patients"
}

violations contains msg if {
    not input.privacy.minimum_necessary.enforced
    msg := "HITRUST CSF 18.b: Minimum necessary standard not enforced for PHI access and disclosure"
}

violations contains msg if {
    not input.privacy.patient_rights.process_exists
    msg := "HITRUST CSF 18.c: Process not established to honor patient rights (access, amendment, accounting of disclosures)"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":       "HITRUST Common Security Framework (CSF)",
    "version":         "v11.3.0",
    "published":       "2023",
    "entity_name":     input.entity_name,
    "entity_type":     input.entity_type,
    "assessed_at":     input.assessment_date,
    "compliant":       compliant,
    "total_controls":  59,
    "violations":      violations,
    "violation_count": count(violations),
    "category_summary": {
        "security_mgmt_program":    [v | some v in violations; contains(v, "CSF 00.")],
        "access_control":           [v | some v in violations; contains(v, "CSF 01.")],
        "hr_security":              [v | some v in violations; contains(v, "CSF 02.")],
        "risk_management":          array.concat([v | some v in violations; contains(v, "CSF 03.")], [v | some v in violations; contains(v, "CSF 17.")]),
        "compliance":               [v | some v in violations; contains(v, "CSF 06.")],
        "asset_management":         [v | some v in violations; contains(v, "CSF 07.")],
        "physical_security":        [v | some v in violations; contains(v, "CSF 08.")],
        "operations":               [v | some v in violations; contains(v, "CSF 09.")],
        "audit_logging":            [v | some v in violations; contains(v, "CSF 12.")],
        "training":                 [v | some v in violations; contains(v, "CSF 13.")],
        "third_party":              [v | some v in violations; contains(v, "CSF 14.")],
        "incident_management":      [v | some v in violations; contains(v, "CSF 15.")],
        "business_continuity":      [v | some v in violations; contains(v, "CSF 16.")],
        "privacy":                  [v | some v in violations; contains(v, "CSF 18.")],
    },
}
