package ny_dfs.main

import rego.v1

# New York Department of Financial Services — 23 NYCRR Part 500
# Cybersecurity Requirements for Financial Services Companies
# Version 2 (November 2023) — significant updates from original 2017 rule
#
# Applies to: all DFS-licensed/registered entities including banks, insurance companies,
#             money transmitters, mortgage servicers, and virtual currency businesses
#
# Key sections:
#   500.2   Cybersecurity Program
#   500.3   Cybersecurity Policy
#   500.4   Chief Information Security Officer (CISO)
#   500.5   Penetration Testing and Vulnerability Assessments
#   500.6   Audit Trail
#   500.7   Access Privileges and Management
#   500.9   Risk Assessment
#   500.10  Cybersecurity Personnel and Intelligence
#   500.11  Third-Party Service Provider Security Policy
#   500.12  Multi-Factor Authentication
#   500.13  Data Retention Limitations
#   500.14  Training and Monitoring
#   500.15  Encryption of Non-Public Information
#   500.16  Incident Response and Business Continuity Plan
#   500.17  Notices to Superintendent
#
# OPA endpoint: POST http://<host>:8182/v1/data/ny_dfs/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── 500.2 — Cybersecurity Program ────────────────────────────────────────────

violations contains msg if {
    not input.cybersecurity_program.exists
    msg := "23 NYCRR 500.2: Cybersecurity program not established to protect information systems and nonpublic information"
}

violations contains msg if {
    not input.cybersecurity_program.risk_based.design
    msg := "23 NYCRR 500.2(b): Cybersecurity program not designed based on covered entity's risk assessment"
}

# ── 500.3 — Cybersecurity Policy ─────────────────────────────────────────────

violations contains msg if {
    not input.cybersecurity_policy.documented
    msg := "23 NYCRR 500.3: Written cybersecurity policy not implemented and maintained"
}

violations contains msg if {
    not input.cybersecurity_policy.board_approved
    msg := "23 NYCRR 500.3: Cybersecurity policy not approved by senior officer or board"
}

violations contains msg if {
    not input.cybersecurity_policy.annual_review
    msg := "23 NYCRR 500.3: Cybersecurity policy not reviewed at least annually"
}

# ── 500.4 — CISO ─────────────────────────────────────────────────────────────

violations contains msg if {
    not input.ciso.designated
    msg := "23 NYCRR 500.4(a): Qualified CISO not designated to oversee cybersecurity program"
}

violations contains msg if {
    not input.ciso.annual_report.to_board
    msg := "23 NYCRR 500.4(b): CISO has not provided annual report to board on cybersecurity program"
}

violations contains msg if {
    not input.ciso.annual_report.includes_material_issues
    msg := "23 NYCRR 500.4(b): CISO annual report does not address material cybersecurity issues"
}

# ── 500.5 — Penetration Testing & Vulnerability Assessments ──────────────────

violations contains msg if {
    not input.testing.penetration_test.annual
    msg := "23 NYCRR 500.5(a)(1): Annual penetration testing of information systems not performed"
}

violations contains msg if {
    not input.testing.vulnerability_assessment.semi_annual
    msg := "23 NYCRR 500.5(a)(2): Bi-annual automated vulnerability scans not conducted"
}

violations contains msg if {
    not input.testing.findings.remediation_tracked
    msg := "23 NYCRR 500.5: Penetration test and vulnerability assessment findings not tracked to remediation"
}

# ── 500.6 — Audit Trail ──────────────────────────────────────────────────────

violations contains msg if {
    not input.audit_trail.systems.tamper_resistant
    msg := "23 NYCRR 500.6(a): Audit trail systems not designed to protect against tampering and alteration"
}

violations contains msg if {
    not input.audit_trail.retention.minimum_3_years_financial
    msg := "23 NYCRR 500.6(b): Financial records audit trail not retained for minimum 3 years"
}

violations contains msg if {
    not input.audit_trail.retention.minimum_5_years_security
    msg := "23 NYCRR 500.6(b): Cybersecurity event audit trail not retained for minimum 5 years"
}

# ── 500.7 — Access Privileges ────────────────────────────────────────────────

violations contains msg if {
    not input.access_control.least_privilege.enforced
    msg := "23 NYCRR 500.7: Least privilege not enforced — access limited to what is necessary for job function"
}

violations contains msg if {
    not input.access_control.privileged_accounts.regular_review
    msg := "23 NYCRR 500.7(b): Privileged account access not reviewed at least annually"
}

violations contains msg if {
    not input.access_control.terminated_users.prompt_revocation
    msg := "23 NYCRR 500.7(c): Access not promptly revoked for terminated employees"
}

violations contains msg if {
    not input.access_control.password_policy.strong
    msg := "23 NYCRR 500.7(d): Strong password policy not enforced for system access"
}

# ── 500.9 — Risk Assessment ───────────────────────────────────────────────────

violations contains msg if {
    not input.risk_assessment.conducted
    msg := "23 NYCRR 500.9: Cybersecurity risk assessment not conducted"
}

violations contains msg if {
    not input.risk_assessment.periodic_review
    msg := "23 NYCRR 500.9(a): Risk assessment not reviewed and updated periodically"
}

violations contains msg if {
    not input.risk_assessment.covers_nonpublic_information
    msg := "23 NYCRR 500.9(a)(2): Risk assessment does not address risks to nonpublic information"
}

# ── 500.10 — Cybersecurity Personnel ─────────────────────────────────────────

violations contains msg if {
    not input.personnel.qualified_staff.available
    msg := "23 NYCRR 500.10(a): Qualified cybersecurity personnel not employed or engaged"
}

violations contains msg if {
    not input.personnel.training.cybersecurity.annual
    msg := "23 NYCRR 500.10(b): Annual cybersecurity training not provided to all relevant personnel"
}

# ── 500.11 — Third-Party Service Provider Security ────────────────────────────

violations contains msg if {
    not input.third_party.policy.documented
    msg := "23 NYCRR 500.11: Written third-party service provider security policy not implemented"
}

violations contains msg if {
    not input.third_party.contracts.security_controls_required
    msg := "23 NYCRR 500.11(a)(1): Third-party contracts do not require implementation of security controls"
}

violations contains msg if {
    not input.third_party.contracts.prompt_notification_required
    msg := "23 NYCRR 500.11(a)(2): Third-party contracts do not require prompt notification of cybersecurity events"
}

violations contains msg if {
    not input.third_party.assessment.periodic_due_diligence
    msg := "23 NYCRR 500.11(a)(3): Periodic due diligence of third-party service providers not conducted"
}

# ── 500.12 — Multi-Factor Authentication ─────────────────────────────────────

violations contains msg if {
    not input.mfa.remote_access.enforced
    msg := "23 NYCRR 500.12: MFA not implemented for remote access to information systems"
}

violations contains msg if {
    not input.mfa.third_party_access.enforced
    msg := "23 NYCRR 500.12: MFA not implemented for third-party access to internal networks"
}

violations contains msg if {
    not input.mfa.privileged_accounts.enforced
    msg := "23 NYCRR 500.12: MFA not implemented for privileged account access"
}

# ── 500.13 — Data Retention Limitations ──────────────────────────────────────

violations contains msg if {
    not input.data_retention.policy.documented
    msg := "23 NYCRR 500.13: Data retention and disposal policy not documented"
}

violations contains msg if {
    not input.data_retention.nonpublic_info.disposed_when_no_longer_needed
    msg := "23 NYCRR 500.13: Nonpublic information not securely disposed when no longer needed"
}

# ── 500.14 — Training and Monitoring ─────────────────────────────────────────

violations contains msg if {
    not input.training.security_awareness.annual
    msg := "23 NYCRR 500.14(a): Annual cybersecurity awareness training not provided to all personnel"
}

violations contains msg if {
    not input.monitoring.anomalous_activity.systems_in_place
    msg := "23 NYCRR 500.14(b): Monitoring systems not in place to detect anomalous activity"
}

violations contains msg if {
    not input.monitoring.user_activity.privileged_users_monitored
    msg := "23 NYCRR 500.14(b): Authorized user activity not monitored to detect unauthorized access"
}

# ── 500.15 — Encryption ───────────────────────────────────────────────────────

violations contains msg if {
    not input.encryption.nonpublic_info.in_transit
    msg := "23 NYCRR 500.15: Nonpublic information not encrypted in transit over external networks"
}

violations contains msg if {
    not input.encryption.nonpublic_info.at_rest
    msg := "23 NYCRR 500.15: Nonpublic information not encrypted at rest"
}

# ── 500.16 — Incident Response Plan ──────────────────────────────────────────

violations contains msg if {
    not input.incident_response.plan.documented
    msg := "23 NYCRR 500.16: Written incident response plan not established and maintained"
}

violations contains msg if {
    not input.incident_response.plan.tested_annually
    msg := "23 NYCRR 500.16: Incident response plan not tested at least annually"
}

violations contains msg if {
    not input.incident_response.plan.roles_defined
    msg := "23 NYCRR 500.16(b)(1): Roles and responsibilities not defined in incident response plan"
}

violations contains msg if {
    not input.business_continuity.plan.documented
    msg := "23 NYCRR 500.16: Business continuity plan not established for material cybersecurity events"
}

# ── 500.17 — Notices to Superintendent ───────────────────────────────────────

violations contains msg if {
    not input.superintendent_notice.process.within_72_hours
    msg := "23 NYCRR 500.17(a): Process not established to notify DFS Superintendent within 72 hours of material cybersecurity event"
}

violations contains msg if {
    not input.superintendent_notice.annual_certification.filed
    msg := "23 NYCRR 500.17(b): Annual certification of compliance not filed with DFS Superintendent"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":      "NY DFS Cybersecurity Regulation",
    "regulation":     "23 NYCRR Part 500 (v2, November 2023)",
    "entity_name":    input.entity_name,
    "entity_type":    input.entity_type,
    "dfs_license":    input.dfs_license_number,
    "assessed_at":    input.assessment_date,
    "compliant":      compliant,
    "total_controls": 41,
    "violations":     violations,
    "violation_count": count(violations),
}
