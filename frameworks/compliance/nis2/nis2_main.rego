package nis2.main

import rego.v1

# EU Network and Information Security Directive 2 (NIS2) — Directive (EU) 2022/2555
# Transposed into national law by October 2024. Covers 18 sectors:
#   Essential entities:  energy, transport, banking, financial market infrastructure,
#                        health, drinking water, wastewater, digital infrastructure,
#                        ICT service management, public administration, space
#   Important entities:  postal/courier, waste management, chemicals, food,
#                        manufacturing (medical devices, computers, machinery, vehicles),
#                        digital providers, research
#
# 10 minimum security measures (Article 21):
#   1. Risk analysis and information system security policies
#   2. Incident handling
#   3. Business continuity and crisis management
#   4. Supply chain security
#   5. Security in network and information systems acquisition/development/maintenance
#   6. Effectiveness assessment of cybersecurity risk management measures
#   7. Cyber hygiene and cybersecurity training
#   8. Cryptography and encryption policies
#   9. HR security, access control, and asset management
#  10. Multi-factor authentication
#
# OPA endpoint: POST http://<host>:8182/v1/data/nis2/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── Article 21(2)(a) — Risk Analysis & Security Policies ────────────────────

violations contains msg if {
    not input.risk_management.risk_analysis.documented
    msg := "NIS2 Art.21(2)(a): Risk analysis for network and information systems not documented"
}

violations contains msg if {
    not input.risk_management.security_policies.approved_by_management
    msg := "NIS2 Art.21(2)(a): Information security policies not approved by management body"
}

violations contains msg if {
    not input.risk_management.risk_review.frequency_annual
    msg := "NIS2 Art.21(2)(a): Risk analysis not reviewed at least annually or after significant changes"
}

# ── Article 21(2)(b) — Incident Handling ────────────────────────────────────

violations contains msg if {
    not input.incident_handling.plan.documented
    msg := "NIS2 Art.21(2)(b): Incident handling plan not documented and tested"
}

violations contains msg if {
    not input.incident_handling.significant_incident.early_warning_24h
    msg := "NIS2 Art.23(4)(a): Early warning to CSIRT/authority not issued within 24 hours of significant incident"
}

violations contains msg if {
    not input.incident_handling.significant_incident.notification_72h
    msg := "NIS2 Art.23(4)(b): Incident notification to authority not issued within 72 hours"
}

violations contains msg if {
    not input.incident_handling.significant_incident.final_report_1month
    msg := "NIS2 Art.23(4)(d): Final incident report not submitted within 1 month"
}

violations contains msg if {
    not input.incident_handling.log_retention.minimum_1_year
    msg := "NIS2 Art.21(2)(b): Security logs not retained for minimum 1 year"
}

# ── Article 21(2)(c) — Business Continuity ──────────────────────────────────

violations contains msg if {
    not input.business_continuity.bcp.documented
    msg := "NIS2 Art.21(2)(c): Business continuity plan not documented"
}

violations contains msg if {
    not input.business_continuity.bcp.tested_annually
    msg := "NIS2 Art.21(2)(c): Business continuity plan not tested at least annually"
}

violations contains msg if {
    not input.business_continuity.drp.documented
    msg := "NIS2 Art.21(2)(c): Disaster recovery plan not documented"
}

violations contains msg if {
    not input.business_continuity.crisis_management.plan_exists
    msg := "NIS2 Art.21(2)(c): Crisis management plan not established"
}

# ── Article 21(2)(d) — Supply Chain Security ────────────────────────────────

violations contains msg if {
    not input.supply_chain.vendor_assessment.process_exists
    msg := "NIS2 Art.21(2)(d): Supplier and third-party security assessment process not established"
}

violations contains msg if {
    not input.supply_chain.critical_suppliers.identified
    msg := "NIS2 Art.21(2)(d): Critical ICT suppliers not identified and risk-assessed"
}

violations contains msg if {
    not input.supply_chain.contractual_requirements.security_clauses
    msg := "NIS2 Art.21(2)(d): Security requirements not included in supplier contracts"
}

# ── Article 21(2)(e) — Secure Acquisition / Development ─────────────────────

violations contains msg if {
    not input.secure_development.sdlc_policy.documented
    msg := "NIS2 Art.21(2)(e): Secure software development lifecycle policy not documented"
}

violations contains msg if {
    not input.secure_development.vulnerability_management.process_exists
    msg := "NIS2 Art.21(2)(e): Vulnerability management process not established"
}

violations contains msg if {
    not input.secure_development.patch_management.timely
    msg := "NIS2 Art.21(2)(e): Timely patch management process not in place"
}

# ── Article 21(2)(f) — Effectiveness Assessment ─────────────────────────────

violations contains msg if {
    not input.effectiveness_assessment.penetration_testing.annual
    msg := "NIS2 Art.21(2)(f): Penetration testing not conducted at least annually"
}

violations contains msg if {
    not input.effectiveness_assessment.audit.regular
    msg := "NIS2 Art.21(2)(f): Regular security audits of cybersecurity measures not performed"
}

# ── Article 21(2)(g) — Cyber Hygiene & Training ─────────────────────────────

violations contains msg if {
    not input.training.cybersecurity_awareness.conducted_annually
    msg := "NIS2 Art.21(2)(g): Cybersecurity awareness training not conducted annually for all staff"
}

violations contains msg if {
    not input.training.management_body.cybersecurity_training
    msg := "NIS2 Art.21(2)(g): Management body members have not received cybersecurity training"
}

violations contains msg if {
    not input.cyber_hygiene.patch_policy.exists
    msg := "NIS2 Art.21(2)(g): Cyber hygiene policy (patching, updates, configurations) not established"
}

# ── Article 21(2)(h) — Cryptography ─────────────────────────────────────────

violations contains msg if {
    not input.cryptography.policy.documented
    msg := "NIS2 Art.21(2)(h): Cryptography and encryption policy not documented"
}

violations contains msg if {
    not input.cryptography.encryption.sensitive_data_at_rest
    msg := "NIS2 Art.21(2)(h): Sensitive data at rest not encrypted"
}

violations contains msg if {
    not input.cryptography.encryption.data_in_transit
    msg := "NIS2 Art.21(2)(h): Data in transit not encrypted with strong protocols"
}

# ── Article 21(2)(i) — HR Security, Access Control & Asset Management ────────

violations contains msg if {
    not input.access_control.principle_of_least_privilege.enforced
    msg := "NIS2 Art.21(2)(i): Principle of least privilege not enforced for system access"
}

violations contains msg if {
    not input.access_control.privileged_accounts.managed
    msg := "NIS2 Art.21(2)(i): Privileged accounts not managed through formal process"
}

violations contains msg if {
    not input.asset_management.inventory.maintained
    msg := "NIS2 Art.21(2)(i): Asset inventory not maintained for network and information systems"
}

violations contains msg if {
    not input.hr_security.joiners_movers_leavers.process_exists
    msg := "NIS2 Art.21(2)(i): HR security process for joiners/movers/leavers not established"
}

# ── Article 21(2)(j) — Multi-Factor Authentication ──────────────────────────

violations contains msg if {
    not input.mfa.remote_access.enforced
    msg := "NIS2 Art.21(2)(j): MFA not enforced for remote access to network and information systems"
}

violations contains msg if {
    not input.mfa.privileged_accounts.enforced
    msg := "NIS2 Art.21(2)(j): MFA not enforced for privileged account access"
}

violations contains msg if {
    not input.mfa.critical_systems.enforced
    msg := "NIS2 Art.21(2)(j): MFA not enforced for access to critical systems"
}

# ── Management Accountability (Article 20) ───────────────────────────────────

violations contains msg if {
    not input.governance.management_body.approved_measures
    msg := "NIS2 Art.20: Management body has not approved cybersecurity risk management measures"
}

violations contains msg if {
    not input.governance.management_body.oversight_accountability
    msg := "NIS2 Art.20: Management body not accountable for implementation of cybersecurity measures"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":       "EU Network and Information Security Directive 2 (NIS2)",
    "directive":       "Directive (EU) 2022/2555",
    "transposition":   "October 2024",
    "entity_name":     input.entity_name,
    "entity_type":     input.entity_type,
    "sector":          input.sector,
    "entity_category": input.entity_category,
    "assessed_at":     input.assessment_date,
    "compliant":       compliant,
    "total_controls":  34,
    "violations":      violations,
    "violation_count": count(violations),
    "article_summary": {
        "art_20_governance":          [v | some v in violations; contains(v, "Art.20")],
        "art_21a_risk_policies":      [v | some v in violations; contains(v, "Art.21(2)(a)")],
        "art_21b_incident_handling":  [v | some v in violations; contains(v, "Art.21(2)(b)")],
        "art_21c_continuity":         [v | some v in violations; contains(v, "Art.21(2)(c)")],
        "art_21d_supply_chain":       [v | some v in violations; contains(v, "Art.21(2)(d)")],
        "art_21e_secure_dev":         [v | some v in violations; contains(v, "Art.21(2)(e)")],
        "art_21f_effectiveness":      [v | some v in violations; contains(v, "Art.21(2)(f)")],
        "art_21g_hygiene_training":   [v | some v in violations; contains(v, "Art.21(2)(g)")],
        "art_21h_cryptography":       [v | some v in violations; contains(v, "Art.21(2)(h)")],
        "art_21i_access_assets":      [v | some v in violations; contains(v, "Art.21(2)(i)")],
        "art_21j_mfa":                [v | some v in violations; contains(v, "Art.21(2)(j)")],
        "art_23_reporting":           [v | some v in violations; contains(v, "Art.23")],
    },
}
