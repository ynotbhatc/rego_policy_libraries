package dora.main

import rego.v1

# EU Digital Operational Resilience Act (DORA) — Regulation (EU) 2022/2554
# Mandatory for all EU financial entities from 17 January 2025.
#
# Five pillars:
#   Pillar 1 — ICT Risk Management (Articles 5–16)
#   Pillar 2 — ICT-Related Incident Reporting (Articles 17–23)
#   Pillar 3 — Digital Operational Resilience Testing (Articles 24–27)
#   Pillar 4 — ICT Third-Party Risk Management (Articles 28–44)
#   Pillar 5 — Information Sharing (Article 45)
#
# OPA endpoint: POST http://<host>:8182/v1/data/dora/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── Pillar 1 — ICT Risk Management ──────────────────────────────────────────

violations contains msg if {
    not input.ict_risk_management.governance_framework.documented
    msg := "DORA Art.5: ICT risk management governance framework not documented"
}

violations contains msg if {
    not input.ict_risk_management.risk_appetite.defined
    msg := "DORA Art.6: ICT risk appetite and tolerance levels not formally defined"
}

violations contains msg if {
    not input.ict_risk_management.asset_inventory.maintained
    msg := "DORA Art.8: ICT asset inventory not maintained (hardware, software, data assets)"
}

violations contains msg if {
    not input.ict_risk_management.threat_intelligence.process_exists
    msg := "DORA Art.13: Threat intelligence gathering and monitoring process absent"
}

violations contains msg if {
    not input.ict_risk_management.recovery_objectives.rto_defined
    msg := "DORA Art.12: Recovery Time Objectives (RTO) not defined for critical ICT systems"
}

violations contains msg if {
    not input.ict_risk_management.recovery_objectives.rpo_defined
    msg := "DORA Art.12: Recovery Point Objectives (RPO) not defined for critical ICT systems"
}

violations contains msg if {
    not input.ict_risk_management.backup_policy.documented
    msg := "DORA Art.12: ICT backup policy not documented or tested"
}

violations contains msg if {
    not input.ict_risk_management.patch_management.process_exists
    msg := "DORA Art.10: Patch and vulnerability management process not established"
}

violations contains msg if {
    not input.ict_risk_management.encryption.in_transit
    msg := "DORA Art.9: Data in transit not encrypted — encryption of sensitive data required"
}

violations contains msg if {
    not input.ict_risk_management.encryption.at_rest
    msg := "DORA Art.9: Data at rest not encrypted — encryption of sensitive data required"
}

violations contains msg if {
    not input.ict_risk_management.mfa.enabled
    msg := "DORA Art.9: Multi-factor authentication not enforced for ICT system access"
}

violations contains msg if {
    not input.ict_risk_management.privileged_access.managed
    msg := "DORA Art.9: Privileged access not managed — PAM controls required"
}

violations contains msg if {
    not input.ict_risk_management.annual_review.completed
    msg := "DORA Art.6: ICT risk management framework annual review not completed"
}

# ── Pillar 2 — ICT Incident Reporting ───────────────────────────────────────

violations contains msg if {
    not input.incident_reporting.classification_process.documented
    msg := "DORA Art.18: ICT incident classification and impact assessment process not documented"
}

violations contains msg if {
    not input.incident_reporting.initial_notification.within_4_hours
    msg := "DORA Art.19: Major incident initial notification to authority not within 4 hours"
}

violations contains msg if {
    not input.incident_reporting.intermediate_report.within_72_hours
    msg := "DORA Art.19: Intermediate incident report to authority not within 72 hours"
}

violations contains msg if {
    not input.incident_reporting.final_report.within_1_month
    msg := "DORA Art.19: Final incident report to authority not within 1 month of resolution"
}

violations contains msg if {
    not input.incident_reporting.incident_register.maintained
    msg := "DORA Art.17: ICT incident register not maintained with required details"
}

violations contains msg if {
    not input.incident_reporting.root_cause_analysis.performed
    msg := "DORA Art.17: Root cause analysis not performed for major ICT incidents"
}

# ── Pillar 3 — Digital Operational Resilience Testing ───────────────────────

violations contains msg if {
    not input.resilience_testing.basic_testing.annual
    msg := "DORA Art.25: Basic resilience testing (vulnerability scans, pen tests) not conducted annually"
}

violations contains msg if {
    not input.resilience_testing.tlpt.conducted
    msg := "DORA Art.26: Threat-Led Penetration Testing (TLPT) not conducted (significant entities: every 3 years)"
}

violations contains msg if {
    not input.resilience_testing.test_results.remediated
    msg := "DORA Art.25: Critical findings from resilience testing not remediated in defined timeframe"
}

violations contains msg if {
    not input.resilience_testing.continuity_drills.conducted
    msg := "DORA Art.25: Business continuity and crisis communication drills not conducted"
}

# ── Pillar 4 — ICT Third-Party Risk Management ──────────────────────────────

violations contains msg if {
    not input.third_party_risk.register.maintained
    msg := "DORA Art.28: ICT third-party service provider register not maintained"
}

violations contains msg if {
    not input.third_party_risk.contracts.exit_strategy
    msg := "DORA Art.30: ICT service contracts do not include exit strategy and transition plan"
}

violations contains msg if {
    not input.third_party_risk.contracts.audit_rights
    msg := "DORA Art.30: ICT service contracts do not include audit and access rights"
}

violations contains msg if {
    not input.third_party_risk.contracts.sla_defined
    msg := "DORA Art.30: ICT service contracts lack SLA definitions for availability and performance"
}

violations contains msg if {
    not input.third_party_risk.concentration_risk.assessed
    msg := "DORA Art.29: ICT concentration risk not assessed (over-reliance on single provider)"
}

violations contains msg if {
    not input.third_party_risk.critical_providers.identified
    msg := "DORA Art.28: Critical ICT third-party providers not identified and assessed"
}

violations contains msg if {
    not input.third_party_risk.due_diligence.performed
    msg := "DORA Art.28: Due diligence not performed for ICT third-party providers"
}

# ── Pillar 5 — Information Sharing ──────────────────────────────────────────

violations contains msg if {
    not input.information_sharing.arrangements.in_place
    msg := "DORA Art.45: Cyber threat information sharing arrangements not established"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":      "EU Digital Operational Resilience Act (DORA)",
    "regulation":     "Regulation (EU) 2022/2554",
    "effective_date": "2025-01-17",
    "entity":         input.entity_name,
    "entity_type":    input.entity_type,
    "assessed_at":    input.assessment_date,
    "compliant":      compliant,
    "total_controls": 30,
    "violations":     violations,
    "violation_count": count(violations),
    "pillar_summary": {
        "ict_risk_management":  pillar1_violations,
        "incident_reporting":   pillar2_violations,
        "resilience_testing":   pillar3_violations,
        "third_party_risk":     pillar4_violations,
        "information_sharing":  pillar5_violations,
    },
}

# Pillar helper sets (partial set rules — OPA serializes as sorted arrays in JSON output)
pillar1_violations contains v if { some v in violations; contains(v, "Art.5") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.6") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.8") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.9") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.10") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.12") }
pillar1_violations contains v if { some v in violations; contains(v, "Art.13") }

pillar2_violations contains v if { some v in violations; contains(v, "Art.17") }
pillar2_violations contains v if { some v in violations; contains(v, "Art.18") }
pillar2_violations contains v if { some v in violations; contains(v, "Art.19") }

pillar3_violations contains v if { some v in violations; contains(v, "Art.25") }
pillar3_violations contains v if { some v in violations; contains(v, "Art.26") }

pillar4_violations contains v if { some v in violations; contains(v, "Art.28") }
pillar4_violations contains v if { some v in violations; contains(v, "Art.29") }
pillar4_violations contains v if { some v in violations; contains(v, "Art.30") }

pillar5_violations contains v if { some v in violations; contains(v, "Art.45") }
