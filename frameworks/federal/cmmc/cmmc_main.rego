package cmmc

import rego.v1

# =============================================================================
# CMMC 2.0 — Master Compliance Orchestrator
# Cybersecurity Maturity Model Certification
# DoD Defense Federal Acquisition Regulation Supplement (DFARS)
#
# Domains:
#   AC  — Access Control         (22 practices)
#   AU  — Audit & Accountability (9 practices)
#   AT  — Awareness & Training   (3 practices)
#   CM  — Configuration Mgmt     (9 practices)
#   IA  — Identification & Auth  (11 practices)
#   IR  — Incident Response      (3 practices)
#   MA  — Maintenance            (6 practices)
#   MP  — Media Protection       (9 practices)
#   PS  — Personnel Security     (2 practices)
#   PE  — Physical Protection    (6 practices)
#   RE  — Recovery               (4 practices)
#   RM  — Risk Management        (3 practices)
#   CA  — Security Assessment    (4 practices)
#   SC  — System & Comm Protect  (16 practices)
#   SI  — System & Info Integrity (7 practices)
# =============================================================================

# ---------------------------------------------------------------------------
# Sub-domain reports (available where modules are loaded)
# ---------------------------------------------------------------------------

ac_report := data.cmmc.access_control.compliance_report
cm_report := data.cmmc.configuration_management.compliance_report
ir_report := data.cmmc.incident_response.compliance_report

# ---------------------------------------------------------------------------
# Identification & Authentication (IA) — inline
# ---------------------------------------------------------------------------

violation_ia contains msg if {
    input.cmmc_level >= 1
    not input.authentication.unique_ids_for_all_users
    msg := "CMMC IA.L1-3.5.1: Users do not have unique identifiers. All CUI system users must have unique IDs."
}

violation_ia contains msg if {
    input.cmmc_level >= 1
    not input.authentication.authenticators_managed
    msg := "CMMC IA.L1-3.5.2: Authenticators (passwords, tokens, keys) are not managed. Authenticator management is required."
}

violation_ia contains msg if {
    input.cmmc_level >= 2
    not input.authentication.mfa_for_privileged_accounts
    msg := "CMMC IA.L2-3.5.3: MFA is not required for privileged accounts. Level 2 requires MFA for privileged and non-local access."
}

violation_ia contains msg if {
    input.cmmc_level >= 2
    not input.authentication.mfa_for_non_local_access
    msg := "CMMC IA.L2-3.5.3: MFA is not required for non-local (remote) access. Level 2 requires MFA for all remote access."
}

violation_ia contains msg if {
    input.cmmc_level >= 2
    input.authentication.password_min_length < 12
    msg := sprintf(
        "CMMC IA.L2-3.5.7: Minimum password length is %v characters. NIST 800-171 guidance recommends at least 12 characters.",
        [input.authentication.password_min_length]
    )
}

# ---------------------------------------------------------------------------
# System & Information Integrity (SI) — inline
# ---------------------------------------------------------------------------

violation_si contains msg if {
    input.cmmc_level >= 1
    some system in input.systems
    not system.malware_protection_enabled
    msg := sprintf(
        "CMMC SI.L1-3.14.2: System '%v' does not have malware protection enabled. Anti-malware is required at all CMMC levels.",
        [system.name]
    )
}

violation_si contains msg if {
    input.cmmc_level >= 1
    some system in input.systems
    system.malware_protection_enabled
    system.malware_definitions_age_days > 1
    msg := sprintf(
        "CMMC SI.L1-3.14.2: Malware definitions on '%v' are %v days old. Definitions must be updated at least daily.",
        [system.name, system.malware_definitions_age_days]
    )
}

violation_si contains msg if {
    input.cmmc_level >= 2
    some system in input.systems
    system.pending_security_patches > 0
    msg := sprintf(
        "CMMC SI.L2-3.14.4: System '%v' has %v pending security patches. Patches must be applied within risk-based timeframes.",
        [system.name, system.pending_security_patches]
    )
}

violation_si contains msg if {
    input.cmmc_level >= 2
    not input.monitoring.security_alerts_monitored
    msg := "CMMC SI.L2-3.14.6: Security alerts and advisories are not monitored. Subscribe to threat intelligence feeds and monitor for advisories."
}

# ---------------------------------------------------------------------------
# System & Communications Protection (SC) — inline
# ---------------------------------------------------------------------------

violation_sc contains msg if {
    input.cmmc_level >= 1
    not input.network.cui_network_monitored
    msg := "CMMC SC.L1-3.13.1: CUI network communications are not monitored. Monitor and control all CUI system communications."
}

violation_sc contains msg if {
    input.cmmc_level >= 2
    not input.network.network_segmentation
    msg := "CMMC SC.L2-3.13.3: CUI systems are not segmented from other networks. Separate user functionality from system management."
}

violation_sc contains msg if {
    input.cmmc_level >= 2
    not input.network.deny_by_default_firewall
    msg := "CMMC SC.L2-3.13.6: Firewall is not configured with deny-by-default. Only explicitly permitted communications should be allowed."
}

violation_sc contains msg if {
    input.cmmc_level >= 2
    not input.network.cui_encrypted_in_transit
    msg := "CMMC SC.L2-3.13.8: CUI is not encrypted in transit. FIPS 140-2 validated encryption is required for CUI transmission."
}

violation_sc contains msg if {
    input.cmmc_level >= 2
    not input.network.fips_140_2_compliant_crypto
    msg := "CMMC SC.L2-3.13.10: Cryptographic mechanisms are not FIPS 140-2 validated. FIPS validation is required for CUI protection."
}

# ---------------------------------------------------------------------------
# Risk Management (RM) — inline
# ---------------------------------------------------------------------------

violation_rm contains msg if {
    input.cmmc_level >= 2
    not input.risk.periodic_risk_assessments
    msg := "CMMC RM.L2-3.11.1: Periodic risk assessments are not conducted. Risk assessments must be performed regularly for CUI systems."
}

violation_rm contains msg if {
    input.cmmc_level >= 2
    not input.risk.vulnerability_scanning_enabled
    msg := "CMMC RM.L2-3.11.2: Vulnerability scanning is not enabled. Regularly scan CUI systems and remediate vulnerabilities."
}

violation_rm contains msg if {
    input.cmmc_level >= 2
    input.risk.vulnerability_scan_age_days > 30
    msg := sprintf(
        "CMMC RM.L2-3.11.2: Last vulnerability scan was %v days ago. Scan at least monthly.",
        [input.risk.vulnerability_scan_age_days]
    )
}

# ---------------------------------------------------------------------------
# Aggregate all violations
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in data.cmmc.access_control.violations],
        [v | some v in data.cmmc.configuration_management.violations]
    ),
    array.concat(
        array.concat(
            [v | some v in data.cmmc.incident_response.violations],
            [v | some v in violation_ia]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_si],
                [v | some v in violation_sc]
            ),
            [v | some v in violation_rm]
        )
    )
)

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

cmmc_compliant if { count(all_violations) == 0 }

total_domain_checks := 6
passing_domains := count([d |
    d := [
        ac_report.compliant,
        cm_report.compliant,
        ir_report.compliant,
        count(violation_ia) == 0,
        count(violation_si) == 0,
        count(violation_sc) == 0,
    ][_]
    d == true
])

compliance_score := round((passing_domains / total_domain_checks) * 100)

# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

cmmc_compliance_report := {
    "standard":         "CMMC 2.0",
    "regulation":       "32 CFR Part 170 / DFARS 252.204-7021",
    "target_level":     input.cmmc_level,
    "compliant":        cmmc_compliant,
    "compliance_score": compliance_score,
    "total_violations": count(all_violations),
    "violations":       all_violations,
    "domains": {
        "access_control":            ac_report,
        "configuration_management":  cm_report,
        "incident_response":         ir_report,
        "identification_authentication": {
            "compliant":       count(violation_ia) == 0,
            "violation_count": count(violation_ia),
            "violations":      violation_ia,
        },
        "system_integrity": {
            "compliant":       count(violation_si) == 0,
            "violation_count": count(violation_si),
            "violations":      violation_si,
        },
        "communications_protection": {
            "compliant":       count(violation_sc) == 0,
            "violation_count": count(violation_sc),
            "violations":      violation_sc,
        },
        "risk_management": {
            "compliant":       count(violation_rm) == 0,
            "violation_count": count(violation_rm),
            "violations":      violation_rm,
        },
    },
}
