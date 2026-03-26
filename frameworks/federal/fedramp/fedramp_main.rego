package fedramp

import rego.v1

# =============================================================================
# FedRAMP — Federal Risk and Authorization Management Program
# Based on NIST SP 800-53 Rev 5 with FedRAMP overlays
#
# Impact Levels:
#   Low       — Up to 125 controls
#   Moderate  — Up to 325 controls (most common for cloud services)
#   High      — Up to 421 controls (law enforcement, emergency services)
#
# Key FedRAMP-specific requirements beyond NIST 800-53:
#   - FedRAMP Tailored baselines
#   - Continuous Monitoring (ConMon)
#   - Annual assessments by 3PAO
#   - FedRAMP-authorized CSP/services only
#   - FIPS 140-2/3 validated cryptography
#   - US-only data residency (by default)
#
# Input shape:
#   input.impact_level          - "low", "moderate", or "high"
#   input.cloud_service         - cloud service configuration
#   input.controls[]            - implemented NIST 800-53 controls
#   input.cryptography          - crypto implementation details
#   input.continuous_monitoring - ConMon program details
#   input.authorization         - ATO/P-ATO status
#   input.data_residency        - data location information
# =============================================================================

# ---------------------------------------------------------------------------
# FedRAMP Authorization Status
# ---------------------------------------------------------------------------

violation_authorization contains msg if {
    not input.authorization.fedramp_authorized
    not input.authorization.in_process
    msg := "FedRAMP: Service is not FedRAMP authorized and not in process. Federal agencies may only use FedRAMP authorized cloud services for federal data."
}

violation_authorization contains msg if {
    input.authorization.fedramp_authorized
    not input.authorization.authorization_type in {"ATO", "P-ATO"}
    msg := sprintf(
        "FedRAMP: Authorization type '%v' is not valid. Must be ATO (Agency) or P-ATO (JAB).",
        [input.authorization.authorization_type]
    )
}

violation_authorization contains msg if {
    input.authorization.fedramp_authorized
    input.authorization.ato_expiry_days < 90
    msg := sprintf(
        "FedRAMP: ATO/P-ATO expires in %v days. Initiate renewal at least 90 days before expiration.",
        [input.authorization.ato_expiry_days]
    )
}

# ---------------------------------------------------------------------------
# FIPS 140-2/3 Cryptography (required at all impact levels)
# ---------------------------------------------------------------------------

violation_crypto contains msg if {
    not input.cryptography.fips_140_validated
    msg := "FedRAMP SC-28(1): Cryptographic modules are not FIPS 140-2 or 140-3 validated. FedRAMP requires FIPS-validated cryptography for federal data."
}

violation_crypto contains msg if {
    input.cryptography.fips_140_validated
    input.cryptography.fips_validation_level < 1
    msg := "FedRAMP: FIPS 140-2 validation level must be at least Level 1. Level 2 is required for sensitive applications."
}

violation_crypto contains msg if {
    some algo in input.cryptography.algorithms_in_use
    algo in {"DES", "3DES", "RC4", "MD5", "SHA1", "RSA-1024"}
    msg := sprintf(
        "FedRAMP SC-8(1): Cryptographic algorithm '%v' is not approved for federal use. Use NSA Suite B or CNSA Suite algorithms.",
        [algo]
    )
}

# ---------------------------------------------------------------------------
# Data Residency (US-only by default)
# ---------------------------------------------------------------------------

violation_data_residency contains msg if {
    some location in input.data_residency.storage_locations
    not location.us_territory
    msg := sprintf(
        "FedRAMP: Federal data stored in non-US location '%v'. FedRAMP requires federal data to remain within US territories unless explicitly authorized.",
        [location.region]
    )
}

violation_data_residency contains msg if {
    some location in input.data_residency.processing_locations
    not location.us_territory
    msg := sprintf(
        "FedRAMP: Federal data processed in non-US location '%v'. Data processing must occur within US territories.",
        [location.region]
    )
}

# ---------------------------------------------------------------------------
# Personnel Security — US Citizens / Persons
# ---------------------------------------------------------------------------

violation_personnel contains msg if {
    input.impact_level in {"moderate", "high"}
    some person in input.personnel
    person.admin_access == true
    not person.us_person
    not person.foreign_national_waiver
    msg := sprintf(
        "FedRAMP PS-3: Personnel '%v' has administrative access but is not a US person and has no foreign national waiver. Moderate/High requires US persons for admin access.",
        [person.name]
    )
}

violation_personnel contains msg if {
    some person in input.personnel
    person.admin_access == true
    not person.background_check_completed
    msg := sprintf(
        "FedRAMP PS-3: Personnel '%v' has administrative access without a completed background check. Background checks are required for all admin personnel.",
        [person.name]
    )
}

# ---------------------------------------------------------------------------
# Continuous Monitoring (ConMon) — FedRAMP-specific
# ---------------------------------------------------------------------------

violation_conmon contains msg if {
    not input.continuous_monitoring.program_documented
    msg := "FedRAMP CA-7: No Continuous Monitoring (ConMon) program documented. FedRAMP requires a formal ConMon program."
}

violation_conmon contains msg if {
    not input.continuous_monitoring.monthly_vulnerability_scans
    msg := "FedRAMP RA-5: Monthly vulnerability scans are not configured. FedRAMP requires vulnerability scans of all system components monthly."
}

violation_conmon contains msg if {
    input.continuous_monitoring.last_vulnerability_scan_days > 30
    msg := sprintf(
        "FedRAMP RA-5: Last vulnerability scan was %v days ago. FedRAMP requires monthly scanning.",
        [input.continuous_monitoring.last_vulnerability_scan_days]
    )
}

violation_conmon contains msg if {
    not input.continuous_monitoring.monthly_os_scan
    msg := "FedRAMP RA-5: Monthly OS-level vulnerability scans are not configured. Separate OS-level scans are required."
}

violation_conmon contains msg if {
    not input.continuous_monitoring.web_app_scan_enabled
    msg := "FedRAMP RA-5: Web application scans are not configured. FedRAMP requires web application vulnerability scanning."
}

violation_conmon contains msg if {
    not input.continuous_monitoring.database_scan_enabled
    msg := "FedRAMP RA-5: Database vulnerability scans are not configured. FedRAMP requires database scanning for systems with databases."
}

violation_conmon contains msg if {
    input.continuous_monitoring.high_vulnerabilities_open_days > 30
    msg := sprintf(
        "FedRAMP RA-5: High-severity vulnerabilities have been open for %v days. FedRAMP requires remediation of High vulnerabilities within 30 days.",
        [input.continuous_monitoring.high_vulnerabilities_open_days]
    )
}

violation_conmon contains msg if {
    input.continuous_monitoring.critical_vulnerabilities_open_days > 15
    msg := sprintf(
        "FedRAMP RA-5: Critical vulnerabilities have been open for %v days. FedRAMP requires remediation of Critical vulnerabilities within 15 days.",
        [input.continuous_monitoring.critical_vulnerabilities_open_days]
    )
}

violation_conmon contains msg if {
    not input.continuous_monitoring.monthly_ato_report_submitted
    msg := "FedRAMP CA-7: Monthly ConMon report has not been submitted to the authorizing official. Monthly reporting is required."
}

# ---------------------------------------------------------------------------
# Third-Party Assessment Organization (3PAO)
# ---------------------------------------------------------------------------

violation_3pao contains msg if {
    not input.authorization.assessed_by_3pao
    msg := "FedRAMP CA-2: System has not been assessed by a FedRAMP-recognized Third Party Assessment Organization (3PAO). 3PAO assessment is required for authorization."
}

violation_3pao contains msg if {
    input.authorization.assessed_by_3pao
    input.authorization.last_3pao_assessment_days > 365
    msg := sprintf(
        "FedRAMP CA-2: Last 3PAO assessment was %v days ago. Annual third-party assessment is required to maintain authorization.",
        [input.authorization.last_3pao_assessment_days]
    )
}

# ---------------------------------------------------------------------------
# Impact Level-specific controls
# ---------------------------------------------------------------------------

violation_moderate_high contains msg if {
    input.impact_level in {"moderate", "high"}
    not input.cloud_service.penetration_test_annual
    msg := "FedRAMP CA-8: Annual penetration testing is not configured. Moderate and High systems require annual pen testing."
}

violation_moderate_high contains msg if {
    input.impact_level in {"moderate", "high"}
    not input.cloud_service.incident_response_plan_approved
    msg := "FedRAMP IR-8: Incident response plan has not been reviewed and approved. Moderate/High systems require an approved IR plan."
}

violation_high contains msg if {
    input.impact_level == "high"
    not input.cloud_service.redundant_processing
    msg := "FedRAMP CP-7: High-impact systems require alternative processing sites. No redundant processing site is configured."
}

violation_high contains msg if {
    input.impact_level == "high"
    not input.cloud_service.two_person_rule_for_critical_ops
    msg := "FedRAMP PE-3(1): High-impact systems require two-person rule for critical operations. Implement dual authorization."
}

# ---------------------------------------------------------------------------
# Supply Chain Risk Management (FedRAMP addition)
# ---------------------------------------------------------------------------

violation_scrm contains msg if {
    input.impact_level in {"moderate", "high"}
    not input.supply_chain.risk_management_plan
    msg := "FedRAMP SR-2: No supply chain risk management plan. Moderate and High systems must assess and manage supply chain risks."
}

violation_scrm contains msg if {
    input.impact_level in {"moderate", "high"}
    some component in input.supply_chain.components
    not component.provenance_verified
    msg := sprintf(
        "FedRAMP SR-4: Component '%v' provenance has not been verified. Component origin must be verified for Moderate/High systems.",
        [component.name]
    )
}

# ---------------------------------------------------------------------------
# Aggregate violations
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_authorization],
        [v | some v in violation_crypto]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_data_residency],
            [v | some v in violation_personnel]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_conmon],
                [v | some v in violation_3pao]
            ),
            array.concat(
                array.concat(
                    [v | some v in violation_moderate_high],
                    [v | some v in violation_high]
                ),
                [v | some v in violation_scrm]
            )
        )
    )
)

fedramp_compliant if { count(all_violations) == 0 }

passing_areas := count([a |
    a := [
        count(violation_authorization) == 0,
        count(violation_crypto) == 0,
        count(violation_data_residency) == 0,
        count(violation_personnel) == 0,
        count(violation_conmon) == 0,
        count(violation_3pao) == 0,
    ][_]
    a == true
])

compliance_score := round((passing_areas / 6) * 100)

fedramp_compliance_report := {
    "standard":         "FedRAMP",
    "impact_level":     input.impact_level,
    "compliant":        fedramp_compliant,
    "compliance_score": compliance_score,
    "total_violations": count(all_violations),
    "violations":       all_violations,
    "areas": {
        "authorization":    {
            "compliant": count(violation_authorization) == 0,
            "violations": violation_authorization,
        },
        "cryptography": {
            "compliant": count(violation_crypto) == 0,
            "violations": violation_crypto,
        },
        "data_residency": {
            "compliant": count(violation_data_residency) == 0,
            "violations": violation_data_residency,
        },
        "personnel_security": {
            "compliant": count(violation_personnel) == 0,
            "violations": violation_personnel,
        },
        "continuous_monitoring": {
            "compliant": count(violation_conmon) == 0,
            "violations": violation_conmon,
        },
        "third_party_assessment": {
            "compliant": count(violation_3pao) == 0,
            "violations": violation_3pao,
        },
        "supply_chain": {
            "compliant": count(violation_scrm) == 0,
            "violations": violation_scrm,
        },
    },
}
