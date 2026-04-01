package cmmc.incident_response

import rego.v1

# =============================================================================
# CMMC 2.0 — Incident Response Domain (IR)
# Practices IR.L2-3.6.1 through IR.L2-3.6.3
#
# Input shape:
#   input.incident_response     - IR program configuration
#   input.cmmc_level            - target maturity level
# =============================================================================

# IR.L2-3.6.1 — Establish an operational incident-handling capability
violation_ir_1 contains msg if {
    input.cmmc_level >= 2
    not input.incident_response.plan_documented
    msg := "CMMC IR.L2-3.6.1: No documented incident response plan. An operational IR capability covering preparation, detection, containment, and recovery is required."
}

violation_ir_1 contains msg if {
    input.cmmc_level >= 2
    input.incident_response.plan_documented
    not input.incident_response.plan_tested
    msg := "CMMC IR.L2-3.6.1: Incident response plan has not been tested. Plans must be exercised at least annually."
}

violation_ir_1 contains msg if {
    input.cmmc_level >= 2
    input.incident_response.plan_documented
    input.incident_response.plan_age_days > 365
    msg := sprintf(
        "CMMC IR.L2-3.6.1: Incident response plan is %v days old. Plans must be reviewed and updated annually.",
        [input.incident_response.plan_age_days]
    )
}

# IR.L2-3.6.2 — Track, document, and report incidents
violation_ir_2 contains msg if {
    input.cmmc_level >= 2
    not input.incident_response.incident_tracking_system
    msg := "CMMC IR.L2-3.6.2: No incident tracking system. All incidents affecting CUI must be tracked and documented."
}

violation_ir_2 contains msg if {
    input.cmmc_level >= 2
    not input.incident_response.reporting_to_dod_required_when_applicable
    msg := "CMMC IR.L2-3.6.2: DoD incident reporting procedure not defined. CUI incidents must be reported to appropriate authorities within 72 hours."
}

# IR.L2-3.6.3 — Test the organizational incident response capability
violation_ir_3 contains msg if {
    input.cmmc_level >= 2
    not input.incident_response.tabletop_exercise_completed
    msg := "CMMC IR.L2-3.6.3: No tabletop exercise completed. Incident response capability must be tested through exercises."
}

violations contains msg if { some msg in violation_ir_1 }
violations contains msg if { some msg in violation_ir_2 }
violations contains msg if { some msg in violation_ir_3 }

compliant if { count(violations) == 0 }

compliance_report := {
    "domain":          "Incident Response (IR)",
    "cmmc_level":      input.cmmc_level,
    "compliant":       compliant,
    "violation_count": count(violations),
    "violations":      violations,
    "passing":         3 - count(violations),
}
