package nist_800_171.main

import rego.v1

# NIST SP 800-171 Rev 3 — Main Aggregator
# Protecting Controlled Unclassified Information (CUI) in Nonfederal Systems and Organizations
#
# 110 total requirements across 14 families:
#   3.1  Access Control (AC)               — 22 requirements
#   3.2  Awareness and Training (AT)       —  3 requirements
#   3.3  Audit and Accountability (AU)     —  9 requirements
#   3.4  Configuration Management (CM)     —  9 requirements
#   3.5  Identification and Authentication (IA) — 11 requirements
#   3.6  Incident Response (IR)            —  3 requirements
#   3.7  Maintenance (MA)                  —  6 requirements
#   3.8  Media Protection (MP)             —  9 requirements
#   3.9  Personnel Security (PS)           —  2 requirements
#   3.10 Physical Protection (PE)          —  6 requirements
#   3.11 Risk Assessment (RA)              —  3 requirements
#   3.12 Security Assessment (CA)          —  4 requirements
#   3.13 System and Communications Protection (SC) — 16 requirements
#   3.14 System and Information Integrity (SI) —  7 requirements

# ---------------------------------------------------------------------------
# Per-family compliance status
# ---------------------------------------------------------------------------

# 3.1 Access Control — existing module uses nist_sp800_171_ac_compliant (not compliant).
# The rule has no default so it may be undefined when input is absent; use false as fallback.
ac_compliant := object.get(data.nist.sp800_171.access_control, "nist_sp800_171_ac_compliant", false)

# 3.2 Awareness and Training
at_compliant := data.nist.sp800_171.awareness_training.compliant

# 3.3 Audit and Accountability
au_compliant := data.nist.sp800_171.audit_accountability.compliant

# 3.4 Configuration Management
cm_compliant := data.nist.sp800_171.configuration_management.compliant

# 3.5 Identification and Authentication
ia_compliant := data.nist.sp800_171.identification_authentication.compliant

# 3.6 Incident Response
ir_compliant := data.nist.sp800_171.incident_response.compliant

# 3.7 Maintenance
ma_compliant := data.nist.sp800_171.maintenance.compliant

# 3.8 Media Protection
mp_compliant := data.nist.sp800_171.media_protection.compliant

# 3.9 Personnel Security
ps_compliant := data.nist.sp800_171.personnel_security.compliant

# 3.10 Physical Protection
pe_compliant := data.nist.sp800_171.physical_protection.compliant

# 3.11 Risk Assessment
ra_compliant := data.nist.sp800_171.risk_assessment.compliant

# 3.12 Security Assessment
ca_compliant := data.nist.sp800_171.security_assessment.compliant

# 3.13 System and Communications Protection
sc_compliant := data.nist.sp800_171.system_communications.compliant

# 3.14 System and Information Integrity
si_compliant := data.nist.sp800_171.system_information.compliant

# ---------------------------------------------------------------------------
# Overall compliance
# ---------------------------------------------------------------------------

default overall_compliant := false

overall_compliant if {
    ac_compliant
    at_compliant
    au_compliant
    cm_compliant
    ia_compliant
    ir_compliant
    ma_compliant
    mp_compliant
    ps_compliant
    pe_compliant
    ra_compliant
    ca_compliant
    sc_compliant
    si_compliant
}

# ---------------------------------------------------------------------------
# Families passing count
# ---------------------------------------------------------------------------

families_status := [
    ac_compliant,
    at_compliant,
    au_compliant,
    cm_compliant,
    ia_compliant,
    ir_compliant,
    ma_compliant,
    mp_compliant,
    ps_compliant,
    pe_compliant,
    ra_compliant,
    ca_compliant,
    sc_compliant,
    si_compliant,
]

families_passing := count([s | some s in families_status; s == true])

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

compliance_report := {
    "standard": "NIST SP 800-171 Rev 3 — Protecting Controlled Unclassified Information (CUI)",
    "overall_compliant": overall_compliant,
    "families_passing": families_passing,
    "families_total": 14,
    "families": {
        "3.1_access_control": {
            "compliant": ac_compliant,
            "note": "Access control module uses nist_sp800_171_ac_compliant; see nist_sp800_171_ac_compliance for details",
            "details": object.get(data.nist.sp800_171.access_control, "nist_sp800_171_ac_compliance", {}),
        },
        "3.2_awareness_training": {
            "compliant": at_compliant,
            "details": data.nist.sp800_171.awareness_training.compliance_report,
        },
        "3.3_audit_accountability": {
            "compliant": au_compliant,
            "details": data.nist.sp800_171.audit_accountability.compliance_report,
        },
        "3.4_configuration_management": {
            "compliant": cm_compliant,
            "details": data.nist.sp800_171.configuration_management.compliance_report,
        },
        "3.5_identification_authentication": {
            "compliant": ia_compliant,
            "details": data.nist.sp800_171.identification_authentication.compliance_report,
        },
        "3.6_incident_response": {
            "compliant": ir_compliant,
            "details": data.nist.sp800_171.incident_response.compliance_report,
        },
        "3.7_maintenance": {
            "compliant": ma_compliant,
            "details": data.nist.sp800_171.maintenance.compliance_report,
        },
        "3.8_media_protection": {
            "compliant": mp_compliant,
            "details": data.nist.sp800_171.media_protection.compliance_report,
        },
        "3.9_personnel_security": {
            "compliant": ps_compliant,
            "details": data.nist.sp800_171.personnel_security.compliance_report,
        },
        "3.10_physical_protection": {
            "compliant": pe_compliant,
            "details": data.nist.sp800_171.physical_protection.compliance_report,
        },
        "3.11_risk_assessment": {
            "compliant": ra_compliant,
            "details": data.nist.sp800_171.risk_assessment.compliance_report,
        },
        "3.12_security_assessment": {
            "compliant": ca_compliant,
            "details": data.nist.sp800_171.security_assessment.compliance_report,
        },
        "3.13_system_communications": {
            "compliant": sc_compliant,
            "details": data.nist.sp800_171.system_communications.compliance_report,
        },
        "3.14_system_information": {
            "compliant": si_compliant,
            "details": data.nist.sp800_171.system_information.compliance_report,
        },
    },
}
