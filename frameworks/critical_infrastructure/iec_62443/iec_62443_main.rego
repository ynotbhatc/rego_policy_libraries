package iec_62443_main

import rego.v1

# =============================================================================
# IEC 62443 — Industrial Automation and Control Systems (IACS) Security
# Main Orchestrator — Aggregates All Parts and Foundational Requirements
#
# Standard: IEC 62443 (series)
# Full Title: Security for industrial automation and control systems
# Publisher: International Electrotechnical Commission (IEC)
# Scope: OT/ICS/SCADA cybersecurity for industrial environments
#
# Coverage:
#   Part 2-1 — Security Management System (CSMS)          [part2_security_management.rego]
#   Part 2-3 — Patch Management                           [part2_patch_management.rego]
#   Part 2-4 — IACS Service Provider Requirements         [part2_service_provider.rego]
#   Part 3-2 — Security Risk Assessment for System Design [part3_risk_assessment.rego]
#   Part 3-3 FR 1 — Identification & Authentication       [fr1_identification_authentication.rego]
#   Part 3-3 FR 2 — Use Control                           [fr2_use_control.rego]
#   Part 3-3 FR 3 — System Integrity                      [fr3_system_integrity.rego]
#   Part 3-3 FR 4 — Data Confidentiality                  [fr4_data_confidentiality.rego]
#   Part 3-3 FR 5 — Restricted Data Flow                  [fr5_restricted_data_flow.rego]
#   Part 3-3 FR 6 — Timely Response to Events             [fr6_timely_response.rego]
#   Part 3-3 FR 7 — Resource Availability                 [fr7_resource_availability.rego]
#
# Security Levels:
#   SL 1 — Protection against casual or coincidental violation
#   SL 2 — Protection against intentional violation with simple means
#   SL 3 — Protection against sophisticated attacks (nation-state capable actors)
#   SL 4 — Protection against state-sponsored, highly motivated, well-resourced attacks
#
# OPA Endpoint: POST http://192.168.4.62:8183/v1/data/iec_62443_main
# =============================================================================

import data.iec_62443.fr1
import data.iec_62443.fr2
import data.iec_62443.fr3
import data.iec_62443.fr4
import data.iec_62443.fr5
import data.iec_62443.fr6
import data.iec_62443.fr7
import data.iec_62443.part2_1
import data.iec_62443.part2_3
import data.iec_62443.part2_4
import data.iec_62443.part3_2

# ---------------------------------------------------------------------------
# All violations aggregated across all parts and FRs
# ---------------------------------------------------------------------------

part2_violations := array.concat(
    array.concat(
        [v | some v in part2_1.violations],
        [v | some v in part2_3.violations]
    ),
    [v | some v in part2_4.violations]
)

part3_violations_fr1_fr2 := array.concat(
    [v | some v in fr1.violations],
    [v | some v in fr2.violations]
)

part3_violations_fr3_fr4 := array.concat(
    [v | some v in fr3.violations],
    [v | some v in fr4.violations]
)

part3_violations_fr5_fr6 := array.concat(
    [v | some v in fr5.violations],
    [v | some v in fr6.violations]
)

part3_violations_fr7_risk := array.concat(
    [v | some v in fr7.violations],
    [v | some v in part3_2.violations]
)

part3_violations_group1 := array.concat(
    part3_violations_fr1_fr2,
    part3_violations_fr3_fr4
)

part3_violations_group2 := array.concat(
    part3_violations_fr5_fr6,
    part3_violations_fr7_risk
)

part3_violations := array.concat(
    part3_violations_group1,
    part3_violations_group2
)

all_violations := array.concat(part2_violations, part3_violations)

# ---------------------------------------------------------------------------
# Top-level compliance
# ---------------------------------------------------------------------------

default iec_62443_compliant := false

iec_62443_compliant if { count(all_violations) == 0 }

# ---------------------------------------------------------------------------
# FR-level compliance flags
# ---------------------------------------------------------------------------

default fr1_compliant := false
default fr2_compliant := false
default fr3_compliant := false
default fr4_compliant := false
default fr5_compliant := false
default fr6_compliant := false
default fr7_compliant := false

fr1_compliant if { fr1.compliant }
fr2_compliant if { fr2.compliant }
fr3_compliant if { fr3.compliant }
fr4_compliant if { fr4.compliant }
fr5_compliant if { fr5.compliant }
fr6_compliant if { fr6.compliant }
fr7_compliant if { fr7.compliant }

# ---------------------------------------------------------------------------
# Part 2 compliance flags
# ---------------------------------------------------------------------------

default part2_1_compliant := false
default part2_3_compliant := false
default part2_4_compliant := false
default part3_2_compliant := false

part2_1_compliant if { part2_1.compliant }
part2_3_compliant if { part2_3.compliant }
part2_4_compliant if { part2_4.compliant }
part3_2_compliant if { part3_2.compliant }

# ---------------------------------------------------------------------------
# Compliance scoring
# ---------------------------------------------------------------------------

passing_frs := count([fr |
    fr := [
        fr1_compliant,
        fr2_compliant,
        fr3_compliant,
        fr4_compliant,
        fr5_compliant,
        fr6_compliant,
        fr7_compliant,
    ][_]
    fr == true
])

# Total SRs across all FRs: FR1=13, FR2=12, FR3=9, FR4=3, FR5=4, FR6=2, FR7=8 = 51
total_srs := 51

passing_srs := (
    fr1.compliance_report.passing_srs +
    fr2.compliance_report.passing_srs +
    fr3.compliance_report.passing_srs +
    fr4.compliance_report.passing_srs +
    fr5.compliance_report.passing_srs +
    fr6.compliance_report.passing_srs +
    fr7.compliance_report.passing_srs
)

sr_compliance_score := round((passing_srs / total_srs) * 100)

fr_compliance_score := round((passing_frs / 7) * 100)

# ---------------------------------------------------------------------------
# Complete compliance report
# ---------------------------------------------------------------------------

iec_62443_compliance_report := {
    "standard":             "IEC 62443",
    "full_title":           "Security for Industrial Automation and Control Systems",
    "target_sl":            input.target_sl,
    "compliant":            iec_62443_compliant,
    "total_violations":     count(all_violations),
    "fr_compliance_score":  fr_compliance_score,
    "sr_compliance_score":  sr_compliance_score,
    "passing_frs":          passing_frs,
    "total_frs":            7,
    "passing_srs":          passing_srs,
    "total_srs":            total_srs,

    "part3_3_foundational_requirements": {
        "FR1_identification_authentication": {
            "compliant":   fr1_compliant,
            "total_srs":   13,
            "passing_srs": fr1.compliance_report.passing_srs,
            "violations":  fr1.violations,
        },
        "FR2_use_control": {
            "compliant":   fr2_compliant,
            "total_srs":   12,
            "passing_srs": fr2.compliance_report.passing_srs,
            "violations":  fr2.violations,
        },
        "FR3_system_integrity": {
            "compliant":   fr3_compliant,
            "total_srs":   9,
            "passing_srs": fr3.compliance_report.passing_srs,
            "violations":  fr3.violations,
        },
        "FR4_data_confidentiality": {
            "compliant":   fr4_compliant,
            "total_srs":   3,
            "passing_srs": fr4.compliance_report.passing_srs,
            "violations":  fr4.violations,
        },
        "FR5_restricted_data_flow": {
            "compliant":   fr5_compliant,
            "total_srs":   4,
            "passing_srs": fr5.compliance_report.passing_srs,
            "violations":  fr5.violations,
        },
        "FR6_timely_response": {
            "compliant":   fr6_compliant,
            "total_srs":   2,
            "passing_srs": fr6.compliance_report.passing_srs,
            "violations":  fr6.violations,
        },
        "FR7_resource_availability": {
            "compliant":   fr7_compliant,
            "total_srs":   8,
            "passing_srs": fr7.compliance_report.passing_srs,
            "violations":  fr7.violations,
        },
    },

    "part2_management_requirements": {
        "part2_1_security_management": {
            "compliant":   part2_1_compliant,
            "violations":  part2_1.violations,
        },
        "part2_3_patch_management": {
            "compliant":   part2_3_compliant,
            "violations":  part2_3.violations,
        },
        "part2_4_service_provider": {
            "compliant":   part2_4_compliant,
            "violations":  part2_4.violations,
        },
    },

    "part3_2_risk_assessment": {
        "compliant":   part3_2_compliant,
        "violations":  part3_2.violations,
    },

    "all_violations": all_violations,
}
