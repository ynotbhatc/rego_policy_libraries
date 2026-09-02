package glba.main

import rego.v1

# Gramm-Leach-Bliley Act — FTC Safeguards Rule, 16 CFR Part 314
# (as amended: strengthened requirements effective June 2023; FTC data
# breach notification amendment effective May 2024)
#
# Applies to: "financial institutions" under FTC jurisdiction — a broad
#             definition including mortgage brokers, payday lenders,
#             auto dealers extending credit, tax preparers, collection
#             agencies, credit counselors, and non-bank lenders.
#             (Banking institutions answer to their prudential
#             regulators' parallel safeguards, not the FTC rule.)
#
# Key sections of §314.4 (elements of the information security program):
#   (a)  Qualified Individual designated
#   (b)  Written risk assessment
#   (c)  Safeguards — eight required control areas:
#        (1) access controls          (5) multi-factor authentication
#        (2) data/system inventory    (6) secure disposal
#        (3) encryption               (7) change management
#        (4) secure development       (8) activity monitoring/logging
#   (d)  Regular testing — continuous monitoring OR annual pen test
#        plus vulnerability assessments at least every six months
#   (e)  Training and qualified personnel
#   (f)  Service provider oversight
#   (g)  Program evaluation and adjustment
#   (h)  Written incident response plan
#   (i)  Annual written report to the board by the Qualified Individual
#   (j)  FTC breach notification within 30 days (≥500 consumers,
#        unencrypted customer information — 2024 amendment)
#
# Exemption note: institutions maintaining customer information on
# fewer than 5,000 consumers are exempt from (b) written risk
# assessment, (d)(2) specified testing cadence, (h) written IR plan,
# and (i) annual board report. Pass input.small_institution_exemption
# = true to suppress those violations.
#
# Input contract: entity-level attestation + technical facts, same
# pattern as ny_dfs.main. See tests for the expected shape.

default compliant := false

compliant if {
	count(violations) == 0
}

default small_exempt := false

small_exempt if input.small_institution_exemption == true

# ── 314.4(a) — Qualified Individual ──────────────────────────────────────────

violations contains msg if {
	not input.qualified_individual.designated
	msg := "16 CFR 314.4(a): Qualified Individual not designated to oversee, implement, and enforce the information security program"
}

# ── 314.4(b) — Risk Assessment ───────────────────────────────────────────────

violations contains msg if {
	not small_exempt
	not input.risk_assessment.written
	msg := "16 CFR 314.4(b)(1): Written risk assessment not performed"
}

violations contains msg if {
	not small_exempt
	not input.risk_assessment.criteria_documented
	msg := "16 CFR 314.4(b)(1): Risk assessment lacks documented criteria for evaluating and categorizing security risks and threats"
}

violations contains msg if {
	not small_exempt
	not input.risk_assessment.periodic_reassessment
	msg := "16 CFR 314.4(b)(2): Risk assessment not periodically re-performed to reexamine reasonably foreseeable risks"
}

# ── 314.4(c)(1) — Access Controls ────────────────────────────────────────────

violations contains msg if {
	not input.access_control.authenticate_users
	msg := "16 CFR 314.4(c)(1): Access controls do not authenticate users before permitting access to customer information"
}

violations contains msg if {
	not input.access_control.least_privilege
	msg := "16 CFR 314.4(c)(1): Access to customer information not limited to what is needed to perform duties and functions"
}

violations contains msg if {
	not input.access_control.periodic_review
	msg := "16 CFR 314.4(c)(1): Access permissions to customer information not periodically reviewed"
}

# ── 314.4(c)(2) — Data and System Inventory ──────────────────────────────────

violations contains msg if {
	not input.inventory.data_identified
	msg := "16 CFR 314.4(c)(2): Customer information not identified and its location not inventoried"
}

violations contains msg if {
	not input.inventory.systems_inventoried
	msg := "16 CFR 314.4(c)(2): Systems, devices, platforms, and personnel handling customer information not inventoried"
}

# ── 314.4(c)(3) — Encryption ─────────────────────────────────────────────────

violations contains msg if {
	not input.encryption.customer_info.in_transit
	not input.encryption.compensating_controls_approved
	msg := "16 CFR 314.4(c)(3): Customer information not encrypted in transit over external networks, and no Qualified-Individual-approved compensating controls documented"
}

violations contains msg if {
	not input.encryption.customer_info.at_rest
	not input.encryption.compensating_controls_approved
	msg := "16 CFR 314.4(c)(3): Customer information not encrypted at rest, and no Qualified-Individual-approved compensating controls documented"
}

# ── 314.4(c)(4) — Secure Development ─────────────────────────────────────────

violations contains msg if {
	not input.secure_development.inhouse_practices
	msg := "16 CFR 314.4(c)(4): Secure development practices not adopted for in-house applications handling customer information"
}

violations contains msg if {
	not input.secure_development.external_apps_assessed
	msg := "16 CFR 314.4(c)(4): Security of externally developed applications handling customer information not assessed"
}

# ── 314.4(c)(5) — Multi-Factor Authentication ────────────────────────────────

violations contains msg if {
	not input.mfa.all_information_systems
	not input.mfa.equivalent_approved_in_writing
	msg := "16 CFR 314.4(c)(5): MFA not implemented for individuals accessing information systems, and no reasonably equivalent control approved in writing by the Qualified Individual"
}

# ── 314.4(c)(6) — Secure Disposal ────────────────────────────────────────────

violations contains msg if {
	not input.disposal.within_two_years
	not input.disposal.retention_justified
	msg := "16 CFR 314.4(c)(6): Customer information not securely disposed of within two years of last use, and continued retention not justified by business need or legal requirement"
}

violations contains msg if {
	not input.disposal.retention_policy_reviewed
	msg := "16 CFR 314.4(c)(6): Data retention policy not periodically reviewed to minimize unnecessary retention of customer information"
}

# ── 314.4(c)(7) — Change Management ──────────────────────────────────────────

violations contains msg if {
	not input.change_management.procedures_adopted
	msg := "16 CFR 314.4(c)(7): Change management procedures not adopted for the information system"
}

# ── 314.4(c)(8) — Monitoring and Logging ─────────────────────────────────────

violations contains msg if {
	not input.monitoring.authorized_user_activity
	msg := "16 CFR 314.4(c)(8): Activity of authorized users not monitored and logged"
}

violations contains msg if {
	not input.monitoring.unauthorized_access_detection
	msg := "16 CFR 314.4(c)(8): Unauthorized access to, use of, or tampering with customer information not detected"
}

# ── 314.4(d) — Regular Testing ───────────────────────────────────────────────
# Either continuous monitoring OR (annual pen test + semi-annual vuln
# assessments). Continuous monitoring satisfies the whole element.

violations contains msg if {
	not small_exempt
	not input.testing.continuous_monitoring
	not input.testing.penetration_test.annual
	msg := "16 CFR 314.4(d)(2)(i): Neither continuous monitoring nor annual penetration testing is in place"
}

violations contains msg if {
	not small_exempt
	not input.testing.continuous_monitoring
	not input.testing.vulnerability_assessment.semi_annual
	msg := "16 CFR 314.4(d)(2)(ii): Neither continuous monitoring nor semi-annual vulnerability assessments (including after material changes) are in place"
}

# ── 314.4(e) — Training and Personnel ────────────────────────────────────────

violations contains msg if {
	not input.training.security_awareness
	msg := "16 CFR 314.4(e)(1): Security awareness training not provided to personnel"
}

violations contains msg if {
	not input.personnel.qualified_infosec_staff
	msg := "16 CFR 314.4(e)(2): Qualified information security personnel not employed or engaged"
}

violations contains msg if {
	not input.personnel.knowledge_current
	msg := "16 CFR 314.4(e)(4): Key information security personnel not verified to maintain current knowledge of changing threats and countermeasures"
}

# ── 314.4(f) — Service Provider Oversight ────────────────────────────────────

violations contains msg if {
	not input.service_providers.capability_assessed
	msg := "16 CFR 314.4(f)(1): Service providers not selected based on ability to maintain appropriate safeguards"
}

violations contains msg if {
	not input.service_providers.contracts_require_safeguards
	msg := "16 CFR 314.4(f)(2): Service provider contracts do not require implementation and maintenance of safeguards"
}

violations contains msg if {
	not input.service_providers.periodic_assessment
	msg := "16 CFR 314.4(f)(3): Service providers not periodically assessed based on the risk they present"
}

# ── 314.4(g) — Program Evaluation ────────────────────────────────────────────

violations contains msg if {
	not input.program.adjusted_from_findings
	msg := "16 CFR 314.4(g): Information security program not evaluated and adjusted in light of testing results, operational changes, and circumstances with material impact"
}

# ── 314.4(h) — Incident Response Plan ────────────────────────────────────────

violations contains msg if {
	not small_exempt
	not input.incident_response.plan.written
	msg := "16 CFR 314.4(h): Written incident response plan not established"
}

violations contains msg if {
	not small_exempt
	not input.incident_response.plan.roles_defined
	msg := "16 CFR 314.4(h)(3): Roles, responsibilities, and levels of decision-making authority not defined in incident response plan"
}

violations contains msg if {
	not small_exempt
	not input.incident_response.plan.post_event_revision
	msg := "16 CFR 314.4(h)(7): Incident response plan lacks process for evaluation and revision following a security event"
}

# ── 314.4(i) — Annual Board Report ───────────────────────────────────────────

violations contains msg if {
	not small_exempt
	not input.board_report.annual_written
	msg := "16 CFR 314.4(i): Qualified Individual has not reported in writing to the board (or equivalent) at least annually"
}

violations contains msg if {
	not small_exempt
	not input.board_report.covers_program_status
	msg := "16 CFR 314.4(i)(1)-(2): Annual board report does not cover overall program status, risk assessment, testing results, and security events with management responses"
}

# ── 314.4(j) / §314.5 — FTC Breach Notification (2024 amendment) ─────────────

violations contains msg if {
	not input.breach_notification.ftc_process_within_30_days
	msg := "16 CFR 314.5: Process not established to notify the FTC within 30 days of discovering a security breach involving unencrypted customer information of 500 or more consumers"
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default entity_type := "unknown"

entity_type := input.entity_type

compliance_report := {
	"framework": "GLBA Safeguards Rule",
	"regulation": "16 CFR Part 314 (as amended; breach notification effective May 2024)",
	"entity_name": entity_name,
	"entity_type": entity_type,
	"small_institution_exemption": small_exempt,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 33,
	"violations": violations,
	"violation_count": count(violations),
}
