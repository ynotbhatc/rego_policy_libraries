# METADATA
# title: "Gramm-Leach-Bliley Act — FTC Safeguards Rule, 16 CFR Part 314"
# custom:
#   class: compliance
#   framework: glba
#   source: us-federal
#   domains: [financial, banking]
#   coverage:
#     checks: 35
#     cited: 27
#     expected: 33
#     found: 35
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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

# ── Evidence rule (bad input never passes, issue #301) ───────────────────────
# A yes/no fact passes only as the boolean true. A fact that is missing, null,
# a string such as "true" / "false" / "no", or a number is an evidence problem:
# the control fails and the finding says which ("evidence missing: <field> not
# collected" / "evidence invalid: <field> is not a boolean (got string)").
# Where a control accepts alternatives, any one alternative that is true
# satisfies it, but an alternative of the wrong type fails it: the verdict
# never rests on mistyped evidence.

_absent := "__absent__"

_value(path) := object.get(input, path, _absent)

_yes(path) if _value(path) == true

_collected(path) if _value(path) != _absent

_mistyped(path) if {
	_collected(path)
	not is_boolean(_value(path))
}

_unmet(facts) if {
	every path in facts {
		not _yes(path)
	}
}

_unmet(facts) if {
	some path in facts
	_mistyped(path)
}

_problem(path) := sprintf("evidence missing: input.%s not collected", [concat(".", path)]) if not _collected(path)

_problem(path) := sprintf("evidence invalid: input.%s is not a boolean (got %s)", [concat(".", path), type_name(_value(path))]) if _mistyped(path)

_evidence(facts) := sprintf(" [%s]", [concat("; ", problems)]) if {
	problems := [_problem(path) | some path in facts]
	count(problems) > 0
} else := ""

# ── Applicability — the kind of institution is stated ────────────────────────
# Part 314 applies to financial institutions under FTC jurisdiction (§314.1(b));
# banks answer to their prudential regulators instead. The assessment therefore
# states what kind of institution it covers: a missing, null or empty
# entity_type is an evidence problem, not a default.

_entity_type_stated if {
	is_string(input.entity_type)
	trim_space(input.entity_type) != ""
}

violations contains msg if {
	not _entity_type_stated
	msg := sprintf("GLBA input contract (16 CFR 314.1(b)): the kind of financial institution assessed is not stated%s", [_entity_type_problem])
}

_entity_type_problem := " [evidence missing: input.entity_type not collected]" if {
	not _collected(["entity_type"])
} else := sprintf(" [evidence invalid: input.entity_type is not a non-empty string (got %s)]", [type_name(input.entity_type)])

# ── 314.4(a) — Qualified Individual ──────────────────────────────────────────

violations contains msg if {
	facts := [["qualified_individual", "designated"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(a): Qualified Individual not designated to oversee, implement, and enforce the information security program%s", [_evidence(facts)])
}

# ── 314.4(b) — Risk Assessment ───────────────────────────────────────────────

violations contains msg if {
	not small_exempt
	facts := [["risk_assessment", "written"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(b)(1): Written risk assessment not performed%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["risk_assessment", "criteria_documented"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(b)(1): Risk assessment lacks documented criteria for evaluating and categorizing security risks and threats%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["risk_assessment", "periodic_reassessment"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(b)(2): Risk assessment not periodically re-performed to reexamine reasonably foreseeable risks%s", [_evidence(facts)])
}

# ── 314.4(c)(1) — Access Controls ────────────────────────────────────────────

violations contains msg if {
	facts := [["access_control", "authenticate_users"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(1): Access controls do not authenticate users before permitting access to customer information%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["access_control", "least_privilege"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(1): Access to customer information not limited to what is needed to perform duties and functions%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["access_control", "periodic_review"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(1): Access permissions to customer information not periodically reviewed%s", [_evidence(facts)])
}

# ── 314.4(c)(2) — Data and System Inventory ──────────────────────────────────

violations contains msg if {
	facts := [["inventory", "data_identified"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(2): Customer information not identified and its location not inventoried%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["inventory", "systems_inventoried"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(2): Systems, devices, platforms, and personnel handling customer information not inventoried%s", [_evidence(facts)])
}

# ── 314.4(c)(3) — Encryption ─────────────────────────────────────────────────

violations contains msg if {
	facts := [["encryption", "customer_info", "in_transit"], ["encryption", "compensating_controls_approved"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(3): Customer information not encrypted in transit over external networks, and no Qualified-Individual-approved compensating controls documented%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["encryption", "customer_info", "at_rest"], ["encryption", "compensating_controls_approved"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(3): Customer information not encrypted at rest, and no Qualified-Individual-approved compensating controls documented%s", [_evidence(facts)])
}

# ── 314.4(c)(4) — Secure Development ─────────────────────────────────────────

violations contains msg if {
	facts := [["secure_development", "inhouse_practices"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(4): Secure development practices not adopted for in-house applications handling customer information%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["secure_development", "external_apps_assessed"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(4): Security of externally developed applications handling customer information not assessed%s", [_evidence(facts)])
}

# ── 314.4(c)(5) — Multi-Factor Authentication ────────────────────────────────

violations contains msg if {
	facts := [["mfa", "all_information_systems"], ["mfa", "equivalent_approved_in_writing"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(5): MFA not implemented for individuals accessing information systems, and no reasonably equivalent control approved in writing by the Qualified Individual%s", [_evidence(facts)])
}

# ── 314.4(c)(6) — Secure Disposal ────────────────────────────────────────────

violations contains msg if {
	facts := [["disposal", "within_two_years"], ["disposal", "retention_justified"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(6): Customer information not securely disposed of within two years of last use, and continued retention not justified by business need or legal requirement%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["disposal", "retention_policy_reviewed"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(6): Data retention policy not periodically reviewed to minimize unnecessary retention of customer information%s", [_evidence(facts)])
}

# ── 314.4(c)(7) — Change Management ──────────────────────────────────────────

violations contains msg if {
	facts := [["change_management", "procedures_adopted"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(7): Change management procedures not adopted for the information system%s", [_evidence(facts)])
}

# ── 314.4(c)(8) — Monitoring and Logging ─────────────────────────────────────

violations contains msg if {
	facts := [["monitoring", "authorized_user_activity"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(8): Activity of authorized users not monitored and logged%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["monitoring", "unauthorized_access_detection"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(c)(8): Unauthorized access to, use of, or tampering with customer information not detected%s", [_evidence(facts)])
}

# ── 314.4(d) — Regular Testing ───────────────────────────────────────────────
# Either continuous monitoring OR (annual pen test + semi-annual vuln
# assessments). Continuous monitoring satisfies the whole element.

violations contains msg if {
	not small_exempt
	facts := [["testing", "continuous_monitoring"], ["testing", "penetration_test", "annual"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(d)(2)(i): Neither continuous monitoring nor annual penetration testing is in place%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["testing", "continuous_monitoring"], ["testing", "vulnerability_assessment", "semi_annual"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(d)(2)(ii): Neither continuous monitoring nor semi-annual vulnerability assessments (including after material changes) are in place%s", [_evidence(facts)])
}

# ── 314.4(e) — Training and Personnel ────────────────────────────────────────

violations contains msg if {
	facts := [["training", "security_awareness"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(e)(1): Security awareness training not provided to personnel%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["personnel", "qualified_infosec_staff"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(e)(2): Qualified information security personnel not employed or engaged%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["personnel", "knowledge_current"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(e)(4): Key information security personnel not verified to maintain current knowledge of changing threats and countermeasures%s", [_evidence(facts)])
}

# ── 314.4(f) — Service Provider Oversight ────────────────────────────────────

violations contains msg if {
	facts := [["service_providers", "capability_assessed"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(f)(1): Service providers not selected based on ability to maintain appropriate safeguards%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["service_providers", "contracts_require_safeguards"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(f)(2): Service provider contracts do not require implementation and maintenance of safeguards%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["service_providers", "periodic_assessment"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(f)(3): Service providers not periodically assessed based on the risk they present%s", [_evidence(facts)])
}

# ── 314.4(g) — Program Evaluation ────────────────────────────────────────────

violations contains msg if {
	facts := [["program", "adjusted_from_findings"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(g): Information security program not evaluated and adjusted in light of testing results, operational changes, and circumstances with material impact%s", [_evidence(facts)])
}

# ── 314.4(h) — Incident Response Plan ────────────────────────────────────────

violations contains msg if {
	not small_exempt
	facts := [["incident_response", "plan", "written"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(h): Written incident response plan not established%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["incident_response", "plan", "roles_defined"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(h)(3): Roles, responsibilities, and levels of decision-making authority not defined in incident response plan%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["incident_response", "plan", "post_event_revision"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(h)(7): Incident response plan lacks process for evaluation and revision following a security event%s", [_evidence(facts)])
}

# ── 314.4(i) — Annual Board Report ───────────────────────────────────────────

violations contains msg if {
	not small_exempt
	facts := [["board_report", "annual_written"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(i): Qualified Individual has not reported in writing to the board (or equivalent) at least annually%s", [_evidence(facts)])
}

violations contains msg if {
	not small_exempt
	facts := [["board_report", "covers_program_status"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.4(i)(1)-(2): Annual board report does not cover overall program status, risk assessment, testing results, and security events with management responses%s", [_evidence(facts)])
}

# ── 314.4(j) / §314.5 — FTC Breach Notification (2024 amendment) ─────────────

violations contains msg if {
	facts := [["breach_notification", "ftc_process_within_30_days"]]
	_unmet(facts)
	msg := sprintf("16 CFR 314.5: Process not established to notify the FTC within 30 days of discovering a security breach involving unencrypted customer information of 500 or more consumers%s", [_evidence(facts)])
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
	"failed_controls": min([33, count(violations)]),
}
