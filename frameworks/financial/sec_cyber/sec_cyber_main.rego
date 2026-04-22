package sec_cyber.main

import rego.v1

# SEC Cybersecurity Disclosure Rules
# Final Rule: "Cybersecurity Risk Management, Strategy, Governance, and Incident Disclosure"
# Effective: December 18, 2023 (incident disclosure); June 15, 2023 (annual disclosures)
#
# Key requirements for SEC-registered public companies:
#   1. Material incident disclosure — Form 8-K Item 1.05 within 4 business days
#   2. Annual cybersecurity governance disclosure — Form 10-K
#   3. Board oversight of cybersecurity risk
#   4. Management cybersecurity expertise
#   5. Cybersecurity risk strategy documentation
#
# OPA endpoint: POST http://<host>:8182/v1/data/sec_cyber/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── Form 8-K Item 1.05 — Material Incident Disclosure ───────────────────────

violations contains msg if {
    not input.incident_disclosure.materiality_determination.process_documented
    msg := "SEC Cyber Rule §229.106: No documented process to determine materiality of cybersecurity incidents"
}

violations contains msg if {
    not input.incident_disclosure.materiality_determination.timely
    msg := "SEC Cyber Rule Item 1.05: Materiality determination not made without unreasonable delay after discovery"
}

violations contains msg if {
    not input.incident_disclosure.form_8k.filed_within_4_business_days
    msg := "SEC Cyber Rule Item 1.05: Material cybersecurity incident disclosure not filed on Form 8-K within 4 business days"
}

violations contains msg if {
    not input.incident_disclosure.form_8k.includes_nature_and_scope
    msg := "SEC Cyber Rule Item 1.05(a): Form 8-K does not describe nature, scope, and timing of incident"
}

violations contains msg if {
    not input.incident_disclosure.form_8k.includes_material_impact
    msg := "SEC Cyber Rule Item 1.05(a): Form 8-K does not describe material impact on registrant"
}

violations contains msg if {
    not input.incident_disclosure.delay_request.national_security_process
    msg := "SEC Cyber Rule Item 1.05(c): No process to request disclosure delay when national security exception applies"
}

violations contains msg if {
    not input.incident_disclosure.incident_register.maintained
    msg := "SEC Cyber Rule §229.106: Cybersecurity incident register not maintained for materiality review"
}

# ── Form 10-K — Annual Cybersecurity Disclosures ────────────────────────────

violations contains msg if {
    not input.annual_disclosure.risk_management.strategy_documented
    msg := "SEC Cyber Rule §229.106(b)(1): Cybersecurity risk management strategy not documented for 10-K disclosure"
}

violations contains msg if {
    not input.annual_disclosure.risk_management.integrated_with_overall_risk
    msg := "SEC Cyber Rule §229.106(b)(1): Cybersecurity risk management not integrated with overall enterprise risk management"
}

violations contains msg if {
    not input.annual_disclosure.third_party_risk.assessment_process
    msg := "SEC Cyber Rule §229.106(b)(1): Third-party cybersecurity risk assessment process not established and disclosed"
}

violations contains msg if {
    not input.annual_disclosure.material_risks.identified_and_disclosed
    msg := "SEC Cyber Rule §229.106(b)(2): Material cybersecurity risks and their potential impact not identified and disclosed"
}

violations contains msg if {
    not input.annual_disclosure.previous_incidents.impact_disclosed
    msg := "SEC Cyber Rule §229.106(b)(2): Prior material incidents not disclosed with description of impact on operations"
}

# ── Board Oversight Disclosures ──────────────────────────────────────────────

violations contains msg if {
    not input.governance.board.oversight_responsibility_assigned
    msg := "SEC Cyber Rule §229.106(c)(1): Board-level committee or full board responsibility for cybersecurity oversight not assigned"
}

violations contains msg if {
    not input.governance.board.informed_of_risks_frequency
    msg := "SEC Cyber Rule §229.106(c)(1): Board not informed of cybersecurity risks at required frequency"
}

violations contains msg if {
    not input.governance.board.oversight_process_disclosed
    msg := "SEC Cyber Rule §229.106(c)(1): Board cybersecurity oversight process not disclosed in annual report"
}

# ── Management Cybersecurity Expertise ───────────────────────────────────────

violations contains msg if {
    not input.governance.management.cybersecurity_roles_defined
    msg := "SEC Cyber Rule §229.106(c)(2): Management roles responsible for cybersecurity not defined"
}

violations contains msg if {
    not input.governance.management.expertise_or_expertise_access
    msg := "SEC Cyber Rule §229.106(c)(2): Management lacks cybersecurity expertise or access to expertise"
}

violations contains msg if {
    not input.governance.management.reports_to_board
    msg := "SEC Cyber Rule §229.106(c)(2): Management reporting process to board on cybersecurity risks not established"
}

violations contains msg if {
    not input.governance.management.ciso_or_equivalent
    msg := "SEC Cyber Rule §229.106(c)(2): No CISO or equivalent role with cybersecurity responsibility designated"
}

# ── Cybersecurity Risk Management Program ────────────────────────────────────

violations contains msg if {
    not input.risk_management.program.formal_program_exists
    msg := "SEC Cyber Rule §229.106(b)(1): Formal cybersecurity risk management program not established"
}

violations contains msg if {
    not input.risk_management.standards.framework_adopted
    msg := "SEC Cyber Rule §229.106(b)(1): No recognized cybersecurity framework (NIST CSF, ISO 27001, etc.) adopted"
}

violations contains msg if {
    not input.risk_management.assessments.regular_risk_assessments
    msg := "SEC Cyber Rule §229.106(b)(1): Regular cybersecurity risk assessments not conducted"
}

violations contains msg if {
    not input.risk_management.incident_response.plan_exists
    msg := "SEC Cyber Rule §229.106(b)(1): Cybersecurity incident response plan not established"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":       "SEC Cybersecurity Disclosure Rules",
    "rule":            "17 CFR Parts 229, 232, 239, 240, and 249",
    "effective_date":  "2023-12-18",
    "entity_name":     input.entity_name,
    "ticker":          input.ticker,
    "assessed_at":     input.assessment_date,
    "fiscal_year_end": input.fiscal_year_end,
    "compliant":       compliant,
    "total_controls":  22,
    "violations":      violations,
    "violation_count": count(violations),
    "section_summary": {
        "item_105_8k_disclosure":    [v | some v in violations; contains(v, "Item 1.05")],
        "annual_10k_disclosure":     [v | some v in violations; contains(v, "§229.106(b)")],
        "board_oversight":           [v | some v in violations; contains(v, "§229.106(c)(1)")],
        "management_expertise":      [v | some v in violations; contains(v, "§229.106(c)(2)")],
        "risk_management_program":   [v | some v in violations; contains(v, "§229.106(b)(1)")],
    },
}
