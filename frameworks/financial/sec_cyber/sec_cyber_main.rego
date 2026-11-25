# METADATA
# title: "SEC Cybersecurity Disclosure Rules"
# custom:
#   class: compliance
#   framework: sec_cyber
#   source: sec
#   domains: [financial, public-company]
#   coverage:
#     checks: 23
#     cited: 8
#     expected: 22
#     found: 23
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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

# ── Evidence rule ────────────────────────────────────────────────────────────
# Only the boolean true passes a yes/no fact. A fact that is missing, null, or any
# other type ("true", "false", "no", 0, 1) is an evidence problem: the control fails
# and the finding names the problem. A boolean false keeps the plain finding.

default _input := {}

_input := input if is_object(input)

_fact(path) := object.get(_input, path, null)

_not_true(path) if _fact(path) != true

_finding(msg, path) := msg if _fact(path) == false

_finding(msg, path) := sprintf("%s [evidence missing: input.%s not collected]", [msg, concat(".", path)]) if {
	_fact(path) == null
}

_finding(msg, path) := sprintf("%s [evidence invalid: input.%s is not a boolean (got %s)]", [msg, concat(".", path), type_name(_fact(path))]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Form 8-K Item 1.05 — Material Incident Disclosure ───────────────────────

violations contains msg if {
	finding := "SEC Cyber Rule §229.106: No documented process to determine materiality of cybersecurity incidents"
	_not_true(["incident_disclosure", "materiality_determination", "process_documented"])
	msg := _finding(finding, ["incident_disclosure", "materiality_determination", "process_documented"])
}

violations contains msg if {
	finding := "SEC Cyber Rule Item 1.05: Materiality determination not made without unreasonable delay after discovery"
	_not_true(["incident_disclosure", "materiality_determination", "timely"])
	msg := _finding(finding, ["incident_disclosure", "materiality_determination", "timely"])
}

violations contains msg if {
	finding := "SEC Cyber Rule Item 1.05: Material cybersecurity incident disclosure not filed on Form 8-K within 4 business days"
	_not_true(["incident_disclosure", "form_8k", "filed_within_4_business_days"])
	msg := _finding(finding, ["incident_disclosure", "form_8k", "filed_within_4_business_days"])
}

violations contains msg if {
	finding := "SEC Cyber Rule Item 1.05(a): Form 8-K does not describe nature, scope, and timing of incident"
	_not_true(["incident_disclosure", "form_8k", "includes_nature_and_scope"])
	msg := _finding(finding, ["incident_disclosure", "form_8k", "includes_nature_and_scope"])
}

violations contains msg if {
	finding := "SEC Cyber Rule Item 1.05(a): Form 8-K does not describe material impact on registrant"
	_not_true(["incident_disclosure", "form_8k", "includes_material_impact"])
	msg := _finding(finding, ["incident_disclosure", "form_8k", "includes_material_impact"])
}

violations contains msg if {
	finding := "SEC Cyber Rule Item 1.05(c): No process to request disclosure delay when national security exception applies"
	_not_true(["incident_disclosure", "delay_request", "national_security_process"])
	msg := _finding(finding, ["incident_disclosure", "delay_request", "national_security_process"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106: Cybersecurity incident register not maintained for materiality review"
	_not_true(["incident_disclosure", "incident_register", "maintained"])
	msg := _finding(finding, ["incident_disclosure", "incident_register", "maintained"])
}

# ── Form 10-K — Annual Cybersecurity Disclosures ────────────────────────────

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Cybersecurity risk management strategy not documented for 10-K disclosure"
	_not_true(["annual_disclosure", "risk_management", "strategy_documented"])
	msg := _finding(finding, ["annual_disclosure", "risk_management", "strategy_documented"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Cybersecurity risk management not integrated with overall enterprise risk management"
	_not_true(["annual_disclosure", "risk_management", "integrated_with_overall_risk"])
	msg := _finding(finding, ["annual_disclosure", "risk_management", "integrated_with_overall_risk"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Third-party cybersecurity risk assessment process not established and disclosed"
	_not_true(["annual_disclosure", "third_party_risk", "assessment_process"])
	msg := _finding(finding, ["annual_disclosure", "third_party_risk", "assessment_process"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(2): Material cybersecurity risks and their potential impact not identified and disclosed"
	_not_true(["annual_disclosure", "material_risks", "identified_and_disclosed"])
	msg := _finding(finding, ["annual_disclosure", "material_risks", "identified_and_disclosed"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(2): Prior material incidents not disclosed with description of impact on operations"
	_not_true(["annual_disclosure", "previous_incidents", "impact_disclosed"])
	msg := _finding(finding, ["annual_disclosure", "previous_incidents", "impact_disclosed"])
}

# ── Board Oversight Disclosures ──────────────────────────────────────────────

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(1): Board-level committee or full board responsibility for cybersecurity oversight not assigned"
	_not_true(["governance", "board", "oversight_responsibility_assigned"])
	msg := _finding(finding, ["governance", "board", "oversight_responsibility_assigned"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(1): Board not informed of cybersecurity risks at required frequency"
	_not_true(["governance", "board", "informed_of_risks_frequency"])
	msg := _finding(finding, ["governance", "board", "informed_of_risks_frequency"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(1): Board cybersecurity oversight process not disclosed in annual report"
	_not_true(["governance", "board", "oversight_process_disclosed"])
	msg := _finding(finding, ["governance", "board", "oversight_process_disclosed"])
}

# ── Management Cybersecurity Expertise ───────────────────────────────────────

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(2): Management roles responsible for cybersecurity not defined"
	_not_true(["governance", "management", "cybersecurity_roles_defined"])
	msg := _finding(finding, ["governance", "management", "cybersecurity_roles_defined"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(2): Management lacks cybersecurity expertise or access to expertise"
	_not_true(["governance", "management", "expertise_or_expertise_access"])
	msg := _finding(finding, ["governance", "management", "expertise_or_expertise_access"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(2): Management reporting process to board on cybersecurity risks not established"
	_not_true(["governance", "management", "reports_to_board"])
	msg := _finding(finding, ["governance", "management", "reports_to_board"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(c)(2): No CISO or equivalent role with cybersecurity responsibility designated"
	_not_true(["governance", "management", "ciso_or_equivalent"])
	msg := _finding(finding, ["governance", "management", "ciso_or_equivalent"])
}

# ── Cybersecurity Risk Management Program ────────────────────────────────────

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Formal cybersecurity risk management program not established"
	_not_true(["risk_management", "program", "formal_program_exists"])
	msg := _finding(finding, ["risk_management", "program", "formal_program_exists"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): No recognized cybersecurity framework (NIST CSF, ISO 27001, etc.) adopted"
	_not_true(["risk_management", "standards", "framework_adopted"])
	msg := _finding(finding, ["risk_management", "standards", "framework_adopted"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Regular cybersecurity risk assessments not conducted"
	_not_true(["risk_management", "assessments", "regular_risk_assessments"])
	msg := _finding(finding, ["risk_management", "assessments", "regular_risk_assessments"])
}

violations contains msg if {
	finding := "SEC Cyber Rule §229.106(b)(1): Cybersecurity incident response plan not established"
	_not_true(["risk_management", "incident_response", "plan_exists"])
	msg := _finding(finding, ["risk_management", "incident_response", "plan_exists"])
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default fiscal_year_end := "unknown"

fiscal_year_end := input.fiscal_year_end

default ticker := "unknown"

ticker := input.ticker

compliance_report := {
	"framework": "SEC Cybersecurity Disclosure Rules",
	"rule": "17 CFR Parts 229, 232, 239, 240, and 249",
	"effective_date": "2023-12-18",
	"entity_name": entity_name,
	"ticker": ticker,
	"assessed_at": assessment_date,
	"fiscal_year_end": fiscal_year_end,
	"compliant": compliant,
	"total_controls": 22,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([22, count(violations)]),
	"section_summary": {
		"item_105_8k_disclosure": [v | some v in violations; contains(v, "Item 1.05")],
		"annual_10k_disclosure": [v | some v in violations; contains(v, "§229.106(b)")],
		"board_oversight": [v | some v in violations; contains(v, "§229.106(c)(1)")],
		"management_expertise": [v | some v in violations; contains(v, "§229.106(c)(2)")],
		"risk_management_program": [v | some v in violations; contains(v, "§229.106(b)(1)")],
	},
}
