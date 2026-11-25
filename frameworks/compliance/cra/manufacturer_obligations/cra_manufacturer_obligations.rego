# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 13"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 15
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.manufacturer_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 13
# General obligations on manufacturers of products with digital elements.

default compliant := false

# Article 13(1) — Compliance with essential requirements
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "essential_requirements", "met"])
	text := "CRA Art.13(1): Manufacturer has not ensured compliance with the essential requirements in Annex I"
	msg := concat("", [text, note])
}

# Article 13(2) — Risk assessment performed
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "risk_assessment", "performed"])
	text := "CRA Art.13(2): Manufacturer has not performed a cybersecurity risk assessment for the product"
	msg := concat("", [text, note])
}

# Article 13(3) — Risk assessment included in technical documentation
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "risk_assessment", "in_technical_documentation"])
	text := "CRA Art.13(3): Risk assessment not included in the technical documentation"
	msg := concat("", [text, note])
}

# Article 13(4) — Vulnerability handling throughout product lifecycle
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "vulnerability_handling", "lifetime_coverage"])
	text := "CRA Art.13(4): Vulnerability handling process does not cover the entire declared support period"
	msg := concat("", [text, note])
}

# Article 13(6) — Apply due diligence to integrated third-party components
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "third_party_components", "due_diligence_performed"])
	text := "CRA Art.13(6): Due diligence not performed for integrated third-party components (open-source or commercial)"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["manufacturer", "third_party_components", "vulnerabilities_monitored"])
	text := "CRA Art.13(6): Vulnerabilities in third-party components not actively monitored"
	msg := concat("", [text, note])
}

# Article 13(7) — Report exploited vulnerabilities + severe incidents to ENISA
# (Reporting timeline rules are in cra.incident_reporting; here we just check
# the obligation/awareness/process exists.)
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "reporting", "process_to_enisa_documented"])
	text := "CRA Art.13(7) / 14: Process for reporting exploited vulnerabilities + severe incidents to ENISA not documented"
	msg := concat("", [text, note])
}

# Article 13(8) — Declared support period (also enforced in vulnerability_handling)
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "support_period", "declared"])
	text := "CRA Art.13(8): Manufacturer has not declared a support period for the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	is_number(input.manufacturer.support_period.years)
	input.manufacturer.support_period.years < 5
	msg := sprintf("CRA Art.13(8): Declared support period (%d years) is below the 5-year minimum", [input.manufacturer.support_period.years])
}

violation contains "CRA Art.13(8): evidence missing — support_period.years is not a number; the declared support period cannot be verified" if {
	input.manufacturer.support_period.declared == true
	not is_number(object.get(_root, ["manufacturer", "support_period", "years"], null))
}

# Article 13(10) — User-facing instructions and information
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "user_information", "instructions_provided"])
	text := "CRA Art.13(10): User instructions / information set not provided with the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["manufacturer", "user_information", "security_relevant_info_included"])
	text := "CRA Art.13(10) / Annex II: User information missing security-relevant content (intended use, secure config guidance, support period, contact for vulnerability reporting)"
	msg := concat("", [text, note])
}

# Article 13(12) — Cooperation with market surveillance
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "market_surveillance", "cooperation_committed"])
	text := "CRA Art.13(12): Manufacturer not committed to cooperate with market surveillance authorities upon request"
	msg := concat("", [text, note])
}

# Article 13(14) — End-of-support notification
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "eol", "end_of_support_notification_planned"])
	text := "CRA Art.13(14): Plan to notify users at least 12 months before end-of-support not in place"
	msg := concat("", [text, note])
}

# Process maturity — internal cybersecurity governance for product teams
violation contains msg if {
	note := _unmet(_root, ["manufacturer", "governance", "product_security_role_assigned"])
	text := "CRA Art.13 (general): No designated product security role (PSIRT lead or equivalent) within the manufacturer"
	msg := concat("", [text, note])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Article 13",
	"name": "Manufacturer obligations",
	"controls_evaluated": 14,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
