# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 31 + Annex VII"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 16
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.technical_documentation

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 31 + Annex VII
# Technical documentation requirements. Manufacturers must prepare and
# maintain technical documentation for every product before placing it
# on the market, and keep it available for 10 years (Art.31(4)).

default compliant := false

# Annex VII (1) — General product description
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "product_description", "documented"])
	text := "CRA Annex VII.1(a): General product description not documented"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "product_description", "intended_purpose"])
	text := "CRA Annex VII.1(b): Intended purpose / use cases not documented"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "product_description", "support_period_declared"])
	text := "CRA Annex VII.1(c): Declared support period not documented"
	msg := concat("", [text, note])
}

# Annex VII (2) — Risk assessment
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "risk_assessment", "documented"])
	text := "CRA Annex VII.2(a): Cybersecurity risk assessment not documented"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "risk_assessment", "threats_identified"])
	text := "CRA Annex VII.2(b): Identified threats and threat actors not documented"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "risk_assessment", "mitigations_documented"])
	text := "CRA Annex VII.2(c): Mitigations applied for each identified threat not documented"
	msg := concat("", [text, note])
}

# Annex VII (3) — Design and architecture
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "design", "architecture_diagram"])
	text := "CRA Annex VII.3(a): Architecture/design diagram of the product not provided"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "design", "cybersecurity_controls_mapped"])
	text := "CRA Annex VII.3(b): Mapping of cybersecurity controls to essential requirements not provided"
	msg := concat("", [text, note])
}

# Annex VII (4) — Vulnerability handling process
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "vuln_process", "documented"])
	text := "CRA Annex VII.4: Vulnerability handling process documentation not included"
	msg := concat("", [text, note])
}

# Annex VII (5) — Software bill of materials
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "sbom", "included"])
	text := "CRA Annex VII.5: SBOM not included in technical documentation"
	msg := concat("", [text, note])
}

# Annex VII (6) — Test results
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "testing", "results_documented"])
	text := "CRA Annex VII.6(a): Cybersecurity testing/audit results not documented"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "testing", "third_party_assessment"])
	input.technical_documentation.product.classification in {"important_class_2", "critical"}
	text := "CRA Annex VII.6(b): Third-party conformity assessment not documented (required for Important Class II / Critical products)"
	msg := concat("", [text, note])
}

# Annex VII (7) — Declaration of conformity
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "declaration_of_conformity", "signed"])
	text := "CRA Annex VII.7: EU Declaration of Conformity not signed"
	msg := concat("", [text, note])
}

# Article 31(4) — Retention
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "retention", "maintained_10_years"])
	text := "CRA Art.31(4): Technical documentation not retained for 10 years after product placed on market"
	msg := concat("", [text, note])
}

# Article 31(5) — Availability to authorities
violation contains msg if {
	note := _unmet(_root, ["technical_documentation", "retention", "available_on_request"])
	text := "CRA Art.31(5): Technical documentation not available to market surveillance authorities on request"
	msg := concat("", [text, note])
}

_text_conditions contains ["CRA Annex VII.6(b)", ["technical_documentation", "product", "classification"]]

# A text fact that selects which obligations apply must be supplied as a non-empty string.
violation contains msg if {
	some [cite, path] in _text_conditions
	not _is_text(_fact(_root, path))
	msg := sprintf("%s: applicability not determined — evidence missing: %s not collected as text", [cite, concat(".", path)])
}

_is_text(value) if {
	is_string(value)
	value != ""
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Article 31 / Annex VII",
	"name": "Technical documentation",
	"controls_evaluated": 15,
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
