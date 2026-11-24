# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 19"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 16
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.importer_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 19
# Importer obligations.
#
# Importers placing products with digital elements on the EU market must
# verify the manufacturer has met core CRA obligations before importing.
# In specific cases (Article 21) the importer is treated as a manufacturer
# and incurs the full Article 13 obligation set.

default compliant := false

# Art.19(1) — Verify manufacturer has performed conformity assessment
violation contains msg if {
	note := _unmet(_root, ["importer", "verification", "conformity_assessment_performed"])
	text := "CRA Art.19(1)(a): Importer has not verified that the manufacturer performed the required conformity assessment"
	msg := concat("", [text, note])
}

# Art.19(1) — Verify manufacturer has drawn up technical documentation
violation contains msg if {
	note := _unmet(_root, ["importer", "verification", "technical_documentation_exists"])
	text := "CRA Art.19(1)(b): Importer has not verified that technical documentation has been drawn up by the manufacturer"
	msg := concat("", [text, note])
}

# Art.19(1) — Verify CE marking and Declaration of Conformity
violation contains msg if {
	note := _unmet(_root, ["importer", "verification", "ce_marking_present"])
	text := "CRA Art.19(1)(c): Importer has not verified CE marking is affixed before placing the product on the market"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["importer", "verification", "declaration_of_conformity_accompanies_product"])
	text := "CRA Art.19(1)(d): Declaration of Conformity does not accompany the imported product"
	msg := concat("", [text, note])
}

# Art.19(2) — Importer must indicate name/registered trade name/address on product
violation contains msg if {
	note := _unmet(_root, ["importer", "identification", "name_on_product"])
	text := "CRA Art.19(2)(a): Importer's name or registered trade name not indicated on the product (or packaging/accompanying documents)"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["importer", "identification", "postal_address_on_product"])
	text := "CRA Art.19(2)(b): Importer's postal address not indicated on the product"
	msg := concat("", [text, note])
}

# Art.19(3) — Ensure storage/transport doesn't jeopardise compliance
violation contains msg if {
	note := _unmet(_root, ["importer", "handling", "storage_transport_preserves_compliance"])
	text := "CRA Art.19(3): Storage/transport conditions may jeopardise the product's compliance with essential requirements"
	msg := concat("", [text, note])
}

# Art.19(4) — Inform manufacturer + market surveillance of cybersecurity risk
violation contains msg if {
	input.importer.risk_awareness.product_presents_cyber_risk == true
	note := _unmet(_root, ["importer", "risk_awareness", "manufacturer_informed"])
	text := "CRA Art.19(4): Importer has not informed the manufacturer about a known cybersecurity risk in the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.importer.risk_awareness.significant_risk == true
	note := _unmet(_root, ["importer", "risk_awareness", "market_surveillance_informed"])
	text := "CRA Art.19(4): Importer has not informed market surveillance authorities of a significant cybersecurity risk"
	msg := concat("", [text, note])
}

# Art.19(5) — Cooperate with authorities, provide info/documentation
violation contains msg if {
	note := _unmet(_root, ["importer", "cooperation", "documentation_available_10_years"])
	text := "CRA Art.19(5): Importer does not retain a copy of the Declaration of Conformity for 10 years"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["importer", "cooperation", "cooperate_with_authorities"])
	text := "CRA Art.19(6): Importer not committed to cooperate with market surveillance authorities on request"
	msg := concat("", [text, note])
}

# Art.19(7) — Corrective action when non-conformity suspected
violation contains msg if {
	input.importer.non_conformity_known == true
	note := _unmet(_root, ["importer", "corrective_action", "taken_immediately"])
	text := "CRA Art.19(7): Importer has not taken immediate corrective action upon discovering non-conformity"
	msg := concat("", [text, note])
}

# Art.19(7) — Withdraw or recall non-conforming products
violation contains msg if {
	input.importer.non_conformity_known == true
	input.importer.corrective_action.severity == "high"
	note := _unmet(_root, ["importer", "corrective_action", "withdrawal_or_recall_initiated"])
	text := "CRA Art.19(7): Importer has not withdrawn or recalled a non-conforming product where the risk requires it"
	msg := concat("", [text, note])
}

# Article 21 — Importer treated as manufacturer when placing on market under own name
violation contains msg if {
	input.importer.placed_under_own_brand == true
	note := _unmet(_root, ["importer", "assumed_manufacturer_obligations"])
	text := "CRA Art.21: Importer placing the product under its own name/trademark has not assumed manufacturer obligations under Article 13"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.19(4)", ["importer", "risk_awareness", "product_presents_cyber_risk"]]

_conditions contains ["CRA Art.19(4)", ["importer", "risk_awareness", "significant_risk"]]

_conditions contains ["CRA Art.19(7)", ["importer", "non_conformity_known"]]

_conditions contains ["CRA Art.21", ["importer", "placed_under_own_brand"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

_text_conditions contains ["CRA Art.19(7)", ["importer", "corrective_action", "severity"]] if input.importer.non_conformity_known == true

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
	"family": "Article 19",
	"name": "Importer obligations",
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
