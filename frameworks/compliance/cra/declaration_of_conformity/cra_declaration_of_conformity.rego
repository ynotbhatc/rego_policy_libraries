# METADATA
# title: "EU Cyber Resilience Act (CRA) — Annex V"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 21
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.declaration_of_conformity

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex V
# Content of the EU Declaration of Conformity.
#
# This module checks the CONTENT of the declaration, distinct from
# cra.conformity_assessment which only checks that the declaration
# was prepared and signed. Annex V enumerates the required elements;
# omitting any of them invalidates the declaration even if it exists.

default compliant := false

# Annex V (1) — Product model identifier
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "product_identification", "model_id"])
	text := "CRA Annex V.1: Declaration of Conformity does not state the product model / type identifier"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "product_identification", "serial_or_batch"])
	text := "CRA Annex V.1: Declaration of Conformity does not state the serial/batch identifier"
	msg := concat("", [text, note])
}

# Annex V (2) — Manufacturer details
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "manufacturer", "name"])
	text := "CRA Annex V.2: Declaration of Conformity does not state the manufacturer name"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "manufacturer", "postal_address"])
	text := "CRA Annex V.2: Declaration of Conformity does not state the manufacturer postal address"
	msg := concat("", [text, note])
}

# Annex V (3) — Authorised representative details (where applicable)
violation contains msg if {
	input.declaration_of_conformity.authorised_representative.required == true
	note := _unmet(_root, ["declaration_of_conformity", "authorised_representative", "name"])
	text := "CRA Annex V.3: Authorised representative is required but the declaration does not state their name"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.declaration_of_conformity.authorised_representative.required == true
	note := _unmet(_root, ["declaration_of_conformity", "authorised_representative", "postal_address"])
	text := "CRA Annex V.3: Authorised representative is required but the declaration does not state their postal address"
	msg := concat("", [text, note])
}

# Annex V (4) — Statement of sole responsibility
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "statement_of_sole_responsibility"])
	text := "CRA Annex V.4: Declaration of Conformity does not include the statement 'This declaration of conformity is issued under the sole responsibility of the manufacturer'"
	msg := concat("", [text, note])
}

# Annex V (5) — Object of the declaration (description sufficient for product traceability)
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "object_description", "sufficient_for_traceability"])
	text := "CRA Annex V.5: Object of the declaration (product description) not sufficient for product traceability — must include name, type, additional info"
	msg := concat("", [text, note])
}

# Annex V (6) — Statement of conformity with CRA
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "conformity_statement", "references_cra"])
	text := "CRA Annex V.6: Declaration does not explicitly state conformity with Regulation (EU) 2024/2847"
	msg := concat("", [text, note])
}

# Annex V (7) — Reference to harmonised standards / common specifications used
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "standards", "harmonised_standards_referenced"])
	text := "CRA Annex V.7: Declaration does not reference the harmonised standards or common specifications applied to demonstrate conformity"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.declaration_of_conformity.standards.harmonised_standards_referenced == true
	note := _unmet(_root, ["declaration_of_conformity", "standards", "standard_dates_versions_included"])
	text := "CRA Annex V.7: Declaration references harmonised standards but does not include their dates/versions"
	msg := concat("", [text, note])
}

# Annex V (8) — Notified body involvement (where applicable)
violation contains msg if {
	input.declaration_of_conformity.notified_body.involved == true
	note := _unmet(_root, ["declaration_of_conformity", "notified_body", "name"])
	text := "CRA Annex V.8: Notified body involvement is declared but the notified body name is missing"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.declaration_of_conformity.notified_body.involved == true
	note := _unmet(_root, ["declaration_of_conformity", "notified_body", "id_number"])
	text := "CRA Annex V.8: Notified body involvement is declared but the notified body identification number is missing"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.declaration_of_conformity.notified_body.involved == true
	note := _unmet(_root, ["declaration_of_conformity", "notified_body", "certificate_reference"])
	text := "CRA Annex V.8: Notified body involvement is declared but the issued certificate reference is missing"
	msg := concat("", [text, note])
}

# Annex V (9) — Additional information
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "additional_info", "support_period_stated"])
	text := "CRA Annex V.9: Declaration of Conformity does not state the declared support period"
	msg := concat("", [text, note])
}

# Annex V (10) — Signature
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "signature", "signed_for_manufacturer"])
	text := "CRA Annex V.10: Declaration of Conformity has not been signed for and on behalf of the manufacturer"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "signature", "signatory_name"])
	text := "CRA Annex V.10: Declaration of Conformity signature does not include the signatory's name"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "signature", "signatory_function"])
	text := "CRA Annex V.10: Declaration of Conformity signature does not include the signatory's function"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "signature", "place_and_date"])
	text := "CRA Annex V.10: Declaration of Conformity does not include the place and date of issue"
	msg := concat("", [text, note])
}

# Languages — Annex V preamble (translated into Member State languages where product is sold)
violation contains msg if {
	note := _unmet(_root, ["declaration_of_conformity", "languages", "translated_for_member_states"])
	text := "CRA Annex V (preamble): Declaration not translated into the official languages of the Member States where the product is placed on the market"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Annex V.3", ["declaration_of_conformity", "authorised_representative", "required"]]

_conditions contains ["CRA Annex V.8", ["declaration_of_conformity", "notified_body", "involved"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Annex V",
	"name": "Content of EU Declaration of Conformity",
	"controls_evaluated": 20,
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
