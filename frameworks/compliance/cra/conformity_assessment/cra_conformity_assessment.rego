# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 32 + Annex VIII"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 13
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.conformity_assessment

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 32 + Annex VIII
# Conformity assessment procedures + CE marking.
#
# Product classification (Article 7 + Annex III):
#   - Default (most products)        → Module A (internal control)
#   - Important — Class I            → Module A or B+C
#   - Important — Class II           → Module B+C, B+D, or H (third-party notified body)
#   - Critical                       → European cybersecurity certification scheme (Art.8)

default compliant := false

# Article 32 — Conformity assessment procedure required
violation contains msg if {
	note := _unmet(_root, ["conformity_assessment", "procedure_selected"])
	text := "CRA Art.32(1): Conformity assessment procedure not selected"
	msg := concat("", [text, note])
}

# Article 32(2) — Procedure must match product classification
violation contains msg if {
	input.conformity_assessment.product_class == "important_class_2"
	input.conformity_assessment.procedure_used == "module_a"
	msg := "CRA Art.32(2): Important Class II products require Module B+C, B+D, or H — Module A is insufficient"
}

violation contains msg if {
	input.conformity_assessment.product_class == "critical"
	note := _unmet(_root, ["conformity_assessment", "european_cyber_cert_scheme_used"])
	text := "CRA Art.32(3) / Art.8: Critical products require certification under a European cybersecurity certification scheme"
	msg := concat("", [text, note])
}

# Article 32(4) — Notified body for third-party assessment
violation contains msg if {
	input.conformity_assessment.procedure_used in {"module_b_c", "module_b_d", "module_h"}
	note := _unmet(_root, ["conformity_assessment", "notified_body", "engaged"])
	text := "CRA Art.32(4): Third-party conformity assessment selected but no notified body engaged"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.conformity_assessment.notified_body.engaged == true
	note := _unmet(_root, ["conformity_assessment", "notified_body", "id_number"])
	text := "CRA Art.32(4): Notified body ID number not recorded"
	msg := concat("", [text, note])
}

# Article 32 / Annex VIII — CE marking
violation contains msg if {
	input.conformity_assessment.product_placed_on_market == true
	note := _unmet(_root, ["conformity_assessment", "ce_marking", "affixed"])
	text := "CRA Art.32/Annex VIII(1): CE marking not affixed to product before placement on EU market"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.conformity_assessment.ce_marking.affixed == true
	note := _unmet(_root, ["conformity_assessment", "ce_marking", "visible_legible_indelible"])
	text := "CRA Art.32/Annex VIII(2): CE marking is not visible, legible, and indelible on the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.conformity_assessment.procedure_used in {"module_b_c", "module_b_d", "module_h"}
	note := _unmet(_root, ["conformity_assessment", "ce_marking", "notified_body_number_included"])
	text := "CRA Art.32/Annex VIII(4): Notified body identification number not included with CE marking (required when third-party assessment used)"
	msg := concat("", [text, note])
}

# Article 28(1) — EU Declaration of Conformity
violation contains msg if {
	note := _unmet(_root, ["conformity_assessment", "declaration_of_conformity", "prepared"])
	text := "CRA Art.28(1): EU Declaration of Conformity not prepared"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.conformity_assessment.declaration_of_conformity.prepared == true
	note := _unmet(_root, ["conformity_assessment", "declaration_of_conformity", "includes_required_elements"])
	text := "CRA Art.28(1) / Annex IV: Declaration of Conformity missing required elements (product ID, manufacturer details, harmonised standards used, conformity statement)"
	msg := concat("", [text, note])
}

# Continuous compliance
violation contains msg if {
	note := _unmet(_root, ["conformity_assessment", "reassessment_on_substantial_modification"])
	text := "CRA Art.32(5): Process not in place to re-assess conformity after substantial product modification"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.32/Annex VIII(1)", ["conformity_assessment", "product_placed_on_market"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

_text_conditions contains ["CRA Art.32", ["conformity_assessment", "product_class"]]

_text_conditions contains ["CRA Art.32", ["conformity_assessment", "procedure_used"]]

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
	"family": "Article 32 + Annex VIII",
	"name": "Conformity assessment + CE marking",
	"controls_evaluated": 11,
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
