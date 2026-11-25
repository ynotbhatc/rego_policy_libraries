# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 20"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 17
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.distributor_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 20
# Distributor obligations.
#
# Distributors making products with digital elements available on the EU
# market must act with due care to ensure those products comply with CRA.
# Article 21 also makes a distributor a "manufacturer" when they modify
# the product or sell it under their own name.

default compliant := false

# Art.20(1) — Verify before making the product available
violation contains msg if {
	note := _unmet(_root, ["distributor", "verification", "ce_marking_present"])
	text := "CRA Art.20(1)(a): Distributor has not verified CE marking before making the product available"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["distributor", "verification", "declaration_of_conformity_provided"])
	text := "CRA Art.20(1)(b): Distributor has not verified that the Declaration of Conformity accompanies the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["distributor", "verification", "manufacturer_identification_clear"])
	text := "CRA Art.20(1)(c): Distributor has not verified manufacturer name + contact info are clearly identified on the product"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["distributor", "verification", "importer_identification_clear"])
	input.distributor.product_is_imported == true
	text := "CRA Art.20(1)(c): Distributor has not verified importer name + address are present on imported products"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["distributor", "verification", "user_instructions_provided"])
	text := "CRA Art.20(1)(d): Distributor has not verified user instructions/information are provided with the product"
	msg := concat("", [text, note])
}

# Art.20(2) — Suspend availability when non-compliance suspected
violation contains msg if {
	input.distributor.non_conformity_suspected == true
	note := _unmet(_root, ["distributor", "action", "availability_suspended"])
	text := "CRA Art.20(2): Distributor has not suspended making the product available when non-conformity was suspected"
	msg := concat("", [text, note])
}

# Art.20(2) — Inform manufacturer + importer
violation contains msg if {
	input.distributor.non_conformity_suspected == true
	note := _unmet(_root, ["distributor", "action", "manufacturer_informed"])
	text := "CRA Art.20(2): Distributor has not informed the manufacturer of suspected non-conformity"
	msg := concat("", [text, note])
}

# Art.20(3) — Storage / transport must not jeopardise compliance
violation contains msg if {
	note := _unmet(_root, ["distributor", "handling", "storage_preserves_compliance"])
	text := "CRA Art.20(3): Storage or transport conditions risk jeopardising product compliance with essential requirements"
	msg := concat("", [text, note])
}

# Art.20(4) — Inform market surveillance on significant cyber risk
violation contains msg if {
	input.distributor.risk_awareness.significant_risk_known == true
	note := _unmet(_root, ["distributor", "risk_awareness", "market_surveillance_informed"])
	text := "CRA Art.20(4): Distributor has not informed market surveillance authorities of a known significant cybersecurity risk"
	msg := concat("", [text, note])
}

# Art.20(5) — Provide information + cooperate with authorities
violation contains msg if {
	note := _unmet(_root, ["distributor", "cooperation", "provide_info_on_request"])
	text := "CRA Art.20(5): Distributor not committed to providing requested information to market surveillance authorities"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["distributor", "cooperation", "cooperate_on_corrective_action"])
	text := "CRA Art.20(5): Distributor not committed to cooperating on corrective action when requested"
	msg := concat("", [text, note])
}

# Art.20(6) — Corrective action / withdrawal when non-conformity confirmed
violation contains msg if {
	input.distributor.non_conformity_confirmed == true
	note := _unmet(_root, ["distributor", "corrective_action", "taken"])
	text := "CRA Art.20(6): Distributor has not taken corrective action on confirmed non-conforming products"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.distributor.non_conformity_confirmed == true
	input.distributor.corrective_action.severity == "high"
	note := _unmet(_root, ["distributor", "corrective_action", "withdrawal_or_recall"])
	text := "CRA Art.20(6): Distributor has not withdrawn / recalled non-conforming product where the cyber risk requires it"
	msg := concat("", [text, note])
}

# Article 21 — Distributor becomes manufacturer when modifying or rebranding
violation contains msg if {
	input.distributor.product_modified_after_placement == true
	note := _unmet(_root, ["distributor", "assumed_manufacturer_obligations"])
	text := "CRA Art.21: Distributor that modified the product has not assumed manufacturer obligations under Article 13"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.distributor.sold_under_own_brand == true
	note := _unmet(_root, ["distributor", "assumed_manufacturer_obligations"])
	text := "CRA Art.21: Distributor selling the product under its own name/trademark has not assumed manufacturer obligations"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.20(1)(c)", ["distributor", "product_is_imported"]]

_conditions contains ["CRA Art.20(2)", ["distributor", "non_conformity_suspected"]]

_conditions contains ["CRA Art.20(4)", ["distributor", "risk_awareness", "significant_risk_known"]]

_conditions contains ["CRA Art.20(6)", ["distributor", "non_conformity_confirmed"]]

_conditions contains ["CRA Art.21", ["distributor", "product_modified_after_placement"]]

_conditions contains ["CRA Art.21", ["distributor", "sold_under_own_brand"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

_text_conditions contains ["CRA Art.20(6)", ["distributor", "corrective_action", "severity"]] if input.distributor.non_conformity_confirmed == true

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
	"family": "Article 20",
	"name": "Distributor obligations",
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
