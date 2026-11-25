# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 22 (definition: Art. 3(40))"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 14
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.substantial_modification

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 22 (definition: Art. 3(40))
# Substantial modifications.
#
# When a product undergoes a "substantial modification" — changes the
# intended use, affects compliance with essential requirements, or alters
# the risk profile — the modifier becomes legally responsible as a
# manufacturer and must re-perform conformity assessment.
#
# Key implications: cybersecurity-relevant feature changes, new connectivity
# capability, change of supported platforms, additions to the SBOM, or
# functional changes that affect threat exposure are all triggers.

default compliant := false

# Art.22(1) — Identify modifications that constitute "substantial"
violation contains msg if {
	note := _unmet(_root, ["substantial_modification", "assessment_process", "documented"])
	text := "CRA Art.22(1): No documented process to assess whether a planned change constitutes a substantial modification"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["substantial_modification", "assessment_process", "criteria_published"])
	text := "CRA Art.22(1): Substantial-modification assessment criteria not published / documented"
	msg := concat("", [text, note])
}

# Art.22(2) — Re-assess conformity after substantial modification
violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	note := _unmet(_root, ["substantial_modification", "conformity_reassessment", "performed"])
	text := "CRA Art.22(2): A modification was classified as substantial but conformity assessment has not been re-performed"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	note := _unmet(_root, ["substantial_modification", "conformity_reassessment", "scope_appropriate"])
	text := "CRA Art.22(2): Re-performed conformity assessment scope does not cover the modified aspects of the product"
	msg := concat("", [text, note])
}

# Art.22(3) — Modifier assumes manufacturer's obligations
violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	input.substantial_modification.modifier_is_not_original_manufacturer == true
	note := _unmet(_root, ["substantial_modification", "modifier_assumed_manufacturer_obligations"])
	text := "CRA Art.22(3): Modifier of a substantially-modified product has not assumed manufacturer obligations under Article 13"
	msg := concat("", [text, note])
}

# Connectivity changes — new attack surface
violation contains msg if {
	input.substantial_modification.changes.added_network_connectivity == true
	note := _unmet(_root, ["substantial_modification", "changes", "risk_assessment_updated"])
	text := "CRA Art.22 (Annex I.1 interaction): New network connectivity added without an updated cybersecurity risk assessment"
	msg := concat("", [text, note])
}

# Cryptographic primitive changes
violation contains msg if {
	input.substantial_modification.changes.cryptographic_primitive_changed == true
	note := _unmet(_root, ["substantial_modification", "changes", "cryptographic_review_performed"])
	text := "CRA Art.22 (Annex I.5/6 interaction): Cryptographic primitive changed without security review of the new mechanism"
	msg := concat("", [text, note])
}

# SBOM changes
violation contains msg if {
	input.substantial_modification.changes.sbom_changed == true
	note := _unmet(_root, ["substantial_modification", "changes", "sbom_published_after_change"])
	text := "CRA Art.22 (Annex II.1 interaction): SBOM not refreshed after dependency changes"
	msg := concat("", [text, note])
}

# Update technical documentation
violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	note := _unmet(_root, ["substantial_modification", "documentation_updated"])
	text := "CRA Art.22(2) / Art.28: Substantial modification performed but technical documentation not updated"
	msg := concat("", [text, note])
}

# Declaration of Conformity must be reissued
violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	note := _unmet(_root, ["substantial_modification", "declaration_of_conformity_reissued"])
	text := "CRA Art.22(2) / Annex IV: Substantial modification performed but Declaration of Conformity not reissued"
	msg := concat("", [text, note])
}

# Notify users of relevant security-impacting changes
violation contains msg if {
	input.substantial_modification.changes.security_relevant == true
	note := _unmet(_root, ["substantial_modification", "changes", "users_notified"])
	text := "CRA Art.22 / Annex II: Security-relevant substantial modification not communicated to existing users"
	msg := concat("", [text, note])
}

# Updates to support period commitment
violation contains msg if {
	input.substantial_modification.modification_classified_substantial == true
	note := _unmet(_root, ["substantial_modification", "support_period_recommitted"])
	text := "CRA Art.22 / Art.13(8): Substantial modification did not re-affirm the declared support period for the modified product"
	msg := concat("", [text, note])
}

# Process maturity — review cadence
violation contains msg if {
	note := _unmet(_root, ["substantial_modification", "assessment_process", "reviewed_annually"])
	text := "CRA Art.22: Substantial-modification assessment criteria not reviewed at least annually"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.22(2)", ["substantial_modification", "modification_classified_substantial"]]

_conditions contains ["CRA Art.22(3)", ["substantial_modification", "modifier_is_not_original_manufacturer"]] if input.substantial_modification.modification_classified_substantial == true

_conditions contains ["CRA Art.22 (Annex I.1 interaction)", ["substantial_modification", "changes", "added_network_connectivity"]]

_conditions contains ["CRA Art.22 (Annex I.5/6 interaction)", ["substantial_modification", "changes", "cryptographic_primitive_changed"]]

_conditions contains ["CRA Art.22 (Annex II.1 interaction)", ["substantial_modification", "changes", "sbom_changed"]]

_conditions contains ["CRA Art.22 / Annex II", ["substantial_modification", "changes", "security_relevant"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Article 22 (definition: Art. 3(40))",
	"name": "Substantial modifications",
	"controls_evaluated": 13,
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
