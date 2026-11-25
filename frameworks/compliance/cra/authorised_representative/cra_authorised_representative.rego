# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 18"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 15
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.authorised_representative

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 18
# Authorised representative obligations.
#
# Non-EU manufacturers placing products on the EU market must appoint an
# authorised representative established in the Union. The mandate must be
# in writing. The authorised representative performs specific tasks on
# behalf of the manufacturer (Art.18(3)).

default compliant := false

# Applicability (conditional-applicability article): Art.18 applies only to manufacturers outside
# the Union. Decisions 2026-10-19: `manufacturer_outside_eu` must be declared. An explicit `false`
# is "not applicable" (pass); an undeclared flag is "applicability not determined" (violation).
violation contains "CRA Art.18: applicability not determined — manufacturer_outside_eu not declared" if {
	not is_boolean(object.get(object.get(_root, "authorised_representative", {}), "manufacturer_outside_eu", null))
}

# Art.18(1) — Mandate must be in writing (required, or a representative has actually been appointed)
mandate_applies if input.authorised_representative.required == true

mandate_applies if input.authorised_representative.appointed == true

violation contains msg if {
	mandate_applies
	note := _unmet(_root, ["authorised_representative", "written_mandate_in_place"])
	text := "CRA Art.18(1): Written mandate from the manufacturer to the authorised representative not in place"
	msg := concat("", [text, note])
}

# Art.18(1) — Non-EU manufacturer must appoint an EU rep
violation contains msg if {
	input.authorised_representative.manufacturer_outside_eu == true
	note := _unmet(_root, ["authorised_representative", "appointed"])
	text := "CRA Art.18(1): Non-EU manufacturer has not appointed an authorised representative established in the Union"
	msg := concat("", [text, note])
}

# Art.18(2) — Mandate must enable the rep to perform the tasks in 18(3)
violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "mandate_enables_required_tasks"])
	text := "CRA Art.18(2): Authorised representative's mandate does not enable performance of all tasks required by Art.18(3)"
	msg := concat("", [text, note])
}

# Art.18(3)(a) — Keep Declaration of Conformity + technical documentation
violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "tasks", "keeps_declaration_of_conformity"])
	text := "CRA Art.18(3)(a): Authorised representative does not retain the Declaration of Conformity"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "tasks", "keeps_technical_documentation"])
	text := "CRA Art.18(3)(a): Authorised representative does not retain a copy of the technical documentation"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "tasks", "retention_10_years"])
	text := "CRA Art.18(3)(a): Authorised representative's retention period for documentation is below the 10-year requirement"
	msg := concat("", [text, note])
}

# Art.18(3)(b) — Provide info/documentation to authorities on reasoned request
violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "tasks", "provide_info_on_request"])
	text := "CRA Art.18(3)(b): Authorised representative does not commit to providing information on reasoned request from authorities"
	msg := concat("", [text, note])
}

# Art.18(3)(c) — Cooperate with authorities on actions to eliminate cyber risks
violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "tasks", "cooperate_on_cyber_risk_action"])
	text := "CRA Art.18(3)(c): Authorised representative does not commit to cooperating with authorities on eliminating cybersecurity risks"
	msg := concat("", [text, note])
}

# Art.18(3)(d) — Terminate mandate if manufacturer acts contrary to CRA
violation contains msg if {
	input.authorised_representative.appointed == true
	input.authorised_representative.manufacturer_breaching_cra == true
	note := _unmet(_root, ["authorised_representative", "tasks", "notified_competent_authority"])
	text := "CRA Art.18(3)(d): Authorised representative aware of manufacturer breach of CRA but has not informed competent authorities"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.authorised_representative.appointed == true
	input.authorised_representative.manufacturer_breaching_cra == true
	note := _unmet(_root, ["authorised_representative", "tasks", "mandate_termination_considered"])
	text := "CRA Art.18(3)(d): Authorised representative aware of manufacturer's persistent breach but has not considered mandate termination"
	msg := concat("", [text, note])
}

# Art.18(4) — Cannot delegate manufacturer's core obligations (essential reqs, conformity assessment)
violation contains msg if {
	input.authorised_representative.appointed == true
	input.authorised_representative.tasks.essential_requirements_delegated == true
	msg := "CRA Art.18(4): Manufacturer's obligation to ensure essential requirements compliance has been delegated to the authorised representative — this delegation is not permitted"
}

violation contains msg if {
	input.authorised_representative.appointed == true
	input.authorised_representative.tasks.conformity_assessment_delegated == true
	msg := "CRA Art.18(4): Manufacturer's obligation to perform conformity assessment has been delegated to the authorised representative — this delegation is not permitted"
}

# Art.18(5) — Contact details of the rep included in user information
violation contains msg if {
	input.authorised_representative.appointed == true
	note := _unmet(_root, ["authorised_representative", "contact_in_user_info"])
	text := "CRA Art.18(5): Authorised representative contact details not included in product user information / accompanying documentation"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.18(3)(d)", ["authorised_representative", "manufacturer_breaching_cra"]] if input.authorised_representative.appointed == true

_conditions contains ["CRA Art.18(4)", ["authorised_representative", "tasks", "essential_requirements_delegated"]] if input.authorised_representative.appointed == true

_conditions contains ["CRA Art.18(4)", ["authorised_representative", "tasks", "conformity_assessment_delegated"]] if input.authorised_representative.appointed == true

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Article 18",
	"name": "Authorised representative obligations",
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
