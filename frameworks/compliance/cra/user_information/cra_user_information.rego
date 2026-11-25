# METADATA
# title: "EU Cyber Resilience Act (CRA) — Annex II"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 20
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cra.user_information

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex II
# Information and instructions to the user.
#
# Manufacturers must include this set of information with every product
# placed on the EU market. Granular check separate from Art.13(10), which
# only verifies the manufacturer provides "instructions" at all.

default compliant := false

# Annex II (1) — Manufacturer name, registered trade name, contact
violation contains msg if {
	note := _unmet(_root, ["user_information", "manufacturer", "name_provided"])
	text := "CRA Annex II.1: Manufacturer's name or registered trade name not included in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "manufacturer", "postal_address_provided"])
	text := "CRA Annex II.1: Manufacturer's postal address not included in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "manufacturer", "electronic_contact_provided"])
	text := "CRA Annex II.1: Manufacturer's electronic address or website not included in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "manufacturer", "contact_for_vulnerability_reports"])
	text := "CRA Annex II.1: Single point of contact for vulnerability reports not provided"
	msg := concat("", [text, note])
}

# Annex II (2) — Single point of contact for cybersecurity-related queries
violation contains msg if {
	note := _unmet(_root, ["user_information", "single_point_of_contact", "published"])
	text := "CRA Annex II.2: Single point of contact for cybersecurity-related queries not published"
	msg := concat("", [text, note])
}

# Annex II (3) — Identifier (type/batch/serial/version) of the product
violation contains msg if {
	note := _unmet(_root, ["user_information", "product_identifier", "type_provided"])
	text := "CRA Annex II.3: Product type identifier not provided in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "product_identifier", "batch_or_serial_provided"])
	text := "CRA Annex II.3: Batch or serial number not provided"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "product_identifier", "version_provided"])
	text := "CRA Annex II.3: Product version (software version, firmware) not provided"
	msg := concat("", [text, note])
}

# Annex II (4) — Intended purpose, including the security environment
violation contains msg if {
	note := _unmet(_root, ["user_information", "intended_purpose", "described"])
	text := "CRA Annex II.4: Intended purpose of the product not described in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "intended_purpose", "security_environment_specified"])
	text := "CRA Annex II.4: Security environment / required operating conditions not specified"
	msg := concat("", [text, note])
}

# Annex II (5) — Cybersecurity properties
violation contains msg if {
	note := _unmet(_root, ["user_information", "cybersecurity_properties", "described"])
	text := "CRA Annex II.5: Cybersecurity properties of the product not described to users"
	msg := concat("", [text, note])
}

# Annex II (6) — Use-case-relevant risks/threats
violation contains msg if {
	note := _unmet(_root, ["user_information", "risks_and_threats", "documented"])
	text := "CRA Annex II.6: Use-case-relevant cybersecurity risks and threats not documented for the user"
	msg := concat("", [text, note])
}

# Annex II (7) — Where to find SBOM
violation contains msg if {
	note := _unmet(_root, ["user_information", "sbom_access", "disclosed_to_user"])
	text := "CRA Annex II.7: User information does not disclose where the SBOM can be obtained"
	msg := concat("", [text, note])
}

# Annex II (8) — Support period and end-of-support date
violation contains msg if {
	note := _unmet(_root, ["user_information", "support_period", "disclosed"])
	text := "CRA Annex II.8: Declared support period not disclosed in user information"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "support_period", "end_of_support_date_disclosed"])
	text := "CRA Annex II.8: End-of-support date not disclosed"
	msg := concat("", [text, note])
}

# Annex II (9) — Where to find security updates
violation contains msg if {
	note := _unmet(_root, ["user_information", "updates", "access_method_disclosed"])
	text := "CRA Annex II.9: Method for the user to access security updates not disclosed"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["user_information", "updates", "installation_instructions"])
	text := "CRA Annex II.9: Instructions for installing security updates not provided"
	msg := concat("", [text, note])
}

# Annex II (10) — Secure decommissioning of the product
violation contains msg if {
	note := _unmet(_root, ["user_information", "decommissioning", "guidance_provided"])
	text := "CRA Annex II.10: Guidance on secure decommissioning (data wipe / device disposal) not provided"
	msg := concat("", [text, note])
}

# Annex II (11) — Languages
violation contains msg if {
	note := _unmet(_root, ["user_information", "languages", "member_state_languages_covered"])
	text := "CRA Annex II.11: User information not provided in the official language(s) of the EU Member States where the product is made available"
	msg := concat("", [text, note])
}

# Annex II (12) — Easily understandable to expected users
violation contains msg if {
	note := _unmet(_root, ["user_information", "readability", "appropriate_for_users"])
	text := "CRA Annex II.12: User information not written in a way easily understandable to its expected users"
	msg := concat("", [text, note])
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Annex II",
	"name": "Information and instructions to the user",
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
