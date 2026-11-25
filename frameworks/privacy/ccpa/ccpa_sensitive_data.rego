# METADATA
# title: "Ccpa Sensitive Data"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 15
#     cited: 2
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ccpa.sensitive_data

import rego.v1

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "government_ids", "access_limited_and_encrypted"])
	text := "CPRA §1798.140(ae): SSN and government ID data not access-limited and not encrypted"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "account_credentials", "not_stored_in_plaintext"])
	text := "CPRA §1798.140(ae): Account credentials stored in plaintext"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "precise_geolocation", "explicit_purpose_limitation"])
	text := "CPRA §1798.140(ae): Precise geolocation data (within 1,852m) collected without explicit purpose limitation"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "racial_ethnic_origin", "dpias_conducted"])
	text := "CPRA §1798.140(ae): Data Protection Impact Assessments not conducted for processing racial or ethnic origin data"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "religious_beliefs", "collection_minimized"])
	text := "CPRA §1798.140(ae): Collection of religious or philosophical beliefs data not minimized"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "union_membership", "collection_minimized"])
	text := "CPRA §1798.140(ae): Collection of union membership data not minimized"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "mail_email_text", "not_accessed_except_for_delivery"])
	text := "CPRA §1798.140(ae): Mail, email, or text message content accessed for purposes other than delivery"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "genetic_data", "access_controls_implemented"])
	text := "CPRA §1798.140(ae): Access controls for genetic data not implemented"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "genetic_data", "not_sold"])
	text := "CPRA §1798.140(ae): Genetic data sold or shared without restriction"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "biometric_data", "consent_obtained"])
	text := "CPRA §1798.140(ae): Consent not obtained for collection of biometric data"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "biometric_data", "retention_limited"])
	text := "CPRA §1798.140(ae): Retention of biometric data not limited to stated purpose"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "health_information", "hipaa_aligned_controls"])
	text := "CPRA §1798.140(ae): HIPAA-aligned controls not applied to health information where applicable"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "sex_life_orientation", "not_collected_unless_necessary"])
	text := "CPRA §1798.140(ae): Sex life or sexual orientation data collected without demonstrated necessity"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "automated_decisions", "opt_out_available"])
	text := "CPRA §1798.185(a)(21): Consumers cannot opt out of automated decisions affecting them significantly"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "sensitive_data", "automated_decisions", "logic_explanation_available"])
	text := "CPRA §1798.185(a)(21): Explanation of automated decision-making logic not available upon request"
	msg := concat("", [text, note])
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Sensitive Personal Information (§1798.140(ae), §1798.185(a)(21))",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
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
