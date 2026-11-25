# METADATA
# title: "Ccpa Consumer Rights"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 21
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ccpa.consumer_rights

import rego.v1

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_know", "categories_disclosed"])
	text := "CCPA §1798.110: Categories of personal information collected, purposes, and third parties not disclosed"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_know", "specific_pieces_provided"])
	text := "CCPA §1798.115: Specific pieces of personal information not provided to consumer upon request"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_know", "response_within_45_days"])
	text := "CCPA §1798.100: Response to right-to-know request not fulfilled within 45 days"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_know", "two_requests_per_year_honored"])
	text := "CCPA §1798.100: Two disclosure requests per 12-month period not honored"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_know", "identity_verification_established"])
	text := "CCPA §1798.100: Identity verification process for right-to-know requests not established"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_delete", "deletion_process_established"])
	text := "CCPA §1798.105: Deletion process for personal information not established"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_delete", "deletion_propagated"])
	text := "CCPA §1798.105: Deletion not propagated to service providers and contractors"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_delete", "exceptions_documented"])
	text := "CCPA §1798.105: Exceptions to deletion (legal obligation, security) not documented"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_delete", "confirmation_provided"])
	text := "CCPA §1798.105: Confirmation of deletion not provided to consumer"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_opt_out", "do_not_sell_link_on_homepage"])
	text := "CCPA §1798.135: 'Do Not Sell or Share My Personal Information' link not present on homepage"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_opt_out", "honored_within_15_business_days"])
	text := "CCPA §1798.120: Opt-out of sale or sharing not honored within 15 business days"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_opt_out", "no_reenrollment_within_12_months"])
	text := "CCPA §1798.120: Opted-out consumers re-enrolled for sale or sharing within 12 months without consent"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_opt_out", "gpc_signal_honored"])
	text := "CCPA §1798.135: Global Privacy Control (GPC) signal not honored"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_correct", "correction_process_defined"])
	text := "CPRA §1798.106: Process for consumers to correct inaccurate personal information not defined"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_correct", "correction_propagated"])
	text := "CPRA §1798.106: Correction not propagated to third parties"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_correct", "response_within_45_days"])
	text := "CPRA §1798.106: Response to right-to-correct request not fulfilled within 45 days"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_limit_sensitive", "limit_sensitive_pi_link_available"])
	text := "CPRA §1798.121: 'Limit the Use of My Sensitive Personal Information' link not available"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_limit_sensitive", "use_limited_when_requested"])
	text := "CPRA §1798.121: Sensitive personal information use not limited to specified purposes when consumer requests"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "right_to_limit_sensitive", "honored_within_15_business_days"])
	text := "CPRA §1798.121: Request to limit sensitive personal information use not honored within 15 business days"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "non_discrimination", "no_penalty_for_rights_exercise"])
	text := "CCPA §1798.125: Consumers penalized for exercising privacy rights"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "consumer_rights", "non_discrimination", "no_different_pricing_for_opt_out"])
	text := "CCPA §1798.125: Consumers denied goods, services, or charged different prices for opting out"
	msg := concat("", [text, note])
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Consumer Rights (§1798.100–§1798.125)",
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
