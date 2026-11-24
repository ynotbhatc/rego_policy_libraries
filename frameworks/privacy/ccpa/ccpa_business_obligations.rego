# METADATA
# title: "Ccpa Business Obligations"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 19
#     cited: 6
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package ccpa.business_obligations

import rego.v1

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "published_and_updated_annually"])
	text := "CCPA §1798.130: Comprehensive privacy policy not published or not updated annually"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "lists_categories_collected"])
	text := "CCPA §1798.130: Privacy policy does not list categories of personal information collected in prior 12 months"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "lists_collection_purposes"])
	text := "CCPA §1798.130: Privacy policy does not list purposes for which personal information is collected"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "lists_third_party_categories"])
	text := "CCPA §1798.130: Privacy policy does not list categories of third parties personal information is shared with"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "contact_information_included"])
	text := "CCPA §1798.130: Privacy policy does not include contact information for privacy requests"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "privacy_policy", "ccpa_rights_disclosure_included"])
	text := "CCPA §1798.130: Privacy policy does not include disclosure of CCPA consumer rights"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "notice_at_collection", "provided_at_or_before_collection"])
	text := "CCPA §1798.100(b): Notice not provided at or before point of personal information collection"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "notice_at_collection", "categories_and_purposes_disclosed"])
	text := "CCPA §1798.100(b): Categories of personal information and purposes not disclosed in notice at collection"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "notice_at_collection", "sale_sharing_disclosed_with_opt_out"])
	text := "CCPA §1798.100(b): Sale or sharing of personal information not disclosed with opt-out link where applicable"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "notice_at_collection", "retention_periods_disclosed"])
	text := "CCPA §1798.100(b): Retention periods or criteria for determination not disclosed in notice at collection"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "training", "personnel_trained"])
	text := "CCPA §1798.135(b): Personnel handling privacy requests not trained on CCPA requirements"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "training", "training_documented_and_refreshed"])
	text := "CCPA §1798.135(b): Privacy training not documented or not refreshed annually"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "record_keeping", "requests_retained_24_months"])
	text := "CPRA §1798.185(a)(3): Records of privacy requests and responses not retained for 24 months"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "record_keeping", "annual_metrics_reported"])
	text := "CPRA §1798.185(a)(3): Annual metrics on rights requests not reported (required for large businesses)"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "service_provider_contracts", "written_contracts_limiting_use"])
	text := "CCPA §1798.140: Written contracts with service providers not in place limiting use of personal information"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "service_provider_contracts", "prohibition_on_selling"])
	text := "CCPA §1798.140: Service provider contracts do not prohibit selling of personal information"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "business_obligations", "service_provider_contracts", "subprocessor_restrictions"])
	text := "CCPA §1798.140: Subprocessor restrictions not included in service provider contracts"
	msg := concat("", [text, note])
}

violations contains msg if {
	input.ccpa.business_obligations.data_broker.applicable == true
	note := _unmet(_root, ["ccpa", "business_obligations", "data_broker", "registered_with_cppa"])
	text := "CPRA §1798.99.80: Business qualifies as data broker but is not registered with the California Privacy Protection Agency"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CPRA §1798.99.80", ["ccpa", "business_obligations", "data_broker", "applicable"]]

violations contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Business Obligations (§1798.130–§1798.185)",
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
