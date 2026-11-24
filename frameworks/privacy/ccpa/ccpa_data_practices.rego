# METADATA
# title: "Ccpa Data Practices"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 14
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ccpa.data_practices

import rego.v1

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_minimization", "collected_only_for_disclosed_purposes"])
	text := "CPRA §1798.100(a)(3): Personal information collected for purposes not disclosed to consumer"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_minimization", "collection_limited_to_necessary"])
	text := "CPRA §1798.100(a)(3): Personal information collection not limited to what is reasonably necessary"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_minimization", "not_used_incompatibly"])
	text := "CPRA §1798.100(a)(3): Personal information used in manner incompatible with disclosed purpose"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "purpose_limitation", "not_used_beyond_disclosed_purposes"])
	text := "CPRA §1798.100(a)(3): Personal information used for purposes materially different from those disclosed"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "purpose_limitation", "not_sold_beyond_disclosed_categories"])
	text := "CPRA §1798.100(a)(3): Personal information sold or shared beyond disclosed categories"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "retention_limitation", "schedule_established_and_documented"])
	text := "CPRA §1798.100(a)(3): Retention schedule for personal information not established or not documented"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "retention_limitation", "not_retained_longer_than_necessary"])
	text := "CPRA §1798.100(a)(3): Personal information retained longer than necessary for disclosed purpose"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "retention_limitation", "automated_deletion_enforced"])
	text := "CPRA §1798.100(a)(3): Retention schedule not technically enforced with automated deletion"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "security", "reasonable_security_implemented"])
	text := "CCPA §1798.150: Reasonable security measures not implemented for personal information"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "security", "breach_notification_within_72_hours"])
	text := "CCPA §1798.150: Security incidents not reported to CPPA within 72 hours"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "security", "consumer_notification_without_unreasonable_delay"])
	text := "CCPA §1798.150: Consumer notification after breach delayed unreasonably"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_protection_assessments", "conducted_for_high_risk"])
	text := "CPRA §1798.185(a)(15): Data Protection Assessments not conducted for high-risk processing (profiling, sensitive PI, sharing)"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_protection_assessments", "submitted_to_cppa_on_request"])
	text := "CPRA §1798.185(a)(15): Data Protection Assessments not available for submission to CPPA upon request"
	msg := concat("", [text, note])
}

violations contains msg if {
	note := _unmet(_root, ["ccpa", "data_practices", "data_protection_assessments", "reviewed_annually"])
	text := "CPRA §1798.185(a)(15): Data Protection Assessments not reviewed annually"
	msg := concat("", [text, note])
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Data Practices (§1798.100, §1798.150, §1798.185)",
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
