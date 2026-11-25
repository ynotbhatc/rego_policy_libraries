# METADATA
# title: "Csa Ccm Interoperability"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 19
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.interoperability

import rego.v1

default compliant := false

_base := ["csa_ccm", "interoperability"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("IPY-01: Data portability requirements not documented — ability to export and migrate data must be formally assessed", ["data_portability", "requirements_documented"])
}

violations contains msg if {
	msg := _finding("IPY-01: Data export capability not verified — ability to retrieve all data from the cloud provider must be tested", ["data_portability", "export_capability_verified"])
}

violations contains msg if {
	msg := _finding("IPY-01: Data portability provisions not included in cloud provider contracts or service agreements", ["data_portability", "portability_sla_in_contracts"])
}

violations contains msg if {
	msg := _finding("IPY-01: Data formats used by cloud provider not documented — format dependencies must be understood for portability planning", ["data_portability", "data_formats_documented"])
}

violations contains msg if {
	msg := _finding("IPY-02: APIs not documented — all interfaces used for cloud service integration must be formally documented", ["api_standards", "apis_documented"])
}

violations contains msg if {
	msg := _finding("IPY-02: Non-standard or proprietary protocols not assessed for interoperability risk — standard APIs (REST, OpenAPI) must be preferred", ["api_standards", "standard_protocols_used"])
}

violations contains msg if {
	msg := _finding("IPY-02: API versioning not managed — deprecated API versions must have defined sunset timelines", ["api_standards", "api_versioning_managed"])
}

violations contains msg if {
	msg := _finding("IPY-02: Inventory of third-party API dependencies not maintained for interoperability and continuity assessment", ["api_standards", "api_dependency_inventory"])
}

violations contains msg if {
	msg := _finding("IPY-03: Exit and transition plan not established for cloud provider changes or service termination", ["exit_plan", "exit_plan_established"])
}

violations contains msg if {
	msg := _finding("IPY-03: Data migration procedure not defined as part of exit planning — method for moving data must be documented", ["exit_plan", "data_migration_procedure_defined"])
}

violations contains msg if {
	msg := _finding("IPY-03: Business continuity requirements during provider migration not addressed in exit plan", ["exit_plan", "business_continuity_during_migration"])
}

violations contains msg if {
	msg := _finding("IPY-03: Exit plan not reviewed regularly — plan must remain current with evolving architecture and provider landscape", ["exit_plan", "exit_plan_reviewed_regularly"])
}

violations contains msg if {
	msg := _finding("IPY-03: Transition timelines and dependencies not defined in exit plan", ["exit_plan", "transition_timelines_defined"])
}

violations contains msg if {
	msg := _finding("IPY-04: Open data format standards not preferred — proprietary formats must be assessed for lock-in risk", ["data_format_standards", "open_standards_preferred"])
}

violations contains msg if {
	msg := _finding("IPY-04: Vendor lock-in risk not formally assessed for each cloud service used", ["data_format_standards", "vendor_lock_in_assessed"])
}

violations contains msg if {
	msg := _finding("IPY-04: Data format standards not documented for data at rest and in transit with cloud services", ["data_format_standards", "format_standards_documented"])
}

violations contains msg if {
	msg := _finding("IPY-05: Portability not tested at defined intervals — ability to migrate must be periodically validated", ["portability_testing", "portability_tested"])
}

violations contains msg if {
	msg := _finding("IPY-05: Portability test results not documented — outcomes, gaps, and remediation steps must be recorded", ["portability_testing", "test_results_documented"])
}

violations contains msg if {
	msg := _finding("IPY-05: Portability deficiencies identified during testing not tracked to remediation", ["portability_testing", "deficiencies_remediated"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["IPY-01", "IPY-02", "IPY-03", "IPY-04", "IPY-05"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "IPY — Interoperability & Portability",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 19,
	"violation_count": count(violations),
	"violations": violations,
}
