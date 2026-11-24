# METADATA
# title: "Csa Ccm Supply Chain"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 32
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.supply_chain

import rego.v1

default compliant := false

_base := ["csa_ccm", "supply_chain"]

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
	msg := _finding("STA-01: Supply chain security and third-party risk management policy not formally established", ["supplier_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("STA-01: Cloud service providers and SaaS vendors not included in supply chain security policy scope", ["supplier_policy", "cloud_suppliers_in_scope"])
}

violations contains msg if {
	msg := _finding("STA-01: Supply chain security policy not reviewed and updated at least annually", ["supplier_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("STA-02: Supplier security assessments not conducted before onboarding new cloud or technology vendors", ["supplier_assessments", "assessments_conducted"])
}

violations contains msg if {
	msg := _finding("STA-02: Risk tiering not applied to suppliers — assessment depth must be commensurate with the risk level of access granted", ["supplier_assessments", "risk_tiering_applied"])
}

violations contains msg if {
	msg := _finding("STA-02: Supplier security reassessments not conducted periodically — third-party risk must be reviewed regularly", ["supplier_assessments", "reassessments_conducted_periodically"])
}

violations contains msg if {
	msg := _finding("STA-02: Standardized security questionnaires (CAIQ, SIG) or audits not used for supplier assessments", ["supplier_assessments", "questionnaires_or_audits_used"])
}

violations contains msg if {
	msg := _finding("STA-02: Supplier security certifications (ISO 27001, SOC 2, FedRAMP) not reviewed as part of assessment", ["supplier_assessments", "certifications_reviewed"])
}

violations contains msg if {
	msg := _finding("STA-03: Third-party risk management program not established — structured approach to managing vendor risk required", ["third_party_risk", "risk_management_program_exists"])
}

violations contains msg if {
	msg := _finding("STA-03: Third-party and vendor risks not included in enterprise risk register", ["third_party_risk", "risk_register_includes_vendors"])
}

violations contains msg if {
	msg := _finding("STA-03: Critical vendors and dependencies not identified — concentration risk and single-vendor dependency must be assessed", ["third_party_risk", "critical_vendors_identified"])
}

violations contains msg if {
	msg := _finding("STA-03: Ongoing vendor risk monitoring not implemented — continuous monitoring for changes in vendor risk posture required", ["third_party_risk", "vendor_risk_monitoring_ongoing"])
}

violations contains msg if {
	msg := _finding("STA-04: Subprocessor inventory not maintained — all third parties that process data on behalf of the organization must be catalogued", ["subprocessor_inventory", "inventory_maintained"])
}

violations contains msg if {
	msg := _finding("STA-04: Data sharing with subprocessors not documented — what data is shared, why, and under what terms must be recorded", ["subprocessor_inventory", "data_sharing_documented"])
}

violations contains msg if {
	msg := _finding("STA-04: Process not defined for managing changes to the subprocessor inventory — customers must be notified where required", ["subprocessor_inventory", "subprocessor_changes_managed"])
}

violations contains msg if {
	msg := _finding("STA-04: Subprocessors not assessed for security controls — downstream data processors must meet equivalent security standards", ["subprocessor_inventory", "subprocessors_assessed"])
}

violations contains msg if {
	msg := _finding("STA-05: Security requirements not included in supplier and cloud provider contracts", ["contract_requirements", "security_requirements_in_contracts"])
}

violations contains msg if {
	msg := _finding("STA-05: Right to audit or audit report provision not included in supplier contracts", ["contract_requirements", "right_to_audit_included"])
}

violations contains msg if {
	msg := _finding("STA-05: Incident notification SLA not included in supplier contracts — vendors must notify of breaches within required timeframe", ["contract_requirements", "incident_notification_sla_included"])
}

violations contains msg if {
	msg := _finding("STA-05: Data handling, protection, and deletion requirements not specified in supplier contracts", ["contract_requirements", "data_handling_requirements_specified"])
}

violations contains msg if {
	msg := _finding("STA-05: Contract termination provisions not included — data return and deletion upon contract end must be addressed", ["contract_requirements", "termination_provisions_included"])
}

violations contains msg if {
	msg := _finding("STA-06: Cloud service provider transparency reports not reviewed — government access requests and security disclosures must be assessed", ["transparency", "csp_transparency_report_reviewed"])
}

violations contains msg if {
	msg := _finding("STA-06: Cloud shared responsibility model not formally documented and understood for each cloud service used", ["transparency", "csp_shared_responsibility_understood"])
}

violations contains msg if {
	msg := _finding("STA-06: CSP security posture reports (SOC 2, ISO 27001 certificates) not reviewed at least annually", ["transparency", "csp_security_posture_reviewed"])
}

violations contains msg if {
	msg := _finding("STA-07: Software bill of materials (SBOM) not maintained — software components and their origins must be tracked", ["software_supply_chain", "sbom_maintained"])
}

violations contains msg if {
	msg := _finding("STA-07: Build pipeline integrity not verified — CI/CD pipelines must be secured against supply chain compromise", ["software_supply_chain", "build_pipeline_integrity"])
}

violations contains msg if {
	msg := _finding("STA-07: Third-party code and libraries not reviewed for security risks before use in production", ["software_supply_chain", "third_party_code_reviewed"])
}

violations contains msg if {
	msg := _finding("STA-08: Vendor offboarding procedure not defined — structured process for terminating supplier relationships required", ["offboarding", "vendor_offboarding_procedure_defined"])
}

violations contains msg if {
	msg := _finding("STA-08: Data retrieval or deletion from outgoing vendors not verified — all organizational data must be accounted for at contract end", ["offboarding", "data_retrieved_or_deleted_on_exit"])
}

violations contains msg if {
	msg := _finding("STA-08: Supplier access revoked promptly upon contract termination — all credentials and access paths must be removed", ["offboarding", "access_revoked_on_termination"])
}

violations contains msg if {
	msg := _finding("STA-09: Vendor incident response coordination not defined — process for coordinating response with suppliers during shared incidents required", ["incident_response", "vendor_ir_coordination_defined"])
}

violations contains msg if {
	msg := _finding("STA-09: Vendor security incident notification requirements not enforced through contracts and monitoring", ["incident_response", "vendor_notification_requirements_enforced"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["STA-01", "STA-02", "STA-03", "STA-04", "STA-05", "STA-06", "STA-07", "STA-08", "STA-09"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "STA — Supply Chain Management, Transparency & Accountability",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 32,
	"violation_count": count(violations),
	"violations": violations,
}
