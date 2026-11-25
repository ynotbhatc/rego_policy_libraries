# METADATA
# title: "Csa Ccm Data Security"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 35
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.data_security

import rego.v1

default compliant := false

_base := ["csa_ccm", "data_security"]

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
	msg := _finding("DSP-01: Data security and privacy lifecycle management policy not formally established", ["classification", "policy_established"])
}

violations contains msg if {
	msg := _finding("DSP-01: Data classification scheme not defined — categories and handling requirements must be documented", ["classification", "classification_scheme_defined"])
}

violations contains msg if {
	msg := _finding("DSP-01: Cloud-stored and cloud-processed data not included in data security policy scope", ["classification", "cloud_data_in_scope"])
}

violations contains msg if {
	msg := _finding("DSP-01: Data security policy not reviewed and updated at least annually", ["classification", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("DSP-02: Data labeling not implemented — data must be labeled according to classification scheme", ["labeling", "labeling_implemented"])
}

violations contains msg if {
	msg := _finding("DSP-02: Sensitive and regulated data not consistently labeled across all storage and processing systems", ["labeling", "sensitive_data_labeled"])
}

violations contains msg if {
	msg := _finding("DSP-02: Data labeling not enforced at the time of data creation or ingestion", ["labeling", "labeling_enforced_at_creation"])
}

violations contains msg if {
	msg := _finding("DSP-03: Data retention policy not defined — retention periods must align with legal and regulatory requirements", ["retention", "retention_policy_defined"])
}

violations contains msg if {
	msg := _finding("DSP-03: Data retention schedules not documented per data classification category", ["retention", "retention_schedules_documented"])
}

violations contains msg if {
	msg := _finding("DSP-03: Data retention not enforced through technical controls — automated retention mechanisms must be implemented", ["retention", "retention_enforced_technically"])
}

violations contains msg if {
	msg := _finding("DSP-03: Legal hold process not defined to preserve data beyond normal retention periods when required", ["retention", "legal_hold_process_defined"])
}

violations contains msg if {
	msg := _finding("DSP-04: Data disposal procedures not defined — secure deletion methods must be documented per data type", ["disposal", "disposal_procedures_defined"])
}

violations contains msg if {
	msg := _finding("DSP-04: Secure deletion techniques not used — data must be rendered unrecoverable upon disposal", ["disposal", "secure_deletion_used"])
}

violations contains msg if {
	msg := _finding("DSP-04: Deletion of data from cloud provider systems not verified — confirmation of deletion must be obtained", ["disposal", "cloud_data_deletion_verified"])
}

violations contains msg if {
	msg := _finding("DSP-04: Records of data disposal not maintained for audit and compliance purposes", ["disposal", "disposal_records_maintained"])
}

violations contains msg if {
	msg := _finding("DSP-05: Data loss prevention (DLP) controls not implemented for sensitive data", ["dlp", "dlp_controls_implemented"])
}

violations contains msg if {
	msg := _finding("DSP-05: Data egress monitoring not enabled — unauthorized data exfiltration must be detected", ["dlp", "egress_monitoring_enabled"])
}

violations contains msg if {
	msg := _finding("DSP-05: DLP policies do not cover cloud storage and SaaS applications", ["dlp", "dlp_policies_cover_cloud"])
}

violations contains msg if {
	msg := _finding("DSP-05: DLP alerts not reviewed by security personnel within defined response timeframe", ["dlp", "dlp_alerts_reviewed"])
}

violations contains msg if {
	msg := _finding("DSP-06: Privacy notice not provided to data subjects informing them of data collection and use", ["privacy", "privacy_notice_provided"])
}

violations contains msg if {
	msg := _finding("DSP-06: Consent mechanism not implemented where required by applicable privacy regulations", ["privacy", "consent_mechanism_implemented"])
}

violations contains msg if {
	msg := _finding("DSP-06: Data subject rights (access, erasure, portability, correction) not honored within required timeframes", ["privacy", "data_subject_rights_honored"])
}

violations contains msg if {
	msg := _finding("DSP-06: Privacy impact assessments not conducted for new processing activities involving personal data", ["privacy", "privacy_impact_assessments_conducted"])
}

violations contains msg if {
	msg := _finding("DSP-07: Data flows not mapped — movement of sensitive data across systems and boundaries must be documented", ["data_flows", "data_flows_mapped"])
}

violations contains msg if {
	msg := _finding("DSP-07: Data flow diagrams not maintained and updated when systems or processes change", ["data_flows", "data_flow_diagrams_maintained"])
}

violations contains msg if {
	msg := _finding("DSP-07: Controls not implemented to detect unauthorized data flows or unexpected data movement", ["data_flows", "unauthorized_flows_detected"])
}

violations contains msg if {
	msg := _finding("DSP-08: Cross-border data transfer restrictions not assessed for applicable jurisdictions", ["cross_border", "transfer_restrictions_assessed"])
}

violations contains msg if {
	msg := _finding("DSP-08: Legal mechanisms for cross-border data transfers (SCCs, BCRs, adequacy decisions) not documented", ["cross_border", "transfer_mechanisms_documented"])
}

violations contains msg if {
	msg := _finding("DSP-08: Data residency requirements not enforced in cloud provider configuration", ["cross_border", "cloud_region_data_residency_enforced"])
}

violations contains msg if {
	msg := _finding("DSP-09: Data inventory not maintained — all sensitive and regulated data assets must be catalogued", ["data_inventory", "inventory_maintained"])
}

violations contains msg if {
	msg := _finding("DSP-09: Data owners not assigned for sensitive and regulated data assets", ["data_inventory", "data_owners_assigned"])
}

violations contains msg if {
	msg := _finding("DSP-09: Data inventory not reviewed and updated regularly to reflect changes in data holdings", ["data_inventory", "inventory_reviewed_regularly"])
}

violations contains msg if {
	msg := _finding("DSP-10: Access to sensitive data not restricted based on data classification level", ["access_to_data", "access_based_on_classification"])
}

violations contains msg if {
	msg := _finding("DSP-10: Least-privilege access not enforced for systems and users accessing sensitive data", ["access_to_data", "least_privilege_enforced"])
}

violations contains msg if {
	msg := _finding("DSP-10: Access to sensitive and regulated data not logged for audit and anomaly detection purposes", ["access_to_data", "privileged_data_access_logged"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["DSP-01", "DSP-02", "DSP-03", "DSP-04", "DSP-05", "DSP-06", "DSP-07", "DSP-08", "DSP-09", "DSP-10"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "DSP — Data Security & Privacy Lifecycle Management",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 35,
	"violation_count": count(violations),
	"violations": violations,
}
