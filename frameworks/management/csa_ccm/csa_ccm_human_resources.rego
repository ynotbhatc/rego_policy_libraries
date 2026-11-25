# METADATA
# title: "Csa Ccm Human Resources"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 36
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.human_resources

import rego.v1

default compliant := false

_base := ["csa_ccm", "human_resources"]

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
	msg := _finding("HRS-01: Background check policy for personnel with access to sensitive systems not established", ["background_checks", "policy_established"])
}

violations contains msg if {
	msg := _finding("HRS-01: Background checks not conducted before granting access to sensitive cloud environments", ["background_checks", "checks_conducted_pre_hire"])
}

violations contains msg if {
	msg := _finding("HRS-01: Background check depth not commensurate with the sensitivity of access being granted", ["background_checks", "checks_commensurate_with_access"])
}

violations contains msg if {
	msg := _finding("HRS-01: Background check requirements not applied to contractors and third-party personnel with system access", ["background_checks", "contractors_included"])
}

violations contains msg if {
	msg := _finding("HRS-02: Security awareness training program not established for all personnel", ["security_awareness", "training_program_established"])
}

violations contains msg if {
	msg := _finding("HRS-02: Security awareness training not completed by new employees before granting system access", ["security_awareness", "training_conducted_at_hire"])
}

violations contains msg if {
	msg := _finding("HRS-02: Annual security awareness training not required for all personnel", ["security_awareness", "annual_training_required"])
}

violations contains msg if {
	msg := _finding("HRS-02: Cloud security topics not included in security awareness training curriculum", ["security_awareness", "cloud_security_topics_included"])
}

violations contains msg if {
	msg := _finding("HRS-02: Training completion not tracked to ensure all personnel have completed required training", ["security_awareness", "completion_tracked"])
}

violations contains msg if {
	msg := _finding("HRS-03: Acceptable use policy for information systems and cloud resources not established", ["acceptable_use", "policy_established"])
}

violations contains msg if {
	msg := _finding("HRS-03: Employees have not formally acknowledged and signed the acceptable use policy", ["acceptable_use", "employees_acknowledged"])
}

violations contains msg if {
	msg := _finding("HRS-03: Acceptable use policy not reviewed and updated at least annually", ["acceptable_use", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("HRS-03: Disciplinary process for acceptable use policy violations not defined and communicated", ["acceptable_use", "violations_enforced"])
}

violations contains msg if {
	msg := _finding("HRS-04: Non-disclosure agreements not required for personnel with access to sensitive or proprietary information", ["nda", "nda_required"])
}

violations contains msg if {
	msg := _finding("HRS-04: NDAs not signed before granting access to sensitive information or cloud environments", ["nda", "nda_signed_before_access"])
}

violations contains msg if {
	msg := _finding("HRS-04: NDAs do not explicitly cover cloud-hosted data and third-party cloud environments", ["nda", "nda_covers_cloud_data"])
}

violations contains msg if {
	msg := _finding("HRS-04: NDA signing records not maintained for audit and legal purposes", ["nda", "nda_records_maintained"])
}

violations contains msg if {
	msg := _finding("HRS-05: Employee and contractor termination procedure not formally defined", ["termination", "termination_procedure_defined"])
}

violations contains msg if {
	msg := _finding("HRS-05: System and cloud access not revoked within defined timeframe upon termination", ["termination", "access_revoked_timely"])
}

violations contains msg if {
	msg := _finding("HRS-05: Privileged access not revoked immediately upon termination — elevated access must be removed without delay", ["termination", "privileged_access_revoked_immediately"])
}

violations contains msg if {
	msg := _finding("HRS-05: Return of company-issued assets and credentials not verified upon termination", ["termination", "asset_return_verified"])
}

violations contains msg if {
	msg := _finding("HRS-05: Exit process not documented with checklist of security-relevant steps to complete upon separation", ["termination", "exit_process_documented"])
}

violations contains msg if {
	msg := _finding("HRS-06: Access privileges not tied to job roles — access must be granted based on defined roles and responsibilities", ["role_based_access_removal", "access_tied_to_role"])
}

violations contains msg if {
	msg := _finding("HRS-06: Access not updated when personnel change roles — access must reflect current job responsibilities", ["role_based_access_removal", "access_updated_on_role_change"])
}

violations contains msg if {
	msg := _finding("HRS-06: Periodic access reviews not conducted to verify access remains appropriate for current roles", ["role_based_access_removal", "periodic_access_reviews_conducted"])
}

violations contains msg if {
	msg := _finding("HRS-06: Orphaned accounts (accounts without active owners) not identified and removed", ["role_based_access_removal", "orphaned_accounts_removed"])
}

violations contains msg if {
	msg := _finding("HRS-07: Insider threat program not established — behavioral monitoring and detection controls must be implemented", ["insider_threat", "program_exists"])
}

violations contains msg if {
	msg := _finding("HRS-07: User behavior monitoring not implemented to detect potential insider threat indicators", ["insider_threat", "monitoring_implemented"])
}

violations contains msg if {
	msg := _finding("HRS-07: Mechanism for reporting suspected insider threat activity not established and communicated to personnel", ["insider_threat", "reporting_mechanism_exists"])
}

violations contains msg if {
	msg := _finding("HRS-07: Enhanced monitoring controls not applied to personnel with high-privilege access or elevated risk", ["insider_threat", "high_risk_personnel_controls"])
}

violations contains msg if {
	msg := _finding("HRS-08: Specialized security training not provided to personnel in security-relevant roles (admins, developers, security team)", ["security_roles", "specialized_training_provided"])
}

violations contains msg if {
	msg := _finding("HRS-08: Security certifications not encouraged or required for personnel in cloud security roles", ["security_roles", "certifications_encouraged"])
}

violations contains msg if {
	msg := _finding("HRS-08: Security responsibilities not formally documented in job descriptions for roles with security functions", ["security_roles", "security_responsibilities_documented"])
}

violations contains msg if {
	msg := _finding("HRS-09: Security requirements not formally communicated to third-party personnel before granting access", ["third_party_personnel", "security_requirements_communicated"])
}

violations contains msg if {
	msg := _finding("HRS-09: Third-party personnel access not limited to only what is required for contracted services", ["third_party_personnel", "access_limited_to_required"])
}

violations contains msg if {
	msg := _finding("HRS-09: Third-party personnel access not reviewed regularly to confirm continued business need", ["third_party_personnel", "access_reviewed_regularly"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["HRS-01", "HRS-02", "HRS-03", "HRS-04", "HRS-05", "HRS-06", "HRS-07", "HRS-08", "HRS-09"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "HRS — Human Resources",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 36,
	"violation_count": count(violations),
	"violations": violations,
}
