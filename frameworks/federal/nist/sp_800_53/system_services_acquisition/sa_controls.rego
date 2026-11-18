# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Services Acquisition (SA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 17
#     cited: 17
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.system_services_acquisition

import rego.v1

# NIST SP 800-53 Rev 5 — System and Services Acquisition (SA) Family: the seventeen active base controls
# (SA-1 to SA-5, SA-8 to SA-11, SA-15 to SA-17, SA-20 to SA-24; SA-6, SA-7, SA-12, SA-13, SA-14, SA-18 and
# SA-19 are withdrawn). Enhancements are not evaluated and a base control never fails on an enhancement's
# requirement. Facts live under input.sa_controls.

default compliant := false

_root := "sa_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null), so an absent key, null, or a value of
# the wrong type ("true", "1") lands in the "missing" set and the control fails closed. Each control builds
# one set of missing paths and one set of unmet requirements and has exactly one rule, so it can produce at
# most one finding.
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# Booleans: reqs maps a fact key to the text reported when that fact is false. Only `true` passes.
_bool_missing(sec, reqs) := {_p(array.concat(sec, [k])) | some k, _ in reqs; not is_boolean(_val(array.concat(sec, [k])))}

_bool_unmet(sec, reqs) := {d | some k, d in reqs; _val(array.concat(sec, [k])) == false}

# Organization-defined frequency: observed <sec>.days_since_last against <sec>.odp.frequency_days.
_freq_keys := [["days_since_last"], ["odp", "frequency_days"]]

_freq_missing(sec) := {_p(array.concat(sec, k)) | some k in _freq_keys; not is_number(_val(array.concat(sec, k)))}

_freq_unmet(sec, what) := {d |
	obs := _val(array.concat(sec, ["days_since_last"]))
	odp := _val(array.concat(sec, ["odp", "frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	d := sprintf("%s last %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Counts that must be zero (e.g. overdue remediations). A non-number is missing evidence.
_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not is_number(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# Attestation for organizational controls: {"attested": true, "by": <non-empty string>, "date": <non-empty string>}.
_att_ok(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_detail(sec, what) := d if {
	not _att_ok(_val(array.concat(sec, ["attestation"])))
	d := sprintf("evidence missing — no valid attestation at %s (needs attested: true and a non-empty by and date); this organizational control is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
}

# Policy and procedures (the -1 control of the family).
_pp_bools := {"documented": "policy not documented", "official_designated": "no official designated to manage the policy and procedures"}

_pp_missing := ((_bool_missing(["policy"], _pp_bools) | _bool_missing(["procedures"], {"documented": ""})) | _freq_missing(["policy"])) | _freq_missing(["procedures"])

_pp_unmet := ((_bool_unmet(["policy"], _pp_bools) | _bool_unmet(["procedures"], {"documented": "procedures not documented"})) | _freq_unmet(["policy"], "policy reviewed")) | _freq_unmet(["procedures"], "procedures reviewed")

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

# ---------------------------------------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------------------------------------

# SA-1 Policy and Procedures: input.sa_controls.policy.{documented, official_designated, days_since_last,
# odp.frequency_days} and input.sa_controls.procedures.{documented, days_since_last, odp.frequency_days}.
violation contains msg if {
	count(_pp_missing) + count(_pp_unmet) > 0
	msg := sprintf("NIST SA-1: system and services acquisition policy and procedures: %s", [_detail(_pp_missing, _pp_unmet)])
}

# SA-2 Allocation of Resources: input.sa_controls.resource_allocation.attestation (organizational: capital
# planning and budgeting).
violation contains msg if {
	d := _att_detail(["resource_allocation"], "security and privacy requirements are determined in mission planning, the resources to protect the system are documented and allocated, and security and privacy have a discrete budget line item")
	msg := sprintf("NIST SA-2: %s", [d])
}

# SA-3 System Development Life Cycle: input.sa_controls.sdlc.{security_privacy_incorporated,
# roles_documented, role_holders_identified, risk_management_integrated}.
_sa3 := {
	"security_privacy_incorporated": "the system is not acquired, developed and managed under a life cycle that incorporates security and privacy",
	"roles_documented": "security and privacy roles and responsibilities across the life cycle are not defined and documented",
	"role_holders_identified": "the individuals holding security and privacy roles are not identified",
	"risk_management_integrated": "the security and privacy risk management process is not integrated into life cycle activities",
}

violation contains msg if {
	m := _bool_missing(["sdlc"], _sa3)
	u := _bool_unmet(["sdlc"], _sa3)
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-3: %s", [_detail(m, u)])
}

# SA-4 Acquisition Process: input.sa_controls.acquisition.{contract_language_defined,
# contracts_missing_requirements}. contracts_missing_requirements counts acquisition contracts that do not
# include, explicitly or by reference, the required security and privacy requirements, descriptions and
# acceptance criteria.
violation contains msg if {
	sec := ["acquisition"]
	b := {"contract_language_defined": "no organization-defined contract language for security and privacy requirements"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "contracts_missing_requirements")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "contracts_missing_requirements", "acquisition contracts lack the required security and privacy requirements, descriptions or acceptance criteria")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-4: %s", [_detail(m, u)])
}

# SA-5 System Documentation: input.sa_controls.documentation.{administrator_documentation,
# user_documentation, unavailable_documentation_handled, distributed}.
_sa5 := {
	"administrator_documentation": "administrator documentation (secure configuration, installation, operation, security functions, known privileged-function vulnerabilities) not obtained or developed",
	"user_documentation": "user documentation (security and privacy functions, secure interaction, user responsibilities) not obtained or developed",
	"unavailable_documentation_handled": "attempts to obtain unavailable documentation are not documented and acted on",
	"distributed": "documentation is not distributed to the organization-defined personnel or roles",
}

violation contains msg if {
	m := _bool_missing(["documentation"], _sa5)
	u := _bool_unmet(["documentation"], _sa5)
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-5: %s", [_detail(m, u)])
}

# SA-8 Security and Privacy Engineering Principles: input.sa_controls.engineering_principles.attestation
# (organizational).
violation contains msg if {
	d := _att_detail(["engineering_principles"], "the organization-defined security and privacy engineering principles are applied in the specification, design, development, implementation and modification of the system")
	msg := sprintf("NIST SA-8: %s", [d])
}

# SA-9 External System Services: input.sa_controls.external_services.{oversight_roles_documented,
# compliance_monitored, noncompliant_providers}. noncompliant_providers counts external service providers not
# bound to the organizational security and privacy requirements and the organization-defined controls.
violation contains msg if {
	sec := ["external_services"]
	b := {
		"oversight_roles_documented": "organizational oversight and user roles for external system services are not defined and documented",
		"compliance_monitored": "provider control compliance is not monitored on an ongoing basis",
	}
	m := _bool_missing(sec, b) | _zero_missing(sec, "noncompliant_providers")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "noncompliant_providers", "external service providers are not required to comply with organizational security and privacy requirements")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-9: %s", [_detail(m, u)])
}

# SA-10 Developer Configuration Management: input.sa_controls.developer_cm.{performed, change_integrity_controlled,
# only_approved_changes, changes_documented_with_impact, flaws_tracked_and_reported}.
_sa10 := {
	"performed": "the developer does not perform configuration management",
	"change_integrity_controlled": "the developer does not document, manage and control the integrity of changes to configuration items",
	"only_approved_changes": "the developer implements changes that are not organization-approved",
	"changes_documented_with_impact": "approved changes and their security and privacy impacts are not documented",
	"flaws_tracked_and_reported": "security flaws and their resolution are not tracked and reported",
}

violation contains msg if {
	m := _bool_missing(["developer_cm"], _sa10)
	u := _bool_unmet(["developer_cm"], _sa10)
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-10: %s", [_detail(m, u)])
}

# SA-11 Developer Testing and Evaluation: input.sa_controls.developer_testing.{assessment_plan_implemented,
# evidence_produced, flaw_remediation_process, flaws_corrected, days_since_last, odp.frequency_days}.
_sa11 := {
	"assessment_plan_implemented": "no developer plan for ongoing security and privacy control assessments is implemented",
	"evidence_produced": "no evidence of the assessment plan's execution and the test results is produced",
	"flaw_remediation_process": "no verifiable flaw remediation process",
	"flaws_corrected": "flaws identified in testing and evaluation are not corrected",
}

violation contains msg if {
	sec := ["developer_testing"]
	m := _bool_missing(sec, _sa11) | _freq_missing(sec)
	u := _bool_unmet(sec, _sa11) | _freq_unmet(sec, "developer testing and evaluation performed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-11: %s", [_detail(m, u)])
}

# SA-15 Development Process, Standards, and Tools: input.sa_controls.development_process.{documented,
# addresses_security_privacy, standards_tools_identified, tool_configurations_documented,
# process_changes_controlled} and input.sa_controls.development_process.review.{days_since_last,
# odp.frequency_days}.
_sa15 := {
	"documented": "the developer does not follow a documented development process",
	"addresses_security_privacy": "the development process does not explicitly address security and privacy requirements",
	"standards_tools_identified": "the standards and tools used in development are not identified",
	"tool_configurations_documented": "the tool options and configurations used in development are not documented",
	"process_changes_controlled": "changes to the development process and tools are not documented, managed and integrity-protected",
}

violation contains msg if {
	sec := ["development_process"]
	m := _bool_missing(sec, _sa15) | _freq_missing(["development_process", "review"])
	u := _bool_unmet(sec, _sa15) | _freq_unmet(["development_process", "review"], "development process, standards and tools reviewed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-15: %s", [_detail(m, u)])
}

# SA-16 Developer-provided Training: input.sa_controls.developer_training.attestation (organizational).
violation contains msg if {
	d := _att_detail(["developer_training"], "the developer provides the organization-defined training on the correct use and operation of the implemented security and privacy functions, controls and mechanisms")
	msg := sprintf("NIST SA-16: %s", [d])
}

# SA-17 Developer Security and Privacy Architecture and Design: input.sa_controls.developer_architecture.attestation
# (organizational).
violation contains msg if {
	d := _att_detail(["developer_architecture"], "the developer produces a design specification and security and privacy architecture consistent with the enterprise architecture that describes the required functionality, control allocation and how the functions work together")
	msg := sprintf("NIST SA-17: %s", [d])
}

# SA-20 Customized Development of Critical Components: input.sa_controls.custom_critical_components.attestation
# (organizational).
violation contains msg if {
	d := _att_detail(["custom_critical_components"], "the organization-defined critical system components are reimplemented or custom developed")
	msg := sprintf("NIST SA-20: %s", [d])
}

# SA-21 Developer Screening: input.sa_controls.developer_screening.{criteria_defined, unscreened_developers}.
# unscreened_developers counts developers of the organization-defined systems, components or services who lack the
# required access authorizations or fail the additional screening criteria.
violation contains msg if {
	sec := ["developer_screening"]
	b := {"criteria_defined": "the required access authorizations and additional screening criteria for developers are not defined"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "unscreened_developers")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "unscreened_developers", "developers lack the required access authorizations or screening")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-21: %s", [_detail(m, u)])
}

# SA-22 Unsupported System Components: input.sa_controls.unsupported_components.without_alternative_support,
# the number of components no longer supported by the developer, vendor or manufacturer that are neither replaced
# nor covered by an organization-approved alternative source of support.
violation contains msg if {
	sec := ["unsupported_components"]
	m := _zero_missing(sec, "without_alternative_support")
	u := _zero_unmet(sec, "without_alternative_support", "unsupported system components are neither replaced nor covered by alternative support")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-22: %s", [_detail(m, u)])
}

# SA-23 Specialization: input.sa_controls.specialization.attestation (organizational).
violation contains msg if {
	d := _att_detail(["specialization"], "the organization-defined specialization is employed on the systems or components supporting mission essential services or functions")
	msg := sprintf("NIST SA-23: %s", [d])
}

# SA-24 Design for Cyber Resiliency: input.sa_controls.cyber_resiliency.attestation (organizational).
violation contains msg if {
	d := _att_detail(["cyber_resiliency"], "cyber resiliency goals, objectives, techniques, implementation approaches and design principles are defined and implemented in the risk management or systems security engineering process")
	msg := sprintf("NIST SA-24: %s", [d])
}

compliant if count(violation) == 0

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-8", "SA-9", "SA-10", "SA-11",
	"SA-15", "SA-16", "SA-17", "SA-20", "SA-21", "SA-22", "SA-23", "SA-24",
}

compliance_report := {
	"family": "SA",
	"name": "System and Services Acquisition",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
