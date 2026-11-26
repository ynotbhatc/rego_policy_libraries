# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Services Acquisition (SA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 30
#     cited: 30
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
# SA-19 are withdrawn), the Moderate-baseline enhancements SA-4(1), SA-4(2), SA-4(9), SA-4(10), SA-9(2) and
# SA-15(3), and the High-baseline enhancements SA-4(5), SA-9(1), SA-9(5), SA-11(1) and SA-11(2), and the
# Privacy-baseline enhancement SA-8(33), SA-15(13), the enhancement Release 5.2.0 added (in no baseline), and SA-10(1)
# (TX-RAMP Level 2 selects it; in no NIST or FedRAMP baseline).
# Each enhancement
# is its own requirement with its own finding; a base control never fails on an enhancement's requirement. Facts live under input.sa_controls.

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

# Counts that must be zero (e.g. overdue remediations). A value that is not a non-negative whole number is missing evidence.
# A count: a non-negative whole number. Anything else (absent, null, "1", a negative or a fractional number) is
# evidence missing.
_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not _count_ok(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	_count_ok(n)
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
	d := sprintf("evidence missing — no valid attestation at %s (needs attested: true and a non-empty by and date); not attested: this organizational control is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
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

# SA-10(1) Software and Firmware Integrity Verification (NIST SP 800-53 Rev 5, OSCAL catalog release 5.2.0, public domain):
# "Require the developer of the system, system component, or system service to enable integrity verification of
# software and firmware components." No organization-defined parameter. Facts
# input.sa_controls.developer_cm.integrity_verification.{required, enabled, components_unverified}: required is true
# when the developer is required (contract, statement of work or internal standard) to enable it, enabled when it is
# enabled for the software and firmware components, components_unverified counts the components without it.
_sa10_1 := {
	"required": "the developer is not required to enable integrity verification of software and firmware components",
	"enabled": "integrity verification of software and firmware components is not enabled",
}

violation contains msg if {
	sec := ["developer_cm", "integrity_verification"]
	m := _bool_missing(sec, _sa10_1) | _zero_missing(sec, "components_unverified")
	u := _bool_unmet(sec, _sa10_1) | _zero_unmet(sec, "components_unverified", "software or firmware components without integrity verification")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-10(1): %s", [_detail(m, u)])
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

# ---------------------------------------------------------------------------------------------------------
# Moderate-baseline enhancements (SP 800-53B). Facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# A contract-clause enhancement: <sec>.contracts_missing_requirement counts the acquisition contracts for the
# system, components or services that do not require the developer to deliver the stated item.
_contract_detail(sec, what) := _detail(_zero_missing(sec, "contracts_missing_requirement"), _zero_unmet(sec, "contracts_missing_requirement", what))

# SA-4(1) Functional Properties of Controls: input.sa_controls.acquisition.functional_properties.
# contracts_missing_requirement.
violation contains msg if {
	d := _contract_detail(["acquisition", "functional_properties"], "acquisition contracts do not require the developer to describe the functional properties of the controls to be implemented")
	d != ""
	msg := sprintf("NIST SA-4(1): %s", [d])
}

# SA-4(2) Design and Implementation Information for Controls: input.sa_controls.acquisition.design_information.
# contracts_missing_requirement (contracts that do not require the organization-defined design and
# implementation information at the organization-defined level of detail).
violation contains msg if {
	d := _contract_detail(["acquisition", "design_information"], "acquisition contracts do not require the developer to provide the organization-defined design and implementation information for the controls at the organization-defined level of detail")
	d != ""
	msg := sprintf("NIST SA-4(2): %s", [d])
}

# SA-4(9) Functions, Ports, Protocols, and Services in Use: input.sa_controls.acquisition.ports_protocols_services.
# contracts_missing_requirement.
violation contains msg if {
	d := _contract_detail(["acquisition", "ports_protocols_services"], "acquisition contracts do not require the developer to identify the functions, ports, protocols and services intended for organizational use")
	d != ""
	msg := sprintf("NIST SA-4(9): %s", [d])
}

# SA-4(10) Use of Approved PIV Products: input.sa_controls.acquisition.piv_products.non_approved_products, the
# number of products implementing PIV capability that are not on the FIPS 201-approved products list.
violation contains msg if {
	sec := ["acquisition", "piv_products"]
	m := _zero_missing(sec, "non_approved_products")
	u := _zero_unmet(sec, "non_approved_products", "products implementing PIV capability are not on the FIPS 201-approved products list")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-4(10): %s", [_detail(m, u)])
}

# SA-9(2) Identification of Functions, Ports, Protocols, and Services: input.sa_controls.external_services.
# ports_protocols_services.providers_not_identified, the number of providers of the organization-defined
# external system services that have not identified the functions, ports, protocols and other services the
# use of their service requires.
violation contains msg if {
	sec := ["external_services", "ports_protocols_services"]
	m := _zero_missing(sec, "providers_not_identified")
	u := _zero_unmet(sec, "providers_not_identified", "providers of the organization-defined external system services have not identified the functions, ports, protocols and services their use requires")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-9(2): %s", [_detail(m, u)])
}

# SA-15(3) Criticality Analysis: input.sa_controls.development_process.criticality_analysis.{required,
# decision_points_without_analysis}. required is true when the developer is required to perform a criticality
# analysis at the organization-defined breadth and depth; decision_points_without_analysis counts the
# organization-defined SDLC decision points already passed with no developer criticality analysis on record.
violation contains msg if {
	sec := ["development_process", "criticality_analysis"]
	b := {"required": "the developer is not required to perform a criticality analysis at the organization-defined breadth and depth"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "decision_points_without_analysis")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "decision_points_without_analysis", "organization-defined SDLC decision points passed without a developer criticality analysis")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-15(3): %s", [_detail(m, u)])
}

# ---------------------------------------------------------------------------------------------------------
# High-baseline enhancements (SP 800-53B High and FedRAMP High). Facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# SA-4(5) System, Component, and Service Configurations: input.sa_controls.acquisition.security_configurations.
# {contracts_missing_requirement, components_deviating_from_default}. contracts_missing_requirement counts
# acquisition contracts that do not require delivery with the organization-defined security configurations
# implemented and their use as the default for reinstallation or upgrade; components_deviating_from_default
# counts delivered, reinstalled or upgraded components whose configuration scan differs from that default.
violation contains msg if {
	sec := ["acquisition", "security_configurations"]
	z := {
		"contracts_missing_requirement": "acquisition contracts do not require delivery with the organization-defined security configurations implemented as the default for reinstallation or upgrade",
		"components_deviating_from_default": "delivered, reinstalled or upgraded components do not run the organization-defined security configurations",
	}
	m := {p | some k, _ in z; some p in _zero_missing(sec, k)}
	u := {d | some k, what in z; some d in _zero_unmet(sec, k, what)}
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-4(5): %s", [_detail(m, u)])
}

# SA-9(1) Risk Assessments and Organizational Approvals: input.sa_controls.external_services.
# security_service_acquisitions.{without_prior_risk_assessment, without_approval}: counts of acquired or
# outsourced information security services with no organizational risk assessment dated before the acquisition,
# and of dedicated information security services not approved by the organization-defined personnel or roles
# (from the procurement or vendor-risk register).
violation contains msg if {
	sec := ["external_services", "security_service_acquisitions"]
	z := {
		"without_prior_risk_assessment": "information security services were acquired or outsourced without a prior organizational risk assessment",
		"without_approval": "dedicated information security services were acquired or outsourced without approval by the organization-defined personnel or roles",
	}
	m := {p | some k, _ in z; some p in _zero_missing(sec, k)}
	u := {d | some k, what in z; some d in _zero_unmet(sec, k, what)}
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-9(1): %s", [_detail(m, u)])
}

# SA-9(5) Processing, Storage, and Service Location: input.sa_controls.external_services.location_restriction.
# {locations_defined, resources_outside_locations}. locations_defined is true when the organization-defined
# permitted locations (regions, jurisdictions) are set as an enforced restriction, such as a cloud region
# allow-list policy; resources_outside_locations counts processing, storage or service resources found outside
# them.
violation contains msg if {
	sec := ["external_services", "location_restriction"]
	b := {"locations_defined": "the location of information processing, data or system services is not restricted to organization-defined locations"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "resources_outside_locations")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "resources_outside_locations", "processing, storage or service resources are outside the organization-defined locations")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-9(5): %s", [_detail(m, u)])
}

# SA-11(1) Static Code Analysis: input.sa_controls.developer_testing.static_analysis.{components_not_analyzed,
# results_documented}. components_not_analyzed counts the system's developed components or repositories with no
# static code analysis run in the CI pipeline; results_documented is true when the analysis results are
# retained (SARIF reports or the scanner's findings record).
violation contains msg if {
	sec := ["developer_testing", "static_analysis"]
	b := {"results_documented": "the results of static code analysis are not documented"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "components_not_analyzed")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "components_not_analyzed", "developed components have no static code analysis")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-11(1): %s", [_detail(m, u)])
}

# SA-11(2) Threat Modeling and Vulnerability Analyses: input.sa_controls.developer_testing.threat_modeling.
# {components_without_threat_model, analyses_failing_acceptance}. components_without_threat_model counts
# components with no current threat model and vulnerability analysis using the organization-defined contextual
# information, tools and methods at the organization-defined breadth and depth; analyses_failing_acceptance
# counts analyses whose evidence does not meet the organization-defined acceptance criteria.
violation contains msg if {
	sec := ["developer_testing", "threat_modeling"]
	z := {
		"components_without_threat_model": "components have no developer threat modeling and vulnerability analysis at the organization-defined rigor",
		"analyses_failing_acceptance": "threat modeling and vulnerability analyses do not meet the organization-defined acceptance criteria",
	}
	m := {p | some k, _ in z; some p in _zero_missing(sec, k)}
	u := {d | some k, what in z; some d in _zero_unmet(sec, k, what)}
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-11(2): %s", [_detail(m, u)])
}

compliant if count(violation) == 0

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# SA-8(33) Minimization: the privacy principle of minimization is implemented using the organization-defined
# processes.
# Facts (input.sa_controls.engineering_principles.minimization): odp.processes (non-empty list of the
# organization-defined processes); processes_implemented (list of the processes in place, e.g. from the system
# design record or data-flow review).
_sa8_33_sec := ["engineering_principles", "minimization"]

_sa8_33_req := _val(array.concat(_sa8_33_sec, ["odp", "processes"]))

_sa8_33_obs := _val(array.concat(_sa8_33_sec, ["processes_implemented"]))

_sa8_33_missing := {_p(array.concat(_sa8_33_sec, ["odp", "processes"])) | not _sa8_33_req_ok} | {_p(array.concat(_sa8_33_sec, ["processes_implemented"])) | not is_array(_sa8_33_obs)}

_sa8_33_req_ok if {
	is_array(_sa8_33_req)
	count(_sa8_33_req) > 0
}

_sa8_33_unmet := {sprintf("organization-defined minimization processes not implemented: %v", [sort(lack)]) |
	_sa8_33_req_ok
	is_array(_sa8_33_obs)
	lack := {x | some x in _sa8_33_req; not x in _sa8_33_obs}
	count(lack) > 0
}

violation contains msg if {
	count(_sa8_33_missing) + count(_sa8_33_unmet) > 0
	msg := sprintf("NIST SA-8(33): %s", [_detail(_sa8_33_missing, _sa8_33_unmet)])
}

# ---------------------------------------------------------------------------------------------------------
# Enhancement added by SP 800-53 Release 5.2.0 (27 August 2025). In no SP 800-53B or FedRAMP baseline.
# ---------------------------------------------------------------------------------------------------------

# SA-15(13) Logging Syntax: input.sa_controls.development_process.logging_syntax.{format_defined,
# event_types_defined, detail_level_defined, developer_required, components_not_conforming}. The three *_defined
# facts say the organization-defined secure logging format(s), event types to log and level of detail are set;
# developer_required is true when the developer of the system, component or service is required (contract,
# statement of work or internal standard) to log in that format; components_not_conforming counts the developed
# components whose logs were checked and do not follow it (SP 800-53A examines the developer logs).
_sa15_13 := {
	"format_defined": "the organization-defined secure logging format(s) are not defined",
	"event_types_defined": "the organization-defined event types to log are not defined",
	"detail_level_defined": "the organization-defined level of detail to log is not defined",
	"developer_required": "the developer is not required to log the defined event types in the defined secure logging format at the defined level of detail",
}

violation contains msg if {
	sec := ["development_process", "logging_syntax"]
	m := _bool_missing(sec, _sa15_13) | _zero_missing(sec, "components_not_conforming")
	u := _bool_unmet(sec, _sa15_13) | _zero_unmet(sec, "components_not_conforming", "developed components whose logs do not follow the organization-defined secure logging format, event types and level of detail")
	count(m) + count(u) > 0
	msg := sprintf("NIST SA-15(13): %s", [_detail(m, u)])
}

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SA-1", "SA-2", "SA-3", "SA-4", "SA-4(1)", "SA-4(2)", "SA-4(5)", "SA-4(9)", "SA-4(10)", "SA-5", "SA-8",
	"SA-9", "SA-9(1)", "SA-9(2)", "SA-9(5)", "SA-10", "SA-11", "SA-11(1)", "SA-11(2)", "SA-15", "SA-15(3)",
	"SA-16", "SA-17", "SA-20", "SA-21", "SA-22", "SA-23", "SA-24",
	"SA-8(33)", "SA-15(13)", "SA-10(1)",
}

compliance_report := {
	"family": "SA",
	"name": "System and Services Acquisition",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
