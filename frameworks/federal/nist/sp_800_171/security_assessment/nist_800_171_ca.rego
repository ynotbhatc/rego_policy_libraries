# METADATA
# title: "NIST SP 800-171 Rev 3 - Security Assessment (CA) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 7
#     cited: 3
#     expected: 4
#     found: 7
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.security_assessment

import rego.v1

# NIST SP 800-171 Rev 3 - Security Assessment (CA) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.12 Security Assessment and Monitoring — Protecting Controlled Unclassified Information (CUI)

# 03.12.01 Security Assessment (Rev 2 3.12.1): Periodically assess the security controls in organizational systems to determine
#          if the controls are effective in their application
default security_controls_assessed := false

security_controls_assessed if {
	input.nist_800_171.security_assessment.controls_assessment.periodic_assessments == true
	input.nist_800_171.security_assessment.controls_assessment.effectiveness_determined == true
	input.nist_800_171.security_assessment.controls_assessment.results_documented == true
	input.nist_800_171.security_assessment.controls_assessment.independent_assessor == true
}

# 03.12.02 Plan of Action and Milestones (Rev 2 3.12.2): Develop and implement plans of action designed to correct deficiencies and reduce
#          or eliminate vulnerabilities in organizational systems
default plans_of_action := false

plans_of_action if {
	input.nist_800_171.security_assessment.plans_of_action.poam_documented == true
	input.nist_800_171.security_assessment.plans_of_action.deficiencies_tracked == true
	input.nist_800_171.security_assessment.plans_of_action.milestones_defined == true
	input.nist_800_171.security_assessment.plans_of_action.progress_monitored == true
}

# 03.12.03 Continuous Monitoring (Rev 2 3.12.3): Monitor security controls on an ongoing basis to ensure the continued effectiveness
#          of the controls
default continuous_monitoring := false

continuous_monitoring if {
	input.nist_800_171.security_assessment.continuous_monitoring.monitoring_implemented == true
	input.nist_800_171.security_assessment.continuous_monitoring.ongoing_not_just_periodic == true
	input.nist_800_171.security_assessment.continuous_monitoring.automated_where_possible == true
}

# 03.15.02 (Rev 2 3.12.4, withdrawn in Rev 3: Incorporated into 03.15.02.): Develop, document, and periodically update system security plans that describe
#          system boundaries, system environments, how security requirements are implemented,
#          and the relationships with or connections to other systems
default system_security_plan := false

system_security_plan if {
	input.nist_800_171.security_assessment.ssp.plan_documented == true
	input.nist_800_171.security_assessment.ssp.system_boundary_defined == true
	input.nist_800_171.security_assessment.ssp.environment_described == true
	input.nist_800_171.security_assessment.ssp.requirements_implementation_described == true
	input.nist_800_171.security_assessment.ssp.interconnections_documented == true
	input.nist_800_171.security_assessment.ssp.updated_periodically == true
}

# Violations set
violations contains msg if {
	not security_controls_assessed
	msg := "NIST SP 800-171 03.12.01: Security controls must be periodically assessed by an independent assessor to determine effectiveness"
}

violations contains msg if {
	not plans_of_action
	msg := "NIST SP 800-171 03.12.02: Plans of action (POA&M) must be developed and implemented to correct deficiencies with tracked milestones"
}

violations contains msg if {
	not continuous_monitoring
	msg := "NIST SP 800-171 03.12.03: Security controls must be continuously monitored on an ongoing basis with automated mechanisms where possible"
}

violations contains msg if {
	not system_security_plan
	msg := "NIST SP 800-171 03.15.02 (Rev 2 3.12.4, withdrawn in Rev 3: Incorporated into 03.15.02.): System security plans must be documented, describing boundaries, environments, implementation, and interconnections, and updated periodically"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.12 Security Assessment and Monitoring",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 4,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.12.01_security_controls_assessed": security_controls_assessed,
		"03.12.02_plans_of_action": plans_of_action,
		"03.12.03_continuous_monitoring": continuous_monitoring,
		"03.15.02_system_security_plan": system_security_plan,
	},
}
