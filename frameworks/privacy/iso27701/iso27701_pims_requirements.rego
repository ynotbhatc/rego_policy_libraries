package iso27701.pims_requirements

import rego.v1

violations contains msg if {
	not input.iso27701.pims_requirements.context.privacy_factors_identified
	msg := "ISO 27701 5.2: Privacy context factors not identified across applicable jurisdictions"
}

violations contains msg if {
	not input.iso27701.pims_requirements.context.internal_privacy_factors_documented
	msg := "ISO 27701 5.2: Internal privacy factors (data flows, processing purposes, retention) not documented"
}

violations contains msg if {
	not input.iso27701.pims_requirements.interested_parties.stakeholders_identified
	msg := "ISO 27701 5.3: Stakeholders with privacy interests not identified (data subjects, regulators, processors)"
}

violations contains msg if {
	not input.iso27701.pims_requirements.interested_parties.dpa_requirements_documented
	msg := "ISO 27701 5.3: Requirements of Data Protection Authorities and privacy regulators not documented"
}

violations contains msg if {
	not input.iso27701.pims_requirements.scope.pii_processing_covered
	msg := "ISO 27701 5.4: PIMS scope does not cover all PII processing activities"
}

violations contains msg if {
	not input.iso27701.pims_requirements.scope.third_party_interfaces_in_scope
	msg := "ISO 27701 5.4: Interfaces with third parties processing PII are not included in PIMS scope"
}

violations contains msg if {
	not input.iso27701.pims_requirements.leadership.executive_sponsor_designated
	msg := "ISO 27701 5.5: Executive sponsor for privacy program not designated"
}

violations contains msg if {
	not input.iso27701.pims_requirements.leadership.privacy_resources_allocated
	msg := "ISO 27701 5.5: Privacy resources (budget, staff) not allocated"
}

violations contains msg if {
	not input.iso27701.pims_requirements.privacy_policy.approved_by_top_management
	msg := "ISO 27701 5.6: Overarching privacy policy not approved by top management"
}

violations contains msg if {
	not input.iso27701.pims_requirements.privacy_policy.reviewed_annually
	msg := "ISO 27701 5.6: Privacy policy not reviewed annually"
}

violations contains msg if {
	not input.iso27701.pims_requirements.risk.privacy_risk_assessment_conducted
	msg := "ISO 27701 6.1: Privacy risk assessment not conducted covering all processing activities"
}

violations contains msg if {
	not input.iso27701.pims_requirements.risk.dpias_for_high_risk
	msg := "ISO 27701 6.1: Data Protection Impact Assessments not conducted for high-risk processing activities"
}

violations contains msg if {
	not input.iso27701.pims_requirements.risk.risk_treatment_documented
	msg := "ISO 27701 6.1: Privacy risks not treated or accepted with documented rationale"
}

violations contains msg if {
	not input.iso27701.pims_requirements.objectives.established_and_measurable
	msg := "ISO 27701 6.2: Privacy objectives not established or not measurable"
}

violations contains msg if {
	not input.iso27701.pims_requirements.objectives.communicated
	msg := "ISO 27701 6.2: Privacy objectives not communicated across the organization"
}

violations contains msg if {
	not input.iso27701.pims_requirements.planning_changes.privacy_impact_assessed
	msg := "ISO 27701 6.3: Privacy impact of organizational changes not assessed before implementation"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "ISO/IEC 27701:2019",
	"domain": "Clauses 5-6 — Core PIMS Requirements",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
