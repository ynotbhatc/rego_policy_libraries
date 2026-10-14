# METADATA
# title: "NIST Cybersecurity Framework 2.0 — RESPOND (RS) function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 4
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.csf.respond

import rego.v1

# NIST Cybersecurity Framework 2.0 — RESPOND (RS) function module.
# Develop and implement appropriate activities to take action regarding
# a detected cybersecurity incident.
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

default compliant := false

violation contains msg if {
	not input.respond.analysis.vulnerability_disclosures_addressed
	msg := "CSF ID.RA-08: Vulnerability disclosures from internal/external sources not addressed (fact check carried from CSF 1.1 RS.AN-05, which CPRT records as moved to ID.RA-08)"
}

violation contains msg if {
	not input.respond.communications.events_reported_within_criteria
	msg := "CSF RS.CO-02: Incidents not reported consistent with established criteria"
}

violation contains msg if {
	not input.respond.communications.information_shared_with_stakeholders
	msg := "CSF RS.CO-03: Response information not shared with internal stakeholders"
}

violation contains msg if {
	not input.respond.mitigation.incidents_contained
	msg := "CSF RS.MI-01: Incidents not contained"
}

compliant if count(violation) == 0

compliance_report := {
	"function": "RESPOND",
	"controls_evaluated": 4,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# Lineage of the CSF 1.1-era fact checks this module no longer evaluates (removed; data only, no rule
# behind it, not a control). Keyed by the label the check carried. status "retired": the CSF 1.1 id is
# withdrawn in CSF 2.0 (csf_2_0_ids = CPRT's destinations); "unmapped": the label reused a current CSF 2.0
# id but the check tested something else or only part of it. facts_read: the input the check read. Each 2.0
# subcategory is decided in nist.csf.main on its own basis (facts or attestation).
legacy := {
	"RS.RP-01": {
		"csf_1_1_id": "RS.RP-01",
		"status": "retired",
		"csf_2_0_ids": ["RS.MA-01"],
		"facts_read": ["input.respond.response_planning.response_plan_executed"],
		"legacy_message": "Response plan not executed during or after an incident",
		"reason": "CSF 1.1 RS.RP-01 (\"Response plan is executed during or after an incident\") is withdrawn in CSF 2.0: Incorporated into RS.MA-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide RS.MA-01 on its own",
	},
	"RS.AN-01": {
		"csf_1_1_id": "RS.AN-01",
		"status": "retired",
		"csf_2_0_ids": ["RS.MA-02"],
		"facts_read": ["input.respond.analysis.notifications_investigated"],
		"legacy_message": "Notifications from detection systems not investigated",
		"reason": "CSF 1.1 RS.AN-01 (\"Notifications from detection systems are investigated\") is withdrawn in CSF 2.0: Incorporated into RS.MA-02; this check tests part of a broader CSF 2.0 outcome, so it cannot decide RS.MA-02 on its own",
	},
	"RS.AN-02": {
		"csf_1_1_id": "RS.AN-02",
		"status": "retired",
		"csf_2_0_ids": ["RS.MA-02", "RS.MA-03", "RS.MA-04"],
		"facts_read": ["input.respond.analysis.incident_impact_understood"],
		"legacy_message": "Impact of incident not understood",
		"reason": "CSF 1.1 RS.AN-02 (\"The impact of the incident is understood\") is withdrawn in CSF 2.0: Incorporated into RS.MA-02, RS.MA-03, RS.MA-04; this check its outcome is spread over 3 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"RS.AN-03": {
		"csf_1_1_id": "RS.AN-03",
		"status": "unmapped",
		"csf_2_0_ids": ["RS.AN-03"],
		"facts_read": ["input.respond.analysis.forensics_performed"],
		"legacy_message": "Forensics not performed during/after incident",
		"reason": "CSF 2.0 RS.AN-03 reads \"Analysis is performed to establish what has taken place during an incident and the root cause of the incident\"; this check tests that forensics are performed (a technique), not analysis establishing what took place and the root cause",
	},
	"RS.AN-04": {
		"csf_1_1_id": "RS.AN-04",
		"status": "retired",
		"csf_2_0_ids": ["RS.MA-03"],
		"facts_read": ["input.respond.analysis.incidents_categorized"],
		"legacy_message": "Incidents not categorized consistent with response plan",
		"reason": "CSF 1.1 RS.AN-04 (\"Incidents are categorized consistent with response plans\") is withdrawn in CSF 2.0: Moved to RS.MA-03; not carried because the check tests that incidents are categorized; RS.MA-03 requires that they are categorized and prioritized",
	},
	"RS.CO-01": {
		"csf_1_1_id": "RS.CO-01",
		"status": "retired",
		"csf_2_0_ids": ["PR.AT-01"],
		"facts_read": ["input.respond.communications.personnel_know_roles"],
		"legacy_message": "Personnel don't know their roles when a response is needed",
		"reason": "CSF 1.1 RS.CO-01 (\"Personnel know their roles and order of operations when a response is needed\") is withdrawn in CSF 2.0: Incorporated into PR.AT-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide PR.AT-01 on its own",
	},
	"RS.CO-04": {
		"csf_1_1_id": "RS.CO-04",
		"status": "retired",
		"csf_2_0_ids": ["RS.MA-01", "RS.MA-04"],
		"facts_read": ["input.respond.communications.coordination_with_stakeholders"],
		"legacy_message": "Coordination with external stakeholders not aligned with plan",
		"reason": "CSF 1.1 RS.CO-04 (\"Coordination with stakeholders occurs consistent with response plans\") is withdrawn in CSF 2.0: Incorporated into RS.MA-01, RS.MA-04; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"RS.CO-05": {
		"csf_1_1_id": "RS.CO-05",
		"status": "retired",
		"csf_2_0_ids": ["RS.CO-03"],
		"facts_read": ["input.respond.communications.voluntary_information_sharing"],
		"legacy_message": "Voluntary information sharing with external stakeholders not performed",
		"reason": "CSF 1.1 RS.CO-05 (\"Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness\") is withdrawn in CSF 2.0: Incorporated into RS.CO-03; this check tests part of a broader CSF 2.0 outcome, so it cannot decide RS.CO-03 on its own",
	},
	"RS.MI-02": {
		"csf_1_1_id": "RS.MI-02",
		"status": "unmapped",
		"csf_2_0_ids": ["RS.MI-02"],
		"facts_read": ["input.respond.mitigation.incidents_mitigated"],
		"legacy_message": "Incidents not mitigated",
		"reason": "CSF 2.0 RS.MI-02 reads \"Incidents are eradicated\"; this check tests that incidents are mitigated; the 2.0 text requires that they are eradicated",
	},
	"RS.MI-03": {
		"csf_1_1_id": "RS.MI-03",
		"status": "retired",
		"csf_2_0_ids": ["ID.RA-06"],
		"facts_read": ["input.respond.mitigation.newly_identified_vulnerabilities_mitigated"],
		"legacy_message": "Newly identified vulnerabilities not mitigated or accepted as residual risk",
		"reason": "CSF 1.1 RS.MI-03 (\"Newly identified vulnerabilities are mitigated or documented as accepted risks\") is withdrawn in CSF 2.0: Incorporated into ID.RA-06; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.RA-06 on its own",
	},
	"RS.IM-01": {
		"csf_1_1_id": "RS.IM-01",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM-03", "ID.IM-04"],
		"facts_read": ["input.respond.improvements.response_plans_incorporate_lessons"],
		"legacy_message": "Response plans don't incorporate lessons learned",
		"reason": "CSF 1.1 RS.IM-01 (\"Response plans incorporate lessons learned\") is withdrawn in CSF 2.0: Incorporated into ID.IM-03, ID.IM-04; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"RS.IM-02": {
		"csf_1_1_id": "RS.IM-02",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM-03"],
		"facts_read": ["input.respond.improvements.response_strategies_updated"],
		"legacy_message": "Response strategies not updated",
		"reason": "CSF 1.1 RS.IM-02 (\"Response strategies are updated\") is withdrawn in CSF 2.0: Incorporated into ID.IM-03; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.IM-03 on its own",
	},
}
