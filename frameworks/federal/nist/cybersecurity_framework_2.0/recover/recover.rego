# METADATA
# title: "NIST Cybersecurity Framework 2.0 — RECOVER (RC) function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 1
#     cited: 1
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.csf.recover

import rego.v1

# NIST Cybersecurity Framework 2.0 — RECOVER (RC) function module.
# Develop and implement appropriate activities to maintain plans for resilience
# and to restore any capabilities or services impaired due to an incident.
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

default compliant := false

violation contains msg if {
	not input.recover.recovery_planning.recovery_plan_executed
	msg := "CSF RC.RP-01: Recovery plan not executed during or after a cybersecurity incident"
}

compliant if count(violation) == 0

compliance_report := {
	"function": "RECOVER",
	"controls_evaluated": 1,
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
	"RC.IM-01": {
		"csf_1_1_id": "RC.IM-01",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM-03", "ID.IM-04"],
		"facts_read": ["input.recover.improvements.recovery_plans_incorporate_lessons"],
		"legacy_message": "Recovery plans don't incorporate lessons learned",
		"reason": "CSF 1.1 RC.IM-01 (\"Recovery plans incorporate lessons learned\") is withdrawn in CSF 2.0: Incorporated into ID.IM-03, ID.IM-04; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"RC.CO-01": {
		"csf_1_1_id": "RC.CO-01",
		"status": "retired",
		"csf_2_0_ids": ["RC.CO-04"],
		"facts_read": ["input.recover.communications.public_relations_managed"],
		"legacy_message": "Public relations not managed during recovery",
		"reason": "CSF 1.1 RC.CO-01 (\"Public relations are managed\") is withdrawn in CSF 2.0: Incorporated into RC.CO-04; this check tests part of a broader CSF 2.0 outcome, so it cannot decide RC.CO-04 on its own",
	},
	"RC.IM-02": {
		"csf_1_1_id": "RC.IM-02",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM-03"],
		"facts_read": ["input.recover.improvements.recovery_strategies_updated"],
		"legacy_message": "Recovery strategies not updated",
		"reason": "CSF 1.1 RC.IM-02 (\"Recovery strategies are updated\") is withdrawn in CSF 2.0: Incorporated into ID.IM-03; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.IM-03 on its own",
	},
	"RC.CO-02": {
		"csf_1_1_id": "RC.CO-02",
		"status": "retired",
		"csf_2_0_ids": ["RC.CO-04"],
		"facts_read": ["input.recover.communications.reputation_repaired"],
		"legacy_message": "Reputation repair after an event not performed",
		"reason": "CSF 1.1 RC.CO-02 (\"Reputation is repaired after an incident\") is withdrawn in CSF 2.0: Incorporated into RC.CO-04; this check tests part of a broader CSF 2.0 outcome, so it cannot decide RC.CO-04 on its own",
	},
	"RC.CO-03": {
		"csf_1_1_id": "RC.CO-03",
		"status": "unmapped",
		"csf_2_0_ids": ["RC.CO-03"],
		"facts_read": ["input.recover.communications.recovery_activities_communicated"],
		"legacy_message": "Recovery activities not communicated to internal stakeholders and leadership",
		"reason": "CSF 2.0 RC.CO-03 reads \"Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders\"; this check tests communication to internal stakeholders and leadership only; the 2.0 text also covers designated external stakeholders",
	},
}
