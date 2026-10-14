# METADATA
# title: "NIST Cybersecurity Framework 2.0 — IDENTIFY (ID) function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 8
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.csf.identify

import rego.v1

# NIST Cybersecurity Framework 2.0 — IDENTIFY (ID) function module.
# Develop the organizational understanding to manage cybersecurity risk to
# systems, people, assets, data, and capabilities.
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

default compliant := false

violation contains msg if {
	not input.identify.asset_management.physical_devices_inventoried
	msg := "CSF ID.AM-01: Physical devices and systems not inventoried"
}

violation contains msg if {
	not input.identify.asset_management.organizational_communication_mapped
	msg := "CSF ID.AM-03: Organizational communication and data flows not mapped"
}

violation contains msg if {
	not input.identify.asset_management.resources_prioritized
	msg := "CSF ID.AM-05: Resources not prioritized based on classification/criticality"
}

violation contains msg if {
	not input.identify.risk_assessment.asset_vulnerabilities_identified
	msg := "CSF ID.RA-01: Asset vulnerabilities not identified and documented"
}

violation contains msg if {
	not input.identify.risk_assessment.cyber_threat_intelligence_received
	msg := "CSF ID.RA-02: Cyber threat intelligence not received from information-sharing forums"
}

violation contains msg if {
	not input.identify.risk_assessment.threats_identified_and_documented
	msg := "CSF ID.RA-03: Internal and external threats not identified or documented"
}

violation contains msg if {
	not input.identify.risk_assessment.potential_impacts_identified
	msg := "CSF ID.RA-04: Potential business impacts and likelihoods not identified"
}

violation contains msg if {
	not input.identify.risk_assessment.risk_determined
	msg := "CSF ID.RA-05: Threats/vulnerabilities/likelihoods/impacts not used to determine risk"
}

compliant if count(violation) == 0

compliance_report := {
	"function": "IDENTIFY",
	"controls_evaluated": 8,
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
	"ID.AM-02": {
		"csf_1_1_id": "ID.AM-02",
		"status": "unmapped",
		"csf_2_0_ids": ["ID.AM-02"],
		"facts_read": ["input.identify.asset_management.software_platforms_inventoried"],
		"legacy_message": "Software platforms and applications not inventoried",
		"reason": "CSF 2.0 ID.AM-02 reads \"Inventories of software, services, and systems managed by the organization are maintained\"; this check tests software platforms and applications only; the 2.0 text also covers services and systems",
	},
	"ID.AM-04": {
		"csf_1_1_id": "ID.AM-04",
		"status": "unmapped",
		"csf_2_0_ids": ["ID.AM-04"],
		"facts_read": ["input.identify.asset_management.external_systems_cataloged"],
		"legacy_message": "External information systems not cataloged",
		"reason": "CSF 2.0 ID.AM-04 reads \"Inventories of services provided by suppliers are maintained\"; this check tests that external information systems are catalogued (the CSF 1.1 meaning of this id), not inventories of supplier services",
	},
	"ID.BE-01": {
		"csf_1_1_id": "ID.BE-01",
		"status": "retired",
		"csf_2_0_ids": ["GV.OC-05"],
		"facts_read": ["input.identify.business_environment.role_in_supply_chain_identified"],
		"legacy_message": "Organization's role in the supply chain not identified/communicated",
		"reason": "CSF 1.1 ID.BE-01 (\"The organization’s role in the supply chain is identified and communicated\") is withdrawn in CSF 2.0: Incorporated into GV.OC-05; this check tests part of a broader CSF 2.0 outcome, so it cannot decide GV.OC-05 on its own",
	},
	"ID.BE-02": {
		"csf_1_1_id": "ID.BE-02",
		"status": "retired",
		"csf_2_0_ids": ["GV.OC-01"],
		"facts_read": ["input.identify.business_environment.role_in_critical_infrastructure_identified"],
		"legacy_message": "Role in critical infrastructure / sector not identified",
		"reason": "CSF 1.1 ID.BE-02 (\"The organization’s place in critical infrastructure and its industry sector is identified and communicated\") is withdrawn in CSF 2.0: Incorporated into GV.OC-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide GV.OC-01 on its own",
	},
	"ID.BE-03": {
		"csf_1_1_id": "ID.BE-03",
		"status": "retired",
		"csf_2_0_ids": ["GV.OC-01"],
		"facts_read": ["input.identify.business_environment.priorities_for_mission_established"],
		"legacy_message": "Priorities for organizational mission/objectives/activities not established",
		"reason": "CSF 1.1 ID.BE-03 (\"Priorities for organizational mission, objectives, and activities are established and communicated\") is withdrawn in CSF 2.0: Incorporated into GV.OC-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide GV.OC-01 on its own",
	},
	"ID.RM-01": {
		"csf_1_1_id": "ID.RM-01",
		"status": "retired",
		"csf_2_0_ids": ["GV.RM-01", "GV.RM-06", "GV.RR-03"],
		"facts_read": ["input.identify.risk_management.processes_established"],
		"legacy_message": "Risk management processes not established/managed/agreed-to",
		"reason": "CSF 1.1 ID.RM-01 (\"Risk management processes are established, managed, and agreed to by organizational stakeholders\") is withdrawn in CSF 2.0: Incorporated into GV.RM-01, GV.RM-06, GV.RR-03; this check its outcome is spread over 3 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"ID.RM-02": {
		"csf_1_1_id": "ID.RM-02",
		"status": "retired",
		"csf_2_0_ids": ["GV.RM-02", "GV.RM-04"],
		"facts_read": ["input.identify.risk_management.risk_tolerance_determined"],
		"legacy_message": "Organizational risk tolerance not determined or clearly expressed",
		"reason": "CSF 1.1 ID.RM-02 (\"Organizational risk tolerance is determined and clearly expressed\") is withdrawn in CSF 2.0: Incorporated into GV.RM-02, GV.RM-04; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"ID.SC-01": {
		"csf_1_1_id": "ID.SC-01",
		"status": "retired",
		"csf_2_0_ids": ["GV.RM-05", "GV.SC-01", "GV.SC-06", "GV.SC-09", "GV.SC-10"],
		"facts_read": ["input.identify.supply_chain.cyber_scrm_processes_established"],
		"legacy_message": "Cyber supply chain risk management processes not established",
		"reason": "CSF 1.1 ID.SC-01 (\"Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders\") is withdrawn in CSF 2.0: Incorporated into GV.RM-05, GV.SC-01, GV.SC-06, GV.SC-09, GV.SC-10; this check its outcome is spread over 5 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"ID.SC-02": {
		"csf_1_1_id": "ID.SC-02",
		"status": "retired",
		"csf_2_0_ids": ["GV.OC-02", "GV.SC-03", "GV.SC-04", "GV.SC-07", "ID.RA-10"],
		"facts_read": ["input.identify.supply_chain.suppliers_identified"],
		"legacy_message": "Suppliers and third-party partners not identified/prioritized/assessed",
		"reason": "CSF 1.1 ID.SC-02 (\"Suppliers and third party partners of information systems, components, and services are identified, prioritized, and assessed using a cyber supply chain risk assessment process\") is withdrawn in CSF 2.0: Incorporated into GV.OC-02, GV.SC-03, GV.SC-04, GV.SC-07, ID.RA-10; this check its outcome is spread over 5 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
}
