# METADATA
# title: "DORA level-2 technical standard — ICT subcontracting (critical/important functions)"
# custom:
#   class: compliance
#   framework: dora
#   source: eu
#   domains: [financial, eu]
package dora.rts_subcontracting

import rego.v1

# DORA level-2 technical standard — ICT subcontracting (critical/important functions).
# Commission Delegated Regulation (EU) 2025/532, in force 2025-07-22
#
# Entity-side obligations only; checks are attestations keyed to the
# RTS article they implement. Fail-closed: absent or non-true facts
# are violations.

default compliant := false

violation contains msg if {
	not input.third_party_risk.subcontracting.risk_assessment.covers_chain_complexity == true
	msg := "DORA RTS 2025/532 Art.1: Subcontracting risk assessment considers chain length/complexity, subcontractor locations, data shared, group membership, concentration, transferability and disruption risk — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.group_consistency.ensured == true
	msg := "DORA RTS 2025/532 Art.2: Parent undertaking ensures subcontracting conditions are implemented consistently across all group financial entities — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.permissibility_decision.documented == true
	msg := "DORA RTS 2025/532 Art.3(1): Pre-contract decision documented on whether ICT services supporting critical/important functions may be subcontracted — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.provider_vetting_capability_verified == true
	msg := "DORA RTS 2025/532 Art.3(1)(a): Verified the ICT provider can select and assess operational and financial abilities of potential subcontractors — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.full_chain_identified == true
	msg := "DORA RTS 2025/532 Art.3(1)(b): ICT provider can identify ALL subcontractors in the chain and notify the entity with assessment information — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.regulatory_compliance_enabled == true
	msg := "DORA RTS 2025/532 Art.3(1)(c): Subcontracts enable the financial entity to meet its own DORA and Union/national legal obligations — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.access_rights_parity_verified == true
	msg := "DORA RTS 2025/532 Art.3(1)(d): Subcontractors grant the entity and competent/resolution authorities the same access and inspection rights as the main provider — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.provider_monitoring_capacity_verified == true
	msg := "DORA RTS 2025/532 Art.3(1)(e): ICT provider has sufficient ability, expertise and resources to monitor ICT risk at subcontractor level — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.entity_monitoring_capacity_verified == true
	msg := "DORA RTS 2025/532 Art.3(1)(f): Financial entity itself has sufficient resources and expertise to monitor subcontracting-chain ICT risk — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.failure_impact_assessed == true
	msg := "DORA RTS 2025/532 Art.3(1)(g): Impact of a possible subcontractor failure on resilience and financial soundness assessed — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.location_risk_assessed == true
	msg := "DORA RTS 2025/532 Art.3(1)(h): Geographic-location risks of potential subcontractors (and parents/service locations) assessed — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.concentration_risk_assessed == true
	msg := "DORA RTS 2025/532 Art.3(1)(i): ICT concentration risk at entity level assessed for the subcontracting chain (DORA Art.29) — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.due_diligence.supervisory_access_obstacles_assessed == true
	msg := "DORA RTS 2025/532 Art.3(1)(j): Assessed whether supervisory inspection/audit rights face obstacles anywhere in the chain — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.risk_assessment.periodic_review_performed == true
	msg := "DORA RTS 2025/532 Art.3(2): Subcontracting risk assessment periodically re-performed against changes in functions, threats, concentration and geopolitics — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.risk_assessment.independent_of_provider == true
	msg := "DORA RTS 2025/532 Art.3(3): Entity's own risk assessment evidenced — final responsibility not delegated to provider-performed assessments — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.eligible_services_specified == true
	msg := "DORA RTS 2025/532 Art.4(1): Contract identifies which ICT services supporting critical/important functions may be subcontracted and under which conditions — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.provider_responsibility_clause == true
	msg := "DORA RTS 2025/532 Art.4(1)(a): Contract makes the ICT provider responsible for all services delivered by its subcontractors — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.monitoring_reporting_obligations == true
	msg := "DORA RTS 2025/532 Art.4(1)(b)-(c): Contract obliges continuous provider monitoring of subcontracted services with specified reporting to the entity — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.data_location_specified == true
	msg := "DORA RTS 2025/532 Art.4(1)(d)-(e): Contract obliges subcontractor location-risk assessment and specifies where subcontractors process/store data — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.flow_down_obligations == true
	msg := "DORA RTS 2025/532 Art.4(1)(f): Contract requires monitoring/reporting obligations to flow down into the provider's subcontractor contracts — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.chain_continuity_required == true
	msg := "DORA RTS 2025/532 Art.4(1)(g)-(h): Contract requires service continuity through the whole chain on subcontractor failure, incl. contingency plans with service levels — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.security_standards_specified == true
	msg := "DORA RTS 2025/532 Art.4(1)(i): Contract specifies ICT security standards applicable through the subcontracting chain — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.audit_rights_flow_down == true
	msg := "DORA RTS 2025/532 Art.4(1)(j): Contract requires subcontractors to grant the entity and authorities the same access, inspection and audit rights — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.material_change_notification_clause == true
	msg := "DORA RTS 2025/532 Art.4(1)(k): Contract requires provider notification of any material change to subcontracting arrangements — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.termination_rights_clause == true
	msg := "DORA RTS 2025/532 Art.4(1)(l): Contract grants termination rights when RTS Art.6 or DORA Art.28(7) conditions are met — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.contract.remediation_timeline_documented == true
	msg := "DORA RTS 2025/532 Art.4(2): Required contractual changes implemented timely with documented implementation timelines — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.material_changes.notice_period_defined == true
	msg := "DORA RTS 2025/532 Art.5(1)-(2): Contract requires advance notice of intended material subcontracting changes with a reasonable approval/objection period — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.material_changes.approval_before_implementation == true
	msg := "DORA RTS 2025/532 Art.5(3): Material changes implemented only after entity approval or non-objection — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.material_changes.risk_tolerance_objection_process == true
	msg := "DORA RTS 2025/532 Art.5(4): Objection-and-modification process exercised when a proposed change exceeds risk tolerance, before implementation — not attested"
}

violation contains msg if {
	not input.third_party_risk.subcontracting.termination.triggers_defined == true
	msg := "DORA RTS 2025/532 Art.6: Termination triggers defined: change despite objection; change before notice expiry without approval; subcontracting of a non-permitted service — not attested"
}

compliant if {
	count(violation) == 0
}

compliance_report := {
	"family": "ICT subcontracting (critical/important functions)",
	"regulation": "Commission Delegated Regulation (EU) 2025/532, in force 2025-07-22",
	"controls_evaluated": 30,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
