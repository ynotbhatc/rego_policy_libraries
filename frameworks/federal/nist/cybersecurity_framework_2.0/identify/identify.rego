package nist.csf.identify

import rego.v1

# NIST Cybersecurity Framework 2.0 — IDENTIFY (ID) function
# Develop the organizational understanding to manage cybersecurity risk to
# systems, people, assets, data, and capabilities.

default compliant := false

# ID.AM — Asset Management
violation contains msg if {
    not input.identify.asset_management.physical_devices_inventoried
    msg := "CSF ID.AM-01: Physical devices and systems not inventoried"
}

violation contains msg if {
    not input.identify.asset_management.software_platforms_inventoried
    msg := "CSF ID.AM-02: Software platforms and applications not inventoried"
}

violation contains msg if {
    not input.identify.asset_management.organizational_communication_mapped
    msg := "CSF ID.AM-03: Organizational communication and data flows not mapped"
}

violation contains msg if {
    not input.identify.asset_management.external_systems_cataloged
    msg := "CSF ID.AM-04: External information systems not cataloged"
}

violation contains msg if {
    not input.identify.asset_management.resources_prioritized
    msg := "CSF ID.AM-05: Resources not prioritized based on classification/criticality"
}

# ID.BE — Business Environment
violation contains msg if {
    not input.identify.business_environment.role_in_supply_chain_identified
    msg := "CSF ID.BE-01: Organization's role in the supply chain not identified/communicated"
}

violation contains msg if {
    not input.identify.business_environment.role_in_critical_infrastructure_identified
    msg := "CSF ID.BE-02: Role in critical infrastructure / sector not identified"
}

violation contains msg if {
    not input.identify.business_environment.priorities_for_mission_established
    msg := "CSF ID.BE-03: Priorities for organizational mission/objectives/activities not established"
}

# ID.GV — Governance (deferred to GOVERN function in CSF 2.0; included here for legacy)

# ID.RA — Risk Assessment
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

# ID.RM — Risk Management Strategy
violation contains msg if {
    not input.identify.risk_management.processes_established
    msg := "CSF ID.RM-01: Risk management processes not established/managed/agreed-to"
}

violation contains msg if {
    not input.identify.risk_management.risk_tolerance_determined
    msg := "CSF ID.RM-02: Organizational risk tolerance not determined or clearly expressed"
}

# ID.SC — Supply Chain Risk Management
violation contains msg if {
    not input.identify.supply_chain.cyber_scrm_processes_established
    msg := "CSF ID.SC-01: Cyber supply chain risk management processes not established"
}

violation contains msg if {
    not input.identify.supply_chain.suppliers_identified
    msg := "CSF ID.SC-02: Suppliers and third-party partners not identified/prioritized/assessed"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "function": "IDENTIFY",
    "controls_evaluated": 17,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
