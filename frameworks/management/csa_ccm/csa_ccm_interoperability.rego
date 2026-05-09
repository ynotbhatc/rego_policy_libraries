package csa_ccm.interoperability

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.interoperability.data_portability.requirements_documented
    msg := "IPY-01: Data portability requirements not documented — ability to export and migrate data must be formally assessed"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_portability.export_capability_verified
    msg := "IPY-01: Data export capability not verified — ability to retrieve all data from the cloud provider must be tested"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_portability.portability_sla_in_contracts
    msg := "IPY-01: Data portability provisions not included in cloud provider contracts or service agreements"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_portability.data_formats_documented
    msg := "IPY-01: Data formats used by cloud provider not documented — format dependencies must be understood for portability planning"
}

violations contains msg if {
    not input.csa_ccm.interoperability.api_standards.apis_documented
    msg := "IPY-02: APIs not documented — all interfaces used for cloud service integration must be formally documented"
}

violations contains msg if {
    not input.csa_ccm.interoperability.api_standards.standard_protocols_used
    msg := "IPY-02: Non-standard or proprietary protocols not assessed for interoperability risk — standard APIs (REST, OpenAPI) must be preferred"
}

violations contains msg if {
    not input.csa_ccm.interoperability.api_standards.api_versioning_managed
    msg := "IPY-02: API versioning not managed — deprecated API versions must have defined sunset timelines"
}

violations contains msg if {
    not input.csa_ccm.interoperability.api_standards.api_dependency_inventory
    msg := "IPY-02: Inventory of third-party API dependencies not maintained for interoperability and continuity assessment"
}

violations contains msg if {
    not input.csa_ccm.interoperability.exit_plan.exit_plan_established
    msg := "IPY-03: Exit and transition plan not established for cloud provider changes or service termination"
}

violations contains msg if {
    not input.csa_ccm.interoperability.exit_plan.data_migration_procedure_defined
    msg := "IPY-03: Data migration procedure not defined as part of exit planning — method for moving data must be documented"
}

violations contains msg if {
    not input.csa_ccm.interoperability.exit_plan.business_continuity_during_migration
    msg := "IPY-03: Business continuity requirements during provider migration not addressed in exit plan"
}

violations contains msg if {
    not input.csa_ccm.interoperability.exit_plan.exit_plan_reviewed_regularly
    msg := "IPY-03: Exit plan not reviewed regularly — plan must remain current with evolving architecture and provider landscape"
}

violations contains msg if {
    not input.csa_ccm.interoperability.exit_plan.transition_timelines_defined
    msg := "IPY-03: Transition timelines and dependencies not defined in exit plan"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_format_standards.open_standards_preferred
    msg := "IPY-04: Open data format standards not preferred — proprietary formats must be assessed for lock-in risk"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_format_standards.vendor_lock_in_assessed
    msg := "IPY-04: Vendor lock-in risk not formally assessed for each cloud service used"
}

violations contains msg if {
    not input.csa_ccm.interoperability.data_format_standards.format_standards_documented
    msg := "IPY-04: Data format standards not documented for data at rest and in transit with cloud services"
}

violations contains msg if {
    not input.csa_ccm.interoperability.portability_testing.portability_tested
    msg := "IPY-05: Portability not tested at defined intervals — ability to migrate must be periodically validated"
}

violations contains msg if {
    not input.csa_ccm.interoperability.portability_testing.test_results_documented
    msg := "IPY-05: Portability test results not documented — outcomes, gaps, and remediation steps must be recorded"
}

violations contains msg if {
    not input.csa_ccm.interoperability.portability_testing.deficiencies_remediated
    msg := "IPY-05: Portability deficiencies identified during testing not tracked to remediation"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "IPY — Interoperability & Portability",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
