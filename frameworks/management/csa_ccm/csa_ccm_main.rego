package csa_ccm.main

import rego.v1

import data.csa_ccm.audit_assurance
import data.csa_ccm.application_security
import data.csa_ccm.business_continuity
import data.csa_ccm.change_control
import data.csa_ccm.cryptography
import data.csa_ccm.data_security
import data.csa_ccm.governance
import data.csa_ccm.human_resources
import data.csa_ccm.identity_access
import data.csa_ccm.interoperability
import data.csa_ccm.infrastructure
import data.csa_ccm.logging_monitoring
import data.csa_ccm.incident_management
import data.csa_ccm.supply_chain
import data.csa_ccm.threat_vulnerability
import data.csa_ccm.endpoint_management

default overall_compliant := false

domain_reports := {
    "audit_assurance": {
        "compliant": audit_assurance.compliant,
        "details": audit_assurance.compliance_report,
    },
    "application_security": {
        "compliant": application_security.compliant,
        "details": application_security.compliance_report,
    },
    "business_continuity": {
        "compliant": business_continuity.compliant,
        "details": business_continuity.compliance_report,
    },
    "change_control": {
        "compliant": change_control.compliant,
        "details": change_control.compliance_report,
    },
    "cryptography": {
        "compliant": cryptography.compliant,
        "details": cryptography.compliance_report,
    },
    "data_security": {
        "compliant": data_security.compliant,
        "details": data_security.compliance_report,
    },
    "governance": {
        "compliant": governance.compliant,
        "details": governance.compliance_report,
    },
    "human_resources": {
        "compliant": human_resources.compliant,
        "details": human_resources.compliance_report,
    },
    "identity_access": {
        "compliant": identity_access.compliant,
        "details": identity_access.compliance_report,
    },
    "interoperability": {
        "compliant": interoperability.compliant,
        "details": interoperability.compliance_report,
    },
    "infrastructure": {
        "compliant": infrastructure.compliant,
        "details": infrastructure.compliance_report,
    },
    "logging_monitoring": {
        "compliant": logging_monitoring.compliant,
        "details": logging_monitoring.compliance_report,
    },
    "incident_management": {
        "compliant": incident_management.compliant,
        "details": incident_management.compliance_report,
    },
    "supply_chain": {
        "compliant": supply_chain.compliant,
        "details": supply_chain.compliance_report,
    },
    "threat_vulnerability": {
        "compliant": threat_vulnerability.compliant,
        "details": threat_vulnerability.compliance_report,
    },
    "endpoint_management": {
        "compliant": endpoint_management.compliant,
        "details": endpoint_management.compliance_report,
    },
}

domains_passing := count([domain |
    some domain, report in domain_reports
    report.compliant == true
])

overall_compliant if {
    audit_assurance.compliant
    application_security.compliant
    business_continuity.compliant
    change_control.compliant
    cryptography.compliant
    data_security.compliant
    governance.compliant
    human_resources.compliant
    identity_access.compliant
    interoperability.compliant
    infrastructure.compliant
    logging_monitoring.compliant
    incident_management.compliant
    supply_chain.compliant
    threat_vulnerability.compliant
    endpoint_management.compliant
}

compliance_report := {
    "framework":       "Cloud Security Alliance Cloud Controls Matrix (CSA CCM)",
    "compliant":       overall_compliant,
    "total_controls":  197,
    "violations":      [],
    "violation_count": 0,
    "standard": "CSA Cloud Controls Matrix (CCM) v4.0",
    "overall_compliant": overall_compliant,
    "domains_passing": domains_passing,
    "domains_total": 16,
    "domains": domain_reports,
}
