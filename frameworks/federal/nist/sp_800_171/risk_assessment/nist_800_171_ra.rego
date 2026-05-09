package nist.sp800_171.risk_assessment

import rego.v1

# NIST SP 800-171 Rev 3 - Risk Assessment (RA) Requirements
# Family: 3.11 — Protecting Controlled Unclassified Information (CUI)

# 3.11.1: Periodically assess the risk to organizational operations, organizational assets,
#          and individuals, resulting from the operation of organizational systems and the
#          associated processing, storage, or transmission of CUI (at least annually)
default risk_assessment_performed := false

risk_assessment_performed if {
    input.nist_800_171.risk_assessment.assessment.performed_annually == true
    input.nist_800_171.risk_assessment.assessment.covers_operations == true
    input.nist_800_171.risk_assessment.assessment.covers_assets == true
    input.nist_800_171.risk_assessment.assessment.covers_individuals == true
    input.nist_800_171.risk_assessment.assessment.results_documented == true
}

# 3.11.2: Scan for vulnerabilities in organizational systems and applications periodically
#          and when new vulnerabilities affecting those systems are identified
default vulnerability_scanning := false

vulnerability_scanning if {
    input.nist_800_171.risk_assessment.vulnerability_scanning.periodic_scans_performed == true
    input.nist_800_171.risk_assessment.vulnerability_scanning.triggered_on_new_vulnerabilities == true
    input.nist_800_171.risk_assessment.vulnerability_scanning.covers_all_systems == true
    input.nist_800_171.risk_assessment.vulnerability_scanning.results_documented == true
}

# 3.11.3: Remediate vulnerabilities in accordance with risk assessments
#          (critical vulnerabilities within 15 days, high within 30 days)
default vulnerability_remediation := false

vulnerability_remediation if {
    input.nist_800_171.risk_assessment.remediation.risk_based_prioritization == true
    input.nist_800_171.risk_assessment.remediation.critical_days <= 15
    input.nist_800_171.risk_assessment.remediation.high_days <= 30
    input.nist_800_171.risk_assessment.remediation.tracking_system == true
}

# Violations set
violations contains msg if {
    not risk_assessment_performed
    msg := "NIST 800-171 3.11.1: Risk assessments must be performed at least annually covering operations, assets, individuals, and CUI handling"
}

violations contains msg if {
    not vulnerability_scanning
    msg := "NIST 800-171 3.11.2: Vulnerability scans must be performed periodically and triggered when new vulnerabilities affecting systems are identified"
}

violations contains msg if {
    not vulnerability_remediation
    msg := "NIST 800-171 3.11.3: Vulnerabilities must be remediated per risk assessment priority: critical within 15 days, high within 30 days"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.11 Risk Assessment",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 3,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.11.1_risk_assessment_performed": risk_assessment_performed,
        "3.11.2_vulnerability_scanning": vulnerability_scanning,
        "3.11.3_vulnerability_remediation": vulnerability_remediation,
    },
}
