# METADATA
# title: "NIST SP 800-171 Rev 3 - Risk Assessment (RA) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 3
#     cited: 2
#     expected: 2
#     found: 3
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.risk_assessment

import rego.v1

# NIST SP 800-171 Rev 3 - Risk Assessment (RA) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.11 Risk Assessment — Protecting Controlled Unclassified Information (CUI)

# 03.11.01 Risk Assessment (Rev 2 3.11.1): Periodically assess the risk to organizational operations, organizational assets,
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

# 03.11.02 Vulnerability Monitoring and Scanning (Rev 2 3.11.2): Scan for vulnerabilities in organizational systems and applications periodically
#          and when new vulnerabilities affecting those systems are identified
default vulnerability_scanning := false

vulnerability_scanning if {
	input.nist_800_171.risk_assessment.vulnerability_scanning.periodic_scans_performed == true
	input.nist_800_171.risk_assessment.vulnerability_scanning.triggered_on_new_vulnerabilities == true
	input.nist_800_171.risk_assessment.vulnerability_scanning.covers_all_systems == true
	input.nist_800_171.risk_assessment.vulnerability_scanning.results_documented == true
}

# 03.11.02 (Rev 2 3.11.3, withdrawn in Rev 3: Incorporated into 03.11.02.): Remediate vulnerabilities in accordance with risk assessments
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
	msg := "NIST SP 800-171 03.11.01: Risk assessments must be performed at least annually covering operations, assets, individuals, and CUI handling"
}

violations contains msg if {
	not vulnerability_scanning
	msg := "NIST SP 800-171 03.11.02: Vulnerability scans must be performed periodically and triggered when new vulnerabilities affecting systems are identified"
}

violations contains msg if {
	not vulnerability_remediation
	msg := "NIST SP 800-171 03.11.02 (Rev 2 3.11.3, withdrawn in Rev 3: Incorporated into 03.11.02.): Vulnerabilities must be remediated per risk assessment priority: critical within 15 days, high within 30 days"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.11 Risk Assessment",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 2,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.11.01_risk_assessment_performed": risk_assessment_performed,
		"03.11.02_vulnerability_scanning": vulnerability_scanning,
		"03.11.02_vulnerability_remediation": vulnerability_remediation,
	},
}
