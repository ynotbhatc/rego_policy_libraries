package cmmc.risk_assessment

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.11: Risk Assessment
# NIST SP 800-171 Rev 2 — 3 Practices
# =============================================================================

# 3.11.1 — Periodically assess the risk to organizational operations, assets,
#           and individuals resulting from the operation of organizational
#           systems and associated processing, storage, or transmission of CUI. (L2)
default compliant_3_11_1 := false
compliant_3_11_1 if {
    input.risk.risk_assessment_conducted == true
    input.risk.risk_assessment_frequency_days <= 365
    input.risk.risk_assessment_documented == true
}

violation_3_11_1 contains msg if {
    not input.risk.risk_assessment_conducted
    msg := "3.11.1: No periodic risk assessment has been conducted for CUI systems"
}
violation_3_11_1 contains msg if {
    input.risk.risk_assessment_frequency_days > 365
    msg := sprintf("3.11.1: Risk assessment conducted every %v days (must be at least annually)", [input.risk.risk_assessment_frequency_days])
}
violation_3_11_1 contains msg if {
    not input.risk.risk_assessment_documented
    msg := "3.11.1: Risk assessment results are not documented"
}

# 3.11.2 — Scan for vulnerabilities in organizational systems and applications
#           periodically and when new vulnerabilities affecting those systems
#           and applications are identified. (L2)
default compliant_3_11_2 := false
compliant_3_11_2 if {
    input.risk.vulnerability_scanning_enabled == true
    input.risk.scan_frequency_days <= 30
    input.risk.scan_results_reviewed == true
    input.risk.new_vuln_scan_triggered == true
}

violation_3_11_2 contains msg if {
    not input.risk.vulnerability_scanning_enabled
    msg := "3.11.2: Vulnerability scanning is not enabled for CUI systems"
}
violation_3_11_2 contains msg if {
    input.risk.scan_frequency_days > 30
    msg := sprintf("3.11.2: Vulnerability scans run every %v days (must be at least monthly)", [input.risk.scan_frequency_days])
}
violation_3_11_2 contains msg if {
    not input.risk.scan_results_reviewed
    msg := "3.11.2: Vulnerability scan results are not reviewed and acted upon"
}
violation_3_11_2 contains msg if {
    not input.risk.new_vuln_scan_triggered
    msg := "3.11.2: New vulnerability disclosures do not trigger additional scans"
}

# 3.11.3 — Remediate vulnerabilities in accordance with risk assessments. (L2)
default compliant_3_11_3 := false
compliant_3_11_3 if {
    input.risk.vuln_remediation_policy == true
    input.risk.critical_vuln_remediation_days <= 15
    input.risk.high_vuln_remediation_days <= 30
    input.risk.remediation_tracked == true
}

violation_3_11_3 contains msg if {
    not input.risk.vuln_remediation_policy
    msg := "3.11.3: No vulnerability remediation policy aligned to risk assessment"
}
violation_3_11_3 contains msg if {
    input.risk.critical_vuln_remediation_days > 15
    msg := sprintf("3.11.3: Critical vulnerabilities remediated within %v days (must be ≤15)", [input.risk.critical_vuln_remediation_days])
}
violation_3_11_3 contains msg if {
    input.risk.high_vuln_remediation_days > 30
    msg := sprintf("3.11.3: High vulnerabilities remediated within %v days (must be ≤30)", [input.risk.high_vuln_remediation_days])
}
violation_3_11_3 contains msg if {
    not input.risk.remediation_tracked
    msg := "3.11.3: Vulnerability remediation status is not tracked to closure"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_3_11_1],
        [v | some v in violation_3_11_2]
    ),
    [v | some v in violation_3_11_3]
)

practices := [
    {"id": "3.11.1", "level": 2, "compliant": compliant_3_11_1},
    {"id": "3.11.2", "level": 2, "compliant": compliant_3_11_2},
    {"id": "3.11.3", "level": 2, "compliant": compliant_3_11_3},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Risk Assessment",
    "domain_id": "3.11",
    "total_practices": 3,
    "passing": passing_count,
    "failing": 3 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
