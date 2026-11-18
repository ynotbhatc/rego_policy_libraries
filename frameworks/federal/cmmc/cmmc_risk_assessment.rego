# METADATA
# title: "CMMC 2.0 — Domain 3.11: Risk Assessment"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 27
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.risk_assessment

import rego.v1

# Organisation-defined parameters. Where NIST SP 800-171 R2 leaves a period,
# frequency or count to the organisation ("a defined period", "periodically",
# "a specified number"; NIST SP 800-171A objectives "... is defined"), the
# organisation's value is read from input.org_defined.<name> and the observed
# value is compared with it. Either one missing, or not a number, is a finding.
# is_number guards every comparison: OPA orders null below numbers and strings
# above them.
_odp(name) := v if {
	v := input.org_defined[name]
	is_number(v)
}

_actual(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

_at_most(path, name) if _actual(path) <= _odp(name)

_at_least(path, name) if _actual(path) >= _odp(name)

# 32 CFR 170.14(d): "periodically" means an organisation-defined interval of no
# more than one year.
_periodic_ok(name) if _odp(name) <= 365

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
	_at_most(["risk", "risk_assessment_frequency_days"], "risk_assessment_interval_days")
	_periodic_ok("risk_assessment_interval_days")
	input.risk.risk_assessment_documented == true
}

violation_3_11_1 contains msg if {
	not input.risk.risk_assessment_conducted
	msg := "3.11.1: No periodic risk assessment has been conducted for CUI systems"
}

violation_3_11_1 contains "3.11.1: evidence missing - input.org_defined.risk_assessment_interval_days (organisation-defined value, NIST SP 800-171A 3.11.1[a]) not supplied or not a number" if {
	not _odp("risk_assessment_interval_days")
}

violation_3_11_1 contains "3.11.1: evidence missing - input.risk.risk_assessment_frequency_days not collected or not a number" if {
	not _actual(["risk", "risk_assessment_frequency_days"])
}

violation_3_11_1 contains msg if {
	_actual(["risk", "risk_assessment_frequency_days"]) > _odp("risk_assessment_interval_days")
	msg := sprintf("3.11.1: risk assessed every %v days, beyond the organisation-defined interval of %v days", [_actual(["risk", "risk_assessment_frequency_days"]), _odp("risk_assessment_interval_days")])
}

violation_3_11_1 contains msg if {
	_odp("risk_assessment_interval_days") > 365
	msg := sprintf("3.11.1: the organisation-defined interval of %v days exceeds one year; 32 CFR 170.14(d) limits a periodic interval to one year", [_odp("risk_assessment_interval_days")])
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
	_at_most(["risk", "scan_frequency_days"], "vulnerability_scan_interval_days")
	_periodic_ok("vulnerability_scan_interval_days")
	input.risk.scan_results_reviewed == true
	input.risk.new_vuln_scan_triggered == true
}

violation_3_11_2 contains msg if {
	not input.risk.vulnerability_scanning_enabled
	msg := "3.11.2: Vulnerability scanning is not enabled for CUI systems"
}

violation_3_11_2 contains "3.11.2: evidence missing - input.org_defined.vulnerability_scan_interval_days (organisation-defined value, NIST SP 800-171A 3.11.2[a]) not supplied or not a number" if {
	not _odp("vulnerability_scan_interval_days")
}

violation_3_11_2 contains "3.11.2: evidence missing - input.risk.scan_frequency_days not collected or not a number" if {
	not _actual(["risk", "scan_frequency_days"])
}

violation_3_11_2 contains msg if {
	_actual(["risk", "scan_frequency_days"]) > _odp("vulnerability_scan_interval_days")
	msg := sprintf("3.11.2: vulnerability scans run every %v days, beyond the organisation-defined interval of %v days", [_actual(["risk", "scan_frequency_days"]), _odp("vulnerability_scan_interval_days")])
}

violation_3_11_2 contains msg if {
	_odp("vulnerability_scan_interval_days") > 365
	msg := sprintf("3.11.2: the organisation-defined interval of %v days exceeds one year; 32 CFR 170.14(d) limits a periodic interval to one year", [_odp("vulnerability_scan_interval_days")])
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
	_at_most(["risk", "critical_vuln_remediation_days"], "critical_vulnerability_remediation_days")
	_at_most(["risk", "high_vuln_remediation_days"], "high_vulnerability_remediation_days")
	input.risk.remediation_tracked == true
}

violation_3_11_3 contains msg if {
	not input.risk.vuln_remediation_policy
	msg := "3.11.3: No vulnerability remediation policy aligned to risk assessment"
}

violation_3_11_3 contains "3.11.3: evidence missing - input.org_defined.critical_vulnerability_remediation_days (organisation-defined value, NIST SP 800-171A (R2 3.11.3: in accordance with risk assessments)) not supplied or not a number" if {
	not _odp("critical_vulnerability_remediation_days")
}

violation_3_11_3 contains "3.11.3: evidence missing - input.risk.critical_vuln_remediation_days not collected or not a number" if {
	not _actual(["risk", "critical_vuln_remediation_days"])
}

violation_3_11_3 contains msg if {
	_actual(["risk", "critical_vuln_remediation_days"]) > _odp("critical_vulnerability_remediation_days")
	msg := sprintf("3.11.3: critical vulnerabilities remediated within %v days, beyond the organisation's risk-based %v days", [_actual(["risk", "critical_vuln_remediation_days"]), _odp("critical_vulnerability_remediation_days")])
}

violation_3_11_3 contains "3.11.3: evidence missing - input.org_defined.high_vulnerability_remediation_days (organisation-defined value, NIST SP 800-171A (R2 3.11.3: in accordance with risk assessments)) not supplied or not a number" if {
	not _odp("high_vulnerability_remediation_days")
}

violation_3_11_3 contains "3.11.3: evidence missing - input.risk.high_vuln_remediation_days not collected or not a number" if {
	not _actual(["risk", "high_vuln_remediation_days"])
}

violation_3_11_3 contains msg if {
	_actual(["risk", "high_vuln_remediation_days"]) > _odp("high_vulnerability_remediation_days")
	msg := sprintf("3.11.3: high vulnerabilities remediated within %v days, beyond the organisation's risk-based %v days", [_actual(["risk", "high_vuln_remediation_days"]), _odp("high_vulnerability_remediation_days")])
}

violation_3_11_3 contains msg if {
	not input.risk.remediation_tracked
	msg := "3.11.3: Vulnerability remediation status is not tracked to closure"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

base_violations := array.concat(
	array.concat(
		[v | some v in violation_3_11_1],
		[v | some v in violation_3_11_2],
	),
	[v | some v in violation_3_11_3],
)

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing or failing must surface a violation, so that the domain verdict
#   (count(all_violations) == 0) can never be true while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	not compliant_3_11_1
	count(violation_3_11_1) == 0
	msg := "3.11.1: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_11_2
	count(violation_3_11_2) == 0
	msg := "3.11.2: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_11_3
	count(violation_3_11_3) == 0
	msg := "3.11.3: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

all_violations := array.concat(base_violations, [m | some m in violation_unmet])

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
	"practices": practices,
}
