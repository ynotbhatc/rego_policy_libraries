# METADATA
# title: "NIST SP 800-53 Rev 5 — Risk Assessment (RA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 13
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.risk_assessment

import rego.v1

# NIST SP 800-53 Rev 5 — Risk Assessment (RA) Family: the nine active base controls (RA-1, RA-2, RA-3, RA-5,
# RA-6, RA-7, RA-8, RA-9, RA-10; RA-4 is withdrawn) and the Moderate-baseline enhancements RA-3(1), RA-5(2),
# RA-5(5) and RA-5(11). Each enhancement is its own requirement with its own finding; a base control never
# fails on an enhancement's requirement. Facts live under input.ra_controls.

default compliant := false

_root := "ra_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null), so an absent key, null, or a value of
# the wrong type ("true", "1") lands in the "missing" set and the control fails closed. Each control builds
# one set of missing paths and one set of unmet requirements and has exactly one rule, so it can produce at
# most one finding.
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# Booleans: reqs maps a fact key to the text reported when that fact is false. Only `true` passes.
_bool_missing(sec, reqs) := {_p(array.concat(sec, [k])) | some k, _ in reqs; not is_boolean(_val(array.concat(sec, [k])))}

_bool_unmet(sec, reqs) := {d | some k, d in reqs; _val(array.concat(sec, [k])) == false}

# Organization-defined frequency: observed <sec>.days_since_last against <sec>.odp.frequency_days.
_freq_keys := [["days_since_last"], ["odp", "frequency_days"]]

_freq_missing(sec) := {_p(array.concat(sec, k)) | some k in _freq_keys; not is_number(_val(array.concat(sec, k)))}

_freq_unmet(sec, what) := {d |
	obs := _val(array.concat(sec, ["days_since_last"]))
	odp := _val(array.concat(sec, ["odp", "frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	d := sprintf("%s last %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Counts that must be zero (e.g. overdue remediations). A non-number is missing evidence.
_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not is_number(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# Attestation for organizational controls: {"attested": true, "by": <non-empty string>, "date": <non-empty string>}.
_att_ok(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_detail(sec, what) := d if {
	not _att_ok(_val(array.concat(sec, ["attestation"])))
	d := sprintf("evidence missing — no valid attestation at %s (needs attested: true and a non-empty by and date); this organizational control is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
}

# Policy and procedures (the -1 control of the family).
_pp_bools := {"documented": "policy not documented", "official_designated": "no official designated to manage the policy and procedures"}

_pp_missing := ((_bool_missing(["policy"], _pp_bools) | _bool_missing(["procedures"], {"documented": ""})) | _freq_missing(["policy"])) | _freq_missing(["procedures"])

_pp_unmet := ((_bool_unmet(["policy"], _pp_bools) | _bool_unmet(["procedures"], {"documented": "procedures not documented"})) | _freq_unmet(["policy"], "policy reviewed")) | _freq_unmet(["procedures"], "procedures reviewed")

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

# ---------------------------------------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------------------------------------

# RA-1 Policy and Procedures: input.ra_controls.policy.{documented, official_designated, days_since_last,
# odp.frequency_days} and input.ra_controls.procedures.{documented, days_since_last, odp.frequency_days}.
violation contains msg if {
	count(_pp_missing) + count(_pp_unmet) > 0
	msg := sprintf("NIST RA-1: risk assessment policy and procedures: %s", [_detail(_pp_missing, _pp_unmet)])
}

# RA-2 Security Categorization: input.ra_controls.categorization.{performed, documented_in_security_plan,
# approved_by_authorizing_official}.
_ra2 := {
	"performed": "the system and the information it processes, stores and transmits are not categorized",
	"documented_in_security_plan": "the categorization and its rationale are not documented in the security plan",
	"approved_by_authorizing_official": "the categorization decision is not reviewed and approved by the authorizing official or designated representative",
}

violation contains msg if {
	m := _bool_missing(["categorization"], _ra2)
	u := _bool_unmet(["categorization"], _ra2)
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-2: %s", [_detail(m, u)])
}

# RA-3 Risk Assessment: input.ra_controls.risk_assessment.{conducted, results_documented, results_disseminated},
# input.ra_controls.risk_assessment.review.{days_since_last, odp.frequency_days} and
# input.ra_controls.risk_assessment.update.{days_since_last, odp.frequency_days}.
_ra3 := {
	"conducted": "no risk assessment conducted (threats, vulnerabilities, likelihood and impact, including impact on individuals from PII processing)",
	"results_documented": "risk assessment results not documented",
	"results_disseminated": "risk assessment results not disseminated to the organization-defined personnel or roles",
}

violation contains msg if {
	m := (_bool_missing(["risk_assessment"], _ra3) | _freq_missing(["risk_assessment", "review"])) | _freq_missing(["risk_assessment", "update"])
	u := (_bool_unmet(["risk_assessment"], _ra3) | _freq_unmet(["risk_assessment", "review"], "risk assessment results reviewed")) | _freq_unmet(["risk_assessment", "update"], "risk assessment updated")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-3: %s", [_detail(m, u)])
}

# RA-5 Vulnerability Monitoring and Scanning: input.ra_controls.vulnerability_scanning.{days_since_last,
# odp.frequency_days, standards_based_tools, reports_analyzed, results_shared, scanner_updatable,
# overdue_remediations}. overdue_remediations counts legitimate vulnerabilities open beyond the
# organization-defined response times.
_ra5 := {
	"standards_based_tools": "scanning tools do not use standards for enumerating platforms and flaws, checklists and impact measurement",
	"reports_analyzed": "vulnerability scan reports and monitoring results are not analyzed",
	"results_shared": "vulnerability information is not shared with the organization-defined personnel or roles",
	"scanner_updatable": "scanning tools cannot readily update the vulnerabilities to be scanned",
}

violation contains msg if {
	sec := ["vulnerability_scanning"]
	m := (_bool_missing(sec, _ra5) | _freq_missing(sec)) | _zero_missing(sec, "overdue_remediations")
	u := (_bool_unmet(sec, _ra5) | _freq_unmet(sec, "vulnerability scan run")) | _zero_unmet(sec, "overdue_remediations", "vulnerabilities open beyond the organization-defined response times")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-5: %s", [_detail(m, u)])
}

# RA-6 Technical Surveillance Countermeasures Survey: input.ra_controls.tscm_survey.attestation (organizational).
violation contains msg if {
	d := _att_detail(["tscm_survey"], "technical surveillance countermeasures surveys are employed at the organization-defined locations and frequency or events")
	msg := sprintf("NIST RA-6: %s", [d])
}

# RA-7 Risk Response: input.ra_controls.risk_response.{per_risk_tolerance, unaddressed_findings}.
# unaddressed_findings counts assessment, monitoring and audit findings with no recorded response.
violation contains msg if {
	sec := ["risk_response"]
	b := {"per_risk_tolerance": "responses to findings are not made in accordance with organizational risk tolerance"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "unaddressed_findings")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "unaddressed_findings", "assessment, monitoring or audit findings have no recorded response")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-7: %s", [_detail(m, u)])
}

# RA-8 Privacy Impact Assessments: input.ra_controls.privacy_impact_assessment.attestation. Whether a PIA is
# required depends on the system and the collection, so the attestation covers both "conducted before
# development, procurement or a new collection" and "not applicable".
violation contains msg if {
	d := _att_detail(["privacy_impact_assessment"], "privacy impact assessments are conducted before developing or procuring PII-processing IT or starting a new PII collection, or none is required")
	msg := sprintf("NIST RA-8: %s", [d])
}

# RA-9 Criticality Analysis: input.ra_controls.criticality_analysis.{performed, critical_components_identified}.
_ra9 := {
	"performed": "no criticality analysis performed at the organization-defined decision points",
	"critical_components_identified": "critical system components and functions are not identified",
}

violation contains msg if {
	m := _bool_missing(["criticality_analysis"], _ra9)
	u := _bool_unmet(["criticality_analysis"], _ra9)
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-9: %s", [_detail(m, u)])
}

# RA-10 Threat Hunting: input.ra_controls.threat_hunting.{capability_established, days_since_last,
# odp.frequency_days}.
violation contains msg if {
	sec := ["threat_hunting"]
	b := {"capability_established": "no cyber threat hunting capability established"}
	m := _bool_missing(sec, b) | _freq_missing(sec)
	u := _bool_unmet(sec, b) | _freq_unmet(sec, "threat hunting employed")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-10: %s", [_detail(m, u)])
}

# ---------------------------------------------------------------------------------------------------------
# Moderate-baseline enhancements (SP 800-53B). Facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# RA-3(1) Supply Chain Risk Assessment: input.ra_controls.risk_assessment.supply_chain.{performed,
# unassessed_components, days_since_last, odp.frequency_days}. unassessed_components counts the
# organization-defined systems, components and services with no supply chain risk assessment on record;
# days_since_last is the age of the last update, compared with the organization-defined frequency.
violation contains msg if {
	sec := ["risk_assessment", "supply_chain"]
	b := {"performed": "supply chain risks are not assessed"}
	m := (_bool_missing(sec, b) | _zero_missing(sec, "unassessed_components")) | _freq_missing(sec)
	u := (_bool_unmet(sec, b) | _zero_unmet(sec, "unassessed_components", "organization-defined systems, components or services have no supply chain risk assessment")) | _freq_unmet(sec, "supply chain risk assessment updated")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-3(1): %s", [_detail(m, u)])
}

# RA-5(2) Update Vulnerabilities to Be Scanned: input.ra_controls.vulnerability_scanning.vulnerability_updates.
# {days_since_last, odp.frequency_days, updated_before_last_scan}. days_since_last is the age of the scanner's
# vulnerability feed or plugin set; updated_before_last_scan is true when the feed was refreshed before the
# most recent scan started.
violation contains msg if {
	sec := ["vulnerability_scanning", "vulnerability_updates"]
	b := {"updated_before_last_scan": "the vulnerabilities to be scanned were not updated before the most recent scan"}
	m := _bool_missing(sec, b) | _freq_missing(sec)
	u := _bool_unmet(sec, b) | _freq_unmet(sec, "vulnerabilities to be scanned updated")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-5(2): %s", [_detail(m, u)])
}

# RA-5(5) Privileged Access: input.ra_controls.vulnerability_scanning.privileged_access.{authorized,
# targets_without_privileged_scan}. authorized is true when the scanner holds an authorized privileged
# (credentialed) account for the organization-defined components; targets_without_privileged_scan counts those
# components whose last scan ran without privileged access (failed or missing credentials).
violation contains msg if {
	sec := ["vulnerability_scanning", "privileged_access"]
	b := {"authorized": "privileged access is not authorized for vulnerability scanning of the organization-defined system components"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "targets_without_privileged_scan")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "targets_without_privileged_scan", "organization-defined system components were scanned without privileged access")
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-5(5): %s", [_detail(m, u)])
}

# RA-5(11) Public Disclosure Program: input.ra_controls.vulnerability_scanning.public_disclosure.channel_published,
# true when a public vulnerability reporting channel is published and reachable (for example a vulnerability
# disclosure policy page or an RFC 9116 security.txt with a contact).
violation contains msg if {
	sec := ["vulnerability_scanning", "public_disclosure"]
	b := {"channel_published": "no public reporting channel for vulnerabilities in organizational systems and components is established"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST RA-5(11): %s", [_detail(m, u)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"RA-1", "RA-2", "RA-3", "RA-3(1)", "RA-5", "RA-5(2)", "RA-5(5)", "RA-5(11)", "RA-6", "RA-7", "RA-8", "RA-9", "RA-10"}

compliance_report := {
	"family": "RA",
	"name": "Risk Assessment",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
