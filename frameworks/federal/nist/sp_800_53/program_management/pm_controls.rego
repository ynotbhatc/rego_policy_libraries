# METADATA
# title: "NIST SP 800-53 Rev 5 — Program Management (PM) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 51
#     cited: 34
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.program_management

import rego.v1

# NIST SP 800-53 Rev 5 — Program Management (PM) Family
# Base controls PM-1 to PM-32 and the Privacy-baseline enhancements PM-5(1) and PM-20(1). Program management is mostly organizational: where a control has no
# machine-checkable evidence it passes only on an attestation object at input.pm_controls.<name>.attestation.
# Other facts live under input.pm_controls and fail closed: a fact that is absent or of the wrong type is
# reported as evidence missing, never as a pass. Booleans pass only on true; numbers must be non-negative
# numbers. Organization-defined frequencies and time periods are compared as an observed value against the
# organisation's own value under .odp, as in IR-2/IR-3.

default compliant := false

_prefix := "input.pm_controls"

_pm := v if {
	v := object.get(input, "pm_controls", {})
	is_object(v)
} else := {}

# --- shared fact checker -----------------------------------------------------------------------------------
# A spec is an object with optional keys:
#   bools:   [[path, text when false]]           pass only on true; a non-boolean is evidence missing
#   strings: [path]                              a non-empty string; anything else is evidence missing
#   bounds:  [[observed path, odp path, fmt]]    both non-negative numbers; observed > odp is unmet
#   zeros:   [[path, fmt]]                       a non-negative whole number; above zero is unmet
_get(p) := object.get(_pm, p, null)

_path(p) := concat(".", array.concat([_prefix], p))

_num(x) if {
	is_number(x)
	x >= 0
}

# A count (zeros): a non-negative whole number.
_count(x) if {
	_num(x)
	floor(x) == x
}

_text(x) if {
	is_string(x)
	trim_space(x) != ""
}

_missing(spec) := ((b | s) | n) | z if {
	b := {_path(e[0]) | some e in object.get(spec, "bools", []); not is_boolean(_get(e[0]))}
	s := {_path(p) | some p in object.get(spec, "strings", []); not _text(_get(p))}
	n := {_path(p) | some e in object.get(spec, "bounds", []); some p in [e[0], e[1]]; not _num(_get(p))}
	z := {_path(e[0]) | some e in object.get(spec, "zeros", []); not _count(_get(e[0]))}
}

_gaps(spec) := (b | n) | z if {
	b := {e[1] | some e in object.get(spec, "bools", []); _get(e[0]) == false}
	n := {sprintf(e[2], [o, l]) |
		some e in object.get(spec, "bounds", [])
		o := _get(e[0])
		l := _get(e[1])
		_num(o)
		_num(l)
		o > l
	}
	z := {sprintf(e[1], [v]) | some e in object.get(spec, "zeros", []); v := _get(e[0]); is_number(v); _count(v); v > 0}
}

_assess(spec) := {"missing": _missing(spec), "gaps": _gaps(spec)}

# Unmet requirements appended to an evidence-missing finding, so one finding lists every unmet element.
_also(g) := "" if {
	count(g) == 0
} else := concat("", ["; also not met: ", concat("; ", sort(g))])

# Organization-defined frequency (IR-2/IR-3 pattern): <p>.days_since_last against <p>.odp.frequency_days.
_freq(p, what) := [
	array.concat(p, ["days_since_last"]),
	array.concat(p, ["odp", "frequency_days"]),
	concat("", [what, " %v days ago; the organization-defined frequency is %v days"]),
]

# Organizational controls with no machine-checkable evidence pass only on an attestation object
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>} at input.pm_controls.<name>.attestation.
_attested(name) if {
	a := object.get(_pm, [name, "attestation"], null)
	a.attested == true
	_text(a.by)
	_text(a.date)
}

# --- PM-1 ---
# Information Security Program Plan. Facts: input.pm_controls.security_program_plan.documented (plan developed with the
# PM-1a content), .disseminated, .approved_by_senior_official, .protected (booleans);
# input.pm_controls.security_program_plan.days_since_last / .odp.frequency_days (PM-1b).
_pm1 := _assess({"bools": [[["security_program_plan", "documented"], "organization-wide information security program plan not developed"], [["security_program_plan", "disseminated"], "information security program plan not disseminated"], [["security_program_plan", "approved_by_senior_official"], "information security program plan not approved by an accountable senior official"], [["security_program_plan", "protected"], "information security program plan not protected from unauthorized disclosure and modification"]], "bounds": [_freq(["security_program_plan"], "information security program plan last reviewed")]})

violation contains msg if {
	count(_pm1.missing) > 0
	msg := sprintf("NIST PM-1: evidence missing — %s not collected%s", [concat(", ", sort(_pm1.missing)), _also(_pm1.gaps)])
}

violation contains msg if {
	count(_pm1.missing) == 0
	count(_pm1.gaps) > 0
	msg := sprintf("NIST PM-1: information security program plan requirements not met: %s", [concat("; ", sort(_pm1.gaps))])
}

# --- PM-2 ---
# Information Security Program Leadership Role: a senior agency information security officer is appointed.
# Evidence: attestation at input.pm_controls.security_officer.attestation (organizational control).
violation contains msg if {
	not _attested("security_officer")
	msg := "NIST PM-2: appointment of a senior agency information security officer with mission and resources not attested — organizational control with no machine-checkable evidence; input.pm_controls.security_officer.attestation must be {attested: true, by, date}"
}

# --- PM-3 ---
# Information Security and Privacy Resources: resources in capital planning and investment requests.
# Evidence: attestation at input.pm_controls.program_resources.attestation (organizational control).
violation contains msg if {
	not _attested("program_resources")
	msg := "NIST PM-3: inclusion of security and privacy program resources in capital planning and investment requests not attested — organizational control with no machine-checkable evidence; input.pm_controls.program_resources.attestation must be {attested: true, by, date}"
}

# --- PM-4 ---
# Plan of Action and Milestones Process. Facts: input.pm_controls.poam.process_implemented (POA&Ms developed, maintained and
# documenting remedial actions for security, privacy and supply chain risk), .reported (per reporting
# requirements), .reviewed_against_risk_strategy (booleans).
_pm4 := _assess({"bools": [[["poam", "process_implemented"], "no process ensures POA&Ms are developed, maintained and document remedial actions"], [["poam", "reported"], "POA&Ms not reported in accordance with established reporting requirements"], [["poam", "reviewed_against_risk_strategy"], "POA&Ms not reviewed for consistency with the risk management strategy and risk response priorities"]]})

violation contains msg if {
	count(_pm4.missing) > 0
	msg := sprintf("NIST PM-4: evidence missing — %s not collected%s", [concat(", ", sort(_pm4.missing)), _also(_pm4.gaps)])
}

violation contains msg if {
	count(_pm4.missing) == 0
	count(_pm4.gaps) > 0
	msg := sprintf("NIST PM-4: plan of action and milestones process requirements not met: %s", [concat("; ", sort(_pm4.gaps))])
}

# --- PM-5 ---
# System Inventory. Facts: input.pm_controls.system_inventory.maintained (boolean); input.pm_controls.system_inventory.days_since_last /
# .odp.frequency_days (time since the inventory was last updated).
_pm5 := _assess({"bools": [[["system_inventory", "maintained"], "no inventory of organizational systems maintained"]], "bounds": [_freq(["system_inventory"], "system inventory last updated")]})

violation contains msg if {
	count(_pm5.missing) > 0
	msg := sprintf("NIST PM-5: evidence missing — %s not collected%s", [concat(", ", sort(_pm5.missing)), _also(_pm5.gaps)])
}

violation contains msg if {
	count(_pm5.missing) == 0
	count(_pm5.gaps) > 0
	msg := sprintf("NIST PM-5: system inventory requirements not met: %s", [concat("; ", sort(_pm5.gaps))])
}

# --- PM-6 ---
# Measures of Performance: security and privacy measures developed, monitored and reported.
# Evidence: attestation at input.pm_controls.performance_measures.attestation (organizational control).
violation contains msg if {
	not _attested("performance_measures")
	msg := "NIST PM-6: development, monitoring and reporting of security and privacy measures of performance not attested — organizational control with no machine-checkable evidence; input.pm_controls.performance_measures.attestation must be {attested: true, by, date}"
}

# --- PM-7 ---
# Enterprise Architecture: developed and maintained with consideration for security and privacy.
# Evidence: attestation at input.pm_controls.enterprise_architecture.attestation (organizational control).
violation contains msg if {
	not _attested("enterprise_architecture")
	msg := "NIST PM-7: an enterprise architecture developed and maintained with security and privacy considered not attested — organizational control with no machine-checkable evidence; input.pm_controls.enterprise_architecture.attestation must be {attested: true, by, date}"
}

# --- PM-8 ---
# Critical Infrastructure Plan: security and privacy addressed in the CI/KR protection plan.
# Evidence: attestation at input.pm_controls.critical_infrastructure_plan.attestation (organizational control).
violation contains msg if {
	not _attested("critical_infrastructure_plan")
	msg := "NIST PM-8: security and privacy addressed in the critical infrastructure and key resources protection plan not attested — organizational control with no machine-checkable evidence; input.pm_controls.critical_infrastructure_plan.attestation must be {attested: true, by, date}"
}

# --- PM-9 ---
# Risk Management Strategy. Facts: input.pm_controls.risk_management_strategy.documented (security and privacy risk),
# .implemented_consistently (booleans); input.pm_controls.risk_management_strategy.days_since_last / .odp.frequency_days.
_pm9 := _assess({"bools": [[["risk_management_strategy", "documented"], "no comprehensive strategy for managing security and privacy risk"], [["risk_management_strategy", "implemented_consistently"], "risk management strategy not implemented consistently across the organization"]], "bounds": [_freq(["risk_management_strategy"], "risk management strategy last reviewed")]})

violation contains msg if {
	count(_pm9.missing) > 0
	msg := sprintf("NIST PM-9: evidence missing — %s not collected%s", [concat(", ", sort(_pm9.missing)), _also(_pm9.gaps)])
}

violation contains msg if {
	count(_pm9.missing) == 0
	count(_pm9.gaps) > 0
	msg := sprintf("NIST PM-9: risk management strategy requirements not met: %s", [concat("; ", sort(_pm9.gaps))])
}

# --- PM-10 ---
# Authorization Process: security and privacy state managed through authorization processes integrated into risk management.
# Evidence: attestation at input.pm_controls.authorization_process.attestation (organizational control).
violation contains msg if {
	not _attested("authorization_process")
	msg := "NIST PM-10: management of systems through authorization processes integrated into the risk management program not attested — organizational control with no machine-checkable evidence; input.pm_controls.authorization_process.attestation must be {attested: true, by, date}"
}

# --- PM-11 ---
# Mission and Business Process Definition. Facts: input.pm_controls.mission_business_processes.defined,
# .protection_needs_determined (booleans); input.pm_controls.mission_business_processes.days_since_last / .odp.frequency_days.
_pm11 := _assess({"bools": [[["mission_business_processes", "defined"], "mission and business processes not defined with consideration for security and privacy"], [["mission_business_processes", "protection_needs_determined"], "information protection and PII processing needs not determined from the mission and business processes"]], "bounds": [_freq(["mission_business_processes"], "mission and business processes last reviewed")]})

violation contains msg if {
	count(_pm11.missing) > 0
	msg := sprintf("NIST PM-11: evidence missing — %s not collected%s", [concat(", ", sort(_pm11.missing)), _also(_pm11.gaps)])
}

violation contains msg if {
	count(_pm11.missing) == 0
	count(_pm11.gaps) > 0
	msg := sprintf("NIST PM-11: mission and business process definition requirements not met: %s", [concat("; ", sort(_pm11.gaps))])
}

# --- PM-12 ---
# Insider Threat Program: implemented, with a cross-discipline incident handling team.
# Evidence: attestation at input.pm_controls.insider_threat_program.attestation (organizational control).
violation contains msg if {
	not _attested("insider_threat_program")
	msg := "NIST PM-12: an insider threat program with a cross-discipline insider threat incident handling team not attested — organizational control with no machine-checkable evidence; input.pm_controls.insider_threat_program.attestation must be {attested: true, by, date}"
}

# --- PM-13 ---
# Security and Privacy Workforce: development and improvement program established.
# Evidence: attestation at input.pm_controls.workforce_program.attestation (organizational control).
violation contains msg if {
	not _attested("workforce_program")
	msg := "NIST PM-13: a security and privacy workforce development and improvement program not attested — organizational control with no machine-checkable evidence; input.pm_controls.workforce_program.attestation must be {attested: true, by, date}"
}

# --- PM-14 ---
# Testing, Training, and Monitoring: plans developed, maintained, executed and reviewed.
# Evidence: attestation at input.pm_controls.testing_training_monitoring.attestation (organizational control).
violation contains msg if {
	not _attested("testing_training_monitoring")
	msg := "NIST PM-14: a process keeping security and privacy testing, training and monitoring plans developed, executed and reviewed not attested — organizational control with no machine-checkable evidence; input.pm_controls.testing_training_monitoring.attestation must be {attested: true, by, date}"
}

# --- PM-15 ---
# Security and Privacy Groups and Associations: contact established and institutionalized.
# Evidence: attestation at input.pm_controls.groups_associations.attestation (organizational control).
violation contains msg if {
	not _attested("groups_associations")
	msg := "NIST PM-15: institutionalized contact with security and privacy groups and associations not attested — organizational control with no machine-checkable evidence; input.pm_controls.groups_associations.attestation must be {attested: true, by, date}"
}

# --- PM-16 ---
# Threat Awareness Program: includes cross-organization threat intelligence sharing.
# Evidence: attestation at input.pm_controls.threat_awareness_program.attestation (organizational control).
violation contains msg if {
	not _attested("threat_awareness_program")
	msg := "NIST PM-16: a threat awareness program with cross-organization threat intelligence sharing not attested — organizational control with no machine-checkable evidence; input.pm_controls.threat_awareness_program.attestation must be {attested: true, by, date}"
}

# --- PM-17 ---
# Protecting CUI on External Systems. Facts: input.pm_controls.cui_external_systems.policy_established (policy and procedures
# for protecting CUI on external systems, boolean); input.pm_controls.cui_external_systems.days_since_last / .odp.frequency_days.
_pm17 := _assess({"bools": [[["cui_external_systems", "policy_established"], "no policy and procedures for protecting CUI processed, stored or transmitted on external systems"]], "bounds": [_freq(["cui_external_systems"], "CUI external-system policy and procedures last reviewed")]})

violation contains msg if {
	count(_pm17.missing) > 0
	msg := sprintf("NIST PM-17: evidence missing — %s not collected%s", [concat(", ", sort(_pm17.missing)), _also(_pm17.gaps)])
}

violation contains msg if {
	count(_pm17.missing) == 0
	count(_pm17.gaps) > 0
	msg := sprintf("NIST PM-17: CUI on external systems requirements not met: %s", [concat("; ", sort(_pm17.gaps))])
}

# --- PM-18 ---
# Privacy Program Plan. Facts: input.pm_controls.privacy_program_plan.documented (plan with the PM-18a content), .disseminated,
# .approved_by_senior_official (booleans); input.pm_controls.privacy_program_plan.days_since_last / .odp.frequency_days (PM-18b).
_pm18 := _assess({"bools": [[["privacy_program_plan", "documented"], "organization-wide privacy program plan not developed"], [["privacy_program_plan", "disseminated"], "privacy program plan not disseminated"], [["privacy_program_plan", "approved_by_senior_official"], "privacy program plan not approved by an accountable senior official"]], "bounds": [_freq(["privacy_program_plan"], "privacy program plan last updated")]})

violation contains msg if {
	count(_pm18.missing) > 0
	msg := sprintf("NIST PM-18: evidence missing — %s not collected%s", [concat(", ", sort(_pm18.missing)), _also(_pm18.gaps)])
}

violation contains msg if {
	count(_pm18.missing) == 0
	count(_pm18.gaps) > 0
	msg := sprintf("NIST PM-18: privacy program plan requirements not met: %s", [concat("; ", sort(_pm18.gaps))])
}

# --- PM-19 ---
# Privacy Program Leadership Role: a senior agency official for privacy is appointed.
# Evidence: attestation at input.pm_controls.privacy_officer.attestation (organizational control).
violation contains msg if {
	not _attested("privacy_officer")
	msg := "NIST PM-19: appointment of a senior agency official for privacy with authority and resources not attested — organizational control with no machine-checkable evidence; input.pm_controls.privacy_officer.attestation must be {attested: true, by, date}"
}

# --- PM-20 ---
# Dissemination of Privacy Program Information: central privacy webpage on the principal public website.
# Evidence: attestation at input.pm_controls.privacy_program_webpage.attestation (organizational control).
violation contains msg if {
	not _attested("privacy_program_webpage")
	msg := "NIST PM-20: a central privacy program webpage with public contact channels not attested — organizational control with no machine-checkable evidence; input.pm_controls.privacy_program_webpage.attestation must be {attested: true, by, date}"
}

# --- PM-21 ---
# Accounting of Disclosures. Facts: input.pm_controls.disclosure_accounting.maintained (date, nature, purpose and recipient of
# each PII disclosure), .retention_met (kept for the life of the PII or five years, whichever is longer),
# .available_on_request (booleans).
_pm21 := _assess({"bools": [[["disclosure_accounting", "maintained"], "no accurate accounting of PII disclosures (date, nature, purpose, recipient) maintained"], [["disclosure_accounting", "retention_met"], "accounting of disclosures not retained for the life of the PII or five years, whichever is longer"], [["disclosure_accounting", "available_on_request"], "accounting of disclosures not made available to the individual on request"]]})

violation contains msg if {
	count(_pm21.missing) > 0
	msg := sprintf("NIST PM-21: evidence missing — %s not collected%s", [concat(", ", sort(_pm21.missing)), _also(_pm21.gaps)])
}

violation contains msg if {
	count(_pm21.missing) == 0
	count(_pm21.gaps) > 0
	msg := sprintf("NIST PM-21: accounting of disclosures requirements not met: %s", [concat("; ", sort(_pm21.gaps))])
}

# --- PM-22 ---
# PII Quality Management. Facts: input.pm_controls.pii_quality.policies_documented (policies and procedures for accuracy review,
# correction or deletion, notice of corrections, and appeals; boolean).
_pm22 := _assess({"bools": [[["pii_quality", "policies_documented"], "organization-wide PII quality management policies and procedures not documented"]]})

violation contains msg if {
	count(_pm22.missing) > 0
	msg := sprintf("NIST PM-22: evidence missing — %s not collected%s", [concat(", ", sort(_pm22.missing)), _also(_pm22.gaps)])
}

violation contains msg if {
	count(_pm22.missing) == 0
	count(_pm22.gaps) > 0
	msg := sprintf("NIST PM-22: PII quality management requirements not met: %s", [concat("; ", sort(_pm22.gaps))])
}

# --- PM-23 ---
# Data Governance Body: established with the organization-defined roles and responsibilities.
# Evidence: attestation at input.pm_controls.data_governance_body.attestation (organizational control).
violation contains msg if {
	not _attested("data_governance_body")
	msg := "NIST PM-23: a data governance body with the organization-defined roles and responsibilities not attested — organizational control with no machine-checkable evidence; input.pm_controls.data_governance_body.attestation must be {attested: true, by, date}"
}

# --- PM-24 ---
# Data Integrity Board: reviews matching program proposals and conducts an annual review.
# Evidence: attestation at input.pm_controls.data_integrity_board.attestation (organizational control).
violation contains msg if {
	not _attested("data_integrity_board")
	msg := "NIST PM-24: a data integrity board reviewing matching programs not attested — organizational control with no machine-checkable evidence; input.pm_controls.data_integrity_board.attestation must be {attested: true, by, date}"
}

# --- PM-25 ---
# Minimization of PII in Testing, Training, and Research. Facts: input.pm_controls.pii_test_train_research.policies_documented,
# .use_minimized, .use_authorized (booleans); input.pm_controls.pii_test_train_research.days_since_last / .odp.frequency_days.
_pm25 := _assess({"bools": [[["pii_test_train_research", "policies_documented"], "policies and procedures for PII use in testing, training and research not documented and implemented"], [["pii_test_train_research", "use_minimized"], "PII used for testing, training and research not limited or minimized"], [["pii_test_train_research", "use_authorized"], "use of PII for testing, training and research not authorized"]], "bounds": [_freq(["pii_test_train_research"], "PII testing, training and research policies last reviewed")]})

violation contains msg if {
	count(_pm25.missing) > 0
	msg := sprintf("NIST PM-25: evidence missing — %s not collected%s", [concat(", ", sort(_pm25.missing)), _also(_pm25.gaps)])
}

violation contains msg if {
	count(_pm25.missing) == 0
	count(_pm25.gaps) > 0
	msg := sprintf("NIST PM-25: PII minimization in testing, training and research requirements not met: %s", [concat("; ", sort(_pm25.gaps))])
}

# --- PM-26 ---
# Complaint Management. Facts: input.pm_controls.complaint_management.process_implemented (accessible mechanisms and filing
# information, boolean); observed maxima against the organization-defined time periods:
# .max_days_to_address vs .odp.address_within_days, .max_days_to_acknowledge vs .odp.acknowledge_within_days,
# .max_days_to_respond vs .odp.respond_within_days.
_pm26 := _assess({"bools": [[["complaint_management", "process_implemented"], "no accessible process for receiving and responding to security and privacy complaints"]], "bounds": [[["complaint_management", "max_days_to_address"], ["complaint_management", "odp", "address_within_days"], "complaints reviewed and addressed up to %v days after receipt; the organization-defined period is %v days"], [["complaint_management", "max_days_to_acknowledge"], ["complaint_management", "odp", "acknowledge_within_days"], "complaints acknowledged up to %v days after receipt; the organization-defined period is %v days"], [["complaint_management", "max_days_to_respond"], ["complaint_management", "odp", "respond_within_days"], "complaints answered up to %v days after receipt; the organization-defined period is %v days"]]})

violation contains msg if {
	count(_pm26.missing) > 0
	msg := sprintf("NIST PM-26: evidence missing — %s not collected%s", [concat(", ", sort(_pm26.missing)), _also(_pm26.gaps)])
}

violation contains msg if {
	count(_pm26.missing) == 0
	count(_pm26.gaps) > 0
	msg := sprintf("NIST PM-26: complaint management requirements not met: %s", [concat("; ", sort(_pm26.gaps))])
}

# --- PM-27 ---
# Privacy Reporting. Facts: input.pm_controls.privacy_reporting.reports_disseminated (organization-defined reports to oversight
# bodies and officials, boolean); input.pm_controls.privacy_reporting.days_since_last / .odp.frequency_days.
_pm27 := _assess({"bools": [[["privacy_reporting", "reports_disseminated"], "privacy reports not developed and disseminated to the organization-defined oversight bodies and officials"]], "bounds": [_freq(["privacy_reporting"], "privacy reports last reviewed")]})

violation contains msg if {
	count(_pm27.missing) > 0
	msg := sprintf("NIST PM-27: evidence missing — %s not collected%s", [concat(", ", sort(_pm27.missing)), _also(_pm27.gaps)])
}

violation contains msg if {
	count(_pm27.missing) == 0
	count(_pm27.gaps) > 0
	msg := sprintf("NIST PM-27: privacy reporting requirements not met: %s", [concat("; ", sort(_pm27.gaps))])
}

# --- PM-28 ---
# Risk Framing. Facts: input.pm_controls.risk_framing.documented (assumptions, constraints, priorities and trade-offs, risk
# tolerance), .distributed (booleans); input.pm_controls.risk_framing.days_since_last / .odp.frequency_days.
_pm28 := _assess({"bools": [[["risk_framing", "documented"], "risk assumptions, constraints, priorities and risk tolerance not identified and documented"], [["risk_framing", "distributed"], "risk framing results not distributed to the organization-defined personnel"]], "bounds": [_freq(["risk_framing"], "risk framing considerations last reviewed")]})

violation contains msg if {
	count(_pm28.missing) > 0
	msg := sprintf("NIST PM-28: evidence missing — %s not collected%s", [concat(", ", sort(_pm28.missing)), _also(_pm28.gaps)])
}

violation contains msg if {
	count(_pm28.missing) == 0
	count(_pm28.gaps) > 0
	msg := sprintf("NIST PM-28: risk framing requirements not met: %s", [concat("; ", sort(_pm28.gaps))])
}

# --- PM-29 ---
# Risk Management Program Leadership Roles: a Senior Accountable Official for Risk Management and a Risk Executive (function).
# Evidence: attestation at input.pm_controls.risk_leadership_roles.attestation (organizational control).
violation contains msg if {
	not _attested("risk_leadership_roles")
	msg := "NIST PM-29: appointment of a Senior Accountable Official for Risk Management and a Risk Executive (function) not attested — organizational control with no machine-checkable evidence; input.pm_controls.risk_leadership_roles.attestation must be {attested: true, by, date}"
}

# --- PM-30 ---
# Supply Chain Risk Management Strategy. Facts: input.pm_controls.scrm_strategy.documented, .implemented_consistently (booleans);
# input.pm_controls.scrm_strategy.days_since_last / .odp.frequency_days.
_pm30 := _assess({"bools": [[["scrm_strategy", "documented"], "no organization-wide supply chain risk management strategy"], [["scrm_strategy", "implemented_consistently"], "supply chain risk management strategy not implemented consistently across the organization"]], "bounds": [_freq(["scrm_strategy"], "supply chain risk management strategy last reviewed")]})

violation contains msg if {
	count(_pm30.missing) > 0
	msg := sprintf("NIST PM-30: evidence missing — %s not collected%s", [concat(", ", sort(_pm30.missing)), _also(_pm30.gaps)])
}

violation contains msg if {
	count(_pm30.missing) == 0
	count(_pm30.gaps) > 0
	msg := sprintf("NIST PM-30: supply chain risk management strategy requirements not met: %s", [concat("; ", sort(_pm30.gaps))])
}

# --- PM-31 ---
# Continuous Monitoring Strategy. Facts: input.pm_controls.continuous_monitoring.strategy_documented, .metrics_established,
# .ongoing_monitoring, .analysis_and_response (booleans); input.pm_controls.continuous_monitoring.status_reporting.days_since_last /
# .status_reporting.odp.frequency_days (status reported to the organization-defined personnel).
_pm31 := _assess({"bools": [[["continuous_monitoring", "strategy_documented"], "no organization-wide continuous monitoring strategy"], [["continuous_monitoring", "metrics_established"], "organization-wide metrics and monitoring and assessment frequencies not established"], [["continuous_monitoring", "ongoing_monitoring"], "organization-defined metrics not monitored on an ongoing basis"], [["continuous_monitoring", "analysis_and_response"], "assessment and monitoring results not correlated, analyzed and acted on"]], "bounds": [_freq(["continuous_monitoring", "status_reporting"], "security and privacy status last reported")]})

violation contains msg if {
	count(_pm31.missing) > 0
	msg := sprintf("NIST PM-31: evidence missing — %s not collected%s", [concat(", ", sort(_pm31.missing)), _also(_pm31.gaps)])
}

violation contains msg if {
	count(_pm31.missing) == 0
	count(_pm31.gaps) > 0
	msg := sprintf("NIST PM-31: continuous monitoring strategy requirements not met: %s", [concat("; ", sort(_pm31.gaps))])
}

# --- PM-32 ---
# Purposing: systems supporting mission essential functions analyzed for use consistent with intended purpose.
# Evidence: attestation at input.pm_controls.purposing.attestation (organizational control).
violation contains msg if {
	not _attested("purposing")
	msg := "NIST PM-32: analysis that mission-essential systems are used consistent with their intended purpose not attested — organizational control with no machine-checkable evidence; input.pm_controls.purposing.attestation must be {attested: true, by, date}"
}

compliant if count(violation) == 0

# --- PM-5(1) ---
# Inventory of Personally Identifiable Information: an inventory of every system, application and project that
# processes PII is established, maintained and updated at the organization-defined frequency.
# Facts: input.pm_controls.pii_inventory.maintained (boolean); .unlisted_pii_processing (count of systems,
# applications or projects found processing PII, e.g. by data discovery, that the inventory does not list);
# .days_since_last / .odp.frequency_days (age of the last update).
_pm5_1 := _assess({"bools": [[["pii_inventory", "maintained"], "no inventory of the systems, applications and projects that process PII is maintained"]], "bounds": [_freq(["pii_inventory"], "PII inventory last updated")], "zeros": [[["pii_inventory", "unlisted_pii_processing"], "%v systems, applications or projects process PII but are not in the PII inventory"]]})

violation contains msg if {
	count(_pm5_1.missing) > 0
	msg := sprintf("NIST PM-5(1): evidence missing — %s not collected%s", [concat(", ", sort(_pm5_1.missing)), _also(_pm5_1.gaps)])
}

violation contains msg if {
	count(_pm5_1.missing) == 0
	count(_pm5_1.gaps) > 0
	msg := sprintf("NIST PM-5(1): PII inventory requirements not met: %s", [concat("; ", sort(_pm5_1.gaps))])
}

# --- PM-20(1) ---
# Privacy Policies on Websites, Applications, and Digital Services: every external-facing website, mobile
# application and digital service posts a privacy policy that is in plain language, gives the public what it needs
# to decide whether and how to interact, and is updated on each substantive change with a date stamp.
# Facts: input.pm_controls.public_privacy_policies.services_without_policy (count of external-facing services with
# no posted policy, e.g. from a crawl of the public inventory); .policies_without_revision_date (count of posted
# policies with no date of last change); .plain_language, .decision_information_provided,
# .updated_on_substantive_change (booleans, from the privacy office's review of the policies).
_pm20_1 := _assess({"bools": [[["public_privacy_policies", "plain_language"], "posted privacy policies are not written in plain language and organized to be easy to understand"], [["public_privacy_policies", "decision_information_provided"], "posted privacy policies do not give the public the information needed to decide whether and how to interact with the organization"], [["public_privacy_policies", "updated_on_substantive_change"], "posted privacy policies are not updated whenever the practices they describe change substantively"]], "zeros": [[["public_privacy_policies", "services_without_policy"], "%v external-facing websites, applications or digital services have no posted privacy policy"], [["public_privacy_policies", "policies_without_revision_date"], "%v posted privacy policies carry no date of their most recent change"]]})

violation contains msg if {
	count(_pm20_1.missing) > 0
	msg := sprintf("NIST PM-20(1): evidence missing — %s not collected%s", [concat(", ", sort(_pm20_1.missing)), _also(_pm20_1.gaps)])
}

violation contains msg if {
	count(_pm20_1.missing) == 0
	count(_pm20_1.gaps) > 0
	msg := sprintf("NIST PM-20(1): public privacy policy requirements not met: %s", [concat("; ", sort(_pm20_1.gaps))])
}

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"PM-1", "PM-2", "PM-3", "PM-4", "PM-5", "PM-6", "PM-7", "PM-8", "PM-9", "PM-10", "PM-11", "PM-12", "PM-13", "PM-14", "PM-15", "PM-16", "PM-17", "PM-18", "PM-19", "PM-20", "PM-21", "PM-22", "PM-23", "PM-24", "PM-25", "PM-26", "PM-27", "PM-28", "PM-29", "PM-30", "PM-31", "PM-32", "PM-5(1)", "PM-20(1)"}

compliance_report := {
	"family": "PM",
	"name": "Program Management",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
