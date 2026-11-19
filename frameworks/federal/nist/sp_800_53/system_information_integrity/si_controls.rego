# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Information Integrity (SI) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 19
#     cited: 19
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.system_information_integrity

import rego.v1

# NIST SP 800-53 Rev 5 — System and Information Integrity (SI) Family
# Flaw remediation, malicious code protection, monitoring, integrity verification.
#
# Evaluated: SI-1, SI-2, SI-2(2), SI-3, SI-4, SI-4(2), SI-4(4), SI-4(5), SI-5, SI-6, SI-7, SI-7(1), SI-7(7),
# SI-8, SI-8(2), SI-10, SI-11, SI-12, SI-16 (19 ids; the enhancements are the Moderate-baseline ids from
# SP 800-53B, each its own requirement: a base control never fails on an enhancement's requirement).

default compliant := false

_root := "si_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null).
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# The original base-control checks keep their pass condition (`not input.si_controls.<path>`: only an absent
# fact or false fails). The finding says which: false keeps the original text; an absent fact (or a path through
# a non-object) is evidence missing.
_legacy(path, text) := text if {
	_val(path) == false
} else := sprintf("evidence missing — %s not collected", [_p(path)])

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

# Counts that must be zero. A non-number is missing evidence.
_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not is_number(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

violation contains msg if {
	not input.si_controls.policy.documented
	msg := sprintf("NIST SI-1: %s", [_legacy(["policy", "documented"], "System and information integrity policy not documented")])
}

violation contains msg if {
	not input.si_controls.flaw_remediation.timely
	msg := sprintf("NIST SI-2: %s", [_legacy(["flaw_remediation", "timely"], "Flaw remediation (patching) not performed within defined timeframes")])
}

violation contains msg if {
	not input.si_controls.malicious_code_protection.deployed
	msg := sprintf("NIST SI-3: %s", [_legacy(["malicious_code_protection", "deployed"], "Malicious code protection (antivirus/EDR) not deployed at entry/exit points")])
}

violation contains msg if {
	not input.si_controls.system_monitoring.continuous
	msg := sprintf("NIST SI-4: %s", [_legacy(["system_monitoring", "continuous"], "System monitoring (IDS/IPS, log review) not continuous")])
}

violation contains msg if {
	not input.si_controls.security_alerts.acted_upon
	msg := sprintf("NIST SI-5: %s", [_legacy(["security_alerts", "acted_upon"], "Security alerts/advisories not received and acted upon")])
}

violation contains msg if {
	not input.si_controls.security_function_verification.tested
	msg := sprintf("NIST SI-6: %s", [_legacy(["security_function_verification", "tested"], "Security function verification not periodically tested")])
}

violation contains msg if {
	not input.si_controls.software_firmware_integrity.verified
	msg := sprintf("NIST SI-7: %s", [_legacy(["software_firmware_integrity", "verified"], "Software and firmware integrity not verified before execution")])
}

violation contains msg if {
	not input.si_controls.spam_protection.enabled
	msg := sprintf("NIST SI-8: %s", [_legacy(["spam_protection", "enabled"], "Spam protection not enabled at gateways or endpoints")])
}

violation contains msg if {
	not input.si_controls.input_validation.enforced
	msg := sprintf("NIST SI-10: %s", [_legacy(["input_validation", "enforced"], "Information input validation not enforced")])
}

violation contains msg if {
	not input.si_controls.error_handling.no_info_disclosure
	msg := sprintf("NIST SI-11: %s", [_legacy(["error_handling", "no_info_disclosure"], "Error handling discloses sensitive information")])
}

violation contains msg if {
	not input.si_controls.information_management_retention.policy_enforced
	msg := sprintf("NIST SI-12: %s", [_legacy(["information_management_retention", "policy_enforced"], "Information management/retention policies not enforced")])
}

violation contains msg if {
	not input.si_controls.memory_protection.enabled
	msg := sprintf("NIST SI-16: %s", [_legacy(["memory_protection", "enabled"], "Memory protection (ASLR, DEP, NX) not enabled")])
}

# ---------------------------------------------------------------------------------------------------------
# Moderate-baseline enhancements (SP 800-53B). Facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# SI-2(2) Automated Flaw Remediation Status: input.si_controls.flaw_remediation.automated_status.{automated,
# days_since_last, odp.frequency_days}. automated is true when patch status is determined by an automated
# mechanism (patch-compliance scan or agent report, not a manual check); days_since_last is the age of its
# last run across the system components.
violation contains msg if {
	sec := ["flaw_remediation", "automated_status"]
	b := {"automated": "installed security-relevant software and firmware updates are not determined by automated mechanisms"}
	m := _bool_missing(sec, b) | _freq_missing(sec)
	u := _bool_unmet(sec, b) | _freq_unmet(sec, "automated flaw remediation status determined")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-2(2): %s", [_detail(m, u)])
}

# SI-4(2) Automated Tools and Mechanisms for Real-time Analysis: input.si_controls.system_monitoring.
# real_time_analysis.automated_tools_enabled, true when events are analyzed in near real time by automated tools
# (for example a SIEM with streaming ingestion and correlation rules enabled).
violation contains msg if {
	sec := ["system_monitoring", "real_time_analysis"]
	b := {"automated_tools_enabled": "no automated tools and mechanisms support near real-time analysis of events"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(2): %s", [_detail(m, u)])
}

# SI-4(4) Inbound and Outbound Communications Traffic: input.si_controls.system_monitoring.traffic_monitoring.
# {criteria_defined, inbound_monitored, outbound_monitored, days_since_last, odp.frequency_days}; days_since_last
# is the age of the last monitoring pass over the traffic, against the organization-defined frequency.
_si4_4 := {
	"criteria_defined": "criteria for unusual or unauthorized activities or conditions in inbound and outbound traffic are not determined",
	"inbound_monitored": "inbound communications traffic is not monitored for the organization-defined unusual or unauthorized activities",
	"outbound_monitored": "outbound communications traffic is not monitored for the organization-defined unusual or unauthorized activities",
}

violation contains msg if {
	sec := ["system_monitoring", "traffic_monitoring"]
	m := _bool_missing(sec, _si4_4) | _freq_missing(sec)
	u := _bool_unmet(sec, _si4_4) | _freq_unmet(sec, "inbound and outbound traffic monitored")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(4): %s", [_detail(m, u)])
}

# SI-4(5) System-generated Alerts: input.si_controls.system_monitoring.alerts.{recipients_configured,
# indicators_without_alert}. recipients_configured is true when alerts route to the organization-defined
# personnel or roles; indicators_without_alert counts the organization-defined compromise indicators with no
# enabled alert rule.
violation contains msg if {
	sec := ["system_monitoring", "alerts"]
	b := {"recipients_configured": "system-generated compromise alerts are not routed to the organization-defined personnel or roles"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "indicators_without_alert")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "indicators_without_alert", "organization-defined compromise indicators have no enabled alert")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(5): %s", [_detail(m, u)])
}

# SI-7(1) Integrity Checks: input.si_controls.software_firmware_integrity.integrity_checks.{unchecked_items,
# days_since_last, odp.frequency_days}. unchecked_items counts the organization-defined software, firmware and
# information items not covered by an integrity check (for example AIDE, IMA/EVM or measured boot);
# days_since_last is the age of the last check, against the organization-defined frequency.
violation contains msg if {
	sec := ["software_firmware_integrity", "integrity_checks"]
	m := _zero_missing(sec, "unchecked_items") | _freq_missing(sec)
	u := _zero_unmet(sec, "unchecked_items", "organization-defined software, firmware or information items have no integrity check") | _freq_unmet(sec, "integrity check performed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-7(1): %s", [_detail(m, u)])
}

# SI-7(7) Integration of Detection and Response: input.si_controls.software_firmware_integrity.
# incident_response_integration.unauthorized_changes_routed, true when detections of the organization-defined
# unauthorized changes raise incidents in the incident response capability (integrity-tool alerts forwarded to
# the incident ticketing or SOAR workflow).
violation contains msg if {
	sec := ["software_firmware_integrity", "incident_response_integration"]
	b := {"unauthorized_changes_routed": "detection of the organization-defined unauthorized changes is not incorporated into the incident response capability"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-7(7): %s", [_detail(m, u)])
}

# SI-8(2) Automatic Updates: input.si_controls.spam_protection.automatic_updates.{enabled, days_since_last,
# odp.frequency_days}; days_since_last is the age of the last signature or rule update.
violation contains msg if {
	sec := ["spam_protection", "automatic_updates"]
	b := {"enabled": "spam protection mechanisms are not updated automatically"}
	m := _bool_missing(sec, b) | _freq_missing(sec)
	u := _bool_unmet(sec, b) | _freq_unmet(sec, "spam protection updated")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-8(2): %s", [_detail(m, u)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SI-1", "SI-2", "SI-2(2)", "SI-3", "SI-4", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-5", "SI-6", "SI-7",
	"SI-7(1)", "SI-7(7)", "SI-8", "SI-8(2)", "SI-10", "SI-11", "SI-12", "SI-16",
}

compliance_report := {
	"family": "SI",
	"name": "System and Information Integrity",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
