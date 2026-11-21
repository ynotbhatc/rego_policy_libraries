# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Information Integrity (SI) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 49
#     cited: 49
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
# SI-8, SI-8(2), SI-10, SI-11, SI-12, SI-16 (the Moderate baseline), and SI-2(3), SI-4(1), SI-4(10), SI-4(11),
# SI-4(12), SI-4(14), SI-4(16), SI-4(18), SI-4(19), SI-4(20), SI-4(22), SI-4(23), SI-5(1), SI-7(2), SI-7(5),
# SI-7(15), SI-13, SI-14, SI-15, SI-17 to SI-23 (the NIST and FedRAMP High-baseline ids and the remaining base
# controls), and SI-12(1), SI-12(2), SI-12(3), SI-18(4) (the Privacy-baseline enhancements): 49 ids. Each enhancement is its own requirement: a base control never fails on an enhancement's
# requirement. Every boolean passes only on true.

default compliant := false

_root := "si_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null).
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# The original base-control checks pass only when their fact is exactly true. The finding says why not: false
# keeps the original text; an absent fact, a non-boolean ("true", 1, null) or a path through a non-object is
# evidence missing.
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

# Counts that must be zero. A value that is not a non-negative whole number is missing evidence.
# A count: a non-negative whole number. Anything else (absent, null, "1", a negative or a fractional number) is
# evidence missing.
_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not _count_ok(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	_count_ok(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

violation contains msg if {
	not _val(["policy", "documented"]) == true
	msg := sprintf("NIST SI-1: %s", [_legacy(["policy", "documented"], "System and information integrity policy not documented")])
}

violation contains msg if {
	not _val(["flaw_remediation", "timely"]) == true
	msg := sprintf("NIST SI-2: %s", [_legacy(["flaw_remediation", "timely"], "Flaw remediation (patching) not performed within defined timeframes")])
}

violation contains msg if {
	not _val(["malicious_code_protection", "deployed"]) == true
	msg := sprintf("NIST SI-3: %s", [_legacy(["malicious_code_protection", "deployed"], "Malicious code protection (antivirus/EDR) not deployed at entry/exit points")])
}

violation contains msg if {
	not _val(["system_monitoring", "continuous"]) == true
	msg := sprintf("NIST SI-4: %s", [_legacy(["system_monitoring", "continuous"], "System monitoring (IDS/IPS, log review) not continuous")])
}

violation contains msg if {
	not _val(["security_alerts", "acted_upon"]) == true
	msg := sprintf("NIST SI-5: %s", [_legacy(["security_alerts", "acted_upon"], "Security alerts/advisories not received and acted upon")])
}

violation contains msg if {
	not _val(["security_function_verification", "tested"]) == true
	msg := sprintf("NIST SI-6: %s", [_legacy(["security_function_verification", "tested"], "Security function verification not periodically tested")])
}

violation contains msg if {
	not _val(["software_firmware_integrity", "verified"]) == true
	msg := sprintf("NIST SI-7: %s", [_legacy(["software_firmware_integrity", "verified"], "Software and firmware integrity not verified before execution")])
}

violation contains msg if {
	not _val(["spam_protection", "enabled"]) == true
	msg := sprintf("NIST SI-8: %s", [_legacy(["spam_protection", "enabled"], "Spam protection not enabled at gateways or endpoints")])
}

violation contains msg if {
	not _val(["input_validation", "enforced"]) == true
	msg := sprintf("NIST SI-10: %s", [_legacy(["input_validation", "enforced"], "Information input validation not enforced")])
}

violation contains msg if {
	not _val(["error_handling", "no_info_disclosure"]) == true
	msg := sprintf("NIST SI-11: %s", [_legacy(["error_handling", "no_info_disclosure"], "Error handling discloses sensitive information")])
}

violation contains msg if {
	not _val(["information_management_retention", "policy_enforced"]) == true
	msg := sprintf("NIST SI-12: %s", [_legacy(["information_management_retention", "policy_enforced"], "Information management/retention policies not enforced")])
}

violation contains msg if {
	not _val(["memory_protection", "enabled"]) == true
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

# ---------------------------------------------------------------------------------------------------------
# High-baseline enhancements and the remaining base controls (SI-13 to SI-23). Each id has one rule and so at
# most one finding; enhancement facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# An observed value against an organization-defined limit: <sec>.<obs> must not exceed <sec>.odp.<lim>. Either
# value not a number is missing evidence.
_limit_missing(sec, obs, lim) := {_p(array.concat(sec, k)) | some k in [[obs], ["odp", lim]]; not is_number(_val(array.concat(sec, k)))}

_limit_unmet(sec, obs, lim, what) := {d |
	o := _val(array.concat(sec, [obs]))
	l := _val(array.concat(sec, ["odp", lim]))
	is_number(o)
	is_number(l)
	o > l
	d := sprintf("%s is %v; the organization-defined limit is %v", [what, o, l])
}

# Several zero-counts at once: reqs maps a count key to the text reported after the count when it is above zero.
_zeros_missing(sec, reqs) := {p | some k, _ in reqs; some p in _zero_missing(sec, k)}

_zeros_unmet(sec, reqs) := {d | some k, what in reqs; some d in _zero_unmet(sec, k, what)}

# Attestation, only where no machine-checkable evidence can exist: <sec>.attestation must be
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>}.
_att_ok(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_detail(sec, what) := d if {
	not _att_ok(_val(array.concat(sec, ["attestation"])))
	d := sprintf("evidence missing — %s not attested (needs attested: true and a non-empty by and date); this organizational requirement is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
}

# SI-2(3) Time to Remediate Flaws and Benchmarks for Corrective Actions: input.si_controls.flaw_remediation.
# time_to_remediate.{measured, max_days_to_remediate, odp.benchmark_days}. measured is true when the time from
# flaw identification to remediation is recorded (for example scanner first-seen to patch-closed timestamps);
# max_days_to_remediate is the longest such time in the reporting period, against the organization-defined
# benchmark for corrective action.
violation contains msg if {
	sec := ["flaw_remediation", "time_to_remediate"]
	b := {"measured": "the time between flaw identification and flaw remediation is not measured"}
	m := _bool_missing(sec, b) | _limit_missing(sec, "max_days_to_remediate", "benchmark_days")
	u := _bool_unmet(sec, b) | _limit_unmet(sec, "max_days_to_remediate", "benchmark_days", "the longest time from flaw identification to remediation (days)")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-2(3): %s", [_detail(m, u)])
}

# SI-4(1) System-wide Intrusion Detection System: input.si_controls.system_monitoring.system_wide_ids.
# {integrated, tools_not_connected}. integrated is true when the individual intrusion detection tools feed one
# system-wide intrusion detection capability; tools_not_connected counts the intrusion detection tools that do
# not.
violation contains msg if {
	sec := ["system_monitoring", "system_wide_ids"]
	b := {"integrated": "individual intrusion detection tools are not connected and configured into a system-wide intrusion detection system"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "tools_not_connected")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "tools_not_connected", "intrusion detection tools are not connected to the system-wide intrusion detection system")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(1): %s", [_detail(m, u)])
}

# SI-4(10) Visibility of Encrypted Communications: input.si_controls.system_monitoring.encrypted_traffic_visibility.
# traffic_types_not_visible, the number of organization-defined encrypted traffic types that the
# organization-defined monitoring tools cannot inspect (no TLS inspection, decryption tap or endpoint sensor).
violation contains msg if {
	sec := ["system_monitoring", "encrypted_traffic_visibility"]
	m := _zero_missing(sec, "traffic_types_not_visible")
	u := _zero_unmet(sec, "traffic_types_not_visible", "organization-defined encrypted communications traffic types are not visible to the organization-defined monitoring tools")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(10): %s", [_detail(m, u)])
}

# SI-4(11) Analyze Communications Traffic Anomalies: input.si_controls.system_monitoring.outbound_anomaly_analysis.
# {external_interfaces_not_analyzed, interior_points_not_analyzed}: counts of external interfaces and
# organization-defined interior points whose outbound traffic is not analyzed for anomalies.
_si4_11 := {
	"external_interfaces_not_analyzed": "external system interfaces have no outbound traffic anomaly analysis",
	"interior_points_not_analyzed": "organization-defined interior points have no outbound traffic anomaly analysis",
}

violation contains msg if {
	sec := ["system_monitoring", "outbound_anomaly_analysis"]
	m := _zeros_missing(sec, _si4_11)
	u := _zeros_unmet(sec, _si4_11)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(11): %s", [_detail(m, u)])
}

# SI-4(12) Automated Organization-generated Alerts: input.si_controls.system_monitoring.organization_alerts.
# {automated, recipients_configured, triggers_without_alert}. automated is true when the alerts are raised by
# the organization-defined automated mechanisms; recipients_configured when they reach the organization-defined
# personnel or roles; triggers_without_alert counts organization-defined triggering activities with no enabled
# alert.
violation contains msg if {
	sec := ["system_monitoring", "organization_alerts"]
	b := {
		"automated": "organization-generated alerts for inappropriate or unusual activities are not raised by automated mechanisms",
		"recipients_configured": "organization-generated alerts are not routed to the organization-defined personnel or roles",
	}
	m := _bool_missing(sec, b) | _zero_missing(sec, "triggers_without_alert")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "triggers_without_alert", "organization-defined triggering activities have no enabled alert")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(12): %s", [_detail(m, u)])
}

# SI-4(14) Wireless Intrusion Detection: input.si_controls.system_monitoring.wireless_ids.{deployed,
# rogue_device_detection, attack_detection}.
violation contains msg if {
	sec := ["system_monitoring", "wireless_ids"]
	b := {
		"deployed": "no wireless intrusion detection system is employed",
		"rogue_device_detection": "the wireless intrusion detection system does not identify rogue wireless devices",
		"attack_detection": "the wireless intrusion detection system does not detect attack attempts and potential compromises",
	}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(14): %s", [_detail(m, u)])
}

# SI-4(16) Correlate Monitoring Information: input.si_controls.system_monitoring.correlation.
# sources_not_correlated, the number of monitoring tools and mechanisms whose output is not correlated (for
# example not ingested by the SIEM correlation engine).
violation contains msg if {
	sec := ["system_monitoring", "correlation"]
	m := _zero_missing(sec, "sources_not_correlated")
	u := _zero_unmet(sec, "sources_not_correlated", "monitoring tools and mechanisms are not correlated with the rest of the system's monitoring information")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(16): %s", [_detail(m, u)])
}

# SI-4(18) Analyze Traffic and Covert Exfiltration: input.si_controls.system_monitoring.covert_exfiltration.
# {external_interfaces_not_analyzed, interior_points_not_analyzed}: counts of external interfaces and
# organization-defined interior points whose outbound traffic is not analyzed for covert exfiltration (DNS
# tunnelling, steganography, beaconing).
_si4_18 := {
	"external_interfaces_not_analyzed": "external system interfaces have no covert exfiltration analysis of outbound traffic",
	"interior_points_not_analyzed": "organization-defined interior points have no covert exfiltration analysis of outbound traffic",
}

violation contains msg if {
	sec := ["system_monitoring", "covert_exfiltration"]
	m := _zeros_missing(sec, _si4_18)
	u := _zeros_unmet(sec, _si4_18)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(18): %s", [_detail(m, u)])
}

# SI-4(19) Risk for Individuals: input.si_controls.system_monitoring.individual_risk.
# individuals_without_additional_monitoring, the number of individuals identified by the organization-defined
# sources as posing increased risk who are not on the organization-defined additional monitoring (for example
# absent from the UEBA watch list).
violation contains msg if {
	sec := ["system_monitoring", "individual_risk"]
	m := _zero_missing(sec, "individuals_without_additional_monitoring")
	u := _zero_unmet(sec, "individuals_without_additional_monitoring", "individuals identified as posing an increased level of risk lack the organization-defined additional monitoring")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(19): %s", [_detail(m, u)])
}

# SI-4(20) Privileged Users: input.si_controls.system_monitoring.privileged_users.
# accounts_without_additional_monitoring, the number of privileged accounts not under the organization-defined
# additional monitoring (for example session recording or privileged-command auditing).
violation contains msg if {
	sec := ["system_monitoring", "privileged_users"]
	m := _zero_missing(sec, "accounts_without_additional_monitoring")
	u := _zero_unmet(sec, "accounts_without_additional_monitoring", "privileged accounts lack the organization-defined additional monitoring")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(20): %s", [_detail(m, u)])
}

# SI-4(22) Unauthorized Network Services: input.si_controls.system_monitoring.unauthorized_services.{detection_enabled,
# response_configured, unhandled_detections}. detection_enabled is true when listening network services are
# compared with the services approved by the organization-defined process; response_configured when a detection
# is audited or alerted as the organization defines; unhandled_detections counts unauthorized services detected
# and neither audited nor alerted.
violation contains msg if {
	sec := ["system_monitoring", "unauthorized_services"]
	b := {
		"detection_enabled": "network services not authorized or approved by the organization-defined process are not detected",
		"response_configured": "detection of an unauthorized network service is not audited or alerted as the organization defines",
	}
	m := _bool_missing(sec, b) | _zero_missing(sec, "unhandled_detections")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "unhandled_detections", "detected unauthorized network services were neither audited nor alerted")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(22): %s", [_detail(m, u)])
}

# SI-4(23) Host-based Devices: input.si_controls.system_monitoring.host_based.components_without_monitoring, the
# number of organization-defined system components without the organization-defined host-based monitoring
# mechanisms (agent not installed or not reporting).
violation contains msg if {
	sec := ["system_monitoring", "host_based"]
	m := _zero_missing(sec, "components_without_monitoring")
	u := _zero_unmet(sec, "components_without_monitoring", "organization-defined system components lack the organization-defined host-based monitoring mechanisms")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-4(23): %s", [_detail(m, u)])
}

# SI-5(1) Automated Alerts and Advisories: input.si_controls.security_alerts.automated_broadcast.automated, true
# when security alert and advisory information is broadcast throughout the organization by the
# organization-defined automated mechanisms (mailing list, chat channel or ticket automation fed by the advisory
# sources).
violation contains msg if {
	sec := ["security_alerts", "automated_broadcast"]
	b := {"automated": "security alerts and advisories are not broadcast throughout the organization by automated mechanisms"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-5(1): %s", [_detail(m, u)])
}

# SI-7(2) Automated Notifications of Integrity Violations: input.si_controls.software_firmware_integrity.
# automated_notifications.{enabled, recipients_configured}: the integrity tools notify automatically, and the
# notifications reach the organization-defined personnel or roles.
violation contains msg if {
	sec := ["software_firmware_integrity", "automated_notifications"]
	b := {
		"enabled": "integrity verification tools do not notify automatically on discovering discrepancies",
		"recipients_configured": "integrity violation notifications are not routed to the organization-defined personnel or roles",
	}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-7(2): %s", [_detail(m, u)])
}

# SI-7(5) Automated Response to Integrity Violations: input.si_controls.software_firmware_integrity.
# automated_response.{enabled, components_without_response}. enabled is true when an integrity violation
# triggers the organization-defined action (shut down, restart, or the organization-defined controls) without
# manual steps; components_without_response counts components where that action is not configured.
violation contains msg if {
	sec := ["software_firmware_integrity", "automated_response"]
	b := {"enabled": "integrity violations do not trigger the organization-defined automated response"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "components_without_response")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "components_without_response", "system components have no automated response to integrity violations configured")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-7(5): %s", [_detail(m, u)])
}

# SI-7(15) Code Authentication: input.si_controls.software_firmware_integrity.code_authentication.
# {signature_verification_enforced, unauthenticated_installations}. signature_verification_enforced is true when
# installation of the organization-defined software or firmware requires a valid cryptographic signature (for
# example gpgcheck=1, Secure Boot, signed firmware updates); unauthenticated_installations counts installations
# of those components without signature verification.
violation contains msg if {
	sec := ["software_firmware_integrity", "code_authentication"]
	b := {"signature_verification_enforced": "cryptographic authentication of the organization-defined software or firmware before installation is not enforced"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "unauthenticated_installations")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "unauthenticated_installations", "software or firmware installations were not cryptographically authenticated")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-7(15): %s", [_detail(m, u)])
}

# SI-13 Predictable Failure Prevention: input.si_controls.predictable_failure_prevention.{components_without_mttf,
# substitution_criteria_defined, components_without_standby}. components_without_mttf counts the
# organization-defined components with no mean time to failure determined for their environment;
# components_without_standby counts those with no substitute component and exchange means per the
# organization-defined MTTF substitution criteria.
violation contains msg if {
	sec := ["predictable_failure_prevention"]
	b := {"substitution_criteria_defined": "the MTTF substitution criteria are not defined"}
	z := {
		"components_without_mttf": "organization-defined system components have no mean time to failure determined",
		"components_without_standby": "organization-defined system components have no substitute component or means to exchange active and standby components",
	}
	m := _bool_missing(sec, b) | _zeros_missing(sec, z)
	u := _bool_unmet(sec, b) | _zeros_unmet(sec, z)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-13: %s", [_detail(m, u)])
}

# SI-14 Non-persistence: input.si_controls.non_persistence.{components_not_from_known_state,
# oldest_instance_age_days, odp.max_lifetime_days}. components_not_from_known_state counts the
# organization-defined components and services that are not started from a known state (golden image or
# immutable template); oldest_instance_age_days is the age of the longest-running instance, against the
# organization-defined termination frequency (use 0 days for end-of-session termination).
violation contains msg if {
	sec := ["non_persistence"]
	m := _zero_missing(sec, "components_not_from_known_state") | _limit_missing(sec, "oldest_instance_age_days", "max_lifetime_days")
	u := _zero_unmet(sec, "components_not_from_known_state", "organization-defined non-persistent components are not initiated in a known state") | _limit_unmet(sec, "oldest_instance_age_days", "max_lifetime_days", "the oldest non-persistent instance's age (days)")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-14: %s", [_detail(m, u)])
}

# SI-15 Information Output Filtering: input.si_controls.output_filtering.applications_without_validation, the
# number of organization-defined software programs or applications whose output is not validated against the
# expected content.
violation contains msg if {
	sec := ["output_filtering"]
	m := _zero_missing(sec, "applications_without_validation")
	u := _zero_unmet(sec, "applications_without_validation", "organization-defined software programs or applications have no output validation")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-15: %s", [_detail(m, u)])
}

# SI-17 Fail-safe Procedures: input.si_controls.fail_safe.{procedures_defined, conditions_without_procedure}.
# procedures_defined is true when the organization-defined list of failure conditions and fail-safe procedures
# exists; conditions_without_procedure counts listed failure conditions with no implemented fail-safe
# procedure.
violation contains msg if {
	sec := ["fail_safe"]
	b := {"procedures_defined": "the organization-defined failure conditions and fail-safe procedures are not defined"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "conditions_without_procedure")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "conditions_without_procedure", "failure conditions have no implemented fail-safe procedure")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-17: %s", [_detail(m, u)])
}

# SI-18 Personally Identifiable Information Quality Operations: input.si_controls.pii_quality.{days_since_last,
# odp.frequency_days, uncorrected_records}. days_since_last is the age of the last accuracy, relevance,
# timeliness and completeness check of PII, against the organization-defined frequency; uncorrected_records counts
# PII records found inaccurate or outdated and neither corrected nor deleted.
violation contains msg if {
	sec := ["pii_quality"]
	m := _freq_missing(sec) | _zero_missing(sec, "uncorrected_records")
	u := _freq_unmet(sec, "PII accuracy, relevance, timeliness and completeness checked") | _zero_unmet(sec, "uncorrected_records", "inaccurate or outdated PII records are neither corrected nor deleted")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-18: %s", [_detail(m, u)])
}

# SI-19 De-identification: input.si_controls.de_identification.{datasets_with_identifying_elements,
# days_since_last, odp.frequency_days}. datasets_with_identifying_elements counts datasets that still hold the
# organization-defined PII elements (a data-discovery scan result); days_since_last is the age of the last
# evaluation of de-identification effectiveness, against the organization-defined frequency.
violation contains msg if {
	sec := ["de_identification"]
	m := _zero_missing(sec, "datasets_with_identifying_elements") | _freq_missing(sec)
	u := _zero_unmet(sec, "datasets_with_identifying_elements", "datasets still contain the organization-defined PII elements") | _freq_unmet(sec, "de-identification effectiveness evaluated")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-19: %s", [_detail(m, u)])
}

# SI-20 Tainting: input.si_controls.tainting.components_without_taint, the number of organization-defined systems
# or components with no embedded data or capability (canary tokens, honey records, watermarks) to detect
# exfiltration or improper removal.
violation contains msg if {
	sec := ["tainting"]
	m := _zero_missing(sec, "components_without_taint")
	u := _zero_unmet(sec, "components_without_taint", "organization-defined systems or components have no embedded tainting data or capability")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-20: %s", [_detail(m, u)])
}

# SI-21 Information Refresh: input.si_controls.information_refresh.{days_since_last, odp.frequency_days}:
# the age of the organization-defined information (oldest copy not regenerated on demand), against the
# organization-defined refresh frequency.
violation contains msg if {
	sec := ["information_refresh"]
	m := _freq_missing(sec)
	u := _freq_unmet(sec, "organization-defined information refreshed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-21: %s", [_detail(m, u)])
}

# SI-22 Information Diversity: input.si_controls.information_diversity.{functions_without_alternative_source,
# components_without_failover}. functions_without_alternative_source counts organization-defined essential
# functions and services with no identified alternative information source; components_without_failover counts
# organization-defined systems or components not configured to use the alternative source when the primary is
# corrupted or unavailable.
_si22 := {
	"functions_without_alternative_source": "organization-defined essential functions or services have no identified alternative information source",
	"components_without_failover": "organization-defined systems or components cannot use an alternative information source when the primary is corrupted or unavailable",
}

violation contains msg if {
	sec := ["information_diversity"]
	m := _zeros_missing(sec, _si22)
	u := _zeros_unmet(sec, _si22)
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-22: %s", [_detail(m, u)])
}

# SI-23 Information Fragmentation: input.si_controls.information_fragmentation.attestation (organizational: the
# decision to fragment, the circumstances and the distribution across components are design decisions with no
# machine-readable record).
violation contains msg if {
	d := _att_detail(["information_fragmentation"], "under the organization-defined circumstances the organization-defined information is fragmented and distributed across the organization-defined systems or components")
	msg := sprintf("NIST SI-23: %s", [d])
}

compliant if count(violation) == 0

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# Organization-defined lists for SI-12(1) to SI-12(3): <sec>.odp.<odp_key> must be a non-empty list and
# <sec>.<obs_key> a list; anything else is evidence missing.
_si_list_missing(sec, odp_key, obs_key) := {_p(array.concat(sec, ["odp", odp_key])) | not _si_nonempty_list(_val(array.concat(sec, ["odp", odp_key])))} | {_p(array.concat(sec, [obs_key])) | not is_array(_val(array.concat(sec, [obs_key])))}

_si_nonempty_list(x) if {
	is_array(x)
	count(x) > 0
}

# Every item of the organization-defined list must be observed.
_si_list_lacking(sec, odp_key, obs_key, what) := {sprintf("%s: %v", [what, sort(lack)]) |
	req := _val(array.concat(sec, ["odp", odp_key]))
	obs := _val(array.concat(sec, [obs_key]))
	_si_nonempty_list(req)
	is_array(obs)
	lack := {x | some x in req; not x in obs}
	count(lack) > 0
}

# SI-12(1) Limit Personally Identifiable Information Elements: PII processed in the information life cycle is
# limited to the organization-defined elements.
# Facts (input.si_controls.information_management_retention.pii_elements): odp.permitted_elements (non-empty
# list); elements_processed (list of the PII elements the system's data stores hold, e.g. from data discovery).
violation contains msg if {
	sec := ["information_management_retention", "pii_elements"]
	m := _si_list_missing(sec, "permitted_elements", "elements_processed")
	u := {sprintf("PII elements processed outside the organization-defined list: %v", [sort(extra)]) |
		obs := _val(array.concat(sec, ["elements_processed"]))
		req := _val(array.concat(sec, ["odp", "permitted_elements"]))
		is_array(obs)
		_si_nonempty_list(req)
		extra := {x | some x in obs; not x in req}
		count(extra) > 0
	}
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-12(1): %s", [_detail(m, u)])
}

# SI-12(2) Minimize Personally Identifiable Information in Testing, Training, and Research: the
# organization-defined techniques are used to minimize PII used for research, testing or training.
# Facts (input.si_controls.information_management_retention.pii_minimization): odp.techniques (non-empty list,
# e.g. masking, synthetic data, de-identification); techniques_applied (list); unminimized_datasets (count of
# research, test or training data sets found holding PII the techniques were not applied to).
violation contains msg if {
	sec := ["information_management_retention", "pii_minimization"]
	m := _si_list_missing(sec, "techniques", "techniques_applied") | _zero_missing(sec, "unminimized_datasets")
	u := _si_list_lacking(sec, "techniques", "techniques_applied", "organization-defined PII minimization techniques not used") | _zero_unmet(sec, "unminimized_datasets", "research, testing or training data sets hold PII that was not minimized")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-12(2): %s", [_detail(m, u)])
}

# SI-12(3) Information Disposal: the organization-defined techniques are used to dispose of, destroy or erase
# information after its retention period.
# Facts (input.si_controls.information_management_retention.disposal): odp.techniques (non-empty list);
# techniques_applied (list); records_past_retention (count of records held beyond their retention period and not
# disposed of).
violation contains msg if {
	sec := ["information_management_retention", "disposal"]
	m := _si_list_missing(sec, "techniques", "techniques_applied") | _zero_missing(sec, "records_past_retention")
	u := _si_list_lacking(sec, "techniques", "techniques_applied", "organization-defined disposal techniques not used") | _zero_unmet(sec, "records_past_retention", "records held beyond their retention period and not disposed of")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-12(3): %s", [_detail(m, u)])
}

# SI-18(4) Individual Requests: PII is corrected or deleted on request by individuals or their designated
# representatives.
# Facts (input.si_controls.pii_quality.individual_requests): process_implemented (boolean: a request channel and
# workflow exist); requests_not_actioned (count of correction or deletion requests past the organization's
# response period and not completed, from the request tracking system).
violation contains msg if {
	sec := ["pii_quality", "individual_requests"]
	b := {"process_implemented": "no process corrects or deletes PII on request by individuals or their designated representatives"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "requests_not_actioned")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "requests_not_actioned", "requests to correct or delete PII not actioned")
	count(m) + count(u) > 0
	msg := sprintf("NIST SI-18(4): %s", [_detail(m, u)])
}

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SI-1", "SI-2", "SI-2(2)", "SI-2(3)", "SI-3", "SI-4", "SI-4(1)", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-4(10)",
	"SI-4(11)", "SI-4(12)", "SI-4(14)", "SI-4(16)", "SI-4(18)", "SI-4(19)", "SI-4(20)", "SI-4(22)", "SI-4(23)",
	"SI-5", "SI-5(1)", "SI-6", "SI-7", "SI-7(1)", "SI-7(2)", "SI-7(5)", "SI-7(7)", "SI-7(15)", "SI-8", "SI-8(2)",
	"SI-10", "SI-11", "SI-12", "SI-13", "SI-14", "SI-15", "SI-16", "SI-17", "SI-18", "SI-19", "SI-20", "SI-21",
	"SI-22", "SI-23",
	"SI-12(1)", "SI-12(2)", "SI-12(3)", "SI-18(4)",
}

compliance_report := {
	"family": "SI",
	"name": "System and Information Integrity",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
