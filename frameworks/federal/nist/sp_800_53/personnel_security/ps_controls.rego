# METADATA
# title: "NIST SP 800-53 Rev 5 — Personnel Security (PS) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 21
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.personnel_security

import rego.v1

# NIST SP 800-53 Rev 5 — Personnel Security (PS) Family
# Base controls PS-1 to PS-9 and the NIST / FedRAMP High enhancements PS-3(3) and PS-4(2) (11 ids); an
# enhancement is its own finding and a base control never fails for it. Facts live under input.ps_controls and every control fails closed: a fact
# that is absent or of the wrong type is reported as evidence missing, never as a pass. Booleans pass only on
# true; numbers must be non-negative numbers. Organization-defined frequencies and time periods are compared as
# an observed value against the organisation's own value under .odp, as in IR-2/IR-3.

default compliant := false

_prefix := "input.ps_controls"

_ps := v if {
	v := object.get(input, "ps_controls", {})
	is_object(v)
} else := {}

# --- shared fact checker -----------------------------------------------------------------------------------
# A spec is an object with optional keys:
#   bools:   [[path, text when false]]           pass only on true; a non-boolean is evidence missing
#   strings: [path]                              a non-empty string; anything else is evidence missing
#   bounds:  [[observed path, odp path, fmt]]    both non-negative numbers; observed > odp is unmet
#   zeros:   [[path, fmt]]                       a non-negative number; above zero is unmet
#   lists:   [path]                              a non-empty list (an organization-defined set); otherwise missing
_get(p) := object.get(_ps, p, null)

_path(p) := concat(".", array.concat([_prefix], p))

_num(x) if {
	is_number(x)
	x >= 0
}

_text(x) if {
	is_string(x)
	trim_space(x) != ""
}

_missing(spec) := (((b | s) | n) | z) | l if {
	b := {_path(e[0]) | some e in object.get(spec, "bools", []); not is_boolean(_get(e[0]))}
	s := {_path(p) | some p in object.get(spec, "strings", []); not _text(_get(p))}
	n := {_path(p) | some e in object.get(spec, "bounds", []); some p in [e[0], e[1]]; not _num(_get(p))}
	z := {_path(e[0]) | some e in object.get(spec, "zeros", []); not _num(_get(e[0]))}
	l := {concat("", [_path(p), " (non-empty list)"]) | some p in object.get(spec, "lists", []); not _list(_get(p))}
}

_list(x) if {
	is_array(x)
	count(x) > 0
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
	z := {sprintf(e[1], [v]) | some e in object.get(spec, "zeros", []); v := _get(e[0]); _num(v); v > 0}
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
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>} at input.ps_controls.<name>.attestation.
_attested(name) if {
	a := object.get(_ps, [name, "attestation"], null)
	a.attested == true
	_text(a.by)
	_text(a.date)
}

# --- PS-1 ---
# Policy and Procedures. Facts: input.ps_controls.policy.documented, input.ps_controls.procedures.documented, input.ps_controls.official.designated
# (booleans); input.ps_controls.policy.days_since_last / .odp.frequency_days and input.ps_controls.procedures.days_since_last /
# .odp.frequency_days (PS-1c review frequencies).
_ps1 := _assess({"bools": [[["policy", "documented"], "personnel security policy not documented"], [["procedures", "documented"], "personnel security procedures not documented"], [["official", "designated"], "no official designated to manage the personnel security policy and procedures"]], "bounds": [_freq(["policy"], "personnel security policy last reviewed"), _freq(["procedures"], "personnel security procedures last reviewed")]})

violation contains msg if {
	count(_ps1.missing) > 0
	msg := sprintf("NIST PS-1: evidence missing — %s not collected%s", [concat(", ", sort(_ps1.missing)), _also(_ps1.gaps)])
}

violation contains msg if {
	count(_ps1.missing) == 0
	count(_ps1.gaps) > 0
	msg := sprintf("NIST PS-1: personnel security policy and procedures requirements not met: %s", [concat("; ", sort(_ps1.gaps))])
}

# --- PS-2 ---
# Position Risk Designation. Facts: input.ps_controls.position_risk.positions_without_designation (number of positions with no
# risk designation), input.ps_controls.position_risk.screening_criteria_established (boolean); input.ps_controls.position_risk.days_since_last /
# .odp.frequency_days (PS-2c).
_ps2 := _assess({"bools": [[["position_risk", "screening_criteria_established"], "screening criteria not established for individuals filling positions"]], "bounds": [_freq(["position_risk"], "position risk designations last reviewed")], "zeros": [[["position_risk", "positions_without_designation"], "%v organizational positions have no risk designation"]]})

violation contains msg if {
	count(_ps2.missing) > 0
	msg := sprintf("NIST PS-2: evidence missing — %s not collected%s", [concat(", ", sort(_ps2.missing)), _also(_ps2.gaps)])
}

violation contains msg if {
	count(_ps2.missing) == 0
	count(_ps2.gaps) > 0
	msg := sprintf("NIST PS-2: position risk designation requirements not met: %s", [concat("; ", sort(_ps2.gaps))])
}

# --- PS-3 ---
# Personnel Screening. Facts: input.ps_controls.screening.unscreened_with_access (number of individuals authorized for access
# without screening), input.ps_controls.screening.rescreening_overdue (number of individuals whose rescreening under the
# organization-defined conditions and frequency is overdue).
_ps3 := _assess({"zeros": [[["screening", "unscreened_with_access"], "%v individuals were authorized for system access without screening"], [["screening", "rescreening_overdue"], "%v individuals are overdue for rescreening under the organization-defined conditions and frequency"]]})

violation contains msg if {
	count(_ps3.missing) > 0
	msg := sprintf("NIST PS-3: evidence missing — %s not collected%s", [concat(", ", sort(_ps3.missing)), _also(_ps3.gaps)])
}

violation contains msg if {
	count(_ps3.missing) == 0
	count(_ps3.gaps) > 0
	msg := sprintf("NIST PS-3: personnel screening requirements not met: %s", [concat("; ", sort(_ps3.gaps))])
}

# --- PS-4 ---
# Personnel Termination. Facts: input.ps_controls.termination.max_hours_to_disable (longest observed time from termination to
# access disabled) against input.ps_controls.termination.odp.disable_within_hours (organization-defined time period);
# input.ps_controls.termination.active_credentials_after_termination (number of terminated individuals with authenticators or
# credentials still valid); input.ps_controls.termination.exit_interviews_conducted, .property_retrieved, .access_retained (booleans).
_ps4 := _assess({"bools": [[["termination", "exit_interviews_conducted"], "exit interviews covering the organization-defined security topics not conducted"], [["termination", "property_retrieved"], "security-related organizational property not retrieved from terminated individuals"], [["termination", "access_retained"], "access to information and systems formerly controlled by terminated individuals not retained"]], "bounds": [[["termination", "max_hours_to_disable"], ["termination", "odp", "disable_within_hours"], "system access disabled up to %v hours after termination; the organization-defined time period is %v hours"]], "zeros": [[["termination", "active_credentials_after_termination"], "%v terminated individuals still hold valid authenticators or credentials"]]})

violation contains msg if {
	count(_ps4.missing) > 0
	msg := sprintf("NIST PS-4: evidence missing — %s not collected%s", [concat(", ", sort(_ps4.missing)), _also(_ps4.gaps)])
}

violation contains msg if {
	count(_ps4.missing) == 0
	count(_ps4.gaps) > 0
	msg := sprintf("NIST PS-4: personnel termination requirements not met: %s", [concat("; ", sort(_ps4.gaps))])
}

# --- PS-5 ---
# Personnel Transfer. Facts: input.ps_controls.transfer.access_need_reviewed, input.ps_controls.transfer.access_modified (booleans);
# input.ps_controls.transfer.max_days_to_initiate against .odp.initiate_within_days (organization-defined transfer actions and
# period); input.ps_controls.transfer.max_hours_to_notify against .odp.notify_within_hours (notification of the
# organization-defined personnel or roles).
_ps5 := _assess({"bools": [[["transfer", "access_need_reviewed"], "ongoing need for logical and physical access not reviewed on reassignment or transfer"], [["transfer", "access_modified"], "access authorizations not modified to match the changed operational need"]], "bounds": [[["transfer", "max_days_to_initiate"], ["transfer", "odp", "initiate_within_days"], "transfer actions initiated up to %v days after the formal transfer; the organization-defined period is %v days"], [["transfer", "max_hours_to_notify"], ["transfer", "odp", "notify_within_hours"], "personnel notified up to %v hours after the transfer; the organization-defined time period is %v hours"]]})

violation contains msg if {
	count(_ps5.missing) > 0
	msg := sprintf("NIST PS-5: evidence missing — %s not collected%s", [concat(", ", sort(_ps5.missing)), _also(_ps5.gaps)])
}

violation contains msg if {
	count(_ps5.missing) == 0
	count(_ps5.gaps) > 0
	msg := sprintf("NIST PS-5: personnel transfer requirements not met: %s", [concat("; ", sort(_ps5.gaps))])
}

# --- PS-6 ---
# Access Agreements. Facts: input.ps_controls.access_agreements.documented, input.ps_controls.access_agreements.resign_required (booleans);
# input.ps_controls.access_agreements.unsigned_with_access (number of individuals with access and no signed agreement);
# input.ps_controls.access_agreements.days_since_last / .odp.frequency_days (PS-6b).
_ps6 := _assess({"bools": [[["access_agreements", "documented"], "access agreements not developed and documented"], [["access_agreements", "resign_required"], "individuals are not required to re-sign updated access agreements"]], "bounds": [_freq(["access_agreements"], "access agreements last reviewed")], "zeros": [[["access_agreements", "unsigned_with_access"], "%v individuals hold access without a signed access agreement"]]})

violation contains msg if {
	count(_ps6.missing) > 0
	msg := sprintf("NIST PS-6: evidence missing — %s not collected%s", [concat(", ", sort(_ps6.missing)), _also(_ps6.gaps)])
}

violation contains msg if {
	count(_ps6.missing) == 0
	count(_ps6.gaps) > 0
	msg := sprintf("NIST PS-6: access agreement requirements not met: %s", [concat("; ", sort(_ps6.gaps))])
}

# --- PS-7 ---
# External Personnel Security. Facts: input.ps_controls.external_personnel.requirements_established,
# .compliance_required, .requirements_documented, .compliance_monitored (booleans);
# input.ps_controls.external_personnel.max_hours_to_notify against .odp.notify_within_hours (providers' notice of transfers or
# terminations to the organization-defined personnel).
_ps7 := _assess({"bools": [[["external_personnel", "requirements_established"], "personnel security requirements, roles and responsibilities for external providers not established"], [["external_personnel", "compliance_required"], "external providers not required to comply with organizational personnel security policies and procedures"], [["external_personnel", "requirements_documented"], "external personnel security requirements not documented"], [["external_personnel", "compliance_monitored"], "provider compliance with personnel security requirements not monitored"]], "bounds": [[["external_personnel", "max_hours_to_notify"], ["external_personnel", "odp", "notify_within_hours"], "providers reported transfers or terminations up to %v hours later; the organization-defined time period is %v hours"]]})

violation contains msg if {
	count(_ps7.missing) > 0
	msg := sprintf("NIST PS-7: evidence missing — %s not collected%s", [concat(", ", sort(_ps7.missing)), _also(_ps7.gaps)])
}

violation contains msg if {
	count(_ps7.missing) == 0
	count(_ps7.gaps) > 0
	msg := sprintf("NIST PS-7: external personnel security requirements not met: %s", [concat("; ", sort(_ps7.gaps))])
}

# --- PS-8 ---
# Personnel Sanctions. Facts: input.ps_controls.sanctions.process_employed (boolean); input.ps_controls.sanctions.max_hours_to_notify against
# .odp.notify_within_hours (notice to the organization-defined personnel when a sanctions process starts).
_ps8 := _assess({"bools": [[["sanctions", "process_employed"], "no formal sanctions process for individuals failing to comply with security and privacy policies"]], "bounds": [[["sanctions", "max_hours_to_notify"], ["sanctions", "odp", "notify_within_hours"], "personnel notified up to %v hours after a sanctions process was initiated; the organization-defined time period is %v hours"]]})

violation contains msg if {
	count(_ps8.missing) > 0
	msg := sprintf("NIST PS-8: evidence missing — %s not collected%s", [concat(", ", sort(_ps8.missing)), _also(_ps8.gaps)])
}

violation contains msg if {
	count(_ps8.missing) == 0
	count(_ps8.gaps) > 0
	msg := sprintf("NIST PS-8: personnel sanctions requirements not met: %s", [concat("; ", sort(_ps8.gaps))])
}

# --- PS-9 ---
# Position Descriptions: security and privacy roles and responsibilities incorporated into position descriptions.
# Evidence: attestation at input.ps_controls.position_descriptions.attestation (organizational control).
violation contains msg if {
	not _attested("position_descriptions")
	msg := "NIST PS-9: incorporation of security and privacy roles and responsibilities into position descriptions not attested — organizational control with no machine-checkable evidence; input.ps_controls.position_descriptions.attestation must be {attested: true, by, date}"
}

# --- PS-3(3) ---
# Information Requiring Special Protective Measures: individuals with access to a system processing information
# that needs special protection hold valid access authorizations demonstrated by assigned official government
# duties and satisfy the organization-defined additional screening criteria.
# Facts (input.ps_controls.screening.special_protection): odp.criteria (non-empty list of the additional criteria);
# individuals_without_valid_authorization (number of such individuals with no valid access authorization tied to
# official duties); individuals_not_meeting_criteria (number not meeting the additional criteria).
_ps3_3 := _assess({"lists": [["screening", "special_protection", "odp", "criteria"]], "zeros": [[["screening", "special_protection", "individuals_without_valid_authorization"], "%v individuals with access to specially protected information hold no valid access authorization tied to official duties"], [["screening", "special_protection", "individuals_not_meeting_criteria"], "%v individuals with access to specially protected information do not satisfy the organization-defined additional screening criteria"]]})

violation contains msg if {
	count(_ps3_3.missing) > 0
	msg := sprintf("NIST PS-3(3): evidence missing — %s not collected%s", [concat(", ", sort(_ps3_3.missing)), _also(_ps3_3.gaps)])
}

violation contains msg if {
	count(_ps3_3.missing) == 0
	count(_ps3_3.gaps) > 0
	msg := sprintf("NIST PS-3(3): special protective screening requirements not met: %s", [concat("; ", sort(_ps3_3.gaps))])
}

# --- PS-4(2) ---
# Automated Actions: the organization-defined automated mechanisms notify the organization-defined personnel of
# termination actions and/or disable access to system resources.
# Facts (input.ps_controls.termination.automated_actions): odp.mechanisms (non-empty list, e.g. HR-to-IdP
# deprovisioning); odp.actions (non-empty list drawn from "notify" and "disable_access"); enabled (boolean: the
# mechanism is active); terminations_without_automated_action (number of terminations in the review period where
# the selected actions were not performed by the mechanism).
_ps4_2_actions := {"notify", "disable_access"}

_ps4_2_actions_ok if {
	a := object.get(_ps, ["termination", "automated_actions", "odp", "actions"], null)
	_list(a)
	every x in a {
		x in _ps4_2_actions
	}
}

_ps4_2_base := _assess({"bools": [[["termination", "automated_actions", "enabled"], "the automated termination mechanism is not enabled"]], "lists": [["termination", "automated_actions", "odp", "mechanisms"]], "zeros": [[["termination", "automated_actions", "terminations_without_automated_action"], "%v terminations were not acted on by the automated mechanism"]]})

_ps4_2_missing := _ps4_2_base.missing | {"input.ps_controls.termination.automated_actions.odp.actions (non-empty list of notify, disable_access)" | not _ps4_2_actions_ok}

violation contains msg if {
	count(_ps4_2_missing) > 0
	msg := sprintf("NIST PS-4(2): evidence missing — %s not collected%s", [concat(", ", sort(_ps4_2_missing)), _also(_ps4_2_base.gaps)])
}

violation contains msg if {
	count(_ps4_2_missing) == 0
	count(_ps4_2_base.gaps) > 0
	msg := sprintf("NIST PS-4(2): automated termination actions not performed: %s", [concat("; ", sort(_ps4_2_base.gaps))])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"PS-1", "PS-2", "PS-3", "PS-3(3)", "PS-4", "PS-4(2)", "PS-5", "PS-6", "PS-7", "PS-8", "PS-9"}

compliance_report := {
	"family": "PS",
	"name": "Personnel Security",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
