# METADATA
# title: "NIST SP 800-53 Rev 5 — Incident Response (IR) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 11
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.incident_response

import rego.v1

# NIST SP 800-53 Rev 5 — Incident Response (IR) Family
# Detect, analyze, contain, eradicate, and recover from incidents.

default compliant := false

violation contains msg if {
	not input.ir_controls.policy.documented
	msg := "NIST IR-1: Incident response policy and procedures not documented"
}

# IR-2 and IR-3 frequencies are organization-defined (IR-2 "[frequency] thereafter"; IR-3 "[frequency]").
# The organisation supplies the frequency in days under .odp.frequency_days; the observed age is compared
# with it. Either value missing is reported as missing evidence. (The old *_within_year booleans are not read.)
_freq_missing(path, obs, odp) := {m |
	some pair in [[obs, "days_since_last"], [odp, "odp.frequency_days (organization-defined frequency)"]]
	not is_number(pair[0])
	m := concat("", ["input.ir_controls.", path, ".", pair[1]])
}

_ir2 := object.get(input, ["ir_controls", "training"], {})

_ir2_missing := _freq_missing("training", object.get(_ir2, "days_since_last", null), object.get(_ir2, ["odp", "frequency_days"], null))

violation contains msg if {
	count(_ir2_missing) > 0
	msg := sprintf("NIST IR-2: evidence missing — %s not collected", [concat(", ", sort(_ir2_missing))])
}

violation contains msg if {
	count(_ir2_missing) == 0
	_ir2.days_since_last > _ir2.odp.frequency_days
	msg := sprintf("NIST IR-2: Incident response training last provided %v days ago; the organization-defined frequency is %v days", [_ir2.days_since_last, _ir2.odp.frequency_days])
}

_ir3 := object.get(input, ["ir_controls", "testing"], {})

_ir3_missing := _freq_missing("testing", object.get(_ir3, "days_since_last", null), object.get(_ir3, ["odp", "frequency_days"], null))

violation contains msg if {
	count(_ir3_missing) > 0
	msg := sprintf("NIST IR-3: evidence missing — %s not collected", [concat(", ", sort(_ir3_missing))])
}

violation contains msg if {
	count(_ir3_missing) == 0
	_ir3.days_since_last > _ir3.odp.frequency_days
	msg := sprintf("NIST IR-3: Incident response capability last tested %v days ago; the organization-defined frequency is %v days", [_ir3.days_since_last, _ir3.odp.frequency_days])
}

violation contains msg if {
	not input.ir_controls.handling.process_defined
	msg := "NIST IR-4: Incident handling process (preparation/detection/analysis/containment/eradication/recovery) not defined"
}

# IR-5 Incident Monitoring: "Track and document incidents." (monitoring.continuous is not read: continuous
# monitoring is SI-4, not IR-5.)
violation contains msg if {
	not input.ir_controls.incident_tracking.tracked_and_documented == true
	msg := "NIST IR-5: Incidents not evidenced as tracked and documented (input.ir_controls.incident_tracking.tracked_and_documented)"
}

violation contains msg if {
	not input.ir_controls.reporting.timely
	msg := "NIST IR-6: Incident reporting to internal/external parties not timely"
}

violation contains msg if {
	not input.ir_controls.assistance.available
	msg := "NIST IR-7: Incident response assistance/coordination resources not available"
}

violation contains msg if {
	not input.ir_controls.plan.documented
	msg := "NIST IR-8: Documented incident response plan does not exist"
}

violation contains msg if {
	not input.ir_controls.information_spillage.process_defined
	msg := "NIST IR-9: Information spillage response process not defined"
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8", "IR-9"}

compliance_report := {
	"family": "IR",
	"name": "Incident Response",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
