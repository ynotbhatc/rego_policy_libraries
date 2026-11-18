# METADATA
# title: "NIST SP 800-53 Rev 5 — Planning (PL) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 16
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.planning

import rego.v1

# NIST SP 800-53 Rev 5 — Planning (PL) Family
# Base controls only (PL-1, PL-2, PL-4, PL-7, PL-8, PL-9, PL-10, PL-11); PL-3, PL-5 and PL-6 are withdrawn.
# Facts live under input.pl_controls and every control fails closed: a fact that is absent or of the wrong
# type is reported as evidence missing, never as a pass. Booleans pass only on true; numbers must be
# non-negative numbers. Organization-defined frequencies are compared as observed days_since_last against the
# organisation's odp.frequency_days, as in IR-2/IR-3.

default compliant := false

_prefix := "input.pl_controls"

_pl := v if {
	v := object.get(input, "pl_controls", {})
	is_object(v)
} else := {}

# --- shared fact checker -----------------------------------------------------------------------------------
# A spec is an object with optional keys:
#   bools:   [[path, text when false]]           pass only on true; a non-boolean is evidence missing
#   strings: [path]                              a non-empty string; anything else is evidence missing
#   bounds:  [[observed path, odp path, fmt]]    both non-negative numbers; observed > odp is unmet
#   zeros:   [[path, fmt]]                       a non-negative number; above zero is unmet
_get(p) := object.get(_pl, p, null)

_path(p) := concat(".", array.concat([_prefix], p))

_num(x) if {
	is_number(x)
	x >= 0
}

_text(x) if {
	is_string(x)
	trim_space(x) != ""
}

_missing(spec) := ((b | s) | n) | z if {
	b := {_path(e[0]) | some e in object.get(spec, "bools", []); not is_boolean(_get(e[0]))}
	s := {_path(p) | some p in object.get(spec, "strings", []); not _text(_get(p))}
	n := {_path(p) | some e in object.get(spec, "bounds", []); some p in [e[0], e[1]]; not _num(_get(p))}
	z := {_path(e[0]) | some e in object.get(spec, "zeros", []); not _num(_get(e[0]))}
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
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>} at input.pl_controls.<name>.attestation.
_attested(name) if {
	a := object.get(_pl, [name, "attestation"], null)
	a.attested == true
	_text(a.by)
	_text(a.date)
}

# --- PL-1 ---
# Policy and Procedures. Facts: input.pl_controls.policy.documented, input.pl_controls.procedures.documented, input.pl_controls.official.designated
# (booleans); input.pl_controls.policy.days_since_last / .odp.frequency_days and input.pl_controls.procedures.days_since_last /
# .odp.frequency_days (PL-1c review frequencies).
_pl1 := _assess({"bools": [[["policy", "documented"], "planning policy not documented"], [["procedures", "documented"], "planning procedures not documented"], [["official", "designated"], "no official designated to manage the planning policy and procedures"]], "bounds": [_freq(["policy"], "planning policy last reviewed"), _freq(["procedures"], "planning procedures last reviewed")]})

violation contains msg if {
	count(_pl1.missing) > 0
	msg := sprintf("NIST PL-1: evidence missing — %s not collected%s", [concat(", ", sort(_pl1.missing)), _also(_pl1.gaps)])
}

violation contains msg if {
	count(_pl1.missing) == 0
	count(_pl1.gaps) > 0
	msg := sprintf("NIST PL-1: planning policy and procedures requirements not met: %s", [concat("; ", sort(_pl1.gaps))])
}

# --- PL-2 ---
# System Security and Privacy Plans. Facts: input.pl_controls.ssp.documented (plans developed), .required_content_complete
# (every PL-2a element present), .distributed (to the organization-defined personnel), .protected (from
# unauthorized disclosure and modification) — booleans; input.pl_controls.ssp.days_since_last / .odp.frequency_days (PL-2c).
_pl2 := _assess({"bools": [[["ssp", "documented"], "system security and privacy plans not developed"], [["ssp", "required_content_complete"], "plans do not contain every element PL-2a requires"], [["ssp", "distributed"], "plans not distributed to the organization-defined personnel or roles"], [["ssp", "protected"], "plans not protected from unauthorized disclosure and modification"]], "bounds": [_freq(["ssp"], "plans last reviewed")]})

violation contains msg if {
	count(_pl2.missing) > 0
	msg := sprintf("NIST PL-2: evidence missing — %s not collected%s", [concat(", ", sort(_pl2.missing)), _also(_pl2.gaps)])
}

violation contains msg if {
	count(_pl2.missing) == 0
	count(_pl2.gaps) > 0
	msg := sprintf("NIST PL-2: system security and privacy plan requirements not met: %s", [concat("; ", sort(_pl2.gaps))])
}

# --- PL-4 ---
# Rules of Behavior. Facts: input.pl_controls.rules_of_behavior.established (rules established and provided to individuals
# requiring access), .reacknowledgment_required (PL-4d) — booleans; .users_without_acknowledgment (number of
# individuals with access and no documented acknowledgment, PL-4b); .days_since_last / .odp.frequency_days (PL-4c).
_pl4 := _assess({"bools": [[["rules_of_behavior", "established"], "rules of behavior not established and provided to individuals requiring access"], [["rules_of_behavior", "reacknowledgment_required"], "individuals are not required to re-acknowledge revised rules of behavior"]], "bounds": [_freq(["rules_of_behavior"], "rules of behavior last reviewed")], "zeros": [[["rules_of_behavior", "users_without_acknowledgment"], "%v individuals hold access without a documented acknowledgment of the rules of behavior"]]})

violation contains msg if {
	count(_pl4.missing) > 0
	msg := sprintf("NIST PL-4: evidence missing — %s not collected%s", [concat(", ", sort(_pl4.missing)), _also(_pl4.gaps)])
}

violation contains msg if {
	count(_pl4.missing) == 0
	count(_pl4.gaps) > 0
	msg := sprintf("NIST PL-4: rules of behavior requirements not met: %s", [concat("; ", sort(_pl4.gaps))])
}

# --- PL-7 ---
# Concept of Operations. Facts: input.pl_controls.conops.documented (boolean); input.pl_controls.conops.days_since_last / .odp.frequency_days.
_pl7 := _assess({"bools": [[["conops", "documented"], "no Concept of Operations (CONOPS) developed for the system"]], "bounds": [_freq(["conops"], "CONOPS last reviewed")]})

violation contains msg if {
	count(_pl7.missing) > 0
	msg := sprintf("NIST PL-7: evidence missing — %s not collected%s", [concat(", ", sort(_pl7.missing)), _also(_pl7.gaps)])
}

violation contains msg if {
	count(_pl7.missing) == 0
	count(_pl7.gaps) > 0
	msg := sprintf("NIST PL-7: concept of operations requirements not met: %s", [concat("; ", sort(_pl7.gaps))])
}

# --- PL-8 ---
# Security and Privacy Architectures. Facts: input.pl_controls.architecture.protection_approach_described,
# .pii_processing_described, .enterprise_integration_described, .external_dependencies_described (PL-8a),
# .changes_reflected (PL-8c) — booleans; input.pl_controls.architecture.days_since_last / .odp.frequency_days (PL-8b).
_pl8 := _assess({"bools": [[["architecture", "protection_approach_described"], "architecture does not describe the approach to protecting confidentiality, integrity and availability"], [["architecture", "pii_processing_described"], "architecture does not describe the approach to processing PII to minimize privacy risk"], [["architecture", "enterprise_integration_described"], "architecture does not describe its integration into the enterprise architecture"], [["architecture", "external_dependencies_described"], "architecture does not describe assumptions about and dependencies on external systems and services"], [["architecture", "changes_reflected"], "planned architecture changes not reflected in plans, CONOPS, criticality analysis, procedures and acquisitions"]], "bounds": [_freq(["architecture"], "security and privacy architectures last reviewed")]})

violation contains msg if {
	count(_pl8.missing) > 0
	msg := sprintf("NIST PL-8: evidence missing — %s not collected%s", [concat(", ", sort(_pl8.missing)), _also(_pl8.gaps)])
}

violation contains msg if {
	count(_pl8.missing) == 0
	count(_pl8.gaps) > 0
	msg := sprintf("NIST PL-8: security and privacy architecture requirements not met: %s", [concat("; ", sort(_pl8.gaps))])
}

# --- PL-9 ---
# Central Management. Facts: input.pl_controls.central_management.centrally_managed (boolean: the organization-defined
# controls and related processes are centrally managed).
_pl9 := _assess({"bools": [[["central_management", "centrally_managed"], "the organization-defined controls and related processes are not centrally managed"]]})

violation contains msg if {
	count(_pl9.missing) > 0
	msg := sprintf("NIST PL-9: evidence missing — %s not collected%s", [concat(", ", sort(_pl9.missing)), _also(_pl9.gaps)])
}

violation contains msg if {
	count(_pl9.missing) == 0
	count(_pl9.gaps) > 0
	msg := sprintf("NIST PL-9: central management requirements not met: %s", [concat("; ", sort(_pl9.gaps))])
}

# --- PL-10 ---
# Baseline Selection. Facts: input.pl_controls.baseline.selected (boolean); input.pl_controls.baseline.name (non-empty string naming the
# selected control baseline, e.g. "NIST SP 800-53B moderate").
_pl10 := _assess({"bools": [[["baseline", "selected"], "no control baseline selected for the system"]], "strings": [["baseline", "name"]]})

violation contains msg if {
	count(_pl10.missing) > 0
	msg := sprintf("NIST PL-10: evidence missing — %s not collected%s", [concat(", ", sort(_pl10.missing)), _also(_pl10.gaps)])
}

violation contains msg if {
	count(_pl10.missing) == 0
	count(_pl10.gaps) > 0
	msg := sprintf("NIST PL-10: baseline selection requirements not met: %s", [concat("; ", sort(_pl10.gaps))])
}

# --- PL-11 ---
# Baseline Tailoring. Facts: input.pl_controls.tailoring.actions_applied (boolean: the selected baseline was tailored by
# applying the specified tailoring actions).
_pl11 := _assess({"bools": [[["tailoring", "actions_applied"], "the selected control baseline has not been tailored"]]})

violation contains msg if {
	count(_pl11.missing) > 0
	msg := sprintf("NIST PL-11: evidence missing — %s not collected%s", [concat(", ", sort(_pl11.missing)), _also(_pl11.gaps)])
}

violation contains msg if {
	count(_pl11.missing) == 0
	count(_pl11.gaps) > 0
	msg := sprintf("NIST PL-11: baseline tailoring requirements not met: %s", [concat("; ", sort(_pl11.gaps))])
}

compliant if count(violation) == 0

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"PL-1", "PL-2", "PL-4", "PL-7", "PL-8", "PL-9", "PL-10", "PL-11"}

compliance_report := {
	"family": "PL",
	"name": "Planning",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
