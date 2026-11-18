# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 4 -- Microsoft Intune admin center
#
# Section 4 has exactly 2 recommendations and uses TWO-level control ids
# (4.1, 4.2) where every other section uses three or four. That is the
# benchmark's own numbering, not a typo.
#
# Both are reachable from Microsoft Graph, but only with the
# DeviceManagementConfiguration.Read.All application permission, which is
# an ADDITION to what the other collectors need. Without it both controls
# report as unevaluable rather than passing.
#
# Input contract (aac.m365.m365_intune_facts):
#   input.intune.secure_by_default                  - bool
#   input.intune.enrollment_platform_restrictions[] - {display_name, platforms{}}
#   input.intune.unavailable                        - {fact_key: reason}

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 7
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_m365_v7.intune

import rego.v1

default compliant := false

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

default unavailable := {}

unavailable := input.intune.unavailable if is_object(input.intune.unavailable)

default collected := false

collected if {
	input.intune.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# ── CIS 4.1 -- devices without a compliance policy are 'not compliant' ─
# Intune calls this "secure by default". When false, a device that no
# compliance policy targets is treated as compliant, so Conditional
# Access admits it.
violation contains msg if {
	available("device_management_settings")
	input.intune.secure_by_default == false
	msg := "CIS 4.1: devices not targeted by a compliance policy are marked compliant rather than 'not compliant' -- an unmanaged device satisfies device-compliance Conditional Access by default"
}

# ── CIS 4.2 -- personal device enrollment blocked ────────────────────
_restrictions := input.intune.enrollment_platform_restrictions if {
	available("enrollment_configurations")
	is_array(input.intune.enrollment_platform_restrictions)
}

violation contains msg if {
	count(_restrictions) == 0
	msg := "CIS 4.2: no platform enrollment restriction is configured, so device enrollment for personally owned devices is not blocked by default"
}

violation contains msg if {
	some r in _restrictions
	is_object(r.platforms)
	some platform, settings in r.platforms
	settings.personal_device_enrollment_blocked == false
	msg := sprintf("CIS 4.2: enrollment restriction '%s' permits personally owned %s devices; personal device enrollment should be blocked by default", [object.get(r, "display_name", "(unnamed)"), platform])
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "4",
	"name": "Microsoft Intune admin center",
	"section_total_controls": 2,
	"controls_evaluated": 2,
	"controls": ["4.1", "4.2"],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Per-control results ──────────────────────────────────────────────
# `decidable` holds the controls of this section whose facts were all
# collected; CONTROL_EVIDENCE names the input paths each one reads ("[]"
# = every element of a list). A control that is not decidable is reported
# by id as evidence missing (rules at the end of the file) and the main
# report marks it "evidence_missing": an absent fact must never read as a
# pass. Each gate restates the condition of its rule above; change them
# together.
CONTROL_EVIDENCE := {
	"4.1": ["intune.secure_by_default"],
	"4.2": ["intune.enrollment_platform_restrictions[].platforms.*.personal_device_enrollment_blocked"],
}

decidable contains "4.1" if {
	available("device_management_settings")
	is_boolean(input.intune.secure_by_default)
}

decidable contains "4.2" if {
	every r in _restrictions {
		is_object(r.platforms)
		every _, settings in r.platforms {
			is_boolean(settings.personal_device_enrollment_blocked)
		}
	}
}

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks, so the per-control results and an
# exporter reading the ids agree on what was not evaluated. A key this module
# does not know is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"device_management_settings": ["4.1"],
	"enrollment_configurations": ["4.2"],
}

_section_controls := _natural_sort(object.keys(CONTROL_EVIDENCE))

# ids in benchmark order
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_section_controls, "Intune facts were not collected (intune.collected is not true); collecting them requires the DeviceManagementConfiguration.Read.All application permission"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("intune.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names the controls it leaves undecided
_evidence_gaps contains _gap(ids, g[1]) if {
	some g in _source_gaps
	ids := [id | some id in g[0]; not id in decidable]
	count(ids) > 0
}

_evidence_gaps contains msg if {
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 4 (Intune): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
