package crosswalk.framework_overlay

import rego.v1

# Framework inheritance overlay — "report against many."
#
# Sits on top of crosswalk.correlation (the 800-53 control spine) and
# answers, from a SINGLE assessment: for each framework that declares its
# 800-53 inheritance, which of its controls are discharged, which have gaps,
# and which are not covered by the spine at all.
#
# HONESTY RULES (match the rest of the library):
#   - Only frameworks with an AUTHORITATIVELY-SOURCED mapping are reported.
#     Each framework map in data.crosswalk.framework_maps carries a `source`
#     and `status` ("authoritative" | "pending"). Maps marked "pending" (no
#     grounded source yet) are listed under `frameworks_pending`, never scored.
#   - A framework control is "satisfied" only if it maps to ≥1 evaluated
#     spine control AND all of them are satisfied.
#   - A framework control whose 800-53 controls were not evaluated is
#     "not_covered" — explicit, never counted as a pass.
#
# Data contract (data.crosswalk.framework_maps):
#   {
#     "<framework_key>": {
#       "name": "...", "source": "URL/citation", "status": "authoritative",
#       "map": { "<framework_control_id>": ["AC-17", "SC-28", ...], ... }
#     }, ...
#   }
#
# Input: same as crosswalk.correlation (input.findings).

import data.crosswalk.correlation

default _maps := {}

_maps := data.crosswalk.framework_maps.maps

_control_status := correlation.control_status

# Per-framework coverage, authoritative maps only.
coverage[fw] := result if {
	some fw, spec in _maps
	spec.status == "authoritative"
	result := _coverage_for(spec.map)
}

_coverage_for(fwmap) := {
	"satisfied": sat,
	"gaps": gaps,
	"not_covered": notcov,
	"controls_total": count(fwmap),
	"controls_satisfied": count(sat),
} if {
	sat := sort([fc |
		some fc, ctrls in fwmap
		count(ctrls) > 0
		every c in ctrls {_control_status[c] == "satisfied"}
		some c in ctrls
		_control_status[c] # at least one actually evaluated
	])
	gaps := sort([fc |
		some fc, ctrls in fwmap
		some c in ctrls
		_control_status[c] == "gap"
	])
	# not_covered: framework controls whose spine controls were never evaluated
	notcov := sort([fc |
		some fc, ctrls in fwmap
		not _any_evaluated(ctrls)
	])
}

_any_evaluated(ctrls) if {
	some c in ctrls
	_control_status[c]
}

frameworks_reported := sort([fw | some fw, _ in coverage])

frameworks_pending := sort([fw |
	some fw, spec in _maps
	spec.status == "pending"
])

# One-assessment summary: what this run discharged, across all frameworks.
summary := {
	"spine": correlation.summary,
	"frameworks_reported": frameworks_reported,
	"frameworks_pending": frameworks_pending,
	"coverage": coverage,
}
