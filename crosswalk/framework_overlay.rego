# METADATA
# title: "Framework inheritance overlay — \"report against many.\""
# custom:
#   class: compliance
#   framework: crosswalk
#   source: nist
#   domains: [crosswalk, security-controls]
#   coverage:
#     checks: 0
#     cited: 0
#     density: overlay
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
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
# A map need not be the identity. The NIST-published maps (nist_csf_2_0, nist_800_171_r3, iso_27001_2022;
# scripts/gen_nist_framework_maps.py) send one framework id to several 800-53 controls and enhancements. The
# rules above are unchanged for them: one gap among the mapped controls is a gap; "satisfied" needs every mapped
# id evaluated and satisfied, which a mapped enhancement prevents (the spine is at base-control granularity), so
# such an id reads "not_covered" with the evaluated controls under `spine` and the rest under `not_evaluated`.
#
# Input: same as crosswalk.correlation (input.findings, input.reports).

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
	# Sets, then sorted: a framework control mapped to several spine controls is listed once.
	sat := sort({fc |
		some fc
		ctrls := fwmap[fc]
		count(ctrls) > 0
		every c in ctrls { _control_status[c] == "satisfied" }
	})
	gaps := sort({fc |
		some fc
		ctrls := fwmap[fc]
		some c in ctrls
		_control_status[c] == "gap"
	})

	# not_covered: every framework control that is neither satisfied nor a gap, so the three lists always
	# partition controls_total. That includes controls whose spine controls were never evaluated and controls
	# only partly evaluated (some satisfied, some never evaluated), which cannot be claimed satisfied.
	notcov := sort([fc |
		some fc
		fwmap[fc]
		not fc in sat
		not fc in gaps
	])
}

_any_evaluated(ctrls) if {
	some c in ctrls
	_control_status[c]
}

# Per-control evidence for a framework that inherits from the spine: the helper a framework module reads to take
# its technical verdict from benchmark results (data.crosswalk.framework_overlay.control_evidence[<key>][<id>]).
#   status         gap | satisfied | not_covered, by the same rules as coverage above
#   spine          the evaluated 800-53 controls behind it, each with its status and contributing rule ids
#   not_evaluated  the mapped 800-53 controls no supplied rule speaks to
# Authoritative maps only. Verdicts are carried through the maps unchanged; nothing is scored or ranked.
control_evidence[fw][fc] := ev if {
	some fw, spec in _maps
	spec.status == "authoritative"
	some fc, ctrls in spec.map
	ev := {
		"status": _evidence_status(ctrls),
		"spine": {c: e | some c in ctrls; e := correlation.control_evidence[c]},
		"not_evaluated": sort({c | some c in ctrls; not _control_status[c]}),
	}
}

_evidence_status(ctrls) := "gap" if {
	some c in ctrls
	_control_status[c] == "gap"
} else := "satisfied" if {
	count(ctrls) > 0
	every c in ctrls { _control_status[c] == "satisfied" }
} else := "not_covered"

# The reverse index of an authoritative map: for an 800-53 id, the framework ids that map to it. A framework
# module reads it to say which of its controls a spine verdict lands on, and which verdicts land on none
# (data.crosswalk.framework_overlay.inherited_by[<key>][<800-53 id>]). Read from the map alone; no input needed.
inherited_by[fw][c] := fcs if {
	some fw, spec in _maps
	spec.status == "authoritative"
	some c in {x | some xs in spec.map; some x in xs}
	fcs := sort({fc | some fc, ctrls in spec.map; c in ctrls})
}

# Where an authoritative map comes from, for a framework module to cite beside the verdicts it takes through it:
# the map's name, source, granularity and, for a generated map, its meta (source URL, sha256, publication date,
# licence, the relationship the publisher states, counts).
map_info[fw] := info if {
	some fw, spec in _maps
	spec.status == "authoritative"
	info := {k: v | some k, v in spec; k != "map"}
}

frameworks_reported := sort([fw | some fw; _ = coverage[fw]])

frameworks_pending := sort([fw |
	some fw
	spec := _maps[fw]
	spec.status == "pending"
])

# One-assessment summary: what this run discharged, across all frameworks.
summary := {
	"spine": correlation.summary,
	"frameworks_reported": frameworks_reported,
	"frameworks_pending": frameworks_pending,
	"coverage": coverage,
}
