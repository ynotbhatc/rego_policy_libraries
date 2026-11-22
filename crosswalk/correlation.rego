# METADATA
# title: "Control-correlation engine — \"assess once, report against many.\""
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
package crosswalk.correlation

import rego.v1

# Control-correlation engine — "assess once, report against many."
#
# THE PATTERN (measured, documented in docs/CONTROL_CORRELATION_PATTERN.md):
# the same underlying control is written many times across standards under
# incompatible IDs (STIG AZLX-23-000050, CIS 4.1.1.1, NIST AC-17). DISA
# already carries the join key — every STIG rule maps to one or more CCIs,
# and each CCI maps to a NIST SP 800-53 control. This module uses the
# shipped stig_id → 800-53 crosswalk (data.crosswalk.stig_800_53.map) to
# roll a platform's findings up onto the 800-53 spine, so one assessment
# discharges every framework that inherits from those controls.
#
# Input contract (either or both):
#   input.reports  : [ <STIG compliance_report>, ... ]   every stig/<platform> report carries
#                    rule_results: [ {"rule": "RHEL-09-255010", "status": "Not_a_Finding" | "Open" |
#                    "Not_Applicable" | "Not_Reviewed"}, ... ] — one row per rule, passes included
#   input.findings : [ { "stig_id": "RHEL-09-255010", "status": ... }, ... ]   (the older shape)
#
# Output:
#   control_status[<800-53 control>] =
#     gap            — at least one mapped rule is Open
#     not_reviewed   — no mapped rule is Open, at least one is Not_Reviewed (an unresolved manual review)
#     satisfied      — every mapped rule is Not_a_Finding or Not_Applicable, and at least one is Not_a_Finding
#     not_applicable — every mapped rule is Not_Applicable
#   A rule with any other status counts as Open. A control no supplied rule maps to is absent: not assessed,
#   never a pass. A report whose facts_supplied is false contributes its rules as Open (the STIG mains already
#   report every rule Open then).
#   summary        — counts + the satisfied / gap control lists for downstream framework rollups
#   control_evidence[<800-53 control>] = {status, rules, open_rules, not_reviewed_rules}: the same verdict as
#     control_status with the contributing rule ids, so a framework module that takes its technical verdict
#     from the spine can show which rules decided it. rules lists every supplied rule the crosswalk maps to
#     the control; open_rules are the ones that make it a gap; not_reviewed_rules the unresolved manual reviews.
#   evidence_supplied     — true when the input carries input.reports or input.findings at all
#   spine_loaded          — true when the stig_id -> 800-53 map is present in data (a consumer that cannot see
#                           the map must not read "no verdict" as "no gap")
#   reports_without_facts — how many supplied reports had facts_supplied == false
#
# This package only carries verdicts through the DISA map. It does not score, weight or rank anything.

crosswalk := data.crosswalk.stig_800_53.map

_known := {"Not_a_Finding", "Open", "Not_Applicable", "Not_Reviewed"}

_norm(s) := s if s in _known

else := "Open"

# [rule, status] rows from both input shapes.
_rows contains [f.stig_id, _norm(f.status)] if {
	some f in input.findings
	is_string(f.stig_id)
}

_rows contains [r.rule, _status_in(rep, r)] if {
	some rep in input.reports
	some r in rep.rule_results
	is_string(r.rule)
}

_status_in(rep, r) := "Open" if {
	rep.facts_supplied == false
} else := _norm(r.status)

_statuses[ctrl] contains st if {
	some row in _rows
	some ctrl in crosswalk[row[0]]
	st := row[1]
}

# Controls referenced by the rules actually supplied.
evaluated_controls := {ctrl | some ctrl, _ in _statuses}

control_status[ctrl] := st if {
	some ctrl, sts in _statuses
	st := _rollup(sts)
}

_rollup(sts) := "gap" if {
	"Open" in sts
} else := "not_reviewed" if {
	"Not_Reviewed" in sts
} else := "satisfied" if {
	"Not_a_Finding" in sts
} else := "not_applicable"

satisfied_controls := {c | some c, s in control_status; s == "satisfied"}

gap_controls := {c | some c, s in control_status; s == "gap"}

not_reviewed_controls := {c | some c, s in control_status; s == "not_reviewed"}

not_applicable_controls := {c | some c, s in control_status; s == "not_applicable"}

# Rule ids behind each control's verdict, grouped by the status they were supplied with.
_rules_by[ctrl][st] contains rule if {
	some row in _rows
	some ctrl in crosswalk[row[0]]
	rule := row[0]
	st := row[1]
}

_rules_with(ctrl, st) := sort(object.get(object.get(_rules_by, ctrl, {}), st, set()))

control_evidence[ctrl] := {
	"status": st,
	"rules": sort({rule | some rules in _rules_by[ctrl]; some rule in rules}),
	"open_rules": _rules_with(ctrl, "Open"),
	"not_reviewed_rules": _rules_with(ctrl, "Not_Reviewed"),
} if {
	some ctrl, st in control_status
}

default evidence_supplied := false

evidence_supplied if _ = input.reports

evidence_supplied if _ = input.findings

default spine_loaded := false

spine_loaded if count(crosswalk) > 0

reports_without_facts := count([rep | some rep in input.reports; rep.facts_supplied == false])

# Family rollup — 800-53 controls grouped by their two-letter family.
_family(ctrl) := split(ctrl, "-")[0]

families_touched := {_family(c) | some c in evaluated_controls}

# Supplied rules the crosswalk has no entry for: they cannot speak to any 800-53 control.
unmapped_rules := {row[0] | some row in _rows; not crosswalk[row[0]]}

summary := {
	"controls_evaluated": count(evaluated_controls),
	"controls_satisfied": count(satisfied_controls),
	"controls_with_gaps": count(gap_controls),
	"controls_not_reviewed": count(not_reviewed_controls),
	"controls_not_applicable": count(not_applicable_controls),
	"families_touched": count(families_touched),
	"rules_supplied": count({row[0] | some row in _rows}),
	"rules_unmapped": count(unmapped_rules),
	"satisfied": sort([c | some c in satisfied_controls]),
	"gaps": sort([c | some c in gap_controls]),
}
