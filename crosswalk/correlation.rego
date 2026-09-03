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
# Input contract:
#   input.findings : [ { "stig_id": "RHEL-09-255010",
#                        "status": "Not_a_Finding" | "Open" | ... }, ... ]
#     (the exact finding shape every stig/<platform> aggregator emits)
#
# Output:
#   control_status[<800-53 control>] = "satisfied" | "gap" | "not_evaluated"
#     satisfied     — every evaluated rule mapped to the control passed
#     gap           — at least one evaluated rule mapped to the control is Open
#     not_evaluated — the control is in the crosswalk but no supplied finding
#                     touches it (honest: we did not assess it, not a pass)
#   summary        — counts + the satisfied-control list for downstream
#                    framework rollups

crosswalk := data.crosswalk.stig_800_53.map

# Controls referenced by the findings actually supplied.
evaluated_controls contains ctrl if {
	some f in input.findings
	some ctrl in crosswalk[f.stig_id]
}

# A control has a gap if any evaluated rule mapping to it is Open.
_gap_controls contains ctrl if {
	some f in input.findings
	f.status == "Open"
	some ctrl in crosswalk[f.stig_id]
}

control_status[ctrl] := "gap" if {
	some ctrl in evaluated_controls
	ctrl in _gap_controls
}

control_status[ctrl] := "satisfied" if {
	some ctrl in evaluated_controls
	not ctrl in _gap_controls
}

satisfied_controls := {c | some c, s in control_status; s == "satisfied"}

gap_controls := {c | some c, s in control_status; s == "gap"}

# Family rollup — 800-53 controls grouped by their two-letter family.
_family(ctrl) := split(ctrl, "-")[0]

families_touched := {_family(c) | some c in evaluated_controls}

summary := {
	"controls_evaluated": count(evaluated_controls),
	"controls_satisfied": count(satisfied_controls),
	"controls_with_gaps": count(gap_controls),
	"families_touched": count(families_touched),
	"satisfied": sort([c | some c in satisfied_controls]),
	"gaps": sort([c | some c in gap_controls]),
}
