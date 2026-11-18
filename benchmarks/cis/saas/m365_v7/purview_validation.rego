# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 3 -- Microsoft Purview
#
# Input contract (from the aac.m365 collection):
#   input.purview.audit_log_accessible - bool; a directoryAudits probe
#                                        returned at least one record
#
# DLP and sensitivity-label controls come from Security & Compliance
# PowerShell (aac.m365.m365_purview_ps_facts) -- a DIFFERENT endpoint from
# Exchange Online PowerShell despite shipping in the same module.
#
# NOT EVALUATED: 3.4 (Insider Risk Management) and 3.5 (Communication
# Compliance) are empty subsection headers in v7.0.0 with no
# recommendations under them, so there is nothing to evaluate.
#
# Input contract (aac.m365.m365_purview_ps_facts):
#   input.purview_ps.dlp_policies[]   - {Name, Mode, Enabled, Workload,
#                                        TeamsLocation, ...}
#   input.purview_ps.label_policies[] - {Name, Mode, Enabled, Labels}
#   input.purview_ps.unavailable      - {key: reason}

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 10
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_m365_v7.purview

import rego.v1

default compliant := false

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

default facts_present := false

facts_present if {
	is_boolean(input.purview.audit_log_accessible)
}

# CIS 3.1.1 -- unified audit log search must be enabled. If the audit log
# cannot be read the control is unevaluable, not compliant. The fact is a
# probe of the Entra directoryAudits endpoint (it returned at least one
# record); the benchmark itself reads UnifiedAuditLogIngestionEnabled from
# Get-AdminAuditLogConfig (Exchange Online PowerShell), which the collector
# does not call yet, so a pass here is the probe's, not the benchmark's.
violation contains msg if {
	input.purview.audit_log_accessible == false
	msg := "CIS 3.1.1: unified audit log search returned no records -- audit logging is not enabled, so tenant activity is not retained for investigation"
}

default ps_unavailable := {}

ps_unavailable := input.purview_ps.unavailable if is_object(input.purview_ps.unavailable)

default ps_collected := false

ps_collected if {
	input.purview_ps.collected == true
}

ps_available(key) if {
	ps_collected
	not ps_unavailable[key]
}

_ps_list(key) := input.purview_ps[key] if {
	ps_available(key)
	is_array(input.purview_ps[key])
}

dlp_policies := _ps_list("dlp_policies")

label_policies := _ps_list("label_policies")

# A DLP policy enforces when it is enabled and not in a Test mode. Mode must
# be read: an absent Mode used to default to "" and count as enforcing.
enforcing(p) if {
	p.Enabled == true
	is_string(p.Mode)
	not startswith(lower(p.Mode), "test")
}

_dlp_readable(p) if {
	is_boolean(p.Enabled)
	is_string(p.Mode)
}

# TeamsLocation: a list of locations; null is no location
_teams_locations(p) := p.TeamsLocation if is_array(p.TeamsLocation)

_teams_locations(p) := [] if object.get(p, "TeamsLocation", false) == null

# Workload: a comma-separated string or a list of strings
_workloads(p) := [p.Workload] if is_string(p.Workload)

_workloads(p) := [w | some w in p.Workload; is_string(w)] if is_array(p.Workload)

_covers_teams(p) if {
	enforcing(p)
	count(_teams_locations(p)) > 0
}

_covers_copilot(p) if {
	enforcing(p)
	some w in _workloads(p)
	contains(lower(w), "copilot")
}

# a control that asks for SOME qualifying policy fails only when every policy
# could be read and none qualifies
_dlp_all_readable(extra) if {
	every p in dlp_policies {
		_dlp_readable(p)
		_dlp_field_readable(p, extra)
	}
}

_dlp_field_readable(_, "") := true

_dlp_field_readable(p, "TeamsLocation") if is_array(_teams_locations(p))

_dlp_field_readable(p, "Workload") if is_array(_workloads(p))

violation contains msg if {
	_dlp_all_readable("")
	count([p | some p in dlp_policies; enforcing(p)]) == 0
	msg := "CIS 3.2.1: no DLP policy is enabled and enforcing -- a policy in Test mode reports matches but does not prevent the data loss it detects"
}

violation contains msg if {
	_dlp_all_readable("TeamsLocation")
	count([p | some p in dlp_policies; _covers_teams(p)]) == 0
	msg := "CIS 3.2.2: no enabled DLP policy covers Microsoft Teams, so sensitive content shared in chats and channels is not inspected"
}

violation contains msg if {
	_dlp_all_readable("Workload")
	count([p | some p in dlp_policies; _covers_copilot(p)]) == 0
	msg := "CIS 3.2.3: no DLP policy is published for Copilot users, so content Copilot can surface is not covered by data loss prevention"
}

_labels_readable if {
	every p in label_policies {
		is_boolean(p.Enabled)
	}
}

violation contains msg if {
	_labels_readable
	count([p | some p in label_policies; p.Enabled == true]) == 0
	msg := "CIS 3.3.1: no Information Protection sensitivity label policy is published, so users have no labels to classify content with"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "3",
	"name": "Microsoft Purview",
	"section_total_controls": 5,
	"controls_evaluated": 5,
	"controls": ["3.1.1", "3.2.1", "3.2.2", "3.2.3", "3.3.1"],
	"facts_present": facts_present,
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
	"3.1.1": ["purview.audit_log_accessible"],
	"3.2.1": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode"],
	"3.2.2": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode", "purview_ps.dlp_policies[].TeamsLocation"],
	"3.2.3": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode", "purview_ps.dlp_policies[].Workload"],
	"3.3.1": ["purview_ps.label_policies[].Enabled"],
}

decidable contains "3.1.1" if facts_present

# some qualifying policy decides on its own; otherwise every policy must be readable
decidable contains "3.2.1" if {
	some p in dlp_policies
	enforcing(p)
}

decidable contains "3.2.1" if _dlp_all_readable("")

decidable contains "3.2.2" if {
	some p in dlp_policies
	_covers_teams(p)
}

decidable contains "3.2.2" if _dlp_all_readable("TeamsLocation")

decidable contains "3.2.3" if {
	some p in dlp_policies
	_covers_copilot(p)
}

decidable contains "3.2.3" if _dlp_all_readable("Workload")

decidable contains "3.3.1" if {
	some p in label_policies
	p.Enabled == true
}

decidable contains "3.3.1" if _labels_readable

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks, so the per-control results and an
# exporter reading the ids agree on what was not evaluated. A key this module
# does not know is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"dlp_policies": ["3.2.1", "3.2.2", "3.2.3"],
	"label_policies": ["3.3.1"],
}

PS_CONTROLS := ["3.2.1", "3.2.2", "3.2.3", "3.3.1"]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [PS_CONTROLS, "Purview DLP and label facts were not collected (purview_ps.collected is not true)"] if not ps_collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("purview_ps.unavailable.%s: %v", [key, reason])] if {
	ps_collected
	some key, reason in ps_unavailable
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
	some key, reason in ps_unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 3 (Purview): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
