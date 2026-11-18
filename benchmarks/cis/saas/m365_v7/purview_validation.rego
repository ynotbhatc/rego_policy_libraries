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

default facts_present := false

facts_present if {
	is_boolean(input.purview.audit_log_accessible)
}

# CIS 3.1.1 -- unified audit log search must be enabled. If the audit log
# cannot be searched, there is no record for an investigator to read.
violation contains msg if {
	facts_present
	not input.purview.audit_log_accessible
	msg := "CIS 3.1.1: unified audit log search returned no records -- audit logging is not enabled, so tenant activity is not retained for investigation"
}

violation contains msg if {
	not facts_present
	msg := "CIS 3.1.1: audit log facts not collected -- control could not be evaluated (this is not a pass)"
}

# ── DLP and sensitivity labels (Security & Compliance PowerShell) ─────

default ps_unavailable := {}

ps_unavailable := input.purview_ps.unavailable

default ps_collected := false

ps_collected if {
	input.purview_ps.collected == true
}

ps_available(key) if {
	ps_collected
	not ps_unavailable[key]
}

dlp_policies := object.get(input, ["purview_ps", "dlp_policies"], [])

label_policies := object.get(input, ["purview_ps", "label_policies"], [])

# A policy in Test mode reports matches but enforces nothing, so it does
# not satisfy a control asking for DLP to be enabled.
enforcing(p) if {
	p.Enabled == true
	not startswith(lower(object.get(p, "Mode", "")), "test")
}

# CIS 3.2.1 -- DLP policies enabled.
violation contains msg if {
	ps_available("dlp_policies")
	count([p | some p in dlp_policies; enforcing(p)]) == 0
	msg := "CIS 3.2.1: no DLP policy is enabled and enforcing -- a policy in Test mode reports matches but does not prevent the data loss it detects"
}

# CIS 3.2.2 -- DLP covers Microsoft Teams.
violation contains msg if {
	ps_available("dlp_policies")
	count([p |
		some p in dlp_policies
		enforcing(p)
		count(object.get(p, "TeamsLocation", [])) > 0
	]) == 0
	msg := "CIS 3.2.2: no enabled DLP policy covers Microsoft Teams, so sensitive content shared in chats and channels is not inspected"
}

# CIS 3.2.3 -- DLP published for Copilot.
violation contains msg if {
	ps_available("dlp_policies")
	count([p |
		some p in dlp_policies
		enforcing(p)
		contains(lower(object.get(p, "Workload", "")), "copilot")
	]) == 0
	msg := "CIS 3.2.3: no DLP policy is published for Copilot users, so content Copilot can surface is not covered by data loss prevention"
}

# CIS 3.3.1 -- sensitivity label policies published.
violation contains msg if {
	ps_available("label_policies")
	count([p | some p in label_policies; p.Enabled == true]) == 0
	msg := "CIS 3.3.1: no Information Protection sensitivity label policy is published, so users have no labels to classify content with"
}

PURVIEW_PS_CONTROLS := {
	"dlp_policies": "3.2.1",
	"label_policies": "3.3.1",
}

violation contains msg if {
	some key, reason in ps_unavailable
	control := object.get(PURVIEW_PS_CONTROLS, key, "3.2.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not ps_collected
	msg := "CIS 3.2.1: Purview DLP facts were not collected, so whether DLP policies are enabled could not be established (this is not a pass)"
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
# = every element of a list). The main report marks a control that is not
# decidable "evidence_missing" even where no violation above names it: an
# absent fact must never read as a pass. Each gate restates the condition
# of its rule above; change them together.

CONTROL_EVIDENCE := {
	"3.1.1": ["purview.audit_log_accessible"],
	"3.2.1": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode"],
	"3.2.2": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode", "purview_ps.dlp_policies[].TeamsLocation"],
	"3.2.3": ["purview_ps.dlp_policies[].Enabled", "purview_ps.dlp_policies[].Mode", "purview_ps.dlp_policies[].Workload"],
	"3.3.1": ["purview_ps.label_policies[].Enabled"],
}

decidable contains "3.1.1" if facts_present

decidable contains id if {
	some id in ["3.2.1", "3.2.2", "3.2.3"]
	ps_available("dlp_policies")
	is_array(input.purview_ps.dlp_policies)
}

decidable contains "3.3.1" if {
	ps_available("label_policies")
	is_array(input.purview_ps.label_policies)
}
