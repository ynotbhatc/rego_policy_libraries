# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 9: Isolation and Execution Safety"
# custom:
#   class: security
#   framework: cis_mcp_server
#   source: cis
#   domains: [ai, mcp]
#   coverage:
#     checks: 6
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_mcp_server.isolation_execution_safety

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 9: Isolation and Execution Safety.
# Ids, titles, profile levels and Automated/Manual status are taken from the
# official CIS workbook (55 recommendations, all implemented across 10 section
# modules). Messages are in our own words.
#
# Input contract (shared by every section module; <sec> = this package's last segment):
#   input.cis_mcp_server.<sec>.requirements[<id>] : Manual attestation. `true`, or for an
#       id listed in _parts, an object with every listed part set to true.
#       Attestation never satisfies an Automated recommendation.
#   input.cis_mcp_server.<sec>.evidence.<key>     : collected probe results for an Automated
#       recommendation (key per _evidence_key). Absent/empty evidence is a violation.
requirements := {
	"9.1": {"section": 9, "level": "L2", "assessment": "Manual", "title": "Ensure remote MCP servers run in containers or VMs with least privilege and gateway ingress controls applied"},
	"9.2": {"section": 9, "level": "L1", "assessment": "Automated", "title": "Ensure the MCP server process is confined to its working set by OS-level kernel-enforced controls"},
	"9.3": {"section": 9, "level": "L2", "assessment": "Manual", "title": "Ensure local stdio MCP servers run under least-privilege identities with sandbox or container isolation"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.isolation_execution_safety.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.isolation_execution_safety.evidence
	is_object(e)
}

# Manual recommendations whose CIS scope has several components take a
# structured attestation (every listed part true); a bare `true` is not enough.
_parts := {}

attested(id) if {
	requirements[id].assessment == "Manual"
	not _parts[id]
	_att[id] == true
}

attested(id) if {
	requirements[id].assessment == "Manual"
	ps := _parts[id]
	a := _att[id]
	is_object(a)
	every p in ps {
		a[p] == true
	}
}

default _hint(_) := ""

_hint(id) := sprintf(" (attest each of: %s)", [concat(", ", _parts[id])]) if _parts[id]

_collected(id) if {
	o := _ev[_evidence_key[id]]
	is_object(o)
	count(o) > 0
}

_has_fail(id) if {
	some f in fail
	f[0] == id
}

# Recommendations satisfied (consumed by the orchestrator's met/level rollups).
met contains id if {
	some id, m in requirements
	m.assessment == "Manual"
	attested(id)
}

met contains id if {
	some id, _ in _evidence_key
	_collected(id)
	not _has_fail(id)
}

# Fail closed: unattested Manual, missing evidence, or a failed Automated check.
violation contains msg if {
	some id, m in requirements
	m.assessment == "Manual"
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not attested%s", [id, _get(m, "title"), _hint(id)])
}

violation contains msg if {
	some id, key in _evidence_key
	not _collected(id)
	msg := sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, key])
}

violation contains msg if {
	some f in fail
	_collected(f[0])
	msg := sprintf("CIS MCP %s: %s", [f[0], f[1]])
}

# Field accessor that is always defined (null when absent or not an object), so a
# `not <check>(field)` fires on missing evidence instead of evaluating undefined.
default _get(_, _) := null

_get(o, k) := object.get(o, k, null) if is_object(o)

# ── Automated checks ─────────────────────────────────────────────────────────
_evidence_key := {"9.2": "confinement"}

# 9.2 — evidence.confinement: {working_sentinel_readable, out_of_scope_sentinel_denied,
#   mac_profile_present, denials_logged} (probed as the MCP service account)
_cf := object.get(_ev, "confinement", {})

fail contains ["9.2", "service account cannot read its working-set sentinel (probe not attributable)"] if not _get(_cf, "working_sentinel_readable") == true

fail contains ["9.2", "service account can read the out-of-scope sentinel"] if not _get(_cf, "out_of_scope_sentinel_denied") == true

fail contains ["9.2", "no mandatory access control profile confines the server"] if not _get(_cf, "mac_profile_present") == true

fail contains ["9.2", "denied access attempts are not logged"] if not _get(_cf, "denials_logged") == true

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 9,
	"area_name": "Isolation and Execution Safety",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
