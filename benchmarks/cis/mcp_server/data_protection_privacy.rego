# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 6: Data Protection and Privacy"
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
package cis_mcp_server.data_protection_privacy

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 6: Data Protection and Privacy.
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
	"6.1": {"section": 6, "level": "L1", "assessment": "Manual", "title": "Ensure model context is minimized and MIME handling is honored"},
	"6.2": {"section": 6, "level": "L1", "assessment": "Automated", "title": "Ensure tokens and keys are protected in clients and servers"},
	"6.3": {"section": 6, "level": "L1", "assessment": "Manual", "title": "Ensure outbound proxy and DNS controls are applied for resource fetchers"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.data_protection_privacy.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.data_protection_privacy.evidence
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
_evidence_key := {"6.2": "secret_scan"}

# 6.2 — evidence.secret_scan: {scanner_findings (count from the secret scanner over the
#   deployed configuration and installed artifacts), inline_manifest_secrets[]}
_ssc := object.get(_ev, "secret_scan", {})

fail contains ["6.2", sprintf("secret scanner reports embedded credentials (%v findings)", [object.get(_ssc, "scanner_findings", "not reported")])] if {
	not _get(_ssc, "scanner_findings") == 0
}

fail contains ["6.2", "manifest inline-secret review (inline_manifest_secrets) not reported"] if not is_array(_get(_ssc, "inline_manifest_secrets"))

fail contains ["6.2", sprintf("deployment manifest defines a secret inline instead of referencing a managed store: %v", [m])] if {
	some m in _ssc.inline_manifest_secrets
}

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 6,
	"area_name": "Data Protection and Privacy",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
