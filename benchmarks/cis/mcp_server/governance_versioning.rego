# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 1: Governance and Versioning"
# custom:
#   class: security
#   framework: cis_mcp_server
#   source: cis
#   domains: [ai, mcp]
#   coverage:
#     checks: 7
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_mcp_server.governance_versioning

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 1: Governance and Versioning.
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
	"1.1": {"section": 1, "level": "L1", "assessment": "Automated", "title": "Ensure MCP protocol version is pinned and logged"},
	"1.2": {"section": 1, "level": "L1", "assessment": "Manual", "title": "Ensure server capability baseline is established and documented"},
	"1.3": {"section": 1, "level": "L2", "assessment": "Manual", "title": "Ensure newly advertised server capabilities are re-validated before invocation"},
	"1.4": {"section": 1, "level": "L1", "assessment": "Automated", "title": "Ensure MCP client and server identity metadata is captured and validated against the asset inventory"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.governance_versioning.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.governance_versioning.evidence
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
_evidence_key := {
	"1.1": "protocol_version",
	"1.4": "identity",
}

# 1.1 — evidence.protocol_version: {advertised_versions[], approved_versions[],
#   unapproved_version_rejected, missing_header_version_rejected,
#   missing_meta_version_rejected, header_body_mismatch_rejected,
#   version_logged_on_every_request}
_pv := object.get(_ev, "protocol_version", {})

_str_list(x) if {
	is_array(x)
	count(x) > 0
	every v in x {
		is_string(v)
	}
}

fail contains ["1.1", "advertised protocol versions not reported"] if not _str_list(_get(_pv, "advertised_versions"))

fail contains ["1.1", "approved protocol version allowlist empty or not reported"] if not _str_list(_get(_pv, "approved_versions"))

fail contains ["1.1", sprintf("server advertises unapproved protocol version %v", [v])] if {
	_str_list(_pv.approved_versions)
	some v in _pv.advertised_versions
	not v in _get(_pv, "approved_versions")
}

fail contains ["1.1", "a request with an unapproved protocol version is not rejected"] if not _get(_pv, "unapproved_version_rejected") == true

fail contains ["1.1", "a request without the version header is not rejected"] if not _get(_pv, "missing_header_version_rejected") == true

fail contains ["1.1", "a request without the _meta protocol version is not rejected"] if not _get(_pv, "missing_meta_version_rejected") == true

fail contains ["1.1", "a header/body protocol version disagreement is not rejected"] if not _get(_pv, "header_body_mismatch_rejected") == true

fail contains ["1.1", "the asserted protocol version is not logged on every request"] if not _get(_pv, "version_logged_on_every_request") == true

# 1.4 — evidence.identity: {client_identity_on_every_request,
#   server_identity_on_every_response, unregistered_identities[]}
_id := object.get(_ev, "identity", {})

fail contains ["1.4", "client identity is not recorded on every captured request"] if not _get(_id, "client_identity_on_every_request") == true

fail contains ["1.4", "server identity is not recorded on every successful response"] if not _get(_id, "server_identity_on_every_response") == true

fail contains ["1.4", "registry cross-check result (unregistered_identities) not reported"] if not is_array(_get(_id, "unregistered_identities"))

fail contains ["1.4", sprintf("identity not in the asset inventory: %v", [x])] if {
	some x in _id.unregistered_identities
}

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 1,
	"area_name": "Governance and Versioning",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
