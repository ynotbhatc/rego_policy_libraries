# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 2: Transport and Connectivity"
# custom:
#   class: security
#   framework: cis_mcp_server
#   source: cis
#   domains: [ai, mcp]
#   coverage:
#     checks: 8
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_mcp_server.transport_connectivity

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 2: Transport and Connectivity.
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
	"2.1": {"section": 2, "level": "L1", "assessment": "Manual", "title": "Ensure stdio is preferred for local, single-user servers"},
	"2.2": {"section": 2, "level": "L1", "assessment": "Automated", "title": "Ensure TLS is required for HTTP and plaintext is disallowed"},
	"2.3": {"section": 2, "level": "L2", "assessment": "Manual", "title": "Ensure authentication propagates through proxies to request-scoped SSE responses"},
	"2.4": {"section": 2, "level": "L1", "assessment": "Automated", "title": "Ensure required MCP request metadata headers are present and consistent with the request body"},
	"2.5": {"section": 2, "level": "L1", "assessment": "Automated", "title": "Ensure Origin header is validated on all Streamable HTTP requests to prevent DNS rebinding attacks"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.transport_connectivity.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.transport_connectivity.evidence
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
	"2.2": "tls",
	"2.4": "request_headers",
	"2.5": "origin",
}

# 2.2 — evidence.tls: {plaintext_http ("not_served" | "redirect_https" | "upgrade_required" | other),
#   legacy_versions_accepted[], negotiated_version, certificate_valid}
_tls := object.get(_ev, "tls", {})

fail contains ["2.2", sprintf("plaintext HTTP is not refused or redirected to HTTPS (%v)", [object.get(_tls, "plaintext_http", "not reported")])] if {
	not _get(_tls, "plaintext_http") in {"not_served", "redirect_https", "upgrade_required"}
}

fail contains ["2.2", "legacy TLS probe result (legacy_versions_accepted) not reported"] if not is_array(_get(_tls, "legacy_versions_accepted"))

fail contains ["2.2", sprintf("legacy TLS version accepted: %v", [v])] if {
	some v in _tls.legacy_versions_accepted
}

fail contains ["2.2", sprintf("negotiated TLS version is not 1.2 or 1.3 (%v)", [object.get(_tls, "negotiated_version", "not reported")])] if {
	not _get(_tls, "negotiated_version") in {"TLSv1.2", "TLSv1.3"}
}

fail contains ["2.2", "served certificate is not within its validity period"] if not _get(_tls, "certificate_valid") == true

# 2.4 — evidence.request_headers: {missing_header_rejected, mismatched_header_rejected,
#   encoded_header_decoded}
_rh := object.get(_ev, "request_headers", {})

fail contains ["2.4", "a request missing a required routing header is not rejected with HeaderMismatch"] if not _get(_rh, "missing_header_rejected") == true

fail contains ["2.4", "a request whose Mcp-Name header contradicts the body is not rejected"] if not _get(_rh, "mismatched_header_rejected") == true

fail contains ["2.4", "Base64-encoded header values are not decoded before comparison"] if not _get(_rh, "encoded_header_decoded") == true

# 2.5 — evidence.origin: {hostile_origin_status, allowed_origin_status} (HTTP status codes
#   of the request itself, not a CORS preflight). The no-Origin result is informational.
_or := object.get(_ev, "origin", {})

fail contains ["2.5", sprintf("hostile Origin not rejected with 403 (got %v)", [object.get(_or, "hostile_origin_status", "not reported")])] if {
	not _get(_or, "hostile_origin_status") == 403
}

_allowed_origin_ok if {
	is_number(_or.allowed_origin_status)
	_or.allowed_origin_status >= 200
	_or.allowed_origin_status < 400
}

fail contains ["2.5", sprintf("allowlisted Origin not accepted (got %v)", [object.get(_or, "allowed_origin_status", "not reported")])] if {
	not _allowed_origin_ok
}

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 2,
	"area_name": "Transport and Connectivity",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
