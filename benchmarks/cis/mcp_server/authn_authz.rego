# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 3: Authentication and Authorization"
# custom:
#   class: security
#   framework: cis_mcp_server
#   source: cis
#   domains: [ai, mcp]
#   coverage:
#     checks: 13
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_mcp_server.authn_authz

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 3: Authentication and Authorization.
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
	"3.1.1": {"section": 3, "level": "L1", "assessment": "Automated", "title": "Ensure stdio server credentials are sourced from the environment or OS credential store"},
	"3.1.2": {"section": 3, "level": "L1", "assessment": "Manual", "title": "Ensure OIDC/OAuth 2.1 or short-lived API tokens are used for remote servers"},
	"3.2.1": {"section": 3, "level": "L2", "assessment": "Manual", "title": "Ensure per-tool authorization policies are enforced"},
	"3.2.2": {"section": 3, "level": "L1", "assessment": "Manual", "title": "Ensure token passthrough to downstream APIs is forbidden"},
	"3.2.3": {"section": 3, "level": "L1", "assessment": "Manual", "title": "Ensure server-provided tool annotations are not relied upon for authorization or HITL gating decisions"},
	"3.3.1": {"section": 3, "level": "L1", "assessment": "Automated", "title": "Ensure OAuth tokens are audience-bound to the MCP server using Resource Indicators"},
	"3.3.2": {"section": 3, "level": "L2", "assessment": "Automated", "title": "Ensure OAuth discovery metadata is served over TLS and validated against the approved authorization server list"},
	"3.3.3": {"section": 3, "level": "L2", "assessment": "Manual", "title": "Ensure shared downstream service account identities are prohibited across multiple MCP tools or servers"},
	"3.3.4": {"section": 3, "level": "L2", "assessment": "Manual", "title": "Ensure OAuth scopes are minimized and elevated progressively"},
	"3.3.5": {"section": 3, "level": "L2", "assessment": "Manual", "title": "Ensure confused-deputy safeguards are applied for static OAuth client IDs"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.authn_authz.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.authn_authz.evidence
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
	"3.1.1": "stdio_credentials",
	"3.3.1": "token_audience",
	"3.3.2": "oauth_discovery",
}

_str_list(x) if {
	is_array(x)
	count(x) > 0
	every v in x {
		is_string(v)
	}
}

# 3.1.1 — evidence.stdio_credentials: {interactive_oauth_in_launch_config,
#   credential_on_command_line, credential_source ("environment" | "secret_store")}
_sc := object.get(_ev, "stdio_credentials", {})

fail contains ["3.1.1", "interactive/browser OAuth indicators present in the launch configuration"] if not _get(_sc, "interactive_oauth_in_launch_config") == false

fail contains ["3.1.1", "credential appears on the server command line"] if not _get(_sc, "credential_on_command_line") == false

fail contains ["3.1.1", sprintf("credential is not sourced from the environment or a secret store (%v)", [object.get(_sc, "credential_source", "not reported")])] if {
	not _get(_sc, "credential_source") in {"environment", "secret_store"}
}

# 3.3.1 — evidence.token_audience: {canonical_uri, token_aud (string or array),
#   foreign_audience_status}
_ta := object.get(_ev, "token_audience", {})

_aud_bound if {
	is_string(_ta.canonical_uri)
	_ta.canonical_uri != ""
	_ta.token_aud == _ta.canonical_uri
}

_aud_bound if {
	is_string(_ta.canonical_uri)
	_ta.canonical_uri != ""
	is_array(_ta.token_aud)
	_ta.canonical_uri in _ta.token_aud
}

fail contains ["3.3.1", "issued token audience is not bound to this server's canonical URI"] if not _aud_bound

fail contains ["3.3.1", sprintf("token issued for a different resource not rejected with 401 (got %v)", [object.get(_ta, "foreign_audience_status", "not reported")])] if {
	not _get(_ta, "foreign_audience_status") == 401
}

# 3.3.2 — evidence.oauth_discovery: {served_over_tls, resource_matches_canonical_uri,
#   authorization_servers[], approved_authorization_servers[], issuer_mismatches[]}
_od := object.get(_ev, "oauth_discovery", {})

fail contains ["3.3.2", "Protected Resource Metadata is not served over TLS"] if not _get(_od, "served_over_tls") == true

fail contains ["3.3.2", "metadata resource does not match the canonical URI"] if not _get(_od, "resource_matches_canonical_uri") == true

fail contains ["3.3.2", "authorization_servers is empty or not reported"] if not _str_list(_get(_od, "authorization_servers"))

fail contains ["3.3.2", "approved authorization server list empty or not reported"] if not _str_list(_get(_od, "approved_authorization_servers"))

fail contains ["3.3.2", sprintf("advertised authorization server not approved: %v", [s])] if {
	_str_list(_od.approved_authorization_servers)
	some s in _od.authorization_servers
	not s in _get(_od, "approved_authorization_servers")
}

fail contains ["3.3.2", "issuer metadata check result (issuer_mismatches) not reported"] if not is_array(_get(_od, "issuer_mismatches"))

fail contains ["3.3.2", sprintf("authorization server issuer does not match its approved entry: %v", [s])] if {
	some s in _od.issuer_mismatches
}

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 3,
	"area_name": "Authentication and Authorization",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
