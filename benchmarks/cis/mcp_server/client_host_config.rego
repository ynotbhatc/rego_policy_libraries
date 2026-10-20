# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 4: Client (Host) Configuration"
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
package cis_mcp_server.client_host_config

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 4: Client (Host) Configuration.
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
	"4.1.1": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure per-tool consent or pre-approved allowlists are required"},
	"4.1.2": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure project-scoped MCP server definitions are not enabled or executed without explicit user approval"},
	"4.1.3": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure Elicitation requests are consented, redacted, and identity-bound"},
	"4.1.4": {"section": 4, "level": "L2", "assessment": "Automated", "title": "Ensure Sampling consent and redaction controls are implemented where Sampling is in use"},
	"4.1.5": {"section": 4, "level": "L2", "assessment": "Manual", "title": "Ensure a human can deny tool invocations and sensitive or high-impact operations require confirmation"},
	"4.2.1": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure filesystem scope is restricted to least privilege and enforced by OS-level controls"},
	"4.2.2": {"section": 4, "level": "L1", "assessment": "Automated", "title": "Ensure MCP stdio server subprocess environment is restricted to the minimum required variables"},
	"4.2.3": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure untrusted Resource URIs are not directly dereferenced outside MCP without scheme and destination policy"},
	"4.3.1": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure MCP Apps content is rendered in sandboxed isolation with Content Security Policy enforced from declared metadata"},
	"4.3.2": {"section": 4, "level": "L1", "assessment": "Manual", "title": "Ensure MCP Apps permission requests default-deny, all app-to-host messages are logged, and high-risk channels are consented"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.client_host_config.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.client_host_config.evidence
	is_object(e)
}

# Manual recommendations whose CIS scope has several components take a
# structured attestation (every listed part true); a bare `true` is not enough.
_parts := {
	"4.1.2": ["auto_trust_disabled", "approval_required_before_launch", "declined_approval_blocks_launch"],
	"4.1.3": ["user_decision_recorded", "redaction_checked", "secrets_requested_only_via_url_mode", "url_mode_user_verified", "rate_limited"],
	"4.1.5": ["human_can_deny_any_invocation", "high_impact_requires_confirmation", "classification_independent_of_annotations"],
	"4.2.1": ["scope_is_least_privilege", "os_controls_deny_by_default"],
	"4.2.3": ["disallowed_scheme_rejected", "allowlist_covers_server_and_model_uris"],
	"4.3.1": ["sandboxed_isolation", "csp_from_declared_metadata", "restrictive_default_csp", "undeclared_origins_blocked", "effective_policy_logged"],
	"4.3.2": ["permissions_default_deny", "app_messages_logged", "high_risk_channels_consented", "tool_visibility_enforced"],
}

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
	"4.1.4": "sampling",
	"4.2.2": "subprocess_env",
}

_str_list(x) if {
	is_array(x)
	count(x) > 0
	every v in x {
		is_string(v)
	}
}

# 4.1.4 — evidence.sampling: {in_use; when in_use: events_reviewed, events_noncompliant,
#   consent_before_forwarding, redaction_filter_applied, rate_limited}.
# Conditional applicability: a host that neither advertises nor receives sampling is
# not applicable and passes, but in_use must still be reported.
_sp := object.get(_ev, "sampling", {})

fail contains ["4.1.4", "whether Sampling is in use (in_use) not reported"] if not is_boolean(_get(_sp, "in_use"))

fail contains ["4.1.4", "no sampling events reviewed"] if {
	_sp.in_use == true
	not _get(_sp, "events_reviewed") > 0
}

fail contains ["4.1.4", "sampling events lack a user decision or redaction check"] if {
	_sp.in_use == true
	not _get(_sp, "events_noncompliant") == 0
}

fail contains ["4.1.4", "consent is not enforced before a sampling payload is forwarded"] if {
	_sp.in_use == true
	not _get(_sp, "consent_before_forwarding") == true
}

fail contains ["4.1.4", "sampling payload redaction filter not applied"] if {
	_sp.in_use == true
	not _get(_sp, "redaction_filter_applied") == true
}

fail contains ["4.1.4", "sampling is not rate limited"] if {
	_sp.in_use == true
	not _get(_sp, "rate_limited") == true
}

# 4.2.2 — evidence.subprocess_env: {variables[] (names in the running subprocess),
#   allowlist[] (approved names for this server)}
_se := object.get(_ev, "subprocess_env", {})

fail contains ["4.2.2", "subprocess environment allowlist empty or not reported"] if not _str_list(_get(_se, "allowlist"))

fail contains ["4.2.2", "subprocess environment variables not reported"] if not is_array(_get(_se, "variables"))

fail contains ["4.2.2", sprintf("subprocess environment carries a variable not on the allowlist: %v", [v])] if {
	_str_list(_se.allowlist)
	some v in _se.variables
	not v in _get(_se, "allowlist")
}

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 4,
	"area_name": "Client (Host) Configuration",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
