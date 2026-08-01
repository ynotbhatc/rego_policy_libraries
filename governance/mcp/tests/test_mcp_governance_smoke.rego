# Phase 1 contract smoke test — MCP governance decision response.
# This endpoint returns a decision object (not a compliance_report).
# Contract: data.ai_governance.mcp.response must return a well-formed,
# non-empty object with a decision field on empty input (never undefined -> {}).
package ai_governance.mcp_test

import rego.v1

import data.ai_governance.mcp

test_report_wellformed_on_empty_input if {
	result := mcp.response with input as {}
	is_object(result)
	count(result) > 0
	is_string(result.decision)
}

# ---------------------------------------------------------------------------
# Registry-based approval (added 2026-08-01)
#
# The estate names templates BOTH "AAC_<thing>" and "AAC - <thing>". The rule
# originally matched only "AAC_", which missed 98 of 148 AAC templates on the
# reference controller — including the whole NERC-CIP demo set — so ordinary
# work fell through to the default-deny.
# ---------------------------------------------------------------------------

# Scope the override to the subtree. `with data as {...}` would replace the
# whole data document — including this test package — and every test then
# becomes mutually recursive (rego_recursion_error).
_registry := {"controller": {
	"99": "AAC_GoldenImage_Check",
	"212": "AAC - Collate OCP NERC-CIP (Compliance Operator)",
	"777": "Some Unmanaged Template",
}}

_launch(id) := {
	"tool": "api_job_templates_launch_create",
	"arguments": {"id": id},
	"agent": "claude",
}

test_underscore_named_template_allowed if {
	r := mcp.response with input as _launch(99) with data.aac.templates as _registry
	r.allow
	r.risk_level == "low"
}

# The regression this guards: space-dash naming must be approved too.
test_space_dash_named_template_allowed if {
	r := mcp.response with input as _launch(212) with data.aac.templates as _registry
	r.allow
	r.risk_level == "low"
}

test_unregistered_template_denied if {
	r := mcp.response with input as _launch(777) with data.aac.templates as _registry
	not r.allow
	r.risk_level == "high"
}

# `response` is an object literal — one undefined field collapses the whole
# object and OPA hands the MCP server nothing. This is what happened when
# risk_level was broadened to "AAC" while the reason rule still required "AAC_".
test_response_never_collapses_to_undefined if {
	every id in [99, 212, 777] {
		r := mcp.response with input as _launch(id) with data.aac.templates as _registry
		is_boolean(r.allow)
		is_string(r.decision)
		is_string(r.risk_level)
		is_string(r.reason)
	}
}

test_destructive_still_blocked if {
	every t in ["api_users_delete", "api_credentials_create"] {
		r := mcp.response with input as {"tool": t, "agent": "claude"} with data.aac.templates as _registry
		not r.allow
		r.risk_level == "blocked"
	}
}
