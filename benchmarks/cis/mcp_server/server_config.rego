# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 5: Server Configuration"
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
package cis_mcp_server.server_config

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 5: Server Configuration.
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
	"5.1.1": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure tool schemas and argument types are validated"},
	"5.1.2": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure resource templates with explicit URI patterns and MIME types are used"},
	"5.1.3": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure prompt templates declare and validate their arguments"},
	"5.2.1": {"section": 5, "level": "L2", "assessment": "Automated", "title": "Ensure listChanged notifications are rate-limited to prevent client flooding"},
	"5.2.2": {"section": 5, "level": "L1", "assessment": "Manual", "title": "Ensure sessions are not used as authentication and, where present, are bound to user identity"},
	"5.2.3": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure legacy Streamable HTTP session and stream-resumption mechanisms are disabled"},
	"5.3.1": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure logs are separated from the protocol stream in stdio mode"},
	"5.4.1": {"section": 5, "level": "L1", "assessment": "Automated", "title": "Ensure path traversal and arbitrary filesystem access are prevented"},
	"5.5.1": {"section": 5, "level": "L2", "assessment": "Manual", "title": "Ensure authorization, scope, and expiry controls are enforced on MCP Tasks"},
	"5.6.1": {"section": 5, "level": "L2", "assessment": "Manual", "title": "Ensure idempotency keys are required for side-effecting tool calls and duplicate side effects are prevented"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.server_config.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.server_config.evidence
	is_object(e)
}

# Manual recommendations whose CIS scope has several components take a
# structured attestation (every listed part true); a bare `true` is not enough.
_parts := {
	"5.2.2": ["handle_alone_rejected", "handle_bound_to_identity", "handle_unguessable", "handle_expires"],
	"5.5.1": ["cross_identity_retrieval_denied", "denial_is_ownership_decision", "handle_unguessable", "finite_ttl"],
	"5.6.1": ["idempotency_key_required", "duplicate_returns_cached_result", "payload_mismatch_rejected", "side_effect_once", "cross_principal_reuse_denied"],
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
	"5.1.1": "tool_schemas",
	"5.1.2": "resource_templates",
	"5.1.3": "prompts",
	"5.2.1": "list_changed",
	"5.2.3": "legacy_session",
	"5.3.1": "stdio_stream",
	"5.4.1": "path_traversal",
}

_nonempty_str(x) if {
	is_string(x)
	x != ""
}

# 5.1.1 — evidence.tool_schemas: {schemas_failing_compile[], invalid_call_executed,
#   external_ref_refused, schema_limits_bounded}
_ts := object.get(_ev, "tool_schemas", {})

fail contains ["5.1.1", "schema compilation result (schemas_failing_compile) not reported"] if not is_array(_get(_ts, "schemas_failing_compile"))

fail contains ["5.1.1", sprintf("advertised schema does not compile under its dialect: %v", [s])] if {
	some s in _ts.schemas_failing_compile
}

fail contains ["5.1.1", "a schema-violating tool call was executed"] if not _get(_ts, "invalid_call_executed") == false

fail contains ["5.1.1", "validator does not refuse external $ref"] if not _get(_ts, "external_ref_refused") == true

fail contains ["5.1.1", "schema depth and validation time are not bounded"] if not _get(_ts, "schema_limits_bounded") == true

# 5.1.2 — evidence.resource_templates: {templates[] of {uriTemplate, mimeType},
#   missing_resource_error_code}
_rt := object.get(_ev, "resource_templates", {})

fail contains ["5.1.2", "resource template list not reported"] if not is_array(_get(_rt, "templates"))

fail contains ["5.1.2", sprintf("resource template lacks a URI pattern or MIME type: %v", [t])] if {
	some t in _rt.templates
	not _template_ok(t)
}

_template_ok(t) if {
	_nonempty_str(t.uriTemplate)
	_nonempty_str(t.mimeType)
}

fail contains ["5.1.2", sprintf("read of a non-existent resource not rejected with -32602 (got %v)", [object.get(_rt, "missing_resource_error_code", "not reported")])] if {
	not _get(_rt, "missing_resource_error_code") == -32602
}

# 5.1.3 — evidence.prompts: {prompts[] of {name, arguments[] of {name, required?}},
#   missing_required_argument_error_code}
_pr := object.get(_ev, "prompts", {})

fail contains ["5.1.3", "prompt list not reported"] if not is_array(_get(_pr, "prompts"))

_arg_ok(a) if {
	_nonempty_str(a.name)
	not "required" in object.keys(a)
}

_arg_ok(a) if {
	_nonempty_str(a.name)
	is_boolean(a.required)
}

_prompt_ok(p) if {
	_nonempty_str(p.name)
	not "arguments" in object.keys(p)
}

_prompt_ok(p) if {
	_nonempty_str(p.name)
	is_array(p.arguments)
	every a in p.arguments {
		_arg_ok(a)
	}
}

fail contains ["5.1.3", sprintf("prompt argument declarations are malformed: %v", [p])] if {
	some p in _pr.prompts
	not _prompt_ok(p)
}

fail contains ["5.1.3", sprintf("prompts/get missing a required argument not rejected with -32602 (got %v)", [object.get(_pr, "missing_required_argument_error_code", "not reported")])] if {
	not _get(_pr, "missing_required_argument_error_code") == -32602
}

# 5.2.1 — evidence.list_changed: {min_interval_seconds, notifications[] of {type, ts}}
#   (ts = epoch seconds). Two successive notifications of one type closer than the
#   minimum interval is a failure.
_lc := object.get(_ev, "list_changed", {})

fail contains ["5.2.1", "configured minimum listChanged interval not reported"] if not _get(_lc, "min_interval_seconds") > 0

fail contains ["5.2.1", "listChanged notification record not reported"] if not is_array(_get(_lc, "notifications"))

fail contains ["5.2.1", sprintf("%v notifications emitted %v s apart (minimum %v s)", [t, gap, _lc.min_interval_seconds])] if {
	_lc.min_interval_seconds > 0
	some t in {n.type | some n in _lc.notifications}
	ts := sort([n.ts | some n in _lc.notifications; n.type == t])
	count(ts) > 1
	some i in numbers.range(0, count(ts) - 2)
	gap := ts[i + 1] - ts[i]
	gap < _lc.min_interval_seconds
}

# 5.2.3 — evidence.legacy_session: {get_status, delete_status, last_event_id_ignored,
#   session_id_honored, session_id_minted}
_ls := object.get(_ev, "legacy_session", {})

fail contains ["5.2.3", sprintf("standalone GET not rejected with 405 (got %v)", [object.get(_ls, "get_status", "not reported")])] if not _get(_ls, "get_status") == 405

fail contains ["5.2.3", sprintf("DELETE not rejected with 405 (got %v)", [object.get(_ls, "delete_status", "not reported")])] if not _get(_ls, "delete_status") == 405

fail contains ["5.2.3", "Last-Event-ID changes server behaviour (stream resumption honoured)"] if not _get(_ls, "last_event_id_ignored") == true

fail contains ["5.2.3", "a client-supplied Mcp-Session-Id is honoured"] if not _get(_ls, "session_id_honored") == false

fail contains ["5.2.3", "the server mints or echoes an Mcp-Session-Id"] if not _get(_ls, "session_id_minted") == false

# 5.3.1 — evidence.stdio_stream: {stdout_lines_checked, non_jsonrpc_stdout_lines,
#   startup_stdout_clean, log_destinations[] ("stderr" | "file")}
_ss := object.get(_ev, "stdio_stream", {})

fail contains ["5.3.1", "no captured stdout lines were checked"] if not _get(_ss, "stdout_lines_checked") > 0

fail contains ["5.3.1", sprintf("stdout carries non-JSON-RPC output (%v lines)", [object.get(_ss, "non_jsonrpc_stdout_lines", "not reported")])] if {
	not _get(_ss, "non_jsonrpc_stdout_lines") == 0
}

fail contains ["5.3.1", "stdout is not clean during startup"] if not _get(_ss, "startup_stdout_clean") == true

_log_dest_ok if {
	is_array(_ss.log_destinations)
	count(_ss.log_destinations) > 0
}

fail contains ["5.3.1", "logging destinations not reported"] if not _log_dest_ok

fail contains ["5.3.1", sprintf("log output targets %v (must be stderr or a file)", [d])] if {
	some d in _ss.log_destinations
	not d in {"stderr", "file"}
}

# 5.4.1 — evidence.path_traversal: {allowed_read_succeeded, traversal_read_denied,
#   symlink_escape_denied}
_pt := object.get(_ev, "path_traversal", {})

fail contains ["5.4.1", "positive-control read under the approved root did not succeed"] if not _get(_pt, "allowed_read_succeeded") == true

fail contains ["5.4.1", "a ../ traversal read escaping the approved root was not denied"] if not _get(_pt, "traversal_read_denied") == true

fail contains ["5.4.1", "a symlink escaping the approved root was not denied"] if not _get(_pt, "symlink_escape_denied") == true

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 5,
	"area_name": "Server Configuration",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
