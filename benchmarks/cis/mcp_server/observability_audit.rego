# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — Section 7: Observability and Audit"
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
package cis_mcp_server.observability_audit

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 7: Observability and Audit.
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
	"7.1.1": {"section": 7, "level": "L1", "assessment": "Automated", "title": "Ensure lifecycle and invocation metadata is recorded"},
	"7.1.2": {"section": 7, "level": "L1", "assessment": "Automated", "title": "Ensure non-null JSON-RPC request IDs are enforced and included in audit logs"},
	"7.1.3": {"section": 7, "level": "L1", "assessment": "Automated", "title": "Ensure MCP audit records carry accurate, monotonic timestamps"},
	"7.2.1": {"section": 7, "level": "L1", "assessment": "Automated", "title": "Ensure alerts are generated on audience and issuer validation failures"},
	"7.2.2": {"section": 7, "level": "L2", "assessment": "Automated", "title": "Ensure notifications/cancelled and notifications/progress messages are monitored for behavioral anomalies"},
}

# ── shared plumbing ──────────────────────────────────────────────────────────
default _att := {}

_att := a if {
	a := input.cis_mcp_server.observability_audit.requirements
	is_object(a)
}

default _ev := {}

_ev := e if {
	e := input.cis_mcp_server.observability_audit.evidence
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
	"7.1.1": "lifecycle_audit",
	"7.1.2": "request_ids",
	"7.1.3": "audit_timestamps",
	"7.2.1": "validation_failure_alerts",
	"7.2.2": "notification_monitoring",
}

_nonempty_str(x) if {
	is_string(x)
	x != ""
}

_nonempty_val(x) if _nonempty_str(x)

_nonempty_val(x) if is_number(x)

# 7.1.1 — evidence.lifecycle_audit: {entries[] (sampled records, each with timestamp,
#   correlation_id, event_type, server_identity), centralized_with_integrity}
_la := object.get(_ev, "lifecycle_audit", {})

_la_entries_ok if {
	is_array(_la.entries)
	count(_la.entries) > 0
}

fail contains ["7.1.1", "no sampled audit entries"] if not _la_entries_ok

fail contains ["7.1.1", sprintf("audit entry %d lacks %s", [i, f])] if {
	some i, e in _la.entries
	some f in ["timestamp", "correlation_id", "event_type", "server_identity"]
	not _entry_has(e, f)
}

_entry_has(e, f) if _nonempty_str(e[f])

_entry_has(e, f) if {
	is_object(e[f])
	count(e[f]) > 0
}

fail contains ["7.1.1", "logs are not shipped to a central store with integrity protection"] if not _get(_la, "centralized_with_integrity") == true

# 7.1.2 — evidence.request_ids: {null_id_http_status, null_id_error_code,
#   entries_sampled, entries_missing_id}
_ri := object.get(_ev, "request_ids", {})

fail contains ["7.1.2", sprintf("a null JSON-RPC id is not rejected with HTTP 400 / -32600 (got %v / %v)", [object.get(_ri, "null_id_http_status", "not reported"), object.get(_ri, "null_id_error_code", "not reported")])] if {
	not _null_id_rejected
}

_null_id_rejected if {
	_ri.null_id_http_status == 400
	_ri.null_id_error_code == -32600
}

fail contains ["7.1.2", "no audit entries sampled for the request id"] if not _get(_ri, "entries_sampled") > 0

fail contains ["7.1.2", sprintf("audit entries without the JSON-RPC request id: %v", [object.get(_ri, "entries_missing_id", "not reported")])] if {
	not _get(_ri, "entries_missing_id") == 0
}

# 7.1.3 — evidence.audit_timestamps: {timestamps[] (epoch seconds, stream order),
#   unparseable_count, newest_age_seconds, tolerance_seconds (default 300)}
_at := object.get(_ev, "audit_timestamps", {})

_tolerance := object.get(_at, "tolerance_seconds", 300)

_num_list(x) if {
	is_array(x)
	count(x) > 0
	every v in x {
		is_number(v)
	}
}

fail contains ["7.1.3", "no numeric audit timestamps sampled"] if not _num_list(_get(_at, "timestamps"))

fail contains ["7.1.3", "audit records carry unparseable timestamps"] if not _get(_at, "unparseable_count") == 0

fail contains ["7.1.3", sprintf("audit timestamp moves backward at record %d", [i + 1])] if {
	_num_list(_at.timestamps)
	ts := _at.timestamps
	count(ts) > 1
	some i in numbers.range(0, count(ts) - 2)
	ts[i + 1] < ts[i]
}

fail contains ["7.1.3", sprintf("newest audit record is not within %v s of the auditing clock", [_tolerance])] if {
	not _fresh
}

_fresh if {
	is_number(_at.newest_age_seconds)
	is_number(_tolerance)
	abs(_at.newest_age_seconds) <= _tolerance
}

# 7.2.1 — evidence.validation_failure_alerts: {events[] (audience/issuer validation
#   failures, each with error_code), siem_rule_present, wrong_audience_rejected}
_va := object.get(_ev, "validation_failure_alerts", {})

_va_events_ok if {
	is_array(_va.events)
	count(_va.events) > 0
}

fail contains ["7.2.1", "no audience/issuer validation-failure events sampled (force one with a wrong-audience token)"] if not _va_events_ok

fail contains ["7.2.1", sprintf("validation-failure event %d carries no structured error code", [i])] if {
	some i, e in _va.events
	not _nonempty_val(_get(e, "error_code"))
}

fail contains ["7.2.1", "no SIEM rule alerts on audience/issuer validation failures"] if not _get(_va, "siem_rule_present") == true

fail contains ["7.2.1", "a wrong-audience token is not rejected end to end"] if not _get(_va, "wrong_audience_rejected") == true

# 7.2.2 — evidence.notification_monitoring: {notifications[] of {method, server,
#   request_id?, progress_token?}, request_ids[], progress_tokens[],
#   siem_baseline_rules_present}
_nm := object.get(_ev, "notification_monitoring", {})

fail contains ["7.2.2", "originating request ids / progress tokens not reported"] if {
	not is_array(_get(_nm, "request_ids"))
}

fail contains ["7.2.2", "originating request ids / progress tokens not reported"] if {
	not is_array(_get(_nm, "progress_tokens"))
}

fail contains ["7.2.2", "notification record not reported"] if not is_array(_get(_nm, "notifications"))

fail contains ["7.2.2", sprintf("notification %d carries no server identity", [i])] if {
	some i, n in _nm.notifications
	not _nonempty_str(_get(n, "server"))
}

fail contains ["7.2.2", sprintf("cancellation notification %d does not map to an originating request", [i])] if {
	some i, n in _nm.notifications
	n.method == "notifications/cancelled"
	not _get(n, "request_id") in _get(_nm, "request_ids")
}

fail contains ["7.2.2", sprintf("progress notification %d does not map to an issued progress token", [i])] if {
	some i, n in _nm.notifications
	n.method == "notifications/progress"
	not _get(n, "progress_token") in _get(_nm, "progress_tokens")
}

fail contains ["7.2.2", "SIEM per-server baseline and rate-anomaly rules not confirmed"] if not _get(_nm, "siem_baseline_rules_present") == true

# ── report ───────────────────────────────────────────────────────────────────
default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 7,
	"area_name": "Observability and Audit",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
