# Tests for CIS MCP Server Benchmark v1.0.0 — Section 7: Observability and Audit.
package cis_mcp_server.observability_audit_test

import rego.v1

import data.cis_mcp_server.observability_audit

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"observability_audit": {"requirements": {}, "evidence": {"lifecycle_audit": {"entries": [{"timestamp": "2026-10-20T10:00:00Z", "correlation_id": "c-1", "event_type": "tools/call", "server_identity": {"name": "srv", "version": "1.0"}}], "centralized_with_integrity": true}, "request_ids": {"null_id_http_status": 400, "null_id_error_code": -32600, "entries_sampled": 20, "entries_missing_id": 0}, "audit_timestamps": {"timestamps": [100, 100, 105, 130], "unparseable_count": 0, "newest_age_seconds": 12}, "validation_failure_alerts": {"events": [{"error_code": "invalid_audience"}, {"error_code": "invalid_issuer"}], "siem_rule_present": true, "wrong_audience_rejected": true}, "notification_monitoring": {"notifications": [{"method": "notifications/cancelled", "server": "srv", "request_id": 7}, {"method": "notifications/progress", "server": "srv", "progress_token": "p-1"}], "request_ids": [7, 8], "progress_tokens": ["p-1"], "siem_baseline_rules_present": true}}}}}

manual_ids := []

automated_ids := ["7.1.1", "7.1.2", "7.1.3", "7.2.1", "7.2.2"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(observability_audit.violation) == count(observability_audit.requirements) with input as {}
	count(observability_audit.violation) > 0 with input as {}
	not observability_audit.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(observability_audit.violation) == 0 with input as full_input
	observability_audit.section_compliant with input as full_input
}

# Withdraw a single control's evidence -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "remove", "path": "/cis_mcp_server/observability_audit/evidence/request_ids"}])
	count(observability_audit.violation) == 1 with input as broken
	some msg in observability_audit.violation with input as broken
	contains(msg, "7.1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := observability_audit.compliance_report with input as {}
	report.section == 7
	report.area_name == "Observability and Audit"
	report.requirements_evaluated == count(observability_audit.requirements)
	report.violation_count == count(observability_audit.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(observability_audit.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		observability_audit.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		observability_audit.requirements[id].assessment == "Automated"
	}
	every _, m in observability_audit.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := observability_audit.met with input as full_input
	m == object.keys(observability_audit.requirements)
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.observability_audit, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"observability_audit": {"requirements": attest}}}
	vs := observability_audit.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, observability_audit._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/observability_audit/evidence/%s", [observability_audit._evidence_key[id]])])
		vs := observability_audit.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in observability_audit.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/observability_audit/evidence/%s", [observability_audit._evidence_key[id]]), "value": {}}])
		vs := observability_audit.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := observability_audit._evidence_key[id]
		ev := full_input.cis_mcp_server.observability_audit.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/observability_audit/evidence/%s/%s", [k, f])])
			not id in observability_audit.met with input as inp
		}
	}
}

test_fail_7_1_1_entry_missing_correlation if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/lifecycle_audit/entries", "value": [{"timestamp": "t", "event_type": "e", "server_identity": "s"}]}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.1: ")
	}
	some v in vs
	contains(v, "correlation_id")
	not "7.1.1" in observability_audit.met with input as inp
}

test_fail_7_1_1_not_centralized if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/lifecycle_audit/centralized_with_integrity", "value": false}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.1: ")
	}
	some v in vs
	contains(v, "central")
	not "7.1.1" in observability_audit.met with input as inp
}

test_fail_7_1_2_null_id_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/request_ids/null_id_http_status", "value": 200}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.2: ")
	}
	some v in vs
	contains(v, "null JSON-RPC id")
	not "7.1.2" in observability_audit.met with input as inp
}

test_fail_7_1_2_entries_missing_id if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/request_ids/entries_missing_id", "value": 4}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.2: ")
	}
	some v in vs
	contains(v, "without the JSON-RPC request id")
	not "7.1.2" in observability_audit.met with input as inp
}

test_fail_7_1_3_backward_timestamp if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/audit_timestamps/timestamps", "value": [100, 90, 120]}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.3: ")
	}
	some v in vs
	contains(v, "backward")
	not "7.1.3" in observability_audit.met with input as inp
}

test_fail_7_1_3_stale_clock if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/audit_timestamps/newest_age_seconds", "value": 4000}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.1.3: ")
	}
	some v in vs
	contains(v, "within 300")
	not "7.1.3" in observability_audit.met with input as inp
}

test_fail_7_2_1_event_without_code if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/validation_failure_alerts/events", "value": [{"error_code": ""}]}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.2.1: ")
	}
	some v in vs
	contains(v, "no structured error code")
	not "7.2.1" in observability_audit.met with input as inp
}

test_fail_7_2_1_no_siem_rule if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/validation_failure_alerts/siem_rule_present", "value": false}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.2.1: ")
	}
	some v in vs
	contains(v, "SIEM")
	not "7.2.1" in observability_audit.met with input as inp
}

test_fail_7_2_2_orphan_cancellation if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/notification_monitoring/notifications", "value": [{"method": "notifications/cancelled", "server": "srv", "request_id": 99}]}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.2.2: ")
	}
	some v in vs
	contains(v, "originating request")
	not "7.2.2" in observability_audit.met with input as inp
}

test_fail_7_2_2_progress_without_server if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/observability_audit/evidence/notification_monitoring/notifications", "value": [{"method": "notifications/progress", "progress_token": "p-1"}]}])
	vs := observability_audit.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 7.2.2: ")
	}
	some v in vs
	contains(v, "server identity")
	not "7.2.2" in observability_audit.met with input as inp
}
