# Tests for CIS MCP Server Benchmark v1.0.0 — Section 5: Server Configuration.
package cis_mcp_server.server_config_test

import rego.v1

import data.cis_mcp_server.server_config

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"server_config": {"requirements": {"5.2.2": {"handle_alone_rejected": true, "handle_bound_to_identity": true, "handle_unguessable": true, "handle_expires": true}, "5.5.1": {"cross_identity_retrieval_denied": true, "denial_is_ownership_decision": true, "handle_unguessable": true, "finite_ttl": true}, "5.6.1": {"idempotency_key_required": true, "duplicate_returns_cached_result": true, "payload_mismatch_rejected": true, "side_effect_once": true, "cross_principal_reuse_denied": true}}, "evidence": {"tool_schemas": {"schemas_failing_compile": [], "invalid_call_executed": false, "external_ref_refused": true, "schema_limits_bounded": true}, "resource_templates": {"templates": [{"uriTemplate": "file:///docs/{name}", "mimeType": "text/markdown"}], "missing_resource_error_code": -32602}, "prompts": {"prompts": [{"name": "summarize", "arguments": [{"name": "topic", "required": true}, {"name": "tone"}]}, {"name": "hello"}], "missing_required_argument_error_code": -32602}, "list_changed": {"min_interval_seconds": 5, "notifications": [{"type": "tools", "ts": 100}, {"type": "tools", "ts": 110}, {"type": "resources", "ts": 101}, {"type": "resources", "ts": 120}]}, "legacy_session": {"get_status": 405, "delete_status": 405, "last_event_id_ignored": true, "session_id_honored": false, "session_id_minted": false}, "stdio_stream": {"stdout_lines_checked": 40, "non_jsonrpc_stdout_lines": 0, "startup_stdout_clean": true, "log_destinations": ["stderr", "file"]}, "path_traversal": {"allowed_read_succeeded": true, "traversal_read_denied": true, "symlink_escape_denied": true}}}}}

manual_ids := ["5.2.2", "5.5.1", "5.6.1"]

automated_ids := ["5.1.1", "5.1.2", "5.1.3", "5.2.1", "5.2.3", "5.3.1", "5.4.1"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(server_config.violation) == count(server_config.requirements) with input as {}
	count(server_config.violation) > 0 with input as {}
	not server_config.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(server_config.violation) == 0 with input as full_input
	server_config.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/requirements/5.2.2", "value": false}])
	count(server_config.violation) == 1 with input as broken
	some msg in server_config.violation with input as broken
	contains(msg, "5.2.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := server_config.compliance_report with input as {}
	report.section == 5
	report.area_name == "Server Configuration"
	report.requirements_evaluated == count(server_config.requirements)
	report.violation_count == count(server_config.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(server_config.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		server_config.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		server_config.requirements[id].assessment == "Automated"
	}
	every _, m in server_config.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := server_config.met with input as full_input
	m == object.keys(server_config.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/server_config/requirements/%s", [id])])
		vs := server_config.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/requirements/5.2.2", "value": "yes"}])
	count(server_config.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.server_config, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"server_config": {"requirements": attest}}}
	vs := server_config.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, server_config._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/server_config/evidence/%s", [server_config._evidence_key[id]])])
		vs := server_config.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in server_config.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/server_config/evidence/%s", [server_config._evidence_key[id]]), "value": {}}])
		vs := server_config.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := server_config._evidence_key[id]
		ev := full_input.cis_mcp_server.server_config.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/server_config/evidence/%s/%s", [k, f])])
			not id in server_config.met with input as inp
		}
	}
}

# 5.2.2 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_5_2_2_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/requirements/5.2.2", "value": true}])
	vs := server_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 5.2.2:")
	contains(v, "attest each of")
}

# 5.2.2: every component must be attested; one false part fails.
test_5_2_2_each_part_required if {
	every p in server_config._parts["5.2.2"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/server_config/requirements/5.2.2/%s", [p]), "value": false}])
		count(server_config.violation) == 1 with input as inp
		not "5.2.2" in server_config.met with input as inp
	}
}

# 5.2.2: pass with every part attested.
test_5_2_2_pass if {
	"5.2.2" in server_config.met with input as full_input
}

# 5.5.1 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_5_5_1_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/requirements/5.5.1", "value": true}])
	vs := server_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 5.5.1:")
	contains(v, "attest each of")
}

# 5.5.1: every component must be attested; one false part fails.
test_5_5_1_each_part_required if {
	every p in server_config._parts["5.5.1"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/server_config/requirements/5.5.1/%s", [p]), "value": false}])
		count(server_config.violation) == 1 with input as inp
		not "5.5.1" in server_config.met with input as inp
	}
}

# 5.5.1: pass with every part attested.
test_5_5_1_pass if {
	"5.5.1" in server_config.met with input as full_input
}

# 5.6.1 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_5_6_1_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/requirements/5.6.1", "value": true}])
	vs := server_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 5.6.1:")
	contains(v, "attest each of")
}

# 5.6.1: every component must be attested; one false part fails.
test_5_6_1_each_part_required if {
	every p in server_config._parts["5.6.1"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/server_config/requirements/5.6.1/%s", [p]), "value": false}])
		count(server_config.violation) == 1 with input as inp
		not "5.6.1" in server_config.met with input as inp
	}
}

# 5.6.1: pass with every part attested.
test_5_6_1_pass if {
	"5.6.1" in server_config.met with input as full_input
}

test_fail_5_1_1_invalid_call_executed if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/tool_schemas/invalid_call_executed", "value": true}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.1: ")
	}
	some v in vs
	contains(v, "executed")
	not "5.1.1" in server_config.met with input as inp
}

test_fail_5_1_1_schema_does_not_compile if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/tool_schemas/schemas_failing_compile", "value": ["tools/delete.input"]}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.1: ")
	}
	some v in vs
	contains(v, "tools/delete.input")
	not "5.1.1" in server_config.met with input as inp
}

test_fail_5_1_2_template_without_mime if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/resource_templates/templates", "value": [{"uriTemplate": "file:///x/{y}", "mimeType": ""}]}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.2: ")
	}
	some v in vs
	contains(v, "MIME")
	not "5.1.2" in server_config.met with input as inp
}

test_fail_5_1_2_missing_resource_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/resource_templates/missing_resource_error_code", "value": -32603}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.2: ")
	}
	some v in vs
	contains(v, "-32602")
	not "5.1.2" in server_config.met with input as inp
}

test_fail_5_1_3_argument_without_name if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/prompts/prompts", "value": [{"name": "p", "arguments": [{"required": true}]}]}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.3: ")
	}
	some v in vs
	contains(v, "malformed")
	not "5.1.3" in server_config.met with input as inp
}

test_fail_5_1_3_missing_argument_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/prompts/missing_required_argument_error_code", "value": 0}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.1.3: ")
	}
	some v in vs
	contains(v, "-32602")
	not "5.1.3" in server_config.met with input as inp
}

test_fail_5_2_1_flooding if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/list_changed/notifications", "value": [{"type": "tools", "ts": 100}, {"type": "tools", "ts": 101}]}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.2.1: ")
	}
	some v in vs
	contains(v, "1 s apart")
	not "5.2.1" in server_config.met with input as inp
}

test_fail_5_2_3_get_allowed if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/legacy_session/get_status", "value": 200}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.2.3: ")
	}
	some v in vs
	contains(v, "GET")
	not "5.2.3" in server_config.met with input as inp
}

test_fail_5_2_3_session_minted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/legacy_session/session_id_minted", "value": true}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.2.3: ")
	}
	some v in vs
	contains(v, "mints")
	not "5.2.3" in server_config.met with input as inp
}

test_fail_5_3_1_stdout_logging if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/stdio_stream/log_destinations", "value": ["stdout"]}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.3.1: ")
	}
	some v in vs
	contains(v, "stdout")
	not "5.3.1" in server_config.met with input as inp
}

test_fail_5_3_1_dirty_stdout if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/stdio_stream/non_jsonrpc_stdout_lines", "value": 3}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.3.1: ")
	}
	some v in vs
	contains(v, "non-JSON-RPC")
	not "5.3.1" in server_config.met with input as inp
}

test_fail_5_4_1_symlink_escape if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/path_traversal/symlink_escape_denied", "value": false}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.4.1: ")
	}
	some v in vs
	contains(v, "symlink")
	not "5.4.1" in server_config.met with input as inp
}

test_fail_5_4_1_traversal if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/server_config/evidence/path_traversal/traversal_read_denied", "value": false}])
	vs := server_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 5.4.1: ")
	}
	some v in vs
	contains(v, "traversal")
	not "5.4.1" in server_config.met with input as inp
}
