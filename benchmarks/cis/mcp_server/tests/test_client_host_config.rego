# Tests for CIS MCP Server Benchmark v1.0.0 — Section 4: Client (Host) Configuration.
package cis_mcp_server.client_host_config_test

import rego.v1

import data.cis_mcp_server.client_host_config

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"client_host_config": {"requirements": {"4.1.1": true, "4.1.2": {"auto_trust_disabled": true, "approval_required_before_launch": true, "declined_approval_blocks_launch": true}, "4.1.3": {"user_decision_recorded": true, "redaction_checked": true, "secrets_requested_only_via_url_mode": true, "url_mode_user_verified": true, "rate_limited": true}, "4.1.5": {"human_can_deny_any_invocation": true, "high_impact_requires_confirmation": true, "classification_independent_of_annotations": true}, "4.2.1": {"scope_is_least_privilege": true, "os_controls_deny_by_default": true}, "4.2.3": {"disallowed_scheme_rejected": true, "allowlist_covers_server_and_model_uris": true}, "4.3.1": {"sandboxed_isolation": true, "csp_from_declared_metadata": true, "restrictive_default_csp": true, "undeclared_origins_blocked": true, "effective_policy_logged": true}, "4.3.2": {"permissions_default_deny": true, "app_messages_logged": true, "high_risk_channels_consented": true, "tool_visibility_enforced": true}}, "evidence": {"sampling": {"in_use": true, "events_reviewed": 12, "events_noncompliant": 0, "consent_before_forwarding": true, "redaction_filter_applied": true, "rate_limited": true}, "subprocess_env": {"variables": ["PATH", "HOME", "API_TOKEN"], "allowlist": ["PATH", "HOME", "API_TOKEN"]}}}}}

manual_ids := ["4.1.1", "4.1.2", "4.1.3", "4.1.5", "4.2.1", "4.2.3", "4.3.1", "4.3.2"]

automated_ids := ["4.1.4", "4.2.2"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(client_host_config.violation) == count(client_host_config.requirements) with input as {}
	count(client_host_config.violation) > 0 with input as {}
	not client_host_config.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(client_host_config.violation) == 0 with input as full_input
	client_host_config.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.1.1", "value": false}])
	count(client_host_config.violation) == 1 with input as broken
	some msg in client_host_config.violation with input as broken
	contains(msg, "4.1.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := client_host_config.compliance_report with input as {}
	report.section == 4
	report.area_name == "Client (Host) Configuration"
	report.requirements_evaluated == count(client_host_config.requirements)
	report.violation_count == count(client_host_config.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(client_host_config.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		client_host_config.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		client_host_config.requirements[id].assessment == "Automated"
	}
	every _, m in client_host_config.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := client_host_config.met with input as full_input
	m == object.keys(client_host_config.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/client_host_config/requirements/%s", [id])])
		vs := client_host_config.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.1.1", "value": "yes"}])
	count(client_host_config.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.client_host_config, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"client_host_config": {"requirements": attest}}}
	vs := client_host_config.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, client_host_config._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/client_host_config/evidence/%s", [client_host_config._evidence_key[id]])])
		vs := client_host_config.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in client_host_config.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/evidence/%s", [client_host_config._evidence_key[id]]), "value": {}}])
		vs := client_host_config.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := client_host_config._evidence_key[id]
		ev := full_input.cis_mcp_server.client_host_config.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/client_host_config/evidence/%s/%s", [k, f])])
			not id in client_host_config.met with input as inp
		}
	}
}

# 4.1.2 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_1_2_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.1.2", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.1.2:")
	contains(v, "attest each of")
}

# 4.1.2: every component must be attested; one false part fails.
test_4_1_2_each_part_required if {
	every p in client_host_config._parts["4.1.2"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.1.2/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.1.2" in client_host_config.met with input as inp
	}
}

# 4.1.2: pass with every part attested.
test_4_1_2_pass if {
	"4.1.2" in client_host_config.met with input as full_input
}

# 4.1.3 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_1_3_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.1.3", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.1.3:")
	contains(v, "attest each of")
}

# 4.1.3: every component must be attested; one false part fails.
test_4_1_3_each_part_required if {
	every p in client_host_config._parts["4.1.3"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.1.3/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.1.3" in client_host_config.met with input as inp
	}
}

# 4.1.3: pass with every part attested.
test_4_1_3_pass if {
	"4.1.3" in client_host_config.met with input as full_input
}

# 4.1.5 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_1_5_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.1.5", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.1.5:")
	contains(v, "attest each of")
}

# 4.1.5: every component must be attested; one false part fails.
test_4_1_5_each_part_required if {
	every p in client_host_config._parts["4.1.5"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.1.5/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.1.5" in client_host_config.met with input as inp
	}
}

# 4.1.5: pass with every part attested.
test_4_1_5_pass if {
	"4.1.5" in client_host_config.met with input as full_input
}

# 4.2.1 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_2_1_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.2.1", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.2.1:")
	contains(v, "attest each of")
}

# 4.2.1: every component must be attested; one false part fails.
test_4_2_1_each_part_required if {
	every p in client_host_config._parts["4.2.1"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.2.1/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.2.1" in client_host_config.met with input as inp
	}
}

# 4.2.1: pass with every part attested.
test_4_2_1_pass if {
	"4.2.1" in client_host_config.met with input as full_input
}

# 4.2.3 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_2_3_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.2.3", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.2.3:")
	contains(v, "attest each of")
}

# 4.2.3: every component must be attested; one false part fails.
test_4_2_3_each_part_required if {
	every p in client_host_config._parts["4.2.3"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.2.3/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.2.3" in client_host_config.met with input as inp
	}
}

# 4.2.3: pass with every part attested.
test_4_2_3_pass if {
	"4.2.3" in client_host_config.met with input as full_input
}

# 4.3.1 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_3_1_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.3.1", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.3.1:")
	contains(v, "attest each of")
}

# 4.3.1: every component must be attested; one false part fails.
test_4_3_1_each_part_required if {
	every p in client_host_config._parts["4.3.1"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.3.1/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.3.1" in client_host_config.met with input as inp
	}
}

# 4.3.1: pass with every part attested.
test_4_3_1_pass if {
	"4.3.1" in client_host_config.met with input as full_input
}

# 4.3.2 scope changed in the published benchmark: a bare `true` (pre-v1.0.0 attestation) no longer passes.
test_4_3_2_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/requirements/4.3.2", "value": true}])
	vs := client_host_config.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 4.3.2:")
	contains(v, "attest each of")
}

# 4.3.2: every component must be attested; one false part fails.
test_4_3_2_each_part_required if {
	every p in client_host_config._parts["4.3.2"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/client_host_config/requirements/4.3.2/%s", [p]), "value": false}])
		count(client_host_config.violation) == 1 with input as inp
		not "4.3.2" in client_host_config.met with input as inp
	}
}

# 4.3.2: pass with every part attested.
test_4_3_2_pass if {
	"4.3.2" in client_host_config.met with input as full_input
}

test_fail_4_1_4_unredacted_events if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/evidence/sampling/events_noncompliant", "value": 2}])
	vs := client_host_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 4.1.4: ")
	}
	some v in vs
	contains(v, "redaction")
	not "4.1.4" in client_host_config.met with input as inp
}

test_fail_4_1_4_no_consent_gate if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/evidence/sampling/consent_before_forwarding", "value": false}])
	vs := client_host_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 4.1.4: ")
	}
	some v in vs
	contains(v, "consent")
	not "4.1.4" in client_host_config.met with input as inp
}

test_fail_4_2_2_leaked_variable if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/evidence/subprocess_env/variables", "value": ["PATH", "AWS_SECRET_ACCESS_KEY"]}])
	vs := client_host_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 4.2.2: ")
	}
	some v in vs
	contains(v, "AWS_SECRET_ACCESS_KEY")
	not "4.2.2" in client_host_config.met with input as inp
}

test_fail_4_2_2_empty_allowlist if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/evidence/subprocess_env/allowlist", "value": []}])
	vs := client_host_config.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 4.2.2: ")
	}
	some v in vs
	contains(v, "allowlist")
	not "4.2.2" in client_host_config.met with input as inp
}

test_pass_4_1_4_sampling_not_in_use_is_not_applicable if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/client_host_config/evidence/sampling", "value": {"in_use": false}}])
	count(client_host_config.violation) == 0 with input as inp
	"4.1.4" in client_host_config.met with input as inp
}
