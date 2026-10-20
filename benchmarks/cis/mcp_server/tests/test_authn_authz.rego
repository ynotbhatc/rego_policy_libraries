# Tests for CIS MCP Server Benchmark v1.0.0 — Section 3: Authentication and Authorization.
package cis_mcp_server.authn_authz_test

import rego.v1

import data.cis_mcp_server.authn_authz

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"authn_authz": {"requirements": {"3.1.2": true, "3.2.1": true, "3.2.2": true, "3.2.3": true, "3.3.3": true, "3.3.4": true, "3.3.5": true}, "evidence": {"stdio_credentials": {"interactive_oauth_in_launch_config": false, "credential_on_command_line": false, "credential_source": "secret_store"}, "token_audience": {"canonical_uri": "https://mcp.example.com/mcp", "token_aud": ["https://mcp.example.com/mcp"], "foreign_audience_status": 401}, "oauth_discovery": {"served_over_tls": true, "resource_matches_canonical_uri": true, "authorization_servers": ["https://as.example.com"], "approved_authorization_servers": ["https://as.example.com"], "issuer_mismatches": []}}}}}

manual_ids := ["3.1.2", "3.2.1", "3.2.2", "3.2.3", "3.3.3", "3.3.4", "3.3.5"]

automated_ids := ["3.1.1", "3.3.1", "3.3.2"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(authn_authz.violation) == count(authn_authz.requirements) with input as {}
	count(authn_authz.violation) > 0 with input as {}
	not authn_authz.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(authn_authz.violation) == 0 with input as full_input
	authn_authz.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/requirements/3.1.2", "value": false}])
	count(authn_authz.violation) == 1 with input as broken
	some msg in authn_authz.violation with input as broken
	contains(msg, "3.1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := authn_authz.compliance_report with input as {}
	report.section == 3
	report.area_name == "Authentication and Authorization"
	report.requirements_evaluated == count(authn_authz.requirements)
	report.violation_count == count(authn_authz.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(authn_authz.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		authn_authz.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		authn_authz.requirements[id].assessment == "Automated"
	}
	every _, m in authn_authz.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := authn_authz.met with input as full_input
	m == object.keys(authn_authz.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/authn_authz/requirements/%s", [id])])
		vs := authn_authz.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/requirements/3.1.2", "value": "yes"}])
	count(authn_authz.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.authn_authz, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"authn_authz": {"requirements": attest}}}
	vs := authn_authz.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, authn_authz._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/authn_authz/evidence/%s", [authn_authz._evidence_key[id]])])
		vs := authn_authz.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in authn_authz.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/authn_authz/evidence/%s", [authn_authz._evidence_key[id]]), "value": {}}])
		vs := authn_authz.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := authn_authz._evidence_key[id]
		ev := full_input.cis_mcp_server.authn_authz.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/authn_authz/evidence/%s/%s", [k, f])])
			not id in authn_authz.met with input as inp
		}
	}
}

test_fail_3_1_1_credential_on_cmdline if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/stdio_credentials/credential_on_command_line", "value": true}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.1.1: ")
	}
	some v in vs
	contains(v, "command line")
	not "3.1.1" in authn_authz.met with input as inp
}

test_fail_3_1_1_browser_oauth if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/stdio_credentials/interactive_oauth_in_launch_config", "value": true}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.1.1: ")
	}
	some v in vs
	contains(v, "interactive")
	not "3.1.1" in authn_authz.met with input as inp
}

test_fail_3_3_1_wrong_audience if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/token_audience/token_aud", "value": "https://other.example.com"}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.3.1: ")
	}
	some v in vs
	contains(v, "audience")
	not "3.3.1" in authn_authz.met with input as inp
}

test_fail_3_3_1_foreign_token_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/token_audience/foreign_audience_status", "value": 200}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.3.1: ")
	}
	some v in vs
	contains(v, "401")
	not "3.3.1" in authn_authz.met with input as inp
}

test_fail_3_3_2_unapproved_as if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/oauth_discovery/authorization_servers", "value": ["https://as.example.com", "https://evil.example.net"]}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.3.2: ")
	}
	some v in vs
	contains(v, "evil.example.net")
	not "3.3.2" in authn_authz.met with input as inp
}

test_fail_3_3_2_empty_as_list if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/oauth_discovery/authorization_servers", "value": []}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.3.2: ")
	}
	some v in vs
	contains(v, "authorization_servers is empty")
	not "3.3.2" in authn_authz.met with input as inp
}

test_fail_3_3_2_plaintext_metadata if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/oauth_discovery/served_over_tls", "value": false}])
	vs := authn_authz.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 3.3.2: ")
	}
	some v in vs
	contains(v, "TLS")
	not "3.3.2" in authn_authz.met with input as inp
}

test_pass_3_3_1_string_audience if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/authn_authz/evidence/token_audience/token_aud", "value": "https://mcp.example.com/mcp"}])
	count(authn_authz.violation) == 0 with input as inp
	"3.3.1" in authn_authz.met with input as inp
}
