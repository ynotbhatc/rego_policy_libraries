# Tests for CIS MCP Server Benchmark v1.0.0 — Section 2: Transport and Connectivity.
package cis_mcp_server.transport_connectivity_test

import rego.v1

import data.cis_mcp_server.transport_connectivity

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"transport_connectivity": {"requirements": {"2.1": true, "2.3": true}, "evidence": {"tls": {"plaintext_http": "redirect_https", "legacy_versions_accepted": [], "negotiated_version": "TLSv1.3", "certificate_valid": true}, "request_headers": {"missing_header_rejected": true, "mismatched_header_rejected": true, "encoded_header_decoded": true}, "origin": {"hostile_origin_status": 403, "allowed_origin_status": 200}}}}}

manual_ids := ["2.1", "2.3"]

automated_ids := ["2.2", "2.4", "2.5"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(transport_connectivity.violation) == count(transport_connectivity.requirements) with input as {}
	count(transport_connectivity.violation) > 0 with input as {}
	not transport_connectivity.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(transport_connectivity.violation) == 0 with input as full_input
	transport_connectivity.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/requirements/2.1", "value": false}])
	count(transport_connectivity.violation) == 1 with input as broken
	some msg in transport_connectivity.violation with input as broken
	contains(msg, "2.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := transport_connectivity.compliance_report with input as {}
	report.section == 2
	report.area_name == "Transport and Connectivity"
	report.requirements_evaluated == count(transport_connectivity.requirements)
	report.violation_count == count(transport_connectivity.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(transport_connectivity.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		transport_connectivity.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		transport_connectivity.requirements[id].assessment == "Automated"
	}
	every _, m in transport_connectivity.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := transport_connectivity.met with input as full_input
	m == object.keys(transport_connectivity.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/transport_connectivity/requirements/%s", [id])])
		vs := transport_connectivity.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/requirements/2.1", "value": "yes"}])
	count(transport_connectivity.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.transport_connectivity, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"transport_connectivity": {"requirements": attest}}}
	vs := transport_connectivity.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, transport_connectivity._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/transport_connectivity/evidence/%s", [transport_connectivity._evidence_key[id]])])
		vs := transport_connectivity.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in transport_connectivity.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/transport_connectivity/evidence/%s", [transport_connectivity._evidence_key[id]]), "value": {}}])
		vs := transport_connectivity.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := transport_connectivity._evidence_key[id]
		ev := full_input.cis_mcp_server.transport_connectivity.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/transport_connectivity/evidence/%s/%s", [k, f])])
			not id in transport_connectivity.met with input as inp
		}
	}
}

test_fail_2_2_plaintext_served if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/tls/plaintext_http", "value": "served"}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.2: ")
	}
	some v in vs
	contains(v, "plaintext")
	not "2.2" in transport_connectivity.met with input as inp
}

test_fail_2_2_legacy_tls_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/tls/legacy_versions_accepted", "value": ["tls1_1"]}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.2: ")
	}
	some v in vs
	contains(v, "tls1_1")
	not "2.2" in transport_connectivity.met with input as inp
}

test_fail_2_2_expired_certificate if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/tls/certificate_valid", "value": false}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.2: ")
	}
	some v in vs
	contains(v, "certificate")
	not "2.2" in transport_connectivity.met with input as inp
}

test_fail_2_4_mismatch_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/request_headers/mismatched_header_rejected", "value": false}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.4: ")
	}
	some v in vs
	contains(v, "Mcp-Name")
	not "2.4" in transport_connectivity.met with input as inp
}

test_fail_2_5_hostile_origin_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/origin/hostile_origin_status", "value": 200}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.5: ")
	}
	some v in vs
	contains(v, "hostile Origin")
	not "2.5" in transport_connectivity.met with input as inp
}

test_fail_2_5_allowed_origin_refused if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/origin/allowed_origin_status", "value": 403}])
	vs := transport_connectivity.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 2.5: ")
	}
	some v in vs
	contains(v, "allowlisted Origin")
	not "2.5" in transport_connectivity.met with input as inp
}

test_pass_2_2_plaintext_port_not_served if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/evidence/tls/plaintext_http", "value": "not_served"}])
	count(transport_connectivity.violation) == 0 with input as inp
	"2.2" in transport_connectivity.met with input as inp
}
