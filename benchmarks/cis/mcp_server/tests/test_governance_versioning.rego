# Tests for CIS MCP Server Benchmark v1.0.0 — Section 1: Governance and Versioning.
package cis_mcp_server.governance_versioning_test

import rego.v1

import data.cis_mcp_server.governance_versioning

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"governance_versioning": {"requirements": {"1.2": true, "1.3": true}, "evidence": {"protocol_version": {"advertised_versions": ["2025-11-25", "2026-07-28"], "approved_versions": ["2025-06-18", "2025-11-25", "2026-07-28"], "unapproved_version_rejected": true, "missing_header_version_rejected": true, "missing_meta_version_rejected": true, "header_body_mismatch_rejected": true, "version_logged_on_every_request": true}, "identity": {"client_identity_on_every_request": true, "server_identity_on_every_response": true, "unregistered_identities": []}}}}}

manual_ids := ["1.2", "1.3"]

automated_ids := ["1.1", "1.4"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(governance_versioning.violation) == count(governance_versioning.requirements) with input as {}
	count(governance_versioning.violation) > 0 with input as {}
	not governance_versioning.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(governance_versioning.violation) == 0 with input as full_input
	governance_versioning.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/requirements/1.2", "value": false}])
	count(governance_versioning.violation) == 1 with input as broken
	some msg in governance_versioning.violation with input as broken
	contains(msg, "1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := governance_versioning.compliance_report with input as {}
	report.section == 1
	report.area_name == "Governance and Versioning"
	report.requirements_evaluated == count(governance_versioning.requirements)
	report.violation_count == count(governance_versioning.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(governance_versioning.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		governance_versioning.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		governance_versioning.requirements[id].assessment == "Automated"
	}
	every _, m in governance_versioning.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := governance_versioning.met with input as full_input
	m == object.keys(governance_versioning.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/governance_versioning/requirements/%s", [id])])
		vs := governance_versioning.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/requirements/1.2", "value": "yes"}])
	count(governance_versioning.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.governance_versioning, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"governance_versioning": {"requirements": attest}}}
	vs := governance_versioning.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, governance_versioning._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/governance_versioning/evidence/%s", [governance_versioning._evidence_key[id]])])
		vs := governance_versioning.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in governance_versioning.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/governance_versioning/evidence/%s", [governance_versioning._evidence_key[id]]), "value": {}}])
		vs := governance_versioning.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := governance_versioning._evidence_key[id]
		ev := full_input.cis_mcp_server.governance_versioning.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/governance_versioning/evidence/%s/%s", [k, f])])
			not id in governance_versioning.met with input as inp
		}
	}
}

test_fail_1_1_unapproved_version_advertised if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/evidence/protocol_version/advertised_versions", "value": ["2024-11-05", "2026-07-28"]}])
	vs := governance_versioning.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 1.1: ")
	}
	some v in vs
	contains(v, "unapproved protocol version 2024-11-05")
	not "1.1" in governance_versioning.met with input as inp
}

test_fail_1_1_version_not_logged if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/evidence/protocol_version/version_logged_on_every_request", "value": false}])
	vs := governance_versioning.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 1.1: ")
	}
	some v in vs
	contains(v, "not logged")
	not "1.1" in governance_versioning.met with input as inp
}

test_fail_1_1_mismatch_accepted if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/evidence/protocol_version/header_body_mismatch_rejected", "value": false}])
	vs := governance_versioning.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 1.1: ")
	}
	some v in vs
	contains(v, "disagreement")
	not "1.1" in governance_versioning.met with input as inp
}

test_fail_1_4_unregistered_identity if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/evidence/identity/unregistered_identities", "value": ["rogue|0.1"]}])
	vs := governance_versioning.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 1.4: ")
	}
	some v in vs
	contains(v, "rogue|0.1")
	not "1.4" in governance_versioning.met with input as inp
}

test_fail_1_4_client_identity_absent if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/governance_versioning/evidence/identity/client_identity_on_every_request", "value": false}])
	vs := governance_versioning.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 1.4: ")
	}
	some v in vs
	contains(v, "client identity")
	not "1.4" in governance_versioning.met with input as inp
}
