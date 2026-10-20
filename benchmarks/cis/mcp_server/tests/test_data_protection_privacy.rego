# Tests for CIS MCP Server Benchmark v1.0.0 — Section 6: Data Protection and Privacy.
package cis_mcp_server.data_protection_privacy_test

import rego.v1

import data.cis_mcp_server.data_protection_privacy

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"data_protection_privacy": {"requirements": {"6.1": true, "6.3": true}, "evidence": {"secret_scan": {"scanner_findings": 0, "inline_manifest_secrets": []}}}}}

manual_ids := ["6.1", "6.3"]

automated_ids := ["6.2"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(data_protection_privacy.violation) == count(data_protection_privacy.requirements) with input as {}
	count(data_protection_privacy.violation) > 0 with input as {}
	not data_protection_privacy.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(data_protection_privacy.violation) == 0 with input as full_input
	data_protection_privacy.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/data_protection_privacy/requirements/6.1", "value": false}])
	count(data_protection_privacy.violation) == 1 with input as broken
	some msg in data_protection_privacy.violation with input as broken
	contains(msg, "6.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := data_protection_privacy.compliance_report with input as {}
	report.section == 6
	report.area_name == "Data Protection and Privacy"
	report.requirements_evaluated == count(data_protection_privacy.requirements)
	report.violation_count == count(data_protection_privacy.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(data_protection_privacy.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		data_protection_privacy.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		data_protection_privacy.requirements[id].assessment == "Automated"
	}
	every _, m in data_protection_privacy.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := data_protection_privacy.met with input as full_input
	m == object.keys(data_protection_privacy.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/data_protection_privacy/requirements/%s", [id])])
		vs := data_protection_privacy.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/data_protection_privacy/requirements/6.1", "value": "yes"}])
	count(data_protection_privacy.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.data_protection_privacy, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"data_protection_privacy": {"requirements": attest}}}
	vs := data_protection_privacy.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, data_protection_privacy._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/data_protection_privacy/evidence/%s", [data_protection_privacy._evidence_key[id]])])
		vs := data_protection_privacy.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in data_protection_privacy.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/data_protection_privacy/evidence/%s", [data_protection_privacy._evidence_key[id]]), "value": {}}])
		vs := data_protection_privacy.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := data_protection_privacy._evidence_key[id]
		ev := full_input.cis_mcp_server.data_protection_privacy.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/data_protection_privacy/evidence/%s/%s", [k, f])])
			not id in data_protection_privacy.met with input as inp
		}
	}
}

test_fail_6_2_scanner_findings if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/data_protection_privacy/evidence/secret_scan/scanner_findings", "value": 3}])
	vs := data_protection_privacy.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 6.2: ")
	}
	some v in vs
	contains(v, "3 findings")
	not "6.2" in data_protection_privacy.met with input as inp
}

test_fail_6_2_inline_manifest_secret if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/data_protection_privacy/evidence/secret_scan/inline_manifest_secrets", "value": ["deploy/mcp.yaml:API_KEY"]}])
	vs := data_protection_privacy.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 6.2: ")
	}
	some v in vs
	contains(v, "deploy/mcp.yaml:API_KEY")
	not "6.2" in data_protection_privacy.met with input as inp
}
