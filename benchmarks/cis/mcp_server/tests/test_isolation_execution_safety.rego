# Tests for CIS MCP Server Benchmark v1.0.0 — Section 9: Isolation and Execution Safety.
package cis_mcp_server.isolation_execution_safety_test

import rego.v1

import data.cis_mcp_server.isolation_execution_safety

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"isolation_execution_safety": {"requirements": {"9.1": true, "9.3": true}, "evidence": {"confinement": {"working_sentinel_readable": true, "out_of_scope_sentinel_denied": true, "mac_profile_present": true, "denials_logged": true}}}}}

manual_ids := ["9.1", "9.3"]

automated_ids := ["9.2"]

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(isolation_execution_safety.violation) == count(isolation_execution_safety.requirements) with input as {}
	count(isolation_execution_safety.violation) > 0 with input as {}
	not isolation_execution_safety.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(isolation_execution_safety.violation) == 0 with input as full_input
	isolation_execution_safety.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/isolation_execution_safety/requirements/9.1", "value": false}])
	count(isolation_execution_safety.violation) == 1 with input as broken
	some msg in isolation_execution_safety.violation with input as broken
	contains(msg, "9.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := isolation_execution_safety.compliance_report with input as {}
	report.section == 9
	report.area_name == "Isolation and Execution Safety"
	report.requirements_evaluated == count(isolation_execution_safety.requirements)
	report.violation_count == count(isolation_execution_safety.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(isolation_execution_safety.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		isolation_execution_safety.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		isolation_execution_safety.requirements[id].assessment == "Automated"
	}
	every _, m in isolation_execution_safety.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := isolation_execution_safety.met with input as full_input
	m == object.keys(isolation_execution_safety.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/isolation_execution_safety/requirements/%s", [id])])
		vs := isolation_execution_safety.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/isolation_execution_safety/requirements/9.1", "value": "yes"}])
	count(isolation_execution_safety.violation) == 1 with input as inp
}

# Attestation never satisfies an Automated recommendation: attested but no evidence -> each still fails.
test_attestation_does_not_satisfy_automated if {
	attest := object.union(object.get(full_input.cis_mcp_server.isolation_execution_safety, "requirements", {}), {id: true | some id in automated_ids})
	inp := {"cis_mcp_server": {"isolation_execution_safety": {"requirements": attest}}}
	vs := isolation_execution_safety.violation with input as inp
	count(vs) == count(automated_ids)
	every id in automated_ids {
		some v in vs
		v == sprintf("CIS MCP %s: evidence missing — evidence.%s not collected", [id, isolation_execution_safety._evidence_key[id]])
	}
}

# Evidence missing: removing each Automated control's evidence yields one evidence-missing violation.
test_every_automated_evidence_missing if {
	every id in automated_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/isolation_execution_safety/evidence/%s", [isolation_execution_safety._evidence_key[id]])])
		vs := isolation_execution_safety.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: evidence missing", [id]))
		not id in isolation_execution_safety.met with input as inp
	}
}

# An empty evidence object is not evidence.
test_every_automated_empty_evidence_missing if {
	every id in automated_ids {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/isolation_execution_safety/evidence/%s", [isolation_execution_safety._evidence_key[id]]), "value": {}}])
		vs := isolation_execution_safety.violation with input as inp
		count(vs) == 1
		some v in vs
		contains(v, "evidence missing")
	}
}

# A collected evidence object missing a required field fails closed (field-level).
test_every_automated_field_missing_fails if {
	every id in automated_ids {
		k := isolation_execution_safety._evidence_key[id]
		ev := full_input.cis_mcp_server.isolation_execution_safety.evidence[k]
		every f, _ in ev {
			inp := json.remove(full_input, [sprintf("cis_mcp_server/isolation_execution_safety/evidence/%s/%s", [k, f])])
			not id in isolation_execution_safety.met with input as inp
		}
	}
}

test_fail_9_2_out_of_scope_readable if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/isolation_execution_safety/evidence/confinement/out_of_scope_sentinel_denied", "value": false}])
	vs := isolation_execution_safety.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 9.2: ")
	}
	some v in vs
	contains(v, "out-of-scope")
	not "9.2" in isolation_execution_safety.met with input as inp
}

test_fail_9_2_no_mac_profile if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/isolation_execution_safety/evidence/confinement/mac_profile_present", "value": false}])
	vs := isolation_execution_safety.violation with input as inp
	count(vs) >= 1
	every v in vs {
		startswith(v, "CIS MCP 9.2: ")
	}
	some v in vs
	contains(v, "mandatory access control")
	not "9.2" in isolation_execution_safety.met with input as inp
}
