# Tests for CIS MCP Server Benchmark v1.0.0 — Section 8: Supply Chain Security.
package cis_mcp_server.supply_chain_security_test

import rego.v1

import data.cis_mcp_server.supply_chain_security

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"supply_chain_security": {"requirements": {"8.1": {"allowlist_enforced_by_host_or_client": true, "every_allowlisted_server_has_vetting_record": true, "unlisted_servers_refused": true}, "8.2": {"pinned_artifacts_match_approved_hash": true, "no_unpinned_installed_instance": true, "hash_mismatch_blocks_start": true, "update_triggers_revetting": true}, "8.3": {"package_sources_point_to_mirror": true, "public_registry_unreachable_from_host": true, "mirror_holds_only_vetted_artifacts": true, "other_channels_internal_only": true}}}}}

manual_ids := ["8.1", "8.2", "8.3"]

automated_ids := []

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(supply_chain_security.violation) == count(supply_chain_security.requirements) with input as {}
	count(supply_chain_security.violation) > 0 with input as {}
	not supply_chain_security.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(supply_chain_security.violation) == 0 with input as full_input
	supply_chain_security.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/supply_chain_security/requirements/8.1", "value": false}])
	count(supply_chain_security.violation) == 1 with input as broken
	some msg in supply_chain_security.violation with input as broken
	contains(msg, "8.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := supply_chain_security.compliance_report with input as {}
	report.section == 8
	report.area_name == "Supply Chain Security"
	report.requirements_evaluated == count(supply_chain_security.requirements)
	report.violation_count == count(supply_chain_security.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(supply_chain_security.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		supply_chain_security.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		supply_chain_security.requirements[id].assessment == "Automated"
	}
	every _, m in supply_chain_security.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := supply_chain_security.met with input as full_input
	m == object.keys(supply_chain_security.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/supply_chain_security/requirements/%s", [id])])
		vs := supply_chain_security.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/supply_chain_security/requirements/8.1", "value": "yes"}])
	count(supply_chain_security.violation) == 1 with input as inp
}

# 8.1 has several audited components: a bare `true` is not an attestation.
test_8_1_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/supply_chain_security/requirements/8.1", "value": true}])
	vs := supply_chain_security.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 8.1:")
	contains(v, "attest each of")
}

# 8.1: every component must be attested; one false part fails.
test_8_1_each_part_required if {
	every p in supply_chain_security._parts["8.1"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/supply_chain_security/requirements/8.1/%s", [p]), "value": false}])
		count(supply_chain_security.violation) == 1 with input as inp
		not "8.1" in supply_chain_security.met with input as inp
	}
}

# 8.1: pass with every part attested.
test_8_1_pass if {
	"8.1" in supply_chain_security.met with input as full_input
}

# 8.2 has several audited components: a bare `true` is not an attestation.
test_8_2_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/supply_chain_security/requirements/8.2", "value": true}])
	vs := supply_chain_security.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 8.2:")
	contains(v, "attest each of")
}

# 8.2: every component must be attested; one false part fails.
test_8_2_each_part_required if {
	every p in supply_chain_security._parts["8.2"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/supply_chain_security/requirements/8.2/%s", [p]), "value": false}])
		count(supply_chain_security.violation) == 1 with input as inp
		not "8.2" in supply_chain_security.met with input as inp
	}
}

# 8.2: pass with every part attested.
test_8_2_pass if {
	"8.2" in supply_chain_security.met with input as full_input
}

# 8.3 has several audited components: a bare `true` is not an attestation.
test_8_3_bare_true_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/supply_chain_security/requirements/8.3", "value": true}])
	vs := supply_chain_security.violation with input as inp
	count(vs) == 1
	some v in vs
	contains(v, "CIS MCP 8.3:")
	contains(v, "attest each of")
}

# 8.3: every component must be attested; one false part fails.
test_8_3_each_part_required if {
	every p in supply_chain_security._parts["8.3"] {
		inp := json.patch(full_input, [{"op": "replace", "path": sprintf("/cis_mcp_server/supply_chain_security/requirements/8.3/%s", [p]), "value": false}])
		count(supply_chain_security.violation) == 1 with input as inp
		not "8.3" in supply_chain_security.met with input as inp
	}
}

# 8.3: pass with every part attested.
test_8_3_pass if {
	"8.3" in supply_chain_security.met with input as full_input
}
