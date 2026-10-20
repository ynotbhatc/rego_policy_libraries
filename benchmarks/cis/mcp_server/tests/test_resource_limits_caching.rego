# Tests for CIS MCP Server Benchmark v1.0.0 — Section 10: Resource Limits and Caching.
package cis_mcp_server.resource_limits_caching_test

import rego.v1

import data.cis_mcp_server.resource_limits_caching

# Fully compliant input: every Manual recommendation attested, every Automated one with passing evidence.
full_input := {"cis_mcp_server": {"resource_limits_caching": {"requirements": {"10.1": true, "10.2": true}}}}

manual_ids := ["10.1", "10.2"]

automated_ids := []

# Kept for compatibility with earlier tests: the compliant fixture.
all_true := full_input

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(resource_limits_caching.violation) == count(resource_limits_caching.requirements) with input as {}
	count(resource_limits_caching.violation) > 0 with input as {}
	not resource_limits_caching.section_compliant with input as {}
}

# Fully compliant input -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(resource_limits_caching.violation) == 0 with input as full_input
	resource_limits_caching.section_compliant with input as full_input
}

# Withdraw a single attestation -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/resource_limits_caching/requirements/10.1", "value": false}])
	count(resource_limits_caching.violation) == 1 with input as broken
	some msg in resource_limits_caching.violation with input as broken
	contains(msg, "10.1") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := resource_limits_caching.compliance_report with input as {}
	report.section == 10
	report.area_name == "Resource Limits and Caching"
	report.requirements_evaluated == count(resource_limits_caching.requirements)
	report.violation_count == count(resource_limits_caching.requirements)
	report.compliant == false
}

# Workbook fidelity: id set, Automated/Manual split, every level L1 or L2.
test_workbook_ids_and_status if {
	object.keys(resource_limits_caching.requirements) == {id | some id in array.concat(manual_ids, automated_ids)}
	every id in manual_ids {
		resource_limits_caching.requirements[id].assessment == "Manual"
	}
	every id in automated_ids {
		resource_limits_caching.requirements[id].assessment == "Automated"
	}
	every _, m in resource_limits_caching.requirements {
		m.level in {"L1", "L2"}
	}
}

# Pass: every recommendation is met on the compliant input.
test_every_requirement_met_on_full_input if {
	m := resource_limits_caching.met with input as full_input
	m == object.keys(resource_limits_caching.requirements)
}

# Fail: each Manual recommendation, unattested, yields exactly one violation naming it.
test_every_manual_fails_when_unattested if {
	every id in manual_ids {
		inp := json.remove(full_input, [sprintf("cis_mcp_server/resource_limits_caching/requirements/%s", [id])])
		vs := resource_limits_caching.violation with input as inp
		count(vs) == 1
		some v in vs
		startswith(v, sprintf("CIS MCP %s: ", [id]))
		contains(v, "not attested")
	}
}

# A truthy-but-not-true attestation is not an attestation.
test_truthy_attestation_rejected if {
	inp := json.patch(full_input, [{"op": "replace", "path": "/cis_mcp_server/resource_limits_caching/requirements/10.1", "value": "yes"}])
	count(resource_limits_caching.violation) == 1 with input as inp
}
