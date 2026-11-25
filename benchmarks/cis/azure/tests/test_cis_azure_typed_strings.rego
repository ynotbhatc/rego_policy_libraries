package cis_azure.typed_strings_test

# Round 3 (audit 2026-11-24): a string fact is read for what it says, not for being there. A condition that is not
# an attribute expression, an empty role name, a SKU name that is not one Azure returns, a NAT gateway "id" that is
# not a resource id, and a diagnostic-setting log whose enabled is not a boolean never meet a recommendation.

import rego.v1

_green := data.cis_azure.v7_controls_test.green

_report(inp) := r if {
	r := data.cis_azure.main.compliance_report with input as inp
}

_vs(inp) := _report(inp).violations

_has(inp, prefix, part) if {
	some v in _vs(inp)
	startswith(v, prefix)
	contains(v, part)
}

_nat_index := [i | some i, ip in _green.public_ip_addresses; ip.natGateway][0]

_rbac_index := [i | some i, a in _green.role_assignments; a.condition][0]

test_green_still_passes if _report(_green).compliant == true

test_5_12_condition_that_is_not_an_expression_is_not_a_condition if {
	every c in ["false", "no", "none", "true", "x"] {
		inp := json.patch(_green, [{"op": "replace", "path": sprintf("/role_assignments/%d/condition", [_rbac_index]), "value": c}])
		_has(inp, "5.12:", "without a condition")
	}
}

test_5_3_3_role_assignment_without_a_role_name_is_reported if {
	every name in ["", "  "] {
		inp := json.patch(_green, [{"op": "add", "path": "/root_role_assignments/-", "value": {"roleDefinitionName": name, "scope": "/", "principalId": "p-9"}}])
		_has(inp, "5.3.3:", "without its role name")
	}
}

test_5_12_role_assignment_with_an_empty_role_or_scope_is_reported if {
	every a in [{"roleDefinitionName": "", "scope": "/subscriptions/00000000-0000-0000-0000-000000000001"}, {"roleDefinitionName": "Reader", "scope": "false"}] {
		inp := json.patch(_green, [{"op": "add", "path": "/role_assignments/-", "value": a}])
		_has(inp, "5.12:", "without its role name or scope")
	}
}

test_8_4_2_sku_that_is_not_a_sku_name_is_not_collected if {
	every n in ["", "false", "true", "premium-plus"] {
		inp := json.patch(_green, [{"op": "replace", "path": "/bastion_hosts/0/sku/name", "value": n}])
		_has(inp, "8.4.2:", "not a recognised SKU name")
	}
}

test_8_5_nat_gateway_id_must_be_a_resource_id if {
	every id in ["false", "true", "no", "nat", ""] {
		inp := json.patch(_green, [{"op": "replace", "path": sprintf("/public_ip_addresses/%d/natGateway/id", [_nat_index]), "value": id}])
		_has(inp, "8.5:", "not protected by Azure DDoS Protection")
	}
}

test_diagnostic_log_enabled_must_be_a_boolean_and_the_type_is_named if {
	every bad in ["true", "false", 1, 0, null, [], {}] {
		inp := json.patch(_green, [{"op": "replace", "path": "/subscription_diagnostic_settings/0/logs/0/enabled", "value": bad}])
		some v in _vs(inp)
		startswith(v, "6.1.1.2:")
		contains(v, sprintf("enabled of type %v, not a boolean", [type_name(bad)]))
		_report(inp).compliant == false
	}
}
