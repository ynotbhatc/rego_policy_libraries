# A malformed plan is denied (SENTINEL-TF-000 and the type checks in TF-002): the gate never allows a
# document it could not read as a Terraform plan.

package sentinel.terraform_malformed_test

import rego.v1

import data.sentinel.terraform as gate
import data.sentinel_terraform.main

# a plan the gate allows: one tagged instance in an approved region, one closed security group
good_plan := {
	"resource_changes": [
		{
			"address": "aws_instance.web",
			"type": "aws_instance",
			"change": {"actions": ["create"], "after": {"region": "us-east-1", "tags": {"Environment": "prod", "Owner": "platform", "CostCenter": "cc-1"}}},
		},
		{
			"address": "aws_security_group.web",
			"type": "aws_security_group",
			"change": {"actions": ["create"], "after": {
				"tags": {"Environment": "prod", "Owner": "platform", "CostCenter": "cc-1"},
				"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}],
			}},
		},
	],
}

_allowed(inp) if {
	gate.allow with input as inp
	main.compliance_report.compliant == true with input as inp
}

_denied(inp) if {
	not gate.allow with input as inp
	main.compliance_report.compliant == false with input as inp
}

_tf000(inp) if {
	some msg in gate.violations with input as inp
	startswith(msg, "SENTINEL-TF-000: Malformed plan")
}

test_good_plan_is_allowed if _allowed(good_plan)

test_empty_input_is_denied if _denied({})

# A plan with nothing to change omits resource_changes; it is still a plan document.
test_plan_without_changes_is_allowed if {
	_allowed({"format_version": "1.2", "terraform_version": "1.9.0"})
	_allowed({"format_version": "1.2", "resource_changes": []})
}

test_document_that_is_not_a_plan_is_denied if {
	every inp in [{"foo": "bar"}, {"resource_changes": null}, {"format_version": 1}, {"allow": true, "violations": []}] {
		_denied(inp)
		_tf000(inp)
	}
}

test_resource_changes_of_the_wrong_type_is_denied if {
	every bad in ["true", "1", 1, true, {"a": 1}] {
		inp := object.union(good_plan, {"resource_changes": bad})
		_denied(inp)
		_tf000(inp)
	}
}

test_change_of_the_wrong_shape_is_denied if {
	paths := ["/resource_changes/0", "/resource_changes/0/address", "/resource_changes/0/type", "/resource_changes/0/change", "/resource_changes/0/change/actions", "/resource_changes/0/change/after"]
	every path in paths {
		every bad in [null, true, 1] {
			inp := json.patch(good_plan, [{"op": "replace", "path": path, "value": bad}])
			_denied(inp)
			_tf000(inp)
		}
	}

	# a string is the right type only for address and type
	every path in ["/resource_changes/0", "/resource_changes/0/change", "/resource_changes/0/change/actions", "/resource_changes/0/change/after"] {
		inp := json.patch(good_plan, [{"op": "replace", "path": path, "value": "true"}])
		_denied(inp)
		_tf000(inp)
	}
	every path in array.slice(paths, 1, count(paths)) {
		inp := json.patch(good_plan, [{"op": "remove", "path": path}])
		_denied(inp)
		_tf000(inp)
	}
}

test_string_port_on_a_private_rule_is_malformed if {
	inp := json.patch(good_plan, [{"op": "replace", "path": "/resource_changes/1/change/after/ingress/0/from_port", "value": "22"}])
	_denied(inp)
	_tf000(inp)
}

test_explicit_null_resource_changes_is_denied_even_in_a_plan_document if {
	inp := {"format_version": "1.2", "resource_changes": null}
	_denied(inp)
	_tf000(inp)
}

test_delete_needs_no_after if {
	inp := json.patch(good_plan, [
		{"op": "replace", "path": "/resource_changes/0/change/actions", "value": ["delete"]},
		{"op": "replace", "path": "/resource_changes/0/change/after", "value": null},
	])
	_allowed(inp)
}

_world_open := json.patch(good_plan, [{"op": "replace", "path": "/resource_changes/1/change/after/ingress/0/cidr_blocks", "value": ["0.0.0.0/0"]}])

test_world_open_ssh_is_denied if _denied(_world_open)

# A port bound sent as a string (or left out) on a world-open rule cannot hide the port.
test_string_or_missing_port_on_open_rule_is_denied if {
	every field in ["from_port", "to_port"] {
		path := sprintf("/resource_changes/1/change/after/ingress/0/%s", [field])
		_denied(json.patch(_world_open, [{"op": "replace", "path": path, "value": "22"}]))
		_denied(json.patch(_world_open, [{"op": "replace", "path": path, "value": null}]))
		_denied(json.patch(_world_open, [{"op": "remove", "path": path}]))
	}
}

# cidr_blocks sent as a string instead of a list is read as open.
test_cidr_blocks_string_is_denied if {
	inp := json.patch(good_plan, [{"op": "replace", "path": "/resource_changes/1/change/after/ingress/0/cidr_blocks", "value": "0.0.0.0/0"}])
	_denied(inp)
	some msg in gate.violations with input as inp
	contains(msg, "an unreadable CIDR list")
}

test_tags_of_the_wrong_type_are_missing_tags if {
	every bad in [null, "Environment=prod", ["Environment"], true] {
		_denied(json.patch(good_plan, [{"op": "replace", "path": "/resource_changes/0/change/after/tags", "value": bad}]))
	}
}

# A change with several problems at once (no address, no type, no actions) used to make the shape function
# return conflicting values: the whole report was an evaluation error, which the product drops. It is one
# SENTINEL-TF-000 finding, and the report stays defined and denying.
test_change_with_several_problems_is_denied_not_an_error if {
	every bad in [{}, {"address": null, "type": null, "change": {"actions": [null]}}, {"change": {"after": {}}}] {
		inp := {"format_version": "1.2", "resource_changes": [bad]}
		_denied(inp)
		"SENTINEL-TF-000: Malformed plan: resource_changes[0] has no address" in gate.violations with input as inp
	}
}

test_every_leaf_null_is_denied_not_an_error if {
	inp := {"format_version": null, "resource_changes": [{"address": null, "type": null, "change": {"actions": [null], "after": {"tags": {"Owner": null}, "ingress": [{"cidr_blocks": [null], "from_port": null, "to_port": null}]}}}]}
	_denied(inp)
}
