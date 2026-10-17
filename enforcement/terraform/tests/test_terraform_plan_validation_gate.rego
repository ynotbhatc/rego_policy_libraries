package enforcement.terraform.plan_test

import rego.v1

import data.enforcement.terraform.plan

_sg(ingress) := {"resource_changes": [{
	"address": "aws_security_group.a", "type": "aws_security_group",
	"change": {"actions": ["create"], "after": {"ingress": ingress, "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
}]}

test_empty_input_is_not_allowed if {
	not plan.allow with input as {}
	not plan.compliant with input as {}
	v := plan.violation with input as {}
	count(v) == 1
}

test_wrong_key_plan_is_not_allowed if {
	not plan.allow with input as {"changes": []}
}

test_no_change_plan_with_format_version_allowed if {
	plan.allow with input as {"format_version": "1.2"}
	plan.compliant with input as {"format_version": "1.2"}
}

test_empty_resource_changes_allowed if {
	plan.allow with input as {"resource_changes": []}
}

test_all_traffic_ingress_flagged if {
	f := plan.findings with input as _sg([{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])
	"AAC-TF-006" in _fids(f)
	not plan.allow with input as _sg([{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])
}

test_all_traffic_scoped_cidr_not_flagged if {
	f := plan.findings with input as _sg([{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["10.0.0.0/8"]}])
	not "AAC-TF-006" in _fids(f)
}

test_standalone_rule_all_traffic_flagged if {
	inp := {"resource_changes": [{
		"address": "aws_security_group_rule.r", "type": "aws_security_group_rule",
		"change": {"actions": ["create"], "after": {"type": "ingress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}},
	}]}
	f := plan.findings with input as inp
	"AAC-TF-006" in _fids(f)
}

test_tcp_https_only_not_flagged if {
	f := plan.findings with input as _sg([{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}])
	not "AAC-TF-006" in _fids(f)
}

_fids(findings) := {f.control_id | some f in findings}
