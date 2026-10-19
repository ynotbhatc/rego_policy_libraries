package sentinel.terraform_test

import rego.v1

# Validation fix 2026-10-17: protocol "-1" (all traffic) and IPv6 ::/0 ingress were not flagged;
# a null tag value counted as present.

pkg := data.sentinel.terraform

sg(ingress) := {"resource_changes": [{
	"address": "aws_security_group.web", "type": "aws_security_group",
	"change": {"actions": ["create"], "after": {"ingress": ingress, "tags": {"Environment": "x", "Owner": "y", "CostCenter": "z"}}},
}]}

sgr(rule) := {"resource_changes": [{
	"address": "aws_security_group_rule.r", "type": "aws_security_group_rule",
	"change": {"actions": ["create"], "after": object.union(rule, {"type": "ingress", "tags": {"Environment": "x", "Owner": "y", "CostCenter": "z"}})},
}]}

port22_msgs(inp) := {m | some m in pkg.violations with input as inp; contains(m, "sensitive port 22 ")}

test_all_traffic_protocol_flagged if {
	inp := sg([{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])
	count(port22_msgs(inp)) == 1
	not pkg.allow with input as inp
}

test_all_traffic_rule_resource_flagged if {
	inp := sgr({"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]})
	count(port22_msgs(inp)) == 1
}

test_ipv6_open_flagged if {
	inp := sg([{"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]}])
	count(port22_msgs(inp)) == 1
	inp2 := sgr({"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]})
	count(port22_msgs(inp2)) == 1
}

test_ipv4_tcp_22_still_flagged if {
	inp := sg([{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}])
	count(port22_msgs(inp)) == 1
}

test_restricted_cidr_allowed if {
	inp := sg([{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"], "ipv6_cidr_blocks": ["fd00::/8"]}])
	pkg.allow with input as inp
}

test_https_open_to_world_allowed if {
	inp := sg([{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}])
	pkg.allow with input as inp
}

test_icmp_has_no_ports if {
	inp := sg([{"protocol": "icmp", "from_port": -1, "to_port": -1, "cidr_blocks": ["0.0.0.0/0"]}])
	pkg.allow with input as inp
}

test_null_tag_value_is_missing if {
	inp := {"resource_changes": [{"address": "aws_instance.a", "type": "aws_instance", "change": {"actions": ["create"], "after": {"tags": {"Environment": null, "Owner": "y", "CostCenter": "z"}}}}]}
	v := pkg.violations with input as inp
	"SENTINEL-TF-001: Resource 'aws_instance.a' (aws_instance) is missing required tag 'Environment'" in v
}

test_fully_tagged_resource_allowed if {
	inp := {"resource_changes": [{"address": "aws_instance.a", "type": "aws_instance", "change": {"actions": ["create"], "after": {"tags": {"Environment": "e", "Owner": "y", "CostCenter": "z"}}}}]}
	pkg.allow with input as inp
}

test_empty_plan_gate_allows if {
	pkg.allow with input as {"resource_changes": []}
}

# Decisions 2026-10-19: the message names the CIDR actually exposed.
test_tf002_message_names_ipv6_cidr if {
	inp := sg([{"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]}])
	ms := port22_msgs(inp)
	count(ms) == 1
	every m in ms {
		contains(m, "to ::/0")
		not contains(m, "0.0.0.0/0")
	}
}

test_tf002_message_names_ipv4_cidr if {
	inp := sgr({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]})
	every m in port22_msgs(inp) {
		endswith(m, "to 0.0.0.0/0")
	}
	count(port22_msgs(inp)) == 1
}
