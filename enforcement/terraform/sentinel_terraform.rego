# METADATA
# title: "Sentinel-equivalent policy for Terraform plans"
# custom:
#   class: enforcement
#   framework: enforcement_terraform
#   source: aac
#   domains: [iac, terraform]
#   coverage:
#     checks: 4
#     cited: 3
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sentinel.terraform

import rego.v1

# Sentinel-equivalent policy for Terraform plans
# Evaluated against `terraform show -json tfplan.bin` output
# OPA endpoint: POST http://localhost:8181/v1/data/sentinel/terraform/result
#
# Input shape (subset of Terraform plan JSON):
#   input.resource_changes[].address        — "aws_instance.web"
#   input.resource_changes[].type           — "aws_instance"
#   input.resource_changes[].change.actions — ["create"] | ["update"] | ["delete"]
#   input.resource_changes[].change.after   — proposed new state (tags, config)

#
# A document that is not a readable plan is denied, never waved through (SENTINEL-TF-000): the gate
# judges resource_changes, so that list must be there and every entry must have the plan's shape.
# A plan with no changes omits the list; it is accepted only as a plan document (format_version set).

# =============================================================================
# PLAN SHAPE (SENTINEL-TF-000)
# =============================================================================

_changes := object.get(input, "resource_changes", null)

violations contains "SENTINEL-TF-000: Malformed plan: input.resource_changes is missing and the document is not a Terraform plan (no format_version); nothing was evaluated" if {
	not _changes_stated
	not is_string(object.get(input, "format_version", null))
}

violations contains "SENTINEL-TF-000: Malformed plan: input.resource_changes is null; a plan lists its changes or omits the key" if {
	_changes_stated
	_changes == null
}

_changes_stated if "resource_changes" in object.keys(input)

violations contains msg if {
	_changes != null
	not is_array(_changes)
	msg := sprintf("SENTINEL-TF-000: Malformed plan: input.resource_changes must be a list, got %v", [type_name(_changes)])
}

violations contains msg if {
	is_array(_changes)
	some i, change in _changes
	problem := _change_problem(change)
	msg := sprintf("SENTINEL-TF-000: Malformed plan: resource_changes[%d] %v", [i, problem])
}

_change_problem(change) := "is not an object" if not is_object(change)

_change_problem(change) := "has no address" if {
	is_object(change)
	not is_string(object.get(change, "address", null))
}

_change_problem(change) := "has no type" if {
	is_object(change)
	not is_string(object.get(change, "type", null))
}

_change_problem(change) := "has no change.actions list" if {
	is_object(change)
	not _actions_ok(change)
}

# every action other than a pure delete or no-op / read carries the proposed state in change.after
_change_problem(change) := "has no change.after object" if {
	is_object(change)
	_actions_ok(change)
	some action in change.change.actions
	action in {"create", "update"}
	not is_object(object.get(change.change, "after", null))
}

_actions_ok(change) if {
	actions := object.get(change, ["change", "actions"], null)
	is_array(actions)
	count(actions) > 0
	every a in actions {
		is_string(a)
	}
}

# =============================================================================
# REQUIRED TAGS
# =============================================================================

required_tags := {"Environment", "Owner", "CostCenter"}

# A tag is present only when it exists and is not null (a null value is as good as missing)
tag_present(change, tag) if {
	tags := object.get(change.change.after, "tags", {})
	tags[tag] != null
}

violations contains msg if {
	some change in input.resource_changes
	change.change.actions != ["delete"] # tags don't matter for deletions
	some required_tag in required_tags
	not tag_present(change, required_tag)
	msg := sprintf(
		"SENTINEL-TF-001: Resource '%v' (%v) is missing required tag '%v'",
		[change.address, change.type, required_tag],
	)
}

# =============================================================================
# NO PUBLIC INGRESS ON SENSITIVE PORTS
# =============================================================================

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379, 27017}

# Open to the whole internet over IPv4 or IPv6
open_to_world(rule) if rule.cidr_blocks[_] == "0.0.0.0/0"

open_to_world(rule) if rule.ipv6_cidr_blocks[_] == "::/0"

# A CIDR field that is set but is not a list cannot be read: the rule is treated as open.
open_to_world(rule) if {
	some field in ["cidr_blocks", "ipv6_cidr_blocks"]
	value := object.get(rule, field, null)
	value != null
	not is_array(value)
}

# Which world-open CIDR(s) the rule exposes, for the finding message.
world_cidrs(rule) := concat(" and ", [c | some c in ["0.0.0.0/0", "::/0"]; world_cidr_present(rule, c)]) if {
	some c in ["0.0.0.0/0", "::/0"]
	world_cidr_present(rule, c)
} else := "an unreadable CIDR list"

world_cidr_present(rule, "0.0.0.0/0") if rule.cidr_blocks[_] == "0.0.0.0/0"

world_cidr_present(rule, "::/0") if rule.ipv6_cidr_blocks[_] == "::/0"

# Does the rule cover `port`? Protocol "-1"/"all" covers every port (from_port/to_port are 0
# for it); tcp/udp use the range; other protocols (icmp...) have no ports. A rule without a
# protocol is judged by its range.
covers_port(rule, _) if lower(sprintf("%v", [object.get(rule, "protocol", "")])) in {"-1", "all"}

covers_port(rule, port) if {
	lower(sprintf("%v", [object.get(rule, "protocol", "")])) in {"", "tcp", "6", "udp", "17"}
	is_number(rule.from_port)
	is_number(rule.to_port)
	rule.from_port <= port
	rule.to_port >= port
}

# A tcp/udp rule whose range is missing or not numeric cannot be bounded: it is read as covering the port.
covers_port(rule, _) if {
	lower(sprintf("%v", [object.get(rule, "protocol", "")])) in {"", "tcp", "6", "udp", "17"}
	not _range_numeric(rule)
}

_range_numeric(rule) if {
	is_number(rule.from_port)
	is_number(rule.to_port)
}

# aws_security_group inline ingress rules
violations contains msg if {
	some change in input.resource_changes
	change.change.actions != ["delete"]
	change.type == "aws_security_group"
	some rule in object.get(change.change.after, "ingress", [])
	open_to_world(rule)
	some port in sensitive_ports
	covers_port(rule, port)
	msg := sprintf(
		"SENTINEL-TF-002: Security group '%v' exposes sensitive port %v to %v",
		[change.address, port, world_cidrs(rule)],
	)
}

# A port bound in a plan is a number. One sent as a string is a malformed plan wherever the rule points.
violations contains msg if {
	some change in input.resource_changes
	change.change.actions != ["delete"]
	some rule in _ingress_rules(change)
	some field in ["from_port", "to_port"]
	value := object.get(rule, field, null)
	value != null
	not is_number(value)
	msg := sprintf("SENTINEL-TF-000: Malformed plan: '%v' ingress %v must be a number, got %v", [change.address, field, type_name(value)])
}

_ingress_rules(change) := rules if {
	change.type == "aws_security_group"
	rules := object.get(change.change.after, "ingress", [])
	is_array(rules)
}

_ingress_rules(change) := [change.change.after] if change.type == "aws_security_group_rule"

# aws_security_group_rule resources
violations contains msg if {
	some change in input.resource_changes
	change.change.actions != ["delete"]
	change.type == "aws_security_group_rule"
	object.get(change.change.after, "type", "") == "ingress"
	open_to_world(change.change.after)
	some port in sensitive_ports
	covers_port(change.change.after, port)
	msg := sprintf(
		"SENTINEL-TF-002: Security group rule '%v' exposes sensitive port %v to %v",
		[change.address, port, world_cidrs(change.change.after)],
	)
}

# =============================================================================
# APPROVED REGIONS ONLY
# =============================================================================

approved_regions := {"us-east-1", "us-east-2", "us-west-2", "eu-west-1"}

violations contains msg if {
	some change in input.resource_changes
	change.change.actions != ["delete"]
	region := object.get(change.change.after, "region", "")
	region != ""
	not approved_regions[region]
	msg := sprintf(
		"SENTINEL-TF-003: Resource '%v' uses unapproved region '%v' (allowed: %v)",
		[change.address, region, concat(", ", approved_regions)],
	)
}

# =============================================================================
# ALLOW / RESULT
# =============================================================================

default allow := false

allow if {
	count(violations) == 0
}

result := {
	"policy": "Sentinel — Terraform Plan",
	"allow": allow,
	"violation_count": count(violations),
	"violations": [v | some v in violations],
	"required_tags": [t | some t in required_tags],
}
