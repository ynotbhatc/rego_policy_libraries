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
#     as_of: v2.4.1
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
    change.change.actions != ["delete"]           # tags don't matter for deletions
    some required_tag in required_tags
    not tag_present(change, required_tag)
    msg := sprintf(
        "SENTINEL-TF-001: Resource '%v' (%v) is missing required tag '%v'",
        [change.address, change.type, required_tag]
    )
}

# =============================================================================
# NO PUBLIC INGRESS ON SENSITIVE PORTS
# =============================================================================

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379, 27017}

# Open to the whole internet over IPv4 or IPv6
open_to_world(rule) if rule.cidr_blocks[_] == "0.0.0.0/0"

open_to_world(rule) if rule.ipv6_cidr_blocks[_] == "::/0"

# Does the rule cover `port`? Protocol "-1"/"all" covers every port (from_port/to_port are 0
# for it); tcp/udp use the range; other protocols (icmp...) have no ports. A rule without a
# protocol is judged by its range.
covers_port(rule, _) if lower(sprintf("%v", [object.get(rule, "protocol", "")])) in {"-1", "all"}

covers_port(rule, port) if {
    lower(sprintf("%v", [object.get(rule, "protocol", "")])) in {"", "tcp", "6", "udp", "17"}
    rule.from_port <= port
    rule.to_port >= port
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
        "SENTINEL-TF-002: Security group '%v' exposes sensitive port %v to 0.0.0.0/0",
        [change.address, port]
    )
}

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
        "SENTINEL-TF-002: Security group rule '%v' exposes sensitive port %v to 0.0.0.0/0",
        [change.address, port]
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
        [change.address, region, concat(", ", approved_regions)]
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
    "policy":          "Sentinel — Terraform Plan",
    "allow":           allow,
    "violation_count": count(violations),
    "violations":      [v | some v in violations],
    "required_tags":   [t | some t in required_tags],
}
