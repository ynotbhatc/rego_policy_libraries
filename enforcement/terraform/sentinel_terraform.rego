package sentinel.terraform

import rego.v1

# Sentinel-equivalent policy for Terraform plans
# Evaluated against `terraform show -json tfplan.bin` output
# OPA endpoint: POST http://192.168.4.62:8182/v1/data/sentinel/terraform/result
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

violations contains msg if {
    some change in input.resource_changes
    change.change.actions != ["delete"]           # tags don't matter for deletions
    some required_tag in required_tags
    tags := object.get(change.change.after, "tags", {})
    not tags[required_tag]
    msg := sprintf(
        "SENTINEL-TF-001: Resource '%v' (%v) is missing required tag '%v'",
        [change.address, change.type, required_tag]
    )
}

# =============================================================================
# NO PUBLIC INGRESS ON SENSITIVE PORTS
# =============================================================================

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379, 27017}

# aws_security_group inline ingress rules
violations contains msg if {
    some change in input.resource_changes
    change.change.actions != ["delete"]
    change.type == "aws_security_group"
    some rule in object.get(change.change.after, "ingress", [])
    rule.cidr_blocks[_] == "0.0.0.0/0"
    some port in sensitive_ports
    rule.from_port <= port
    rule.to_port >= port
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
    change.change.after.cidr_blocks[_] == "0.0.0.0/0"
    some port in sensitive_ports
    change.change.after.from_port <= port
    change.change.after.to_port >= port
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
