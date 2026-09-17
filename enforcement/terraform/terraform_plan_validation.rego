# Terraform plan enforcement — pre-apply gate against a Terraform plan.
#
# Evaluated against `terraform show -json tfplan.bin` output.
# OPA endpoint: POST /v1/data/enforcement/terraform/plan/compliance_report
#
# Input shape (subset of Terraform plan JSON):
#   input.resource_changes[].address        — "aws_instance.web"
#   input.resource_changes[].type           — "aws_instance"
#   input.resource_changes[].change.actions — ["create"] | ["update"] | ["delete"] | ["no-op"]
#   input.resource_changes[].change.after   — proposed new state (config, tags)
#
# This is the broad pre-apply ruleset (misconfiguration classes that Checkov /
# tfsec / KICS cover). It is vendor-neutral library content: it makes a decision
# from the plan JSON and emits both string violations (auditor-readable) and
# structured findings (id / severity / resource), plus an allow gate.
package enforcement.terraform.plan

import rego.v1

# ── configuration data (override via data.enforcement.terraform.plan.config) ──
required_tags := {"Environment", "Owner", "CostCenter"}

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379, 27017}

approved_regions := {"us-east-1", "us-east-2", "us-west-2", "eu-west-1"}

# ── helpers ───────────────────────────────────────────────────────────────────
# Every managed resource whose change is not a pure delete/no-op, with its
# proposed post-apply state.
_changes contains c if {
	some c in input.resource_changes
	actions := object.get(c.change, "actions", [])
	not actions == ["delete"]
	not actions == ["no-op"]
}

_after(c) := object.get(c.change, "after", {})

# ── findings (structured) ─────────────────────────────────────────────────────
# AAC-TF-001 — S3 bucket must declare server-side encryption.
findings contains f if {
	some c in _changes
	c.type == "aws_s3_bucket"
	after := _after(c)
	not after.server_side_encryption_configuration
	f := _finding("AAC-TF-001", "high", c.address, sprintf("S3 bucket %q has no server_side_encryption_configuration", [c.address]))
}

# AAC-TF-002 — S3 bucket must not be public via a canned ACL.
findings contains f if {
	some c in _changes
	c.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
	acl := object.get(_after(c), "acl", "")
	acl in {"public-read", "public-read-write", "authenticated-read"}
	f := _finding("AAC-TF-002", "critical", c.address, sprintf("S3 %q uses a public/authenticated ACL %q", [c.address, acl]))
}

# AAC-TF-003 — EBS volumes must be encrypted.
findings contains f if {
	some c in _changes
	c.type == "aws_ebs_volume"
	object.get(_after(c), "encrypted", false) == false
	f := _finding("AAC-TF-003", "high", c.address, sprintf("EBS volume %q is not encrypted", [c.address]))
}

# AAC-TF-004 — RDS storage must be encrypted.
findings contains f if {
	some c in _changes
	c.type == "aws_db_instance"
	object.get(_after(c), "storage_encrypted", false) == false
	f := _finding("AAC-TF-004", "high", c.address, sprintf("RDS instance %q has storage_encrypted=false", [c.address]))
}

# AAC-TF-005 — RDS must not be publicly accessible.
findings contains f if {
	some c in _changes
	c.type == "aws_db_instance"
	object.get(_after(c), "publicly_accessible", false) == true
	f := _finding("AAC-TF-005", "critical", c.address, sprintf("RDS instance %q is publicly_accessible", [c.address]))
}

# AAC-TF-006 — no 0.0.0.0/0 ingress to a sensitive port (inline SG rules).
findings contains f if {
	some c in _changes
	c.type == "aws_security_group"
	some rule in object.get(_after(c), "ingress", [])
	"0.0.0.0/0" in object.get(rule, "cidr_blocks", [])
	some port in sensitive_ports
	rule.from_port <= port
	rule.to_port >= port
	f := _finding("AAC-TF-006", "critical", c.address, sprintf("Security group %q exposes port %v to 0.0.0.0/0", [c.address, port]))
}

# AAC-TF-006 — same, for standalone aws_security_group_rule.
findings contains f if {
	some c in _changes
	c.type == "aws_security_group_rule"
	after := _after(c)
	object.get(after, "type", "") == "ingress"
	"0.0.0.0/0" in object.get(after, "cidr_blocks", [])
	some port in sensitive_ports
	after.from_port <= port
	after.to_port >= port
	f := _finding("AAC-TF-006", "critical", c.address, sprintf("Security group rule %q exposes port %v to 0.0.0.0/0", [c.address, port]))
}

# AAC-TF-007 — EC2 instances must require IMDSv2 (http_tokens = "required").
findings contains f if {
	some c in _changes
	c.type == "aws_instance"
	opts := object.get(_after(c), "metadata_options", [])
	not _imdsv2_required(opts)
	f := _finding("AAC-TF-007", "medium", c.address, sprintf("EC2 instance %q does not require IMDSv2 (http_tokens != \"required\")", [c.address]))
}

# AAC-TF-008 — no auto-assigned public IPs on instances.
findings contains f if {
	some c in _changes
	c.type == "aws_instance"
	object.get(_after(c), "associate_public_ip_address", false) == true
	f := _finding("AAC-TF-008", "medium", c.address, sprintf("EC2 instance %q auto-assigns a public IP", [c.address]))
}

# AAC-TF-009 — IAM policies must not grant Action:* on Resource:*.
findings contains f if {
	some c in _changes
	c.type in {"aws_iam_policy", "aws_iam_role_policy"}
	doc := _policy_doc(_after(c))
	some stmt in object.get(doc, "Statement", [])
	object.get(stmt, "Effect", "") == "Allow"
	_wildcard(object.get(stmt, "Action", []))
	_wildcard(object.get(stmt, "Resource", []))
	f := _finding("AAC-TF-009", "critical", c.address, sprintf("IAM policy %q allows Action:* on Resource:*", [c.address]))
}

# AAC-TF-010 — required tags present on taggable resources.
findings contains f if {
	some c in _changes
	tags := object.get(_after(c), "tags", {})
	is_object(tags)
	some t in required_tags
	not tags[t]
	f := _finding("AAC-TF-010", "low", c.address, sprintf("Resource %q (%v) is missing required tag %q", [c.address, c.type, t]))
}

# AAC-TF-011 — resources must stay within approved regions.
findings contains f if {
	some c in _changes
	region := object.get(_after(c), "region", "")
	region != ""
	not region in approved_regions
	f := _finding("AAC-TF-011", "medium", c.address, sprintf("Resource %q uses unapproved region %q", [c.address, region]))
}

# ── helper rules ──────────────────────────────────────────────────────────────
_finding(id, sev, addr, msg) := {
	"control_id": id,
	"severity": sev,
	"resource": addr,
	"description": sprintf("%s: %s", [id, msg]),
}

_imdsv2_required(opts) if {
	some o in opts
	object.get(o, "http_tokens", "") == "required"
}

# IAM policy documents arrive either as a JSON string or already decoded.
_policy_doc(after) := doc if {
	raw := object.get(after, "policy", "")
	is_string(raw)
	raw != ""
	doc := json.unmarshal(raw)
}

_policy_doc(after) := doc if {
	doc := object.get(after, "policy", {})
	is_object(doc)
}

_wildcard(v) if v == "*"

_wildcard(v) if {
	is_array(v)
	"*" in v
}

# ── report + gate ─────────────────────────────────────────────────────────────
violation contains msg if {
	some f in findings
	msg := f.description
}

default compliant := false

compliant if count(violation) == 0

default allow := false

allow if count(findings) == 0

compliance_report := {
	"policy": "Terraform Plan Enforcement",
	"section": "enforcement.terraform.plan",
	"controls_evaluated": 11,
	"allow": allow,
	"compliant": compliant,
	"violation_count": count(violation),
	"violations": [v | some v in violation],
	"findings": [f | some f in findings],
}
