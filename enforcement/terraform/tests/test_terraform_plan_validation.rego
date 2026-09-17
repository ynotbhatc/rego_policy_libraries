package enforcement.terraform.plan_test

import rego.v1

import data.enforcement.terraform.plan

# Helper: wrap a single resource_change into a plan input.
_plan(rc) := {"resource_changes": rc}

_ids(findings) := {f.control_id | some f in findings}

# ── AAC-TF-001 S3 encryption ─────────────────────────────────────────
test_s3_missing_encryption_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_s3_bucket.data", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-001" in _ids(f)
}

test_s3_with_encryption_passes if {
	f := plan.findings with input as _plan([{
		"address": "aws_s3_bucket.data", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {
			"server_side_encryption_configuration": {"rule": {}},
			"tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"},
		}},
	}])
	not "AAC-TF-001" in _ids(f)
}

# ── AAC-TF-002 public ACL ────────────────────────────────────────────
test_public_acl_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_s3_bucket.pub", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"acl": "public-read", "server_side_encryption_configuration": {}, "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-002" in _ids(f)
}

# ── AAC-TF-005 RDS public ────────────────────────────────────────────
test_rds_public_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_db_instance.db", "type": "aws_db_instance",
		"change": {"actions": ["create"], "after": {"publicly_accessible": true, "storage_encrypted": true, "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	ids := _ids(f)
	"AAC-TF-005" in ids
	not "AAC-TF-004" in ids # encryption on
}

# ── AAC-TF-006 open ingress on sensitive port ────────────────────────
test_sg_open_ssh_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_security_group.web", "type": "aws_security_group",
		"change": {"actions": ["create"], "after": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}], "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-006" in _ids(f)
}

test_sg_scoped_ingress_passes if {
	f := plan.findings with input as _plan([{
		"address": "aws_security_group.web", "type": "aws_security_group",
		"change": {"actions": ["create"], "after": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}], "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	not "AAC-TF-006" in _ids(f)
}

# ── AAC-TF-007 IMDSv2 ────────────────────────────────────────────────
test_imdsv2_not_required_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_instance.web", "type": "aws_instance",
		"change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "optional"}], "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-007" in _ids(f)
}

test_imdsv2_required_passes if {
	f := plan.findings with input as _plan([{
		"address": "aws_instance.web", "type": "aws_instance",
		"change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "required"}], "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	not "AAC-TF-007" in _ids(f)
}

# ── AAC-TF-009 IAM wildcard (policy as JSON string) ──────────────────
test_iam_wildcard_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_iam_policy.admin", "type": "aws_iam_policy",
		"change": {"actions": ["create"], "after": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}", "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-009" in _ids(f)
}

# ── AAC-TF-010 required tags ─────────────────────────────────────────
test_missing_tags_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_instance.web", "type": "aws_instance",
		"change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "required"}], "tags": {"Environment": "p"}}},
	}])
	"AAC-TF-010" in _ids(f)
}

# ── AAC-TF-011 region ────────────────────────────────────────────────
test_unapproved_region_flags if {
	f := plan.findings with input as _plan([{
		"address": "aws_instance.web", "type": "aws_instance",
		"change": {"actions": ["create"], "after": {"region": "ap-south-1", "metadata_options": [{"http_tokens": "required"}], "tags": {"Environment": "p", "Owner": "o", "CostCenter": "c"}}},
	}])
	"AAC-TF-011" in _ids(f)
}

# ── deletions and no-ops are ignored ─────────────────────────────────
test_delete_is_ignored if {
	f := plan.findings with input as _plan([{
		"address": "aws_s3_bucket.gone", "type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null},
	}])
	count(f) == 0
}

# ── gate: a clean plan allows ────────────────────────────────────────
test_clean_plan_allows if {
	clean := _plan([{
		"address": "aws_s3_bucket.ok", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {
			"server_side_encryption_configuration": {"rule": {}},
			"tags": {"Environment": "prod", "Owner": "team", "CostCenter": "cc1"},
		}},
	}])
	plan.allow with input as clean
	plan.compliant with input as clean
	report := plan.compliance_report with input as clean
	report.violation_count == 0
}

test_dirty_plan_denies if {
	dirty := _plan([{
		"address": "aws_s3_bucket.bad", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"acl": "public-read"}},
	}])
	not plan.allow with input as dirty
	report := plan.compliance_report with input as dirty
	report.violation_count > 0
	count(report.findings) > 0
}
