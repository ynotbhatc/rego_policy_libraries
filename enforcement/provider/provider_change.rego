# Provider change gate — the OPA decision behind the aac.tfprovider `resource` module.
#
# Input: one planned-diff document (aac-tfprovider docs/CONTRACTS.md §4): one planned change
# to one resource, as the Terraform provider planned it. The module has already replaced every
# value at `sensitive_paths` with "__SENSITIVE__"; this policy never compares such a value
# with an expectation and never echoes it in a reason.
#
#   {
#     "kind": "provider_change", "version": 1,
#     "environment": "lab", "address": "aws_s3_bucket.evidence", "resource_type": "aws_s3_bucket",
#     "provider": {"source": "registry.terraform.io/hashicorp/aws", "version": "6.70.0", "protocol": 6},
#     "action": "create" | "update" | "replace" | "delete" | "no-op",
#     "requires_replace": [...], "prior_state": {...} | null, "planned_state": {...} | null,
#     "config": {...}, "changes": [{"path", "before", "after", "unknown"}],
#     "unknown_paths": [...], "sensitive_paths": [...], "tainted": false,
#     "options": {...}, "context": {...}
#   }
#
# Query: POST /v1/data/provider_change/main  ->  result.decision
#   {"allow": bool, "reasons": [string], "policy_version": "1.0.0", "evaluated_rules": int}
#
# Fail closed: `allow` defaults to false and is true only when `deny` is empty; a document
# without kind, version, action or resource_type is denied with a PC-000 reason. Every deny
# rule contributes a human-readable reason that names the rule, the resource and the finding.

# METADATA
# title: "Provider change gate — allow or deny one planned Terraform-provider resource change"
# custom:
#   class: enforcement
#   framework: enforcement_provider
#   source: aac
#   domains: [iac, terraform, cloud, aws, azure, gcp]
#   coverage:
#     checks: 21
#     cited: 7
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: n/a
#     as_of: v2.4.2
package provider_change.main

import rego.v1

policy_version := "1.0.0"

supported_versions := {1}

valid_actions := {"create", "update", "replace", "delete", "no-op"}

# The marker the resource module writes in place of a sensitive value (§4).
sensitive_marker := "__SENSITIVE__"

# Actions that write a configuration the provider will apply.
write_actions := {"create", "update", "replace"}

# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

default allow := false

allow if count(deny) == 0

reasons := sort([r | some r in deny])

decision := {
	"allow": allow,
	"reasons": reasons,
	"policy_version": policy_version,
	"evaluated_rules": evaluated_rules,
}

# The library-wide report shape, so the compliance repository's framework-map validator and
# the generic assessment can read this package like any other. `decision` is the contract.
compliance_report := {
	"framework": "provider_change",
	"policy_version": policy_version,
	"compliant": allow,
	"violations": reasons,
	"violation_count": count(deny),
	"evaluated_rules": evaluated_rules,
	"decision": decision,
}

# ---------------------------------------------------------------------------
# Rule catalog — one row per rule. `resource_types` and `actions` are sets, or "*" for any.
# evaluated_rules is the number of rows whose scope matches the document; PC-000 always counts.
# ---------------------------------------------------------------------------

rule_catalog := {
	"PC-000": {"title": "Document is a well-formed provider_change v1", "resource_types": "*", "actions": "*"},
	"PC-001": {"title": "No public S3 bucket ACL", "resource_types": {"aws_s3_bucket", "aws_s3_bucket_acl"}, "actions": write_actions},
	"PC-002": {"title": "S3 public access block keeps all four protections on", "resource_types": {"aws_s3_bucket_public_access_block"}, "actions": write_actions},
	"PC-003": {"title": "No ingress from the whole internet", "resource_types": ingress_resource_types, "actions": write_actions},
	"PC-004": {"title": "A protected resource is not replaced or deleted", "resource_types": "*", "actions": {"replace", "delete"}},
	"PC-005": {"title": "Taggable resources carry owner and environment", "resource_types": taggable_resource_types, "actions": write_actions},
	"PC-006": {"title": "No IAM user console access", "resource_types": {"aws_iam_user_login_profile", "aws_iam_user"}, "actions": {"create"}},
}

applicable_rules contains "PC-000"

applicable_rules contains id if {
	some id in object.keys(rule_catalog)
	id != "PC-000"
	rule := rule_catalog[id]
	_in_scope(rule.resource_types, object.get(input, "resource_type", null))
	_in_scope(rule.actions, object.get(input, "action", null))
}

evaluated_rules := count(applicable_rules)

_in_scope(scope, _) if scope == "*"

_in_scope(scope, value) if {
	is_set(scope)
	value in scope
}

# ---------------------------------------------------------------------------
# PC-000 — well-formed input. Missing or wrong kind, version, action or resource_type is a deny.
# ---------------------------------------------------------------------------

default well_formed := false

well_formed if {
	_kind_ok
	_version_ok
	_action_ok
	_resource_type_ok
}

_kind_ok if input.kind == "provider_change"

_version_ok if input.version in supported_versions

_action_ok if input.action in valid_actions

_resource_type_ok if {
	is_string(input.resource_type)
	input.resource_type != ""
}

# METADATA
# scope: rule
# title: "PC-000: kind must be provider_change"
# custom:
#   resource_types: ["*"]
deny contains reason if {
	not _kind_ok
	reason := "PC-000: malformed input — kind must be \"provider_change\""
}

# METADATA
# scope: rule
# title: "PC-000: version must be a supported document version"
# custom:
#   resource_types: ["*"]
deny contains reason if {
	not _version_ok
	reason := sprintf("PC-000: malformed input — version must be one of %v", [[v | some v in supported_versions]])
}

# METADATA
# scope: rule
# title: "PC-000: action must be one of the five planned actions"
# custom:
#   resource_types: ["*"]
deny contains reason if {
	not _action_ok
	reason := "PC-000: malformed input — action must be one of create, update, replace, delete, no-op"
}

# METADATA
# scope: rule
# title: "PC-000: resource_type must be a non-empty string"
# custom:
#   resource_types: ["*"]
deny contains reason if {
	not _resource_type_ok
	reason := "PC-000: malformed input — resource_type must be a non-empty string"
}

# ---------------------------------------------------------------------------
# Views of the document
# ---------------------------------------------------------------------------

_address := a if {
	a := input.address
	is_string(a)
} else := "<no address>"

_type := t if {
	t := input.resource_type
	is_string(t)
} else := "<no resource_type>"

_prior := s if {
	s := input.prior_state
	is_object(s)
} else := {}

_planned := s if {
	s := input.planned_state
	is_object(s)
} else := {}

_config := s if {
	s := input.config
	is_object(s)
} else := {}

# What the provider will apply: the planned state where it is known, the config otherwise.
# A null planned value is unknown-until-apply (§4), so the config value stands in for it.
_effective := object.union(_config, {k: v |
	some k
	v := _planned[k]
	v != null
})

# A known, non-null effective attribute. Undefined when absent or unknown.
_attr(name) := v if {
	v := _effective[name]
	v != null
}

# Nested blocks arrive as arrays of objects; a single block may arrive as one object.
_blocks(v) := v if {
	is_array(v)
} else := [v] if {
	is_object(v)
} else := []

# A string-or-list attribute as a list of strings.
_strings(v) := [v] if {
	is_string(v)
} else := [s | some s in v; is_string(s)] if {
	is_array(v)
} else := []

_obj(v) := v if {
	is_object(v)
} else := {}

# tags (AWS, Azure), tags_all (AWS, computed) and labels (GCP) merged into one map.
_tags_of(state) := object.union(
	object.union(_obj(object.get(state, "tags", {})), _obj(object.get(state, "tags_all", {}))),
	_obj(object.get(state, "labels", {})),
)

_visible(v) if v != sensitive_marker

# ---------------------------------------------------------------------------
# PC-001 — public S3 bucket ACL
# ---------------------------------------------------------------------------

public_acls := {"public-read", "public-read-write", "authenticated-read"}

public_grantee_uris := {
	"http://acs.amazonaws.com/groups/global/AllUsers",
	"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

# METADATA
# scope: rule
# title: "PC-001: No public S3 bucket ACL (canned ACL)"
# custom:
#   resource_types: [aws_s3_bucket, aws_s3_bucket_acl]
deny contains reason if {
	"PC-001" in applicable_rules
	acl := _attr("acl")
	acl in public_acls
	reason := sprintf("PC-001: %s %s grants public access through its ACL (acl=%s)", [_type, _address, acl])
}

# METADATA
# scope: rule
# title: "PC-001: No public S3 bucket ACL (grant to AllUsers or AuthenticatedUsers)"
# custom:
#   resource_types: [aws_s3_bucket, aws_s3_bucket_acl]
deny contains reason if {
	"PC-001" in applicable_rules
	some policy in _blocks(_attr("access_control_policy"))
	some grant in _blocks(object.get(policy, "grant", []))
	some grantee in _blocks(object.get(grant, "grantee", []))
	uri := object.get(grantee, "uri", "")
	uri in public_grantee_uris
	reason := sprintf("PC-001: %s %s grants public access through an ACL grant to %s", [_type, _address, uri])
}

# ---------------------------------------------------------------------------
# PC-002 — S3 public access block: every protection must be on
# ---------------------------------------------------------------------------

public_access_block_flags := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

_flag_on(flag) if _attr(flag) == true

# METADATA
# scope: rule
# title: "PC-002: S3 public access block keeps all four protections on"
# custom:
#   resource_types: [aws_s3_bucket_public_access_block]
deny contains reason if {
	"PC-002" in applicable_rules
	some flag in public_access_block_flags
	not _flag_on(flag)
	reason := sprintf("PC-002: %s %s leaves public access protection off (%s is false or not set)", [_type, _address, flag])
}

# ---------------------------------------------------------------------------
# PC-003 — ingress from the whole internet
# ---------------------------------------------------------------------------

world_cidrs := {"0.0.0.0/0", "::/0"}

# Azure service tags and prefixes that mean "anywhere" (compared lower-cased).
azure_internet_sources := {"*", "internet", "0.0.0.0/0", "::/0"}

ingress_resource_types := {
	"aws_security_group",
	"aws_security_group_rule",
	"aws_vpc_security_group_ingress_rule",
	"azurerm_network_security_rule",
	"google_compute_firewall",
}

# World-open CIDRs in an AWS rule block (inline ingress or aws_security_group_rule).
_open_cidrs(block) := {c |
	some c in array.concat(
		_strings(object.get(block, "cidr_blocks", [])),
		_strings(object.get(block, "ipv6_cidr_blocks", [])),
	)
	c in world_cidrs
}

# METADATA
# scope: rule
# title: "PC-003: No ingress from the whole internet (aws_security_group inline ingress)"
# custom:
#   resource_types: [aws_security_group]
deny contains reason if {
	"PC-003" in applicable_rules
	_type == "aws_security_group"
	some block in _blocks(_attr("ingress"))
	some cidr in _open_cidrs(block)
	reason := sprintf("PC-003: %s %s allows ingress from the whole internet (%s)", [_type, _address, cidr])
}

# METADATA
# scope: rule
# title: "PC-003: No ingress from the whole internet (aws_security_group_rule)"
# custom:
#   resource_types: [aws_security_group_rule]
deny contains reason if {
	"PC-003" in applicable_rules
	_type == "aws_security_group_rule"
	_attr("type") == "ingress"
	some cidr in _open_cidrs(_effective)
	reason := sprintf("PC-003: %s %s allows ingress from the whole internet (%s)", [_type, _address, cidr])
}

# METADATA
# scope: rule
# title: "PC-003: No ingress from the whole internet (aws_vpc_security_group_ingress_rule)"
# custom:
#   resource_types: [aws_vpc_security_group_ingress_rule]
deny contains reason if {
	"PC-003" in applicable_rules
	_type == "aws_vpc_security_group_ingress_rule"
	some field in {"cidr_ipv4", "cidr_ipv6"}
	cidr := _attr(field)
	cidr in world_cidrs
	reason := sprintf("PC-003: %s %s allows ingress from the whole internet (%s)", [_type, _address, cidr])
}

_azure_sources := array.concat(
	_strings(object.get(_effective, "source_address_prefix", [])),
	_strings(object.get(_effective, "source_address_prefixes", [])),
)

# METADATA
# scope: rule
# title: "PC-003: No ingress from the whole internet (azurerm_network_security_rule)"
# custom:
#   resource_types: [azurerm_network_security_rule]
deny contains reason if {
	"PC-003" in applicable_rules
	_type == "azurerm_network_security_rule"
	_attr("direction") == "Inbound"
	_attr("access") == "Allow"
	some source in _azure_sources
	_visible(source)
	lower(source) in azure_internet_sources
	reason := sprintf("PC-003: %s %s allows inbound traffic from the whole internet (source %s)", [_type, _address, source])
}

_gcp_egress if _attr("direction") == "EGRESS"

_gcp_disabled if _attr("disabled") == true

# METADATA
# scope: rule
# title: "PC-003: No ingress from the whole internet (google_compute_firewall)"
# custom:
#   resource_types: [google_compute_firewall]
deny contains reason if {
	"PC-003" in applicable_rules
	_type == "google_compute_firewall"
	not _gcp_egress
	not _gcp_disabled
	count(_blocks(object.get(_effective, "allow", []))) > 0
	some range in _strings(object.get(_effective, "source_ranges", []))
	range in world_cidrs
	reason := sprintf("PC-003: %s %s allows ingress from the whole internet (source range %s)", [_type, _address, range])
}

# ---------------------------------------------------------------------------
# PC-004 — protected resources are never replaced or deleted
# ---------------------------------------------------------------------------

_truthy(v) if v == true

_truthy(v) if {
	is_string(v)
	_visible(v)
	lower(v) == "true"
}

_protected(tags) if {
	some key
	value := tags[key]
	lower(key) == "protected"
	_truthy(value)
}

# METADATA
# scope: rule
# title: "PC-004: A resource tagged protected=true is not replaced or deleted"
# custom:
#   resource_types: ["*"]
deny contains reason if {
	"PC-004" in applicable_rules
	_protected(_tags_of(_prior))
	reason := sprintf("PC-004: %s %s is tagged protected=true and the plan would %s it", [_type, _address, input.action])
}

# ---------------------------------------------------------------------------
# PC-005 — required tags on taggable resources
# ---------------------------------------------------------------------------

required_tags := {"owner", "environment"}

# Resource types whose tags (AWS, Azure) or labels (GCP) the organisation requires. The set is
# data: extend it here, or override it with `with data.provider_change.main.taggable_resource_types`.
taggable_resource_types := {
	# AWS — tags / tags_all
	"aws_instance",
	"aws_launch_template",
	"aws_autoscaling_group",
	"aws_ebs_volume",
	"aws_eip",
	"aws_network_interface",
	"aws_vpc",
	"aws_subnet",
	"aws_route_table",
	"aws_internet_gateway",
	"aws_nat_gateway",
	"aws_security_group",
	"aws_lb",
	"aws_lb_target_group",
	"aws_cloudfront_distribution",
	"aws_apigatewayv2_api",
	"aws_s3_bucket",
	"aws_efs_file_system",
	"aws_backup_vault",
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_dynamodb_table",
	"aws_elasticache_cluster",
	"aws_elasticache_replication_group",
	"aws_sqs_queue",
	"aws_sns_topic",
	"aws_kinesis_stream",
	"aws_lambda_function",
	"aws_ecr_repository",
	"aws_ecs_cluster",
	"aws_ecs_service",
	"aws_eks_cluster",
	"aws_eks_node_group",
	"aws_iam_role",
	"aws_iam_user",
	"aws_iam_policy",
	"aws_kms_key",
	"aws_secretsmanager_secret",
	"aws_cloudwatch_log_group",
	# Azure — tags
	"azurerm_resource_group",
	"azurerm_virtual_network",
	"azurerm_network_security_group",
	"azurerm_public_ip",
	"azurerm_network_interface",
	"azurerm_lb",
	"azurerm_application_gateway",
	"azurerm_linux_virtual_machine",
	"azurerm_windows_virtual_machine",
	"azurerm_linux_virtual_machine_scale_set",
	"azurerm_windows_virtual_machine_scale_set",
	"azurerm_managed_disk",
	"azurerm_storage_account",
	"azurerm_key_vault",
	"azurerm_container_registry",
	"azurerm_kubernetes_cluster",
	"azurerm_postgresql_flexible_server",
	"azurerm_mysql_flexible_server",
	"azurerm_mssql_server",
	"azurerm_mssql_database",
	"azurerm_cosmosdb_account",
	"azurerm_service_plan",
	"azurerm_linux_web_app",
	"azurerm_windows_web_app",
	"azurerm_linux_function_app",
	"azurerm_log_analytics_workspace",
	"azurerm_recovery_services_vault",
	# GCP — labels
	"google_compute_instance",
	"google_compute_instance_template",
	"google_compute_disk",
	"google_compute_image",
	"google_compute_address",
	"google_compute_forwarding_rule",
	"google_storage_bucket",
	"google_container_cluster",
	"google_container_node_pool",
	"google_sql_database_instance",
	"google_pubsub_topic",
	"google_pubsub_subscription",
	"google_bigquery_dataset",
	"google_bigquery_table",
	"google_cloud_run_v2_service",
	"google_cloudfunctions2_function",
	"google_artifact_registry_repository",
	"google_kms_crypto_key",
	"google_secret_manager_secret",
	"google_dataproc_cluster",
	"google_redis_instance",
	"google_project",
}

# A tag counts as present when its key matches (case-insensitively) and its value is not empty.
# A masked value ("__SENSITIVE__") is present: the value exists, it is only not visible here.
_has_tag(tags, name) if {
	some key
	value := tags[key]
	lower(key) == name
	_present(value)
}

_present(v) if v == sensitive_marker

_present(v) if {
	is_string(v)
	v != ""
}

# METADATA
# scope: rule
# title: "PC-005: Taggable resources carry owner and environment"
# custom:
#   resource_types: [see taggable_resource_types]
deny contains reason if {
	"PC-005" in applicable_rules
	some tag in required_tags
	not _has_tag(_tags_of(_effective), tag)
	reason := sprintf("PC-005: %s %s is missing required tag %q (looked in tags, tags_all and labels)", [_type, _address, tag])
}

# ---------------------------------------------------------------------------
# PC-006 — IAM users never get console access
# ---------------------------------------------------------------------------

_empty(v) if v == null

_empty(v) if v == false

_empty(v) if v == ""

_empty(v) if v == []

_empty(v) if v == {}

_login_profile_declared if {
	lp := _effective.login_profile
	not _empty(lp)
}

# METADATA
# scope: rule
# title: "PC-006: No IAM user console access (aws_iam_user_login_profile)"
# custom:
#   resource_types: [aws_iam_user_login_profile]
deny contains reason if {
	"PC-006" in applicable_rules
	_type == "aws_iam_user_login_profile"
	reason := sprintf("PC-006: creating %s %s grants an IAM user console access", [_type, _address])
}

# METADATA
# scope: rule
# title: "PC-006: No IAM user console access (aws_iam_user declaring a login profile)"
# custom:
#   resource_types: [aws_iam_user]
deny contains reason if {
	"PC-006" in applicable_rules
	_type == "aws_iam_user"
	_login_profile_declared
	reason := sprintf("PC-006: creating %s %s with a login profile grants console access", [_type, _address])
}
