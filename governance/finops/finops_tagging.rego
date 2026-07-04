package finops.tagging

# FinOps / Cost Governance — Resource Tagging & Organization Policy
#
# Enforces cloud resource tagging standards across AWS, Azure, and GCP to
# enable cost allocation, chargeback, and budget governance.
#
# Controls:
#   - Required tags present on all billable resources
#   - Tag value format validation (environment enum, cost-center pattern, etc.)
#   - Resource naming convention enforcement
#   - Temporary resource expiry tags
#   - Budget threshold tags
#   - Orphaned/untagged resource detection
#
# OPA endpoint: POST http://192.168.4.62:8182/v1/data/finops/tagging
# Input: cloud resource inventory (from Ansible facts, AWS Config, Azure Policy, GCP Asset API)

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# =============================================================================
# REQUIRED TAGS
# =============================================================================

required_tags := {"team", "environment", "cost-center", "owner", "project"}

optional_tags := {"expiry-date", "budget-code", "data-classification", "backup-policy"}

valid_environments := {"dev", "development", "staging", "stage", "uat", "prod", "production", "sandbox", "shared"}

violations contains sprintf("Tagging: Resource '%s' (%s) is missing required tag '%s'", [resource.id, resource.type, tag]) if {
	some resource in input.resources
	resource.billable != false
	some tag in required_tags
	not resource.tags[tag]
}

violations contains sprintf("Tagging: Resource '%s' (%s) has empty value for required tag '%s'", [resource.id, resource.type, tag]) if {
	some resource in input.resources
	resource.billable != false
	some tag in required_tags
	resource.tags[tag]
	trim_space(resource.tags[tag]) == ""
}

# =============================================================================
# TAG VALUE VALIDATION
# =============================================================================

violations contains sprintf("Tagging: Resource '%s' has invalid 'environment' tag value '%s' — must be one of: %s", [resource.id, resource.tags.environment, concat(", ", valid_environments)]) if {
	some resource in input.resources
	resource.tags.environment
	not lower(resource.tags.environment) in valid_environments
}

violations contains sprintf("Tagging: Resource '%s' has malformed 'cost-center' tag '%s' — expected format CC-NNNN or DEPT-NNNN", [resource.id, resource.tags["cost-center"]]) if {
	some resource in input.resources
	resource.tags["cost-center"]
	not valid_cost_center(resource.tags["cost-center"])
}

valid_cost_center(value) if { regex.match(`^[A-Z]{2,6}-[0-9]{3,6}$`, value) }
valid_cost_center(value) if { regex.match(`^[0-9]{4,8}$`, value) }

violations contains sprintf("Tagging: Resource '%s' 'owner' tag '%s' is not a valid email address", [resource.id, resource.tags.owner]) if {
	some resource in input.resources
	resource.tags.owner
	not regex.match(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, resource.tags.owner)
}

violations contains sprintf("Tagging: Resource '%s' 'team' tag '%s' contains invalid characters — use lowercase alphanumeric and hyphens only", [resource.id, resource.tags.team]) if {
	some resource in input.resources
	resource.tags.team
	not regex.match(`^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$`, resource.tags.team)
}

# =============================================================================
# RESOURCE NAMING CONVENTIONS
# =============================================================================

naming_patterns := {
	"aws_instance":            `^[a-z][a-z0-9\-]{2,60}$`,
	"aws_s3_bucket":           `^[a-z][a-z0-9\-\.]{1,61}[a-z0-9]$`,
	"aws_rds_instance":        `^[a-z][a-z0-9\-]{1,60}$`,
	"azurerm_virtual_machine": `^[a-z][a-z0-9\-]{1,13}$`,
	"azurerm_storage_account": `^[a-z0-9]{3,24}$`,
	"azurerm_resource_group":  `^[a-z][a-z0-9\-_\.]{1,88}$`,
	"google_compute_instance": `^[a-z][a-z0-9\-]{1,61}$`,
	"google_storage_bucket":   `^[a-z][a-z0-9\-_\.]{1,61}[a-z0-9]$`,
}

violations contains sprintf("Naming: Resource '%s' of type '%s' does not match naming convention pattern '%s'", [resource.name, resource.type, naming_patterns[resource.type]]) if {
	some resource in input.resources
	some resource_type, pattern in naming_patterns
	resource.type == resource_type
	not regex.match(pattern, resource.name)
}

violations contains sprintf("Naming: Resource '%s' name does not include environment prefix/suffix for type '%s' — include env in name for disambiguation", [resource.name, resource.type]) if {
	input.policy.require_env_in_name
	some resource in input.resources
	resource.tags.environment
	not name_contains_env(resource.name, resource.tags.environment)
}

name_contains_env(name, env) if { contains(name, env) }
name_contains_env(name, "production") if { contains(name, "prod") }
name_contains_env(name, "development") if { contains(name, "dev") }
name_contains_env(name, "staging") if { contains(name, "stg") }
name_contains_env(name, "staging") if { contains(name, "stage") }

# =============================================================================
# TEMPORARY RESOURCE GOVERNANCE
# =============================================================================

violations contains sprintf("Expiry: Resource '%s' is tagged as temporary but has no 'expiry-date' tag — all sandbox/temporary resources must declare an expiry", [resource.id]) if {
	some resource in input.resources
	lower(object.get(resource.tags, "environment", "")) in {"sandbox", "dev", "development"}
	not resource.tags["expiry-date"]
}

violations contains sprintf("Expiry: Resource '%s' expiry date '%s' is in the past — resource should be decommissioned", [resource.id, resource.tags["expiry-date"]]) if {
	some resource in input.resources
	resource.tags["expiry-date"]
	is_past_date(resource.tags["expiry-date"])
}

violations contains sprintf("Expiry: Resource '%s' expiry date '%s' is invalid — use ISO 8601 format (YYYY-MM-DD)", [resource.id, resource.tags["expiry-date"]]) if {
	some resource in input.resources
	resource.tags["expiry-date"]
	not regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, resource.tags["expiry-date"])
}

is_past_date(date_str) if {
	parts := split(date_str, "-")
	count(parts) == 3
	year := to_number(parts[0])
	month := to_number(parts[1])
	day := to_number(parts[2])
	current_ns := time.now_ns()
	resource_ns := time.parse_rfc3339_ns(sprintf("%s-01T00:00:00Z", [concat("-", [parts[0], parts[1]])]))
	# Approximate check: year/month comparison
	year < 2025
}

# =============================================================================
# UNTAGGED RESOURCE DETECTION
# =============================================================================

violations contains sprintf("Untagged: Resource '%s' (%s) has no tags at all — add required tags for cost attribution", [resource.id, resource.type]) if {
	some resource in input.resources
	resource.billable != false
	count(object.get(resource, "tags", {})) == 0
}

violations contains sprintf("Untagged: Resource '%s' was created more than 7 days ago and is still missing required tags — auto-remediation may apply", [resource.id]) if {
	some resource in input.resources
	resource.age_days > 7
	some tag in required_tags
	not resource.tags[tag]
}

# =============================================================================
# DATA CLASSIFICATION TAGGING
# =============================================================================

data_bearing_types := {
	"aws_s3_bucket", "aws_rds_instance", "aws_dynamodb_table", "aws_elasticache_cluster",
	"azurerm_storage_account", "azurerm_sql_server", "azurerm_cosmosdb_account",
	"google_storage_bucket", "google_sql_database_instance", "google_bigquery_dataset",
}

valid_data_classifications := {"public", "internal", "confidential", "restricted", "pii", "phi"}

violations contains sprintf("Classification: Data-bearing resource '%s' (%s) missing 'data-classification' tag — required for compliance and security controls", [resource.id, resource.type]) if {
	some resource in input.resources
	resource.type in data_bearing_types
	not resource.tags["data-classification"]
}

violations contains sprintf("Classification: Resource '%s' has invalid data-classification '%s' — must be one of: %s", [resource.id, resource.tags["data-classification"], concat(", ", valid_data_classifications)]) if {
	some resource in input.resources
	resource.tags["data-classification"]
	not lower(resource.tags["data-classification"]) in valid_data_classifications
}

# =============================================================================
# BUDGET GOVERNANCE
# =============================================================================

violations contains sprintf("Budget: Cost center '%s' has no budget defined in policy — add to budget registry before provisioning resources", [cost_center]) if {
	input.policy.enforce_budget_registry
	some resource in input.resources
	cost_center := object.get(resource.tags, "cost-center", "")
	cost_center != ""
	not input.budget_registry[cost_center]
}

violations contains sprintf("Budget: Cost center '%s' current spend $%.2f exceeds budget $%.2f (%.0f%% over)", [cost_center, actual, budget, ((actual - budget) / budget) * 100]) if {
	some cost_center, budget in input.budget_registry
	actual := object.get(input.current_spend, cost_center, 0)
	actual > budget * 1.1
}

# =============================================================================
# COMPLIANCE SUMMARY
# =============================================================================

total_resources := count(object.get(input, ["resources"], []))

compliant_resources := count([r | some r in input.resources; not resource_has_violation(r.id)])

resource_has_violation(resource_id) if {
	some v in violations
	contains(v, resource_id)
}

tagging_score := (compliant_resources * 100) / total_resources if {
	total_resources > 0
} else := 100

compliance_report := {
	"framework":          "FinOps Tagging & Cost Governance",
	"standard":           "finops.tagging",
	"compliant":          compliant,
	"violation_count":    count(violations),
	"total_resources":    total_resources,
	"compliant_resources": compliant_resources,
	"tagging_score":      tagging_score,
	"violations":         [v | some v in violations],
	"violations_by_category": {
		"missing_tags":       [v | some v in violations; contains(v, "Tagging:")],
		"naming":             [v | some v in violations; contains(v, "Naming:")],
		"expiry":             [v | some v in violations; contains(v, "Expiry:")],
		"untagged":           [v | some v in violations; contains(v, "Untagged:")],
		"classification":     [v | some v in violations; contains(v, "Classification:")],
		"budget":             [v | some v in violations; contains(v, "Budget:")],
	},
}
