package digital_sovereignty.data_residency

import rego.v1

# Digital Sovereignty — Data Residency
# Ensures regulated data physically resides within approved jurisdictions,
# backups and DR remain in-country, and cross-border transfers are controlled.
#
# Input schema:
#   input.approved_jurisdictions[]        — ISO 3166-1 alpha-2 country codes
#   input.approved_cloud_regions[]        — e.g. ["eu-west-1", "eu-central-1"]
#   input.cloud_resources[]               — storage, databases, object buckets
#     .resource_id, .resource_type
#     .provider, .region, .country
#     .data_classification                — public | internal | sensitive | restricted | sovereign
#     .stores_regulated_data              — bool
#   input.backup_configurations[]
#     .resource_id, .backup_region, .backup_country
#     .offsite_country
#   input.dr_configurations[]
#     .resource_id, .dr_region, .dr_country
#   input.data_flows[]
#     .flow_id, .source_country, .destination_country
#     .data_classification, .transfer_mechanism_documented
#   input.metadata_storage
#     .location_country, .in_approved_jurisdiction
#   input.telemetry_and_logs
#     .location_country, .in_approved_jurisdiction
#     .vendor_access_to_logs             — bool

# =============================================================================
# DATA RESIDENCY — PRIMARY STORAGE
# =============================================================================

# All resources storing regulated or sensitive data must be in approved regions
regulated_data_in_approved_regions if {
	violations := [r |
		r := input.cloud_resources[_]
		r.stores_regulated_data == true
		not r.region in input.approved_cloud_regions
	]
	count(violations) == 0
}

# All resources storing regulated data must be in approved jurisdictions
regulated_data_in_approved_jurisdictions if {
	violations := [r |
		r := input.cloud_resources[_]
		r.stores_regulated_data == true
		not r.country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# Sovereign/restricted data must not be placed in public cloud at all
sovereign_data_not_in_public_cloud if {
	violations := [r |
		r := input.cloud_resources[_]
		r.data_classification in ["sovereign", "restricted"]
		r.infrastructure_type == "public_cloud"
	]
	count(violations) == 0
}

# =============================================================================
# DATA RESIDENCY — BACKUPS
# =============================================================================

# Backups of regulated data must stay in approved jurisdictions
backups_in_approved_jurisdictions if {
	violations := [b |
		b := input.backup_configurations[_]
		resource := input.cloud_resources[_]
		resource.resource_id == b.resource_id
		resource.stores_regulated_data == true
		not b.backup_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# Offsite backups must also remain in approved jurisdictions
offsite_backups_in_jurisdiction if {
	violations := [b |
		b := input.backup_configurations[_]
		resource := input.cloud_resources[_]
		resource.resource_id == b.resource_id
		resource.stores_regulated_data == true
		b.offsite_country
		not b.offsite_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# =============================================================================
# DATA RESIDENCY — DISASTER RECOVERY
# =============================================================================

# DR replicas of regulated data must stay in approved jurisdictions
dr_in_approved_jurisdictions if {
	violations := [dr |
		dr := input.dr_configurations[_]
		resource := input.cloud_resources[_]
		resource.resource_id == dr.resource_id
		resource.stores_regulated_data == true
		not dr.dr_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# =============================================================================
# DATA RESIDENCY — METADATA AND TELEMETRY
# =============================================================================

# Metadata (indexes, manifests, tags) must stay in jurisdiction
metadata_in_jurisdiction if {
	input.metadata_storage.in_approved_jurisdiction == true
	input.metadata_storage.location_country in input.approved_jurisdictions
}

# Logs and telemetry must stay in jurisdiction
telemetry_in_jurisdiction if {
	input.telemetry_and_logs.in_approved_jurisdiction == true
	input.telemetry_and_logs.location_country in input.approved_jurisdictions
}

# Vendor must not have access to logs containing regulated data
no_vendor_log_access if {
	input.telemetry_and_logs.vendor_access_to_logs == false
}

# =============================================================================
# CROSS-BORDER DATA TRANSFERS
# =============================================================================

# All cross-border transfers must have a documented legal mechanism
cross_border_transfers_controlled if {
	violations := [f |
		f := input.data_flows[_]
		f.source_country != f.destination_country
		f.data_classification in ["sensitive", "restricted", "sovereign"]
		not f.transfer_mechanism_documented == true
	]
	count(violations) == 0
}

# No regulated data flows to non-approved countries
no_regulated_data_to_unapproved_countries if {
	violations := [f |
		f := input.data_flows[_]
		f.data_classification in ["sensitive", "restricted", "sovereign"]
		not f.destination_country in input.approved_jurisdictions
	]
	count(violations) == 0
}

# Data flows are inventoried
data_flow_inventory_maintained if {
	input.data_flow_inventory.maintained == true
	input.data_flow_inventory.last_review_date
	review_ns := time.parse_rfc3339_ns(input.data_flow_inventory.last_review_date)
	age_days := (time.now_ns() - review_ns) / (24 * 60 * 60 * 1000000000)
	age_days <= 365
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not regulated_data_in_approved_regions
	r := input.cloud_resources[_]
	r.stores_regulated_data == true
	not r.region in input.approved_cloud_regions
	v := {
		"domain": "data_residency",
		"control": "DR-001",
		"severity": "critical",
		"resource_id": r.resource_id,
		"description": concat("", ["Regulated data stored in unapproved region: ", r.region, " (", r.country, ")"]),
		"remediation": "Migrate resource to an approved cloud region within the approved jurisdiction",
	}
}

violations contains v if {
	not sovereign_data_not_in_public_cloud
	r := input.cloud_resources[_]
	r.data_classification in ["sovereign", "restricted"]
	r.infrastructure_type == "public_cloud"
	v := {
		"domain": "data_residency",
		"control": "DR-002",
		"severity": "critical",
		"resource_id": r.resource_id,
		"description": concat("", ["Sovereign/restricted data stored in public cloud: ", r.resource_id]),
		"remediation": "Move sovereign/restricted data to on-premises or sovereign cloud infrastructure",
	}
}

violations contains v if {
	not backups_in_approved_jurisdictions
	v := {
		"domain": "data_residency",
		"control": "DR-003",
		"severity": "critical",
		"description": "One or more backups of regulated data reside outside approved jurisdictions",
		"remediation": "Reconfigure backup destinations to approved jurisdictions only",
	}
}

violations contains v if {
	not dr_in_approved_jurisdictions
	v := {
		"domain": "data_residency",
		"control": "DR-004",
		"severity": "critical",
		"description": "One or more DR replicas of regulated data reside outside approved jurisdictions",
		"remediation": "Reconfigure DR replication targets to approved jurisdictions only",
	}
}

violations contains v if {
	not metadata_in_jurisdiction
	v := {
		"domain": "data_residency",
		"control": "DR-005",
		"severity": "high",
		"description": concat("", ["Metadata stored outside approved jurisdiction: ", input.metadata_storage.location_country]),
		"remediation": "Move metadata storage (indexes, manifests, tags) to approved jurisdiction",
	}
}

violations contains v if {
	not telemetry_in_jurisdiction
	v := {
		"domain": "data_residency",
		"control": "DR-006",
		"severity": "high",
		"description": concat("", ["Telemetry/logs stored outside approved jurisdiction: ", input.telemetry_and_logs.location_country]),
		"remediation": "Configure log forwarding to store logs within approved jurisdiction",
	}
}

violations contains v if {
	not no_vendor_log_access
	v := {
		"domain": "data_residency",
		"control": "DR-007",
		"severity": "high",
		"description": "Cloud/software vendor has access to logs that may contain regulated data",
		"remediation": "Disable vendor log access or implement log scrubbing before vendor access",
	}
}

violations contains v if {
	not cross_border_transfers_controlled
	f := input.data_flows[_]
	f.source_country != f.destination_country
	f.data_classification in ["sensitive", "restricted", "sovereign"]
	not f.transfer_mechanism_documented == true
	v := {
		"domain": "data_residency",
		"control": "DR-008",
		"severity": "high",
		"flow_id": f.flow_id,
		"description": concat("", ["Cross-border data transfer without documented legal mechanism: ", f.source_country, " → ", f.destination_country]),
		"remediation": "Document legal transfer mechanism (SCCs, adequacy decision, BCRs) for this data flow",
	}
}

violations contains v if {
	not no_regulated_data_to_unapproved_countries
	f := input.data_flows[_]
	f.data_classification in ["sensitive", "restricted", "sovereign"]
	not f.destination_country in input.approved_jurisdictions
	v := {
		"domain": "data_residency",
		"control": "DR-009",
		"severity": "critical",
		"flow_id": f.flow_id,
		"description": concat("", ["Regulated data flowing to unapproved country: ", f.destination_country]),
		"remediation": "Block or reroute data flow to prevent transfer to unapproved jurisdiction",
	}
}

violations contains v if {
	not data_flow_inventory_maintained
	v := {
		"domain": "data_residency",
		"control": "DR-010",
		"severity": "medium",
		"description": "Data flow inventory not maintained or not reviewed within 12 months",
		"remediation": "Maintain and annually review a complete inventory of all regulated data flows",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	regulated_data_in_approved_regions
	regulated_data_in_approved_jurisdictions
	sovereign_data_not_in_public_cloud
	backups_in_approved_jurisdictions
	offsite_backups_in_jurisdiction
	dr_in_approved_jurisdictions
	metadata_in_jurisdiction
	telemetry_in_jurisdiction
	no_vendor_log_access
	cross_border_transfers_controlled
	no_regulated_data_to_unapproved_countries
	data_flow_inventory_maintained
}

report := {
	"domain": "Data Residency",
	"compliant": compliant,
	"controls": {
		"DR-001_regulated_data_in_approved_regions": regulated_data_in_approved_regions,
		"DR-002_sovereign_data_not_in_public_cloud": sovereign_data_not_in_public_cloud,
		"DR-003_backups_in_jurisdiction": backups_in_approved_jurisdictions,
		"DR-004_dr_in_jurisdiction": dr_in_approved_jurisdictions,
		"DR-005_metadata_in_jurisdiction": metadata_in_jurisdiction,
		"DR-006_telemetry_in_jurisdiction": telemetry_in_jurisdiction,
		"DR-007_no_vendor_log_access": no_vendor_log_access,
		"DR-008_cross_border_transfers_controlled": cross_border_transfers_controlled,
		"DR-009_no_regulated_data_to_unapproved": no_regulated_data_to_unapproved_countries,
		"DR-010_data_flow_inventory": data_flow_inventory_maintained,
	},
	"resource_summary": {
		"total_resources": count(input.cloud_resources),
		"regulated_resources": count([r | r := input.cloud_resources[_]; r.stores_regulated_data == true]),
		"in_approved_regions": count([r | r := input.cloud_resources[_]; r.stores_regulated_data == true; r.region in input.approved_cloud_regions]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
