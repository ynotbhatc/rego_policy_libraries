# METADATA
# title: "Digital Sovereignty — Data Residency"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 21
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
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

# NOTE (undefined trap): `not x.field in list` is compiled with the field
# reference hoisted outside the negation, so an ABSENT field makes the whole
# body undefined and the offender is silently skipped. Fields are read with
# object.get() (absent -> "", never an approved value), and the approved lists
# default to [] when missing (fail closed).
approved := object.get(input, "approved_jurisdictions", [])

approved_regions := object.get(input, "approved_cloud_regions", [])

resources := object.get(input, "cloud_resources", [])

backups := object.get(input, "backup_configurations", [])

dr_configs := object.get(input, "dr_configurations", [])

flows := object.get(input, "data_flows", [])

regulated_classes := {"sensitive", "restricted", "sovereign"}

# All resources storing regulated or sensitive data must be in approved regions
region_offenders contains r if {
	some r in resources
	r.stores_regulated_data == true
	not object.get(r, "region", "") in approved_regions
}

default regulated_data_in_approved_regions := false

regulated_data_in_approved_regions if count(region_offenders) == 0

# All resources storing regulated data must be in approved jurisdictions
country_offenders contains r if {
	some r in resources
	r.stores_regulated_data == true
	not object.get(r, "country", "") in approved
}

default regulated_data_in_approved_jurisdictions := false

regulated_data_in_approved_jurisdictions if count(country_offenders) == 0

# Sovereign/restricted data must not be placed in public cloud at all
public_cloud_offenders contains r if {
	some r in resources
	r.data_classification in ["sovereign", "restricted"]
	r.infrastructure_type == "public_cloud"
}

default sovereign_data_not_in_public_cloud := false

sovereign_data_not_in_public_cloud if count(public_cloud_offenders) == 0

# =============================================================================
# DATA RESIDENCY — BACKUPS
# =============================================================================

# A backup/DR entry is in scope when it belongs to a regulated resource OR when
# its resource_id matches no known resource at all (orphan or mistyped id): an
# entry that cannot be tied to a resource is not assumed to be harmless.
known_resource_ids := {r.resource_id | some r in resources; r.resource_id}

regulated_target(entry) if {
	some r in resources
	r.resource_id == entry.resource_id
	r.stores_regulated_data == true
}

regulated_target(entry) if {
	not object.get(entry, "resource_id", null) in known_resource_ids
}

# Backups of regulated data must stay in approved jurisdictions
backup_offenders contains b if {
	some b in backups
	regulated_target(b)
	not object.get(b, "backup_country", "") in approved
}

default backups_in_approved_jurisdictions := false

backups_in_approved_jurisdictions if count(backup_offenders) == 0

# Offsite backups must also remain in approved jurisdictions (offsite_country is
# optional: only a recorded offsite country is checked)
offsite_offenders contains b if {
	some b in backups
	regulated_target(b)
	b.offsite_country
	not b.offsite_country in approved
}

default offsite_backups_in_jurisdiction := false

offsite_backups_in_jurisdiction if count(offsite_offenders) == 0

# =============================================================================
# DATA RESIDENCY — DISASTER RECOVERY
# =============================================================================

# DR replicas of regulated data must stay in approved jurisdictions
dr_offenders contains dr if {
	some dr in dr_configs
	regulated_target(dr)
	not object.get(dr, "dr_country", "") in approved
}

default dr_in_approved_jurisdictions := false

dr_in_approved_jurisdictions if count(dr_offenders) == 0

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

# All cross-border transfers must have a documented legal mechanism. A flow
# with an unrecorded source or destination is not assumed to be domestic.
transfer_offenders contains f if {
	some f in flows
	object.get(f, "source_country", "unknown source") != object.get(f, "destination_country", "unknown destination")
	f.data_classification in regulated_classes
	not f.transfer_mechanism_documented == true
}

default cross_border_transfers_controlled := false

cross_border_transfers_controlled if count(transfer_offenders) == 0

# No regulated data flows to non-approved countries
unapproved_flow_offenders contains f if {
	some f in flows
	f.data_classification in regulated_classes
	not object.get(f, "destination_country", "") in approved
}

default no_regulated_data_to_unapproved_countries := false

no_regulated_data_to_unapproved_countries if count(unapproved_flow_offenders) == 0

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
	some r in region_offenders
	v := {
		"domain": "data_residency",
		"control": "DR-001",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Regulated data stored in unapproved region (or region not recorded): ", object.get(r, "region", "unknown"), " (", object.get(r, "country", "unknown"), ")"]),
		"remediation": "Migrate resource to an approved cloud region within the approved jurisdiction",
	}
}

violations contains v if {
	some r in country_offenders
	v := {
		"domain": "data_residency",
		"control": "DR-011",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Regulated data stored in unapproved jurisdiction (or country not recorded): ", object.get(r, "country", "unknown")]),
		"remediation": "Migrate resource to an approved jurisdiction",
	}
}

violations contains v if {
	count(offsite_offenders) > 0
	v := {
		"domain": "data_residency",
		"control": "DR-012",
		"severity": "critical",
		"description": "One or more offsite backups of regulated data reside outside approved jurisdictions",
		"remediation": "Reconfigure offsite backup destinations to approved jurisdictions only",
	}
}

violations contains v if {
	some r in public_cloud_offenders
	v := {
		"domain": "data_residency",
		"control": "DR-002",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Sovereign/restricted data stored in public cloud: ", object.get(r, "resource_id", "unknown")]),
		"remediation": "Move sovereign/restricted data to on-premises or sovereign cloud infrastructure",
	}
}

violations contains v if {
	count(backup_offenders) > 0
	v := {
		"domain": "data_residency",
		"control": "DR-003",
		"severity": "critical",
		"description": "One or more backups of regulated data reside outside approved jurisdictions",
		"remediation": "Reconfigure backup destinations to approved jurisdictions only",
	}
}

violations contains v if {
	count(dr_offenders) > 0
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
		"description": concat("", ["Metadata stored outside approved jurisdiction (or location not recorded): ", object.get(object.get(input, "metadata_storage", {}), "location_country", "unknown")]),
		"remediation": "Move metadata storage (indexes, manifests, tags) to approved jurisdiction",
	}
}

violations contains v if {
	not telemetry_in_jurisdiction
	v := {
		"domain": "data_residency",
		"control": "DR-006",
		"severity": "high",
		"description": concat("", ["Telemetry/logs stored outside approved jurisdiction (or location not recorded): ", object.get(object.get(input, "telemetry_and_logs", {}), "location_country", "unknown")]),
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
	some f in transfer_offenders
	v := {
		"domain": "data_residency",
		"control": "DR-008",
		"severity": "high",
		"flow_id": object.get(f, "flow_id", "unknown"),
		"description": concat("", ["Cross-border data transfer without documented legal mechanism: ", object.get(f, "source_country", "unknown"), " → ", object.get(f, "destination_country", "unknown")]),
		"remediation": "Document legal transfer mechanism (SCCs, adequacy decision, BCRs) for this data flow",
	}
}

violations contains v if {
	some f in unapproved_flow_offenders
	v := {
		"domain": "data_residency",
		"control": "DR-009",
		"severity": "critical",
		"flow_id": object.get(f, "flow_id", "unknown"),
		"description": concat("", ["Regulated data flowing to unapproved country: ", object.get(f, "destination_country", "unknown")]),
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
		"DR-011_regulated_data_in_approved_jurisdictions": regulated_data_in_approved_jurisdictions,
		"DR-012_offsite_backups_in_jurisdiction": offsite_backups_in_jurisdiction,
	},
	"resource_summary": {
		"total_resources": count(object.get(input, ["cloud_resources"], [])),
		"regulated_resources": count([r | r := input.cloud_resources[_]; r.stores_regulated_data == true]),
		"in_approved_regions": count([r | r := input.cloud_resources[_]; r.stores_regulated_data == true; r.region in input.approved_cloud_regions]),
	},
	"violations": violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default data_flow_inventory_maintained := false
default metadata_in_jurisdiction := false
default no_vendor_log_access := false
default telemetry_in_jurisdiction := false
