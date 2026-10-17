package digital_sovereignty.data_residency_fixes_test

import rego.v1

dr := data.digital_sovereignty.data_residency

good := {
	"approved_jurisdictions": ["DE"],
	"approved_cloud_regions": ["eu-central-1"],
	"cloud_resources": [{"resource_id": "r1", "stores_regulated_data": true, "region": "eu-central-1", "country": "DE"}],
	"backup_configurations": [{"resource_id": "r1", "backup_country": "DE"}],
	"dr_configurations": [{"resource_id": "r1", "dr_country": "DE"}],
	"data_flows": [],
	"metadata_storage": {"in_approved_jurisdiction": true, "location_country": "DE"},
	"telemetry_and_logs": {"in_approved_jurisdiction": true, "location_country": "DE", "vendor_access_to_logs": false},
	"data_flow_inventory": {"maintained": true, "last_review_date": "2100-01-01T00:00:00Z"},
}

with_res(r) := object.union(good, {"cloud_resources": [r]})

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_baseline_compliant if dr.compliant with input as good

test_regulated_resource_without_region_violates_dr001 if {
	inp := with_res({"resource_id": "r1", "stores_regulated_data": true, "country": "DE"})
	not dr.regulated_data_in_approved_regions with input as inp
	has_control(dr.violations, "DR-001") with input as inp
}

test_regulated_resource_without_country_violates_dr011 if {
	inp := with_res({"resource_id": "r1", "stores_regulated_data": true, "region": "eu-central-1"})
	not dr.regulated_data_in_approved_jurisdictions with input as inp
	has_control(dr.violations, "DR-011") with input as inp
	not dr.compliant with input as inp
}

test_foreign_country_has_violation_entry if {
	inp := with_res({"resource_id": "r1", "stores_regulated_data": true, "region": "eu-central-1", "country": "US"})
	has_control(dr.violations, "DR-011") with input as inp
}

test_offsite_backup_outside_jurisdiction_has_violation if {
	inp := object.union(good, {"backup_configurations": [{"resource_id": "r1", "backup_country": "DE", "offsite_country": "US"}]})
	not dr.offsite_backups_in_jurisdiction with input as inp
	has_control(dr.violations, "DR-012") with input as inp
}

test_offsite_backup_in_jurisdiction_ok if {
	inp := object.union(good, {"backup_configurations": [{"resource_id": "r1", "backup_country": "DE", "offsite_country": "DE"}]})
	dr.offsite_backups_in_jurisdiction with input as inp
}

test_orphan_backup_is_checked if {
	inp := object.union(good, {"backup_configurations": [{"resource_id": "typo-r1", "backup_country": "US"}]})
	not dr.backups_in_approved_jurisdictions with input as inp
	has_control(dr.violations, "DR-003") with input as inp
}

test_orphan_backup_in_jurisdiction_ok if {
	inp := object.union(good, {"backup_configurations": [{"resource_id": "typo-r1", "backup_country": "DE"}]})
	dr.backups_in_approved_jurisdictions with input as inp
}

test_unregulated_resource_backup_abroad_not_flagged if {
	inp := object.union(with_res({"resource_id": "r9", "stores_regulated_data": false}), {"backup_configurations": [{"resource_id": "r9", "backup_country": "US"}]})
	dr.backups_in_approved_jurisdictions with input as inp
}

test_orphan_dr_is_checked if {
	inp := object.union(good, {"dr_configurations": [{"resource_id": "typo-r1", "dr_country": "US"}]})
	not dr.dr_in_approved_jurisdictions with input as inp
}

test_backup_without_country_violates if {
	inp := object.union(good, {"backup_configurations": [{"resource_id": "r1"}]})
	not dr.backups_in_approved_jurisdictions with input as inp
}

test_metadata_without_country_still_reports_dr005 if {
	inp := json.remove(good, ["/metadata_storage/location_country"])
	has_control(dr.violations, "DR-005") with input as inp
}

test_telemetry_without_country_still_reports_dr006 if {
	inp := json.remove(good, ["/telemetry_and_logs/location_country"])
	has_control(dr.violations, "DR-006") with input as inp
}

test_flow_without_destination_violates if {
	inp := object.union(good, {"data_flows": [{"flow_id": "f1", "data_classification": "sensitive", "source_country": "DE"}]})
	not dr.no_regulated_data_to_unapproved_countries with input as inp
	has_control(dr.violations, "DR-009") with input as inp
	has_control(dr.violations, "DR-008") with input as inp
}

# Undefined-in-literal trap: report exists while controls fail.
test_report_defined_with_failing_controls if {
	r := dr.report with input as with_res({"resource_id": "r1", "stores_regulated_data": true, "region": "us-east-1", "country": "US"})
	r.compliant == false
	r.controls["DR-001_regulated_data_in_approved_regions"] == false
	r.controls["DR-011_regulated_data_in_approved_jurisdictions"] == false
}
