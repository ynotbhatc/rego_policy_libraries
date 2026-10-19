package digital_sovereignty.software_sovereignty_fixes_test

import rego.v1

ss := data.digital_sovereignty.software_sovereignty

has_control(vs, c) if {
	some v in vs
	v.control == c
}

# Report must exist (and show the failing control) when an update-control rule fails.
test_report_defined_when_vendor_updates_uncontrolled if {
	inp := {"approved_jurisdictions": ["DE"], "update_mechanisms": [{"software_id": "sw1", "update_type": "vendor_pushed"}]}
	r := ss.report with input as inp
	r.compliant == false
	r.controls["SS-005_no_uncontrolled_updates"] == false
	has_control(r.violations, "SS-005")
}

test_report_defined_when_provenance_fails if {
	inp := {"approved_jurisdictions": ["DE"], "software_components": [{"component_id": "c1", "name": "n", "component_type": "os", "vendor_country": "US"}]}
	r := ss.report with input as inp
	r.controls["SS-004_provenance_acceptable"] == false
	has_control(r.violations, "SS-004")
}

test_report_defined_when_telemetry_fails if {
	inp := {"approved_jurisdictions": ["DE"], "software_components": [{"component_id": "c1", "name": "n", "vendor_country": "US", "telemetry_to_vendor": true}]}
	r := ss.report with input as inp
	r.controls["SS-006_telemetry_controlled"] == false
	has_control(r.violations, "SS-006")
}

test_report_defined_when_repo_not_in_jurisdiction if {
	inp := {"approved_jurisdictions": ["DE"], "code_repositories": [{"repo_id": "r1", "location_country": "US", "hosting_provider_jurisdiction": "US"}]}
	r := ss.report with input as inp
	r.controls["SS-010_repos_in_jurisdiction"] == false
}

test_violation_without_names_still_reported if {
	inp := {"approved_jurisdictions": ["DE"], "software_components": [{"component_type": "os"}]}
	has_control(ss.violations, "SS-004") with input as inp
}

# compliant must never be false with an empty violation set.
test_unpinned_dependencies_have_violation if {
	inp := {"dependency_management": {"dependency_pinning_enforced": false}}
	not ss.dependencies_pinned with input as inp
	has_control(ss.violations, "SS-015") with input as inp
}

test_forced_update_without_mitigation_has_violation if {
	inp := {"software_components": [{"component_id": "c1", "forced_update_mechanism": true}]}
	has_control(ss.violations, "SS-013") with input as inp
}

test_untrusted_update_source_has_violation if {
	inp := {"update_mechanisms": [{"software_id": "s", "update_type": "automatic", "update_source_in_jurisdiction": false}]}
	has_control(ss.violations, "SS-012") with input as inp
}

test_repo_without_access_controls_has_violation if {
	inp := {"code_repositories": [{"repo_id": "r1"}]}
	has_control(ss.violations, "SS-016") with input as inp
}

test_integrity_not_verified_has_violation if has_control(ss.violations, "SS-014") with input as {}

test_transitive_deps_missing_has_violation if has_control(ss.violations, "SS-011") with input as {}

explained(_, true, _)

explained(key, false, violations) if has_control(violations, substring(key, 0, 6))

test_every_failed_control_has_a_violation_on_empty_input if {
	r := ss.report with input as {}
	not r.compliant
	every k, passed in r.controls {
		explained(k, passed, r.violations)
	}
}

# decisions 2026-10-19: auditable critical software and OSS license review gate compliant.
test_unauditable_critical_software_violates_ss017 if {
	inp := {"software_components": [{"component_id": "c1", "component_type": "os", "vendor_country": "DE"}]}
	not ss.critical_software_auditable with input as inp
	has_control(ss.violations, "SS-017") with input as inp
	r := ss.report with input as inp
	r.controls["SS-017_critical_software_auditable"] == false
	r.compliant == false
}

test_auditable_critical_software_ok if {
	inp := {"software_components": [{"component_id": "c1", "component_type": "os", "source_available": true}]}
	ss.critical_software_auditable with input as inp
}

test_unreviewed_oss_license_violates_ss018 if {
	inp := {"software_components": [{"component_id": "c1", "license_type": "open_source", "license_reviewed": false}]}
	not ss.open_source_license_reviewed with input as inp
	has_control(ss.violations, "SS-018") with input as inp
}

test_reviewed_oss_license_ok if {
	ss.open_source_license_reviewed with input as {"software_components": [{"component_id": "c1", "license_type": "open_source", "license_reviewed": true}]}
}
