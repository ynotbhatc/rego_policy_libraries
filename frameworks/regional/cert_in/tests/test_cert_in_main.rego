# Tests for cert_in.main — CERT-In Directions of 28 April 2022.
package cert_in.main_test

import rego.v1

import data.cert_in.main

_types := {id: true | some id, _ in main.annexure_i}

_base := {
	"provides_datacentre_vps_cloud_or_vpn": false,
	"is_virtual_asset_service_provider": false,
	"time_sync": {"all_ict_clocks_synchronised": true, "source_is_nic_npl_or_traceable": true},
	"incident_reporting": {
		"reported_within_6_hours_of_noticing": true,
		"reporting_channels_configured": true,
		"procedure_uses_certin_published_format": true,
		"reportable_types": _types,
	},
	"coordination": {
		"acts_on_certin_orders_within_specified_timeframe": true,
		"poc_designated": true,
		"poc_registered_in_annexure_ii_format": true,
		"poc_kept_updated": true,
	},
	"logging": {
		"logs_enabled_on_all_ict_systems": true,
		"logs_retained_180_days_rolling": true,
		"logs_stored_within_indian_jurisdiction": true,
		"logs_provided_with_incident_reports_or_on_order": true,
	},
}

_registration := {
	"fields": {id: true | some id, _ in main._registration_fields},
	"retained_5_years_after_cancellation": true,
}

_vasp := {k: true | some k, _ in main._vasp_checks}

test_annexure_i_has_twenty_types if {
	count(main.annexure_i) == 20
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.direction_v_applies == "undeclared"
	r.annexure_i_covered == 0

	# 2 flags + 2 time + 3 reporting + 20 types + 4 coordination + 4 logging
	r.violation_count == 35
}

test_general_entity_with_full_evidence_is_compliant if {
	main.compliant with input as {"cert_in": _base}
}

test_undeclared_sector_flag_is_a_violation if {
	inp := {"cert_in": object.remove(_base, {"provides_datacentre_vps_cloud_or_vpn"})}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "direction (v)")
}

test_missing_annexure_type_is_one_violation if {
	inp := {"cert_in": json.patch(_base, [{"op": "remove", "path": "/incident_reporting/reportable_types/xi_data_breach"}])}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "Data breach")
}

test_six_hour_reporting_is_checked if {
	inp := {"cert_in": json.patch(_base, [{"op": "replace", "path": "/incident_reporting/reported_within_6_hours_of_noticing", "value": false}])}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "6 hours")
}

test_logs_outside_india_is_a_violation if {
	inp := {"cert_in": json.patch(_base, [{"op": "replace", "path": "/logging/logs_stored_within_indian_jurisdiction", "value": "yes"}])}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "Indian jurisdiction")
}

test_cloud_provider_without_registration_evidence if {
	inp := {"cert_in": object.union(_base, {"provides_datacentre_vps_cloud_or_vpn": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 8
	r.direction_v_applies == true
}

test_cloud_provider_with_registration_is_compliant if {
	inp := {"cert_in": object.union(_base, {"provides_datacentre_vps_cloud_or_vpn": true, "subscriber_registration": _registration})}
	main.compliant with input as inp
}

test_vasp_without_kyc_evidence if {
	inp := {"cert_in": object.union(_base, {"is_virtual_asset_service_provider": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 3
}

test_vasp_with_kyc_is_compliant if {
	inp := {"cert_in": object.union(_base, {"is_virtual_asset_service_provider": true, "virtual_assets": _vasp})}
	main.compliant with input as inp
}

test_report_wellformed_on_empty_input if {
	r := main.compliance_report with input as {}
	is_object(r)
	is_boolean(r.compliant)
	r.effective_date == "2022-06-27"
}
