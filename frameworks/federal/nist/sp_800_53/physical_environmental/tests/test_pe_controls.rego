package nist.sp800_53.physical_environmental_logic_test

# PE-1 to PE-23 (PE-7 withdrawn), PE-6(1) and PE-13(1): all-pass fixture, empty input, one flip per control id, type traps.

import rego.v1

_att := {"attestation": {"attested": true, "by": "Facility security officer", "date": "2026-11-01"}}

_freq := {"days_since_last": 30, "odp": {"frequency_days": 90}}

_pass := {"pe_controls": {
	"policy": {"documented": true, "official_designated": true, "review": {"days_since_last": 100, "odp": {"frequency_days": 365}}},
	"procedures": {"documented": true, "review": {"days_since_last": 200, "odp": {"frequency_days": 365}}},
	"physical_access_authorizations": {
		"access_list_approved_and_maintained": true,
		"credentials_issued": true,
		"removed_when_no_longer_required": true,
		"access_list_review": _freq,
	},
	"physical_access_control": {
		"authorizations_verified_at_entry": true,
		"ingress_egress_controlled": true,
		"audit_logs_maintained": true,
		"public_areas_controlled": true,
		"visitors_escorted_and_monitored": true,
		"access_devices_secured": true,
		"device_inventory": _freq,
		"key_change": {"days_since_last": 200, "odp": {"frequency_days": 365}},
	},
	"monitoring_physical_access": {
		"access_monitored": true, "results_coordinated_with_incident_response": true, "log_review": {"days_since_last": 5, "odp": {"frequency_days": 7}},
		"intrusion_alarms_and_surveillance": {"intrusion_alarms_monitored": true, "surveillance_monitored": true},
	},
	"visitor_access_records": {"retention_days": 400, "odp": {"retention_days": 365}, "review": _freq, "anomalies_reported": true},
	"emergency_power": {"ups_provided": true, "supports_odp_action": true},
	"environmental_controls": {"levels_within_odp": true, "monitoring": {"days_since_last": 1, "odp": {"frequency_days": 1}}},
	"transmission_access": _att,
	"output_devices": _att,
	"power_equipment": _att,
	"emergency_shutoff": _att,
	"emergency_lighting": _att,
	"fire_protection": object.union(_att, {"detection": {"automatic_activation": true, "notifies_personnel": true, "notifies_emergency_responders": true}}),
	"water_damage_protection": _att,
	"delivery_removal": _att,
	"alternate_work_site": _att,
	"component_location": _att,
	"information_leakage": _att,
	"asset_monitoring": _att,
	"emp_protection": _att,
	"component_marking": _att,
	"facility_location": _att,
}}

# Control ids that have a finding ("NIST PE-10: ..." -> "PE-10"); the colon keeps PE-1 apart from PE-10+.
_failing(r) := {id |
	some v in r.violations
	id := substring(v, 5, indexof(v, ":") - 5)
}

_msg(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as {}
	ids := data.nist.sp800_53.physical_environmental.evaluated_controls with input as {}
	count(r.violations) == count(ids)
	_failing(r) == ids
	r.compliant == false
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.physical_environmental.evaluated_controls == {
		"PE-1", "PE-2", "PE-3", "PE-4", "PE-5", "PE-6", "PE-6(1)", "PE-8", "PE-9", "PE-10", "PE-11", "PE-12",
		"PE-13", "PE-13(1)", "PE-14", "PE-15", "PE-16", "PE-17", "PE-18", "PE-19", "PE-20", "PE-21", "PE-22", "PE-23",
	}
}

test_pe1_official_not_designated if {
	inp := object.union(_pass, {"pe_controls": {"policy": {"official_designated": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-1"}
}

test_pe1_lists_every_unmet_element_in_one_finding if {
	inp := object.union(_pass, {"pe_controls": {"policy": {"documented": false}, "procedures": {"documented": null, "review": {"days_since_last": 400}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-1"}
	f := _msg(r, "PE-1")
	count(f) == 1
	contains(f[0], "policy.documented is false")
	contains(f[0], "evidence missing: input.pe_controls.procedures.documented not collected")
	contains(f[0], "Procedures review last done 400 days ago")
}

test_pe2_access_list_review_overdue if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_authorizations": {"access_list_review": {"days_since_last": 91}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-2"}
	contains(_msg(r, "PE-2")[0], "91 days ago")
}

test_pe2_access_not_removed if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_authorizations": {"removed_when_no_longer_required": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-2"}
}

test_pe3_visitors_not_escorted if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_control": {"visitors_escorted_and_monitored": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-3"}
}

test_pe3_key_change_overdue if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_control": {"key_change": {"days_since_last": 400}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-3"}
	contains(_msg(r, "PE-3")[0], "Change of combinations and keys")
}

test_pe3_inventory_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_control": {"device_inventory": {"days_since_last": "1"}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-3"}
	contains(_msg(r, "PE-3")[0], "evidence missing")
}

test_pe3_inventory_days_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"physical_access_control": {"device_inventory": {"days_since_last": null}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-3"}
	contains(_msg(r, "PE-3")[0], "evidence missing")
}

test_pe6_log_review_overdue if {
	inp := object.union(_pass, {"pe_controls": {"monitoring_physical_access": {"log_review": {"days_since_last": 8}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-6"}
}

test_pe6_boolean_as_string_is_a_finding if {
	inp := object.union(_pass, {"pe_controls": {"monitoring_physical_access": {"access_monitored": "true"}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-6"}
	contains(_msg(r, "PE-6")[0], "evidence missing")
}

test_pe8_retention_shorter_than_odp if {
	inp := object.union(_pass, {"pe_controls": {"visitor_access_records": {"retention_days": 90}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-8"}
	contains(_msg(r, "PE-8")[0], "kept 90 days")
}

test_pe8_retention_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"visitor_access_records": {"retention_days": "1000"}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-8"}
	contains(_msg(r, "PE-8")[0], "evidence missing")
}

test_pe8_odp_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"visitor_access_records": {"odp": {"retention_days": null}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-8"}
	contains(_msg(r, "PE-8")[0], "evidence missing")
}

test_pe8_anomalies_not_reported if {
	inp := object.union(_pass, {"pe_controls": {"visitor_access_records": {"anomalies_reported": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-8"}
}

test_pe11_no_ups if {
	inp := object.union(_pass, {"pe_controls": {"emergency_power": {"ups_provided": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-11"}
}

test_pe14_levels_out_of_range if {
	inp := object.union(_pass, {"pe_controls": {"environmental_controls": {"levels_within_odp": false}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-14"}
}

test_pe14_monitoring_overdue if {
	inp := object.union(_pass, {"pe_controls": {"environmental_controls": {"monitoring": {"days_since_last": 3}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-14"}
}

test_pe4_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"transmission_access": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-4"}
}

test_pe5_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"output_devices": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-5"}
}

test_pe9_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"power_equipment": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-9"}
}

test_pe10_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"emergency_shutoff": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-10"}
}

test_pe12_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"emergency_lighting": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-12"}
}

test_pe13_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"fire_protection": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13"}
}

test_pe15_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"water_damage_protection": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-15"}
}

test_pe16_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"delivery_removal": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-16"}
}

test_pe17_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"alternate_work_site": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-17"}
}

test_pe18_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"component_location": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-18"}
}

test_pe19_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"information_leakage": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-19"}
}

test_pe20_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"asset_monitoring": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-20"}
}

test_pe21_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"emp_protection": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-21"}
}

test_pe22_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"component_marking": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-22"}
}

test_pe23_not_attested if {
	inp := object.union(_pass, {"pe_controls": {"facility_location": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-23"}
}

test_pe13_attested_as_string_is_a_finding if {
	inp := object.union(_pass, {"pe_controls": {"fire_protection": {"attestation": {"attested": "true"}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13"}
}

test_pe23_attestation_without_attester_is_a_finding if {
	inp := object.union(_pass, {"pe_controls": {"facility_location": {"attestation": {"by": ""}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-23"}
}

test_empty_input_every_finding_is_evidence_missing if {
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as {}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_pe13_attestation_false_is_not_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"fire_protection": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13"}
	msg := _msg(r, "PE-13")[0]
	contains(msg, "not attested")
	not contains(msg, "evidence missing")
}

test_pe13_attestation_absent_is_evidence_missing_and_pe13_1_unaffected if {
	inp := json.remove(_pass, ["pe_controls/fire_protection/attestation"])
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13"}
	msg := _msg(r, "PE-13")[0]
	contains(msg, "evidence missing — input.pe_controls.fire_protection.attestation not collected")
	contains(msg, "not attested")
}

test_pe6_1_no_surveillance_flips_only_pe6_1 if {
	inp := object.union(_pass, {"pe_controls": {"monitoring_physical_access": {"intrusion_alarms_and_surveillance": {"surveillance_monitored": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-6(1)"}
	not contains(_msg(r, "PE-6(1)")[0], "evidence missing")
}

test_pe6_1_boolean_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"monitoring_physical_access": {"intrusion_alarms_and_surveillance": {"intrusion_alarms_monitored": "true"}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-6(1)"}
	contains(_msg(r, "PE-6(1)")[0], "evidence missing")
}

test_pe6_base_unaffected_by_pe6_1_facts if {
	inp := json.remove(_pass, ["pe_controls/monitoring_physical_access/intrusion_alarms_and_surveillance"])
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-6(1)"}
}

test_pe13_1_no_responder_notification_flips_only_pe13_1 if {
	inp := object.union(_pass, {"pe_controls": {"fire_protection": {"detection": {"notifies_emergency_responders": false}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13(1)"}
}

test_pe13_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"pe_controls": {"fire_protection": {"detection": {"automatic_activation": null}}}})
	r := data.nist.sp800_53.physical_environmental.compliance_report with input as inp
	_failing(r) == {"PE-13(1)"}
	contains(_msg(r, "PE-13(1)")[0], "evidence missing")
}
