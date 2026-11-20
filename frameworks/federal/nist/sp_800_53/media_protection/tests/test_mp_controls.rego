package nist.sp800_53.media_protection_logic_test

# MP-1 to MP-8 and MP-6(1) to MP-6(3): all-pass fixture, empty input, one flip per control id, type traps.

import rego.v1

_att := {"attestation": {"attested": true, "by": "Media custodian", "date": "2026-11-01"}}

_pass := {"mp_controls": {
	"policy": {"documented": true, "official_designated": true, "review": {"days_since_last": 100, "odp": {"frequency_days": 365}}},
	"procedures": {"documented": true, "review": {"days_since_last": 200, "odp": {"frequency_days": 365}}},
	"media_access": {"digital_restricted": true, "non_digital_restricted": true},
	"media_marking": _att,
	"media_storage": _att,
	"media_transport": _att,
	"media_sanitization": {
		"unsanitized_releases": 0, "techniques_per_odp": true, "mechanisms_commensurate": true,
		"tracking": {"tracked_in_system": true, "actions_without_complete_record": 0},
		"equipment_testing": {"days_since_last": 100, "last_test_passed": true, "odp": {"frequency_days": 365}},
		"procedure_testing": {"days_since_last": 100, "odp": {"frequency_days": 365}},
		"nondestructive": {"devices_connected_without_sanitization": 0, "odp": {"circumstances": ["device received from outside the organization"]}},
	},
	"media_use": {"use_restricted_per_odp": true, "ownerless_portable_devices_prohibited": true},
	"media_downgrading": _att,
}}

# Control ids that have a finding ("NIST MP-3: ..." -> "MP-3").
_failing(r) := {id |
	some v in r.violations
	id := substring(v, 5, indexof(v, ":") - 5)
}

_msg(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.media_protection.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.media_protection.compliance_report with input as {}
	ids := data.nist.sp800_53.media_protection.evaluated_controls with input as {}
	count(r.violations) == count(ids)
	_failing(r) == ids
	r.compliant == false
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.media_protection.evaluated_controls == {"MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-6(1)", "MP-6(2)", "MP-6(3)", "MP-7", "MP-8"}
}

test_mp1_procedures_not_documented if {
	inp := object.union(_pass, {"mp_controls": {"procedures": {"documented": false}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-1"}
}

test_mp1_lists_every_unmet_element_in_one_finding if {
	inp := object.union(_pass, {"mp_controls": {
		"policy": {"documented": false, "review": {"days_since_last": "1"}},
		"procedures": {"review": {"days_since_last": 500}},
	}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	f := _msg(r, "MP-1")
	count(f) == 1
	contains(f[0], "policy.documented is false")
	contains(f[0], "evidence missing: input.mp_controls.policy.review.days_since_last not collected")
	contains(f[0], "Procedures review last done 500 days ago")
	_failing(r) == {"MP-1"}
}

test_mp2_non_digital_not_restricted if {
	inp := object.union(_pass, {"mp_controls": {"media_access": {"non_digital_restricted": false}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-2"}
}

test_mp2_boolean_as_string_is_a_finding if {
	inp := object.union(_pass, {"mp_controls": {"media_access": {"digital_restricted": "true"}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-2"}
	contains(_msg(r, "MP-2")[0], "evidence missing")
}

test_mp3_not_attested if {
	inp := object.union(_pass, {"mp_controls": {"media_marking": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-3"}
}

test_mp4_attestation_without_date if {
	inp := object.union(_pass, {"mp_controls": {"media_storage": {"attestation": {"date": ""}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-4"}
}

test_mp5_attested_as_string_is_a_finding if {
	inp := object.union(_pass, {"mp_controls": {"media_transport": {"attestation": {"attested": "true"}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-5"}
}

test_mp6_unsanitized_release if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"unsanitized_releases": 2}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6"}
	contains(_msg(r, "MP-6")[0], "2 media released")
}

test_mp6_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"unsanitized_releases": "1"}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6"}
	contains(_msg(r, "MP-6")[0], "evidence missing")
}

test_mp6_count_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"unsanitized_releases": null}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6"}
	contains(_msg(r, "MP-6")[0], "evidence missing")
}

test_mp7_ownerless_devices_allowed if {
	inp := object.union(_pass, {"mp_controls": {"media_use": {"ownerless_portable_devices_prohibited": false}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-7"}
}

test_mp8_attestation_missing if {
	inp := object.remove(_pass.mp_controls, ["media_downgrading"])
	r := data.nist.sp800_53.media_protection.compliance_report with input as {"mp_controls": inp}
	_failing(r) == {"MP-8"}
}

# --- NIST / FedRAMP High-baseline enhancements -----------------------------------------------------------------

# [id, override that fails only that id, override that removes that id's evidence]
_high_cases := [
	["MP-6(1)", {"media_sanitization": {"tracking": {"actions_without_complete_record": 2}}}, {"media_sanitization": {"tracking": {"tracked_in_system": null}}}],
	["MP-6(2)", {"media_sanitization": {"procedure_testing": {"days_since_last": 400}}}, {"media_sanitization": {"equipment_testing": {"odp": null}}}],
	["MP-6(3)", {"media_sanitization": {"nondestructive": {"devices_connected_without_sanitization": 1}}}, {"media_sanitization": {"nondestructive": {"odp": {"circumstances": []}}}}],
]

test_each_high_id_failing_case_flips_only_that_id if {
	every c in _high_cases {
		inp := object.union(_pass, {"mp_controls": c[1]})
		r := data.nist.sp800_53.media_protection.compliance_report with input as inp
		_failing(r) == {c[0]}
		not contains(concat("", r.violations), "evidence missing")
	}
}

test_each_high_id_missing_evidence_flips_only_that_id if {
	every c in _high_cases {
		inp := object.union(_pass, {"mp_controls": c[2]})
		r := data.nist.sp800_53.media_protection.compliance_report with input as inp
		_failing(r) == {c[0]}
		contains(concat("", r.violations), "evidence missing")
	}
}

test_mp6_2_failed_equipment_test if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"equipment_testing": {"last_test_passed": false}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6(2)"}
}

test_mp6_2_frequency_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"equipment_testing": {"days_since_last": "1"}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6(2)"}
	contains(_msg(r, "MP-6(2)")[0], "evidence missing")
}

test_mp6_3_count_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"nondestructive": {"devices_connected_without_sanitization": null}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6(3)"}
	contains(_msg(r, "MP-6(3)")[0], "evidence missing")
}

test_mp6_1_boolean_as_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"mp_controls": {"media_sanitization": {"tracking": {"tracked_in_system": "true"}}}})
	r := data.nist.sp800_53.media_protection.compliance_report with input as inp
	_failing(r) == {"MP-6(1)"}
	contains(_msg(r, "MP-6(1)")[0], "evidence missing")
}

test_empty_input_every_finding_fails_closed if {
	r := data.nist.sp800_53.media_protection.compliance_report with input as {}
	every v in r.violations {
		_fail_closed(v)
	}
}

_fail_closed(v) if contains(v, "evidence missing")

_fail_closed(v) if contains(v, "not attested")
