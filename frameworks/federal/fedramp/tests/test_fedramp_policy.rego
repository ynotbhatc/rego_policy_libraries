package fedramp_test

# Tests for frameworks/federal/fedramp/fedramp_main.rego (package fedramp): pass, fail and missing-evidence
# per check, and per-impact-level gating and figures (FedRAMP Rev 5 OSCAL baselines, audit 2026-11-17).

import data.fedramp
import rego.v1

good := {
	"authorization": {"fedramp_authorized": true, "authorization_type": "P-ATO", "assessed_by_3pao": true, "last_3pao_assessment_days": 200},
	"cryptography": {"fips_140_validated": true, "algorithms_in_use": ["AES-256", "SHA-384"]},
	"continuous_monitoring": {
		"program_documented": true, "monthly_ato_report_submitted": true,
		"monthly_vulnerability_scans": true, "monthly_os_scan": true, "web_app_scan_enabled": true, "database_scan_enabled": true,
		"last_vulnerability_scan_days": 10, "high_vulnerabilities_open_days": 12, "critical_vulnerabilities_open_days": 3, "moderate_vulnerabilities_open_days": 45, "low_vulnerabilities_open_days": 100,
	},
	"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true, "redundant_processing": true},
	"supply_chain": {"risk_management_plan": true},
	"personnel": [{"name": "ops1", "admin_access": true, "background_check_completed": true}],
	# The agency selectors are stated: "does not apply" is an explicit false, never an absent field.
	"personnel_requirements": {"us_persons_required_for_admin": false},
	"data_residency": {
		"us_only_required": false,
		"storage_locations": [{"region": "us-gov-west-1", "us_territory": true}],
		"processing_locations": [{"region": "us-gov-east-1", "us_territory": true}],
	},
}

_stated := {"data_residency": {"us_only_required": false}, "personnel_requirements": {"us_persons_required_for_admin": false}}

_at(level) := object.union(good, {"impact_level": level})

_ids(inp) := ids if {
	ids := fedramp.failed_checks with input as inp
}

_findings(inp, id) := f if {
	vs := fedramp.all_violations with input as inp
	f := [v | some v in vs; startswith(v, concat("", ["FedRAMP ", id, ":"]))]
}

# --- pass --------------------------------------------------------------------

test_good_input_compliant_at_every_level if {
	every level in ["low", "moderate", "high"] {
		fedramp.fedramp_compliant with input as _at(level)
	}
}

# --- per-impact-level figures and gating ----------------------------------------

test_baseline_sizes_are_rev5 if {
	fedramp.baseline_sizes == {"low": 156, "moderate": 323, "high": 410, "li_saas": 156}
	fedramp.baseline_size == 156 with input as {"impact_level": "low"}
	fedramp.baseline_size == 323 with input as {"impact_level": "moderate"}
	fedramp.baseline_size == 410 with input as {"impact_level": "high"}
	fedramp.baseline_size == null with input as {}
}

test_applicable_checks_per_level if {
	count(fedramp.applicable_checks) == 10 with input as object.union(_stated, {"impact_level": "low"})
	count(fedramp.applicable_checks) == 11 with input as object.union(_stated, {"impact_level": "moderate"})
	count(fedramp.applicable_checks) == 12 with input as object.union(_stated, {"impact_level": "high"})
	count(fedramp.applicable_checks) == 12 with input as _stated
}

test_cp7_not_applied_at_low_applied_at_moderate if {
	inp := object.union(good, {"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true, "redundant_processing": false}})
	not "CP-7" in _ids(object.union(inp, {"impact_level": "low"}))
	"CP-7" in _ids(object.union(inp, {"impact_level": "moderate"}))
}

test_ca8_applies_at_low if {
	inp := object.union(_at("low"), {"cloud_service": {"penetration_test_annual": false}})
	"CA-8" in _ids(inp)
	not "CA-8" in _ids(_at("low"))
}

test_sa_9_5_us_location_only_at_high_unless_agency_requires if {
	inp := object.union(good, {"data_residency": {"storage_locations": [{"region": "eu-west-1", "us_territory": false}], "processing_locations": []}})
	not "SA-9(5)" in _ids(object.union(inp, {"impact_level": "moderate"}))
	"SA-9(5)" in _ids(object.union(inp, {"impact_level": "high"}))
	agency := object.union(inp, {"impact_level": "low", "data_residency": {"us_only_required": true}})
	"SA-9(5)" in _ids(agency)
}

test_us_person_only_when_agency_requires if {
	inp := object.union(_at("high"), {"personnel": [{"name": "fn1", "admin_access": true, "background_check_completed": true, "us_person": false}]})
	not "PS-3(3)" in _ids(inp)
	req := object.union(inp, {"personnel_requirements": {"us_persons_required_for_admin": true}})
	"PS-3(3)" in _ids(req)
	"PS-3(3)" in fedramp.applicable_checks with input as req
}

test_withdrawn_or_unselected_checks_gone if {
	vs := fedramp.all_violations with input as {}
	every v in vs {
		not contains(v, "PE-3(1)")
		not contains(v, "SR-4")
		not contains(v, "Suite B")
		not contains(v, "JAB")
	}
}

# --- fail ----------------------------------------------------------------------

test_invalid_authorization_type_fails if {
	inp := object.union(_at("low"), {"authorization": {"authorization_type": "JAB"}})
	"CA-6" in _ids(inp)
}

test_deprecated_algorithm_fails_sc13 if {
	inp := object.union(_at("moderate"), {"cryptography": {"algorithms_in_use": ["AES-256", "3DES"]}})
	f := _findings(inp, "SC-13")
	count(f) == 1
	contains(f[0], "3DES")
}

test_nsa_approved_satisfies_sc13 if {
	inp := object.union(_at("moderate"), {"cryptography": {"fips_140_validated": false, "nsa_approved": true}})
	not "SC-13" in _ids(inp)
}

test_critical_vuln_held_to_30_days if {
	ok := object.union(_at("low"), {"continuous_monitoring": {"critical_vulnerabilities_open_days": 20}})
	not "RA-5" in _ids(ok)
	late := object.union(_at("low"), {"continuous_monitoring": {"critical_vulnerabilities_open_days": 31}})
	"RA-5" in _ids(late)
}

test_old_3pao_assessment_fails if {
	inp := object.union(_at("low"), {"authorization": {"last_3pao_assessment_days": 400}})
	"CA-2" in _ids(inp)
}

test_admin_without_background_check_fails if {
	inp := object.union(_at("low"), {"personnel": [{"name": "x", "admin_access": true}]})
	"PS-3" in _ids(inp)
}

# --- missing evidence --------------------------------------------------------------

test_empty_input_fails_every_applicable_check if {
	fedramp.failed_checks == fedramp.applicable_checks with input as {}
	not fedramp.fedramp_compliant with input as {}
}

test_missing_scan_ages_are_findings if {
	inp := object.union(_at("low"), {"continuous_monitoring": {"last_vulnerability_scan_days": null}})
	f := _findings(inp, "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_missing_algorithm_inventory_is_finding if {
	inp := json.remove(_at("low"), ["cryptography/algorithms_in_use"])
	f := _findings(inp, "SC-13")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_missing_personnel_is_finding if {
	inp := json.remove(_at("low"), ["personnel"])
	f := _findings(inp, "PS-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_missing_locations_at_high_is_finding if {
	inp := json.remove(_at("high"), ["data_residency"])
	count(_findings(inp, "SA-9(5)")) == 3 # two location lists and the unstated agency selector
}

test_missing_3pao_age_is_finding if {
	inp := json.remove(_at("low"), ["authorization/last_3pao_assessment_days"])
	"CA-2" in _ids(inp)
}

test_report_counts_consistent if {
	r := fedramp.fedramp_compliance_report with input as object.union(_stated, {"impact_level": "high"})
	r.checks_evaluated == 12
	r.checks_failed <= r.checks_evaluated
	r.baseline_size == 410
	r.compliant == false
}

test_policy_report_defined_when_compliant if {
	r := fedramp.fedramp_compliance_report with input as _at("low")
	r.compliant == true
	r.checks_failed == 0
	r.checks_evaluated == 10
	r.baseline_size == 156
}

test_us_person_criterion_not_applied_at_low if {
	inp := object.union(_at("low"), {
		"personnel": [{"name": "fn1", "admin_access": true, "background_check_completed": true, "us_person": false}],
		"personnel_requirements": {"us_persons_required_for_admin": true},
	})
	not "PS-3(3)" in fedramp.applicable_checks with input as inp
	fedramp.fedramp_compliant with input as inp
}

# --- RA-5 risk tiers (FedRAMP ra-05_odp.03: 30 / 90 / 180 days) -----------------------

test_ra5_moderate_tier_90_days if {
	not "RA-5" in _ids(object.union(_at("low"), {"continuous_monitoring": {"moderate_vulnerabilities_open_days": 90}}))
	f := _findings(object.union(_at("low"), {"continuous_monitoring": {"moderate_vulnerabilities_open_days": 91}}), "RA-5")
	count(f) == 1
	contains(f[0], "90 days")
}

test_ra5_low_tier_180_days if {
	not "RA-5" in _ids(object.union(_at("low"), {"continuous_monitoring": {"low_vulnerabilities_open_days": 180}}))
	"RA-5" in _ids(object.union(_at("low"), {"continuous_monitoring": {"low_vulnerabilities_open_days": 181}}))
}

test_ra5_missing_tier_ages_are_missing_evidence if {
	inp := json.remove(_at("low"), ["continuous_monitoring/moderate_vulnerabilities_open_days", "continuous_monitoring/low_vulnerabilities_open_days"])
	f := _findings(inp, "RA-5")
	count(f) == 2
	every m in f {
		contains(m, "evidence missing")
	}
}

# --- KEV ---------------------------------------------------------------------------

_kev(items) := object.union(_at("low"), {"assessment_date": "2026-11-17", "continuous_monitoring": {"kev_findings": items}})

test_kev_not_supplied_is_not_assessed_not_a_finding if {
	fedramp.fedramp_compliant with input as _at("low")
	not fedramp.kev_assessed with input as _at("low")
	r := data.fedramp.main.compliance_report with input as _at("low")
	r.kev_assessed == false
	contains(r.kev_note, "not assessed")
}

test_kev_past_due_fails_even_within_30_days if {
	# 10 days open (inside the 30-day parameter) but past its KEV due date
	inp := object.union(_kev([{"cve": "CVE-2026-0001", "due_date": "2026-11-10", "remediated": false}]), {"continuous_monitoring": {"critical_vulnerabilities_open_days": 10}})
	f := _findings(inp, "RA-5")
	count(f) == 1
	contains(f[0], "CVE-2026-0001")
}

test_kev_not_yet_due_passes if {
	inp := _kev([{"cve": "CVE-2026-0002", "due_date": "2026-12-01", "remediated": false}])
	fedramp.fedramp_compliant with input as inp
	fedramp.kev_assessed with input as inp
}

test_kev_remediated_past_due_passes if {
	fedramp.fedramp_compliant with input as _kev([{"cve": "CVE-2026-0003", "due_date": "2026-01-01", "remediated": true}])
}

test_kev_missing_due_date_is_missing_evidence if {
	f := _findings(_kev([{"cve": "CVE-2026-0004", "remediated": false}]), "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- SP 800-131A Rev. 2 algorithm status ------------------------------------------

_algos(list) := object.union(_at("low"), {"cryptography": {"algorithms_in_use": list}})

test_disallowed_algorithms_fail if {
	every a in ["DES", "3DES", "SKIPJACK", "RC4", "MD5", "RSA-1024"] {
		count(_findings(_algos(["AES-256", a]), "SC-13")) == 1
	}
}

test_sha1_signature_generation_fails if {
	f := _findings(_algos([{"algorithm": "SHA-1", "usage": "signature_generation"}]), "SC-13")
	count(f) == 1
	contains(f[0], "signature generation")
}

test_sha1_allowed_uses_pass if {
	not "SC-13" in _ids(_algos([{"algorithm": "SHA1", "usage": "hmac"}, {"algorithm": "SHA-1", "usage": "signature_verification"}]))
}

test_sha1_without_usage_is_missing_evidence if {
	f := _findings(_algos(["SHA1"]), "SC-13")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_object_entries_for_approved_algorithms_pass if {
	not "SC-13" in _ids(_algos([{"algorithm": "AES-256", "usage": "encryption"}, "SHA-384"]))
}

# A section sent as null reads as empty: every check on it reports missing evidence.
test_null_cryptography_section_is_not_compliant if {
	inp := object.union(_at("low"), {"cryptography": null})
	not fedramp.fedramp_compliant with input as inp
	some msg in fedramp.violation_crypto with input as inp
	contains(msg, "SC-13")
}

# The string "true" is not the boolean true.
test_string_true_authorization_is_not_compliant if {
	inp := json.patch(_at("low"), [{"op": "replace", "path": "/authorization/fedramp_authorized", "value": "true"}])
	not fedramp.fedramp_compliant with input as inp
	some msg in fedramp.violation_authorization with input as inp
	contains(msg, "evidence invalid")
}

test_string_true_admin_access_is_not_compliant if {
	inp := json.patch(_at("low"), [{"op": "replace", "path": "/personnel/0/admin_access", "value": "true"}])
	not fedramp.fedramp_compliant with input as inp
	some msg in fedramp.violation_personnel with input as inp
	contains(msg, "evidence invalid")
}

test_boolean_false_admin_access_is_valid_evidence if {
	inp := json.patch(_at("low"), [{"op": "add", "path": "/personnel/-", "value": {"name": "dev1", "admin_access": false}}])
	fedramp.fedramp_compliant with input as inp
}

# ── Audit 2026-11-24: agency selectors. A wrong-typed selector applies its check and is reported ────

test_us_only_selector_wrong_type_applies_the_check if {
	eu := {"storage_locations": [{"region": "eu-west-1", "us_territory": false}], "processing_locations": []}
	every bad in ["true", "false", "yes", 1, 0, [], {}] {
		inp := object.union(good, {"impact_level": "low", "data_residency": object.union(eu, {"us_only_required": bad})})
		"SA-9(5)" in _ids(inp)
		"SA-9(5)" in fedramp.applicable_checks with input as inp
		some v in fedramp.all_violations with input as inp
		contains(v, "evidence invalid — input.data_residency.us_only_required must be true or false")
		not fedramp.compliant with input as inp
	}
}

test_us_only_selector_false_leaves_it_off_below_high_and_null_or_absent_does_not if {
	eu := {"storage_locations": [{"region": "eu-west-1", "us_territory": false}], "processing_locations": []}
	inp := object.union(good, {"impact_level": "low", "data_residency": object.union(eu, {"us_only_required": false})})
	not "SA-9(5)" in _ids(inp)
	not "SA-9(5)" in fedramp.applicable_checks with input as inp
	# "does not apply" must be stated: null or an absent selector is missing evidence and the check is applied
	base := object.union(good, {"impact_level": "low", "data_residency": eu})
	every i in [object.union(base, {"data_residency": {"us_only_required": null}}), json.remove(base, ["data_residency/us_only_required"])] {
		"SA-9(5)" in _ids(i)
		"SA-9(5)" in fedramp.applicable_checks with input as i
	}
}

test_us_person_selector_wrong_type_applies_the_check if {
	base := object.union(_at("high"), {"personnel": [{"name": "fn1", "admin_access": true, "background_check_completed": true, "us_person": false}]})
	every bad in ["true", "false", 1, 0, []] {
		inp := object.union(base, {"personnel_requirements": {"us_persons_required_for_admin": bad}})
		"PS-3(3)" in _ids(inp)
		"PS-3(3)" in fedramp.applicable_checks with input as inp
		some v in fedramp.all_violations with input as inp
		contains(v, "evidence invalid — input.personnel_requirements.us_persons_required_for_admin must be true or false")
	}
	not "PS-3(3)" in _ids(object.union(base, {"personnel_requirements": {"us_persons_required_for_admin": false}}))
}

test_selector_section_that_is_not_an_object_applies_the_check if {
	inp := object.union(good, {"impact_level": "low", "data_residency": "true"})
	"SA-9(5)" in _ids(inp)
	inp2 := object.union(_at("moderate"), {"personnel_requirements": "true"})
	"PS-3(3)" in _ids(inp2)
	# at Low PS-3(3) is not in the evaluated set, so the selector is not read and nothing is reported for it
	not "PS-3(3)" in _ids(object.union(_at("low"), {"personnel_requirements": "true"}))
}

test_counts_still_add_up_with_an_invalid_selector if {
	inp := object.union(good, {"impact_level": "low", "data_residency": {"us_only_required": "true"}})
	r := data.fedramp.main.compliance_report with input as inp
	r.compliant == false
	every id in r.failed_control_ids {
		id in fedramp.applicable_checks with input as inp
	}
	r.failed_controls <= r.total_controls
}
