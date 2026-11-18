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
		"last_vulnerability_scan_days": 10, "high_vulnerabilities_open_days": 12, "critical_vulnerabilities_open_days": 3,
	},
	"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true, "redundant_processing": true},
	"supply_chain": {"risk_management_plan": true},
	"personnel": [{"name": "ops1", "admin_access": true, "background_check_completed": true}],
	"data_residency": {
		"storage_locations": [{"region": "us-gov-west-1", "us_territory": true}],
		"processing_locations": [{"region": "us-gov-east-1", "us_territory": true}],
	},
}

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
	count(fedramp.applicable_checks) == 10 with input as {"impact_level": "low"}
	count(fedramp.applicable_checks) == 11 with input as {"impact_level": "moderate"}
	count(fedramp.applicable_checks) == 12 with input as {"impact_level": "high"}
	count(fedramp.applicable_checks) == 12 with input as {}
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
	count(_findings(inp, "SA-9(5)")) == 2
}

test_missing_3pao_age_is_finding if {
	inp := json.remove(_at("low"), ["authorization/last_3pao_assessment_days"])
	"CA-2" in _ids(inp)
}

test_report_counts_consistent if {
	r := fedramp.fedramp_compliance_report with input as {"impact_level": "high"}
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
