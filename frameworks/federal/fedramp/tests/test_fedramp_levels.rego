package fedramp.levels_test

# Audit 2026-11-24, round 2. One all-pass fixture per impact level, so the level-dependent checks are
# exercised: CP-7, SA-9(5) and PS-3(3) are not in the FedRAMP Rev 5 Low baseline, and an all-pass input at
# Low says nothing about them. The Moderate and High fixtures set the two agency selectors, so SA-9(5) and
# PS-3(3) are evaluated in both. Every boolean of each fixture is then replaced by "false", "true", "no", 0,
# 1, null and removed, and every number by its string form: none of those may pass.

import data.fedramp
import data.fedramp.main
import rego.v1

all_pass_low := {
	"impact_level": "low",
	"assessment_date": "2026-11-24",
	"authorization": {"fedramp_authorized": true, "authorization_type": "ATO", "assessed_by_3pao": true, "last_3pao_assessment_days": 200},
	"cryptography": {"fips_140_validated": true, "algorithms_in_use": ["AES-256", "SHA-384"]},
	"continuous_monitoring": {
		"program_documented": true, "monthly_ato_report_submitted": true,
		"monthly_vulnerability_scans": true, "monthly_os_scan": true, "web_app_scan_enabled": true, "database_scan_enabled": true,
		"last_vulnerability_scan_days": 10, "high_vulnerabilities_open_days": 12, "critical_vulnerabilities_open_days": 3, "moderate_vulnerabilities_open_days": 45, "low_vulnerabilities_open_days": 100,
	},
	"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true},
	"supply_chain": {"risk_management_plan": true},
	"personnel": [{"name": "ops1", "admin_access": true, "background_check_completed": true}],
	# stated, not left out: "does not apply" is an explicit false (round 3)
	"data_residency": {"us_only_required": false},
}

all_pass_moderate := object.union(all_pass_low, {
	"impact_level": "moderate",
	"authorization": {"fedramp_authorized": true, "authorization_type": "P-ATO", "assessed_by_3pao": true, "last_3pao_assessment_days": 200, "ato_expiry_days": 400},
	"cloud_service": {"penetration_test_annual": true, "incident_response_plan_approved": true, "redundant_processing": true},
	"personnel": [
		{"name": "ops1", "admin_access": true, "background_check_completed": true, "us_person": true},
		{"name": "dev1", "admin_access": false},
	],
	"personnel_requirements": {"us_persons_required_for_admin": true},
	"data_residency": {
		"us_only_required": true,
		"storage_locations": [{"region": "us-gov-west-1", "us_territory": true}],
		"processing_locations": [{"region": "us-gov-east-1", "us_territory": true}],
	},
})

# The largest of the three (the harness takes the passing fixture with the most leaves).
all_pass_high := object.union(all_pass_moderate, {
	"impact_level": "high",
	"continuous_monitoring": object.union(all_pass_low.continuous_monitoring, {"kev_findings": [
		{"cve": "CVE-2024-0001", "due_date": "2026-10-01", "remediated": true},
		{"cve": "CVE-2024-0002", "due_date": "2026-11-01", "remediated": true},
	]}),
	"personnel": [
		{"name": "ops1", "admin_access": true, "background_check_completed": true, "us_person": true},
		{"name": "ops2", "admin_access": true, "background_check_completed": true, "us_person": true},
		{"name": "dev1", "admin_access": false},
	],
	"data_residency": {
		"us_only_required": true,
		"storage_locations": [{"region": "us-gov-west-1", "us_territory": true}, {"region": "us-gov-east-1", "us_territory": true}],
		"processing_locations": [{"region": "us-gov-east-1", "us_territory": true}, {"region": "us-gov-west-1", "us_territory": true}],
	},
})

fixtures := {"low": all_pass_low, "moderate": all_pass_moderate, "high": all_pass_high}

# The agency selectors. They add a requirement the baseline leaves to the agency (SA-9(5) location below
# High, PS-3(3) screening criteria); leaving one out, or sending null, states no agency requirement.
selectors := {["data_residency", "us_only_required"], ["personnel_requirements", "us_persons_required_for_admin"]}

# ato_expiry_days is optional: a P-ATO under continuous authorization has no expiry date.
optional_numbers := {["authorization", "ato_expiry_days"]}

_ptr(path) := concat("/", array.concat([""], [sprintf("%v", [p]) | some p in path]))

_set(fx, path, value) := json.patch(fx, [{"op": "replace", "path": _ptr(path), "value": value}])

_drop(fx, path) := json.remove(fx, [substring(_ptr(path), 1, -1)])

_passes(inp) if {
	r := main.compliance_report with input as inp
	r.compliant == true
}

_bools(fx) := [path | walk(fx, [path, value]); is_boolean(value)]

_numbers(fx) := [path | walk(fx, [path, value]); is_number(value)]

test_each_level_fixture_passes_with_no_findings if {
	every level, fx in fixtures {
		r := main.compliance_report with input as fx
		r.compliant == true
		r.violation_count == 0
		r.failed_controls == 0
		r.impact_level_normalized == level
	}
}

test_level_dependent_checks_are_evaluated_by_the_fixtures if {
	fedramp.applicable_checks == {"RA-2", "CA-6", "CA-2", "CA-7", "RA-5", "SC-13", "CA-8", "IR-8", "SR-2", "PS-3"} with input as all_pass_low
	{"CP-7", "SA-9(5)", "PS-3(3)"} & fedramp.applicable_checks == {"CP-7", "SA-9(5)", "PS-3(3)"} with input as all_pass_moderate
	{"CP-7", "SA-9(5)", "PS-3(3)"} & fedramp.applicable_checks == {"CP-7", "SA-9(5)", "PS-3(3)"} with input as all_pass_high
	kev := main.compliance_report.kev_assessed with input as all_pass_high
	kev == true
}

test_counts_add_up_at_every_level if {
	every _, fx in fixtures {
		every inp in [fx, _set(fx, ["cloud_service", "penetration_test_annual"], "true"), object.remove(fx, ["personnel"])] {
			r := main.compliance_report with input as inp
			r.failed_controls == count(r.failed_control_ids)
			r.failed_controls <= r.total_controls
		}
	}
}

# every boolean, one at a time, as a string, a number or a container: never a pass
test_boolean_of_the_wrong_type_never_passes if {
	every _, fx in fixtures {
		every path in _bools(fx) {
			every bad in ["false", "true", "no", "yes", 0, 1, [], {}] {
				not _passes(_set(fx, path, bad))
			}
		}
	}
}

# every boolean, one at a time, null or removed: never a pass, except the agency selectors
test_boolean_null_or_removed_never_passes if {
	every _, fx in fixtures {
		every path in [p | some p in _bools(fx); not p in selectors] {
			not _passes(_set(fx, path, null))
			not _passes(_drop(fx, path))
		}
	}
}

# admin_access false is a legitimate answer (the person is not an administrator), so it is left out
test_true_boolean_set_false_never_passes if {
	every _, fx in fixtures {
		every path in [p | some p in _bools(fx); not p in selectors; p[count(p) - 1] != "admin_access"; object.get(fx, p, null) == true] {
			not _passes(_set(fx, path, false))
		}
	}
}

# every number, one at a time, as its string form, null or removed
test_number_as_string_never_passes if {
	every _, fx in fixtures {
		every path in _numbers(fx) {
			not _passes(_set(fx, path, sprintf("%v", [object.get(fx, path, null)])))
		}
	}
}

test_number_null_or_removed_never_passes if {
	every _, fx in fixtures {
		every path in [p | some p in _numbers(fx); not p in optional_numbers] {
			not _passes(_set(fx, path, null))
			not _passes(_drop(fx, path))
		}
	}
}

test_section_null_or_removed_never_passes if {
	# assessment_date is report metadata unless KEV findings are compared with it; personnel_requirements
	# holds only a selector. At Moderate the data_residency section is read only when its selector is on, so
	# removing the section removes the agency requirement with it (at High FedRAMP fixes the location).
	every level, fx in fixtures {
		every key in [k | some k, _ in fx; not k in {"assessment_date", "personnel_requirements"}; [level, k] != ["moderate", "data_residency"]] {
			not _passes(object.union(fx, {key: null}))
			not _passes(object.remove(fx, [key]))
		}
	}
}

# --- the named evidence problems -------------------------------------------------

_violations(inp) := v if {
	v := fedramp.all_violations with input as inp
}

test_cp7_names_the_evidence_problem if {
	some a in _violations(_set(all_pass_moderate, ["cloud_service", "redundant_processing"], "true"))
	endswith(a, "[evidence invalid: input.cloud_service.redundant_processing is not a boolean (got string)]")
	some b in _violations(_drop(all_pass_high, ["cloud_service", "redundant_processing"]))
	endswith(b, "[evidence missing: input.cloud_service.redundant_processing not collected]")
	some c in _violations(_set(all_pass_high, ["cloud_service", "redundant_processing"], false))
	endswith(c, "CP-7 is in the Moderate and High baselines.")
}

test_cp7_not_evaluated_at_low if {
	# not in the Low baseline: the fact is not read there, whatever it holds
	every bad in ["false", null, false] {
		_passes(object.union(all_pass_low, {"cloud_service": object.union(all_pass_low.cloud_service, {"redundant_processing": bad})}))
	}
}

test_location_names_the_evidence_problem if {
	some a in _violations(_set(all_pass_high, ["data_residency", "storage_locations", 0, "us_territory"], "true"))
	endswith(a, "[evidence invalid: us_territory is not a boolean (got string)]")
	some b in _violations(_drop(all_pass_moderate, ["data_residency", "processing_locations", 0, "us_territory"]))
	endswith(b, "[evidence missing: us_territory not collected for this location]")
	some c in _violations(_set(all_pass_high, ["data_residency", "storage_locations", 1], "us-gov-east-1"))
	endswith(c, "[evidence invalid: the location entry is not an object (got string)]")
}

test_empty_location_list_is_missing_evidence if {
	every field in ["storage_locations", "processing_locations"] {
		every fx in [all_pass_moderate, all_pass_high] {
			inp := _set(fx, ["data_residency", field], [])
			not _passes(inp)
			some v in _violations(inp)
			v == sprintf("FedRAMP SA-9(5): evidence missing — input.data_residency.%s is empty; no location was collected", [field])
		}
	}
}

test_location_list_of_the_wrong_type_is_missing_evidence if {
	every bad in ["us-gov-west-1", {"region": "us-gov-west-1", "us_territory": true}, null, true] {
		not _passes(_set(all_pass_high, ["data_residency", "storage_locations"], bad))
	}
}

# Selector semantics, pinned (owner ruling, round 3): "does not apply" must be an explicit statement. Only
# the boolean false states it. An absent or null selector is missing evidence and the check it selects is
# applied (so the report fails), anything else is invalid evidence.
test_selector_must_be_stated if {
	every path in selectors {
		every fx in [all_pass_moderate, all_pass_high] {
			_passes(_set(fx, path, false))
			_passes(_set(fx, path, true))
			not _passes(_drop(fx, path))
			not _passes(_set(fx, path, null))
		}
	}
	not _passes(_drop(all_pass_moderate, ["data_residency"]))
	not _passes(_set(all_pass_moderate, ["data_residency"], null))
	not _passes(_drop(all_pass_moderate, ["personnel_requirements"]))
	not _passes(_set(all_pass_moderate, ["personnel_requirements"], null))
	not _passes(_drop(all_pass_low, ["data_residency"]))
	some v in _violations(_drop(all_pass_moderate, ["data_residency", "us_only_required"]))
	contains(v, "input.data_residency.us_only_required not stated")
	some w in _violations(_drop(all_pass_moderate, ["personnel_requirements", "us_persons_required_for_admin"]))
	contains(w, "input.personnel_requirements.us_persons_required_for_admin not stated")
	"SA-9(5)" in fedramp.applicable_checks with input as _drop(all_pass_moderate, ["data_residency", "us_only_required"])
	"PS-3(3)" in fedramp.applicable_checks with input as _drop(all_pass_high, ["personnel_requirements", "us_persons_required_for_admin"])
	not "SA-9(5)" in fedramp.applicable_checks with input as _set(all_pass_moderate, ["data_residency", "us_only_required"], false)
	# PS-3(3) is not in the Low baseline, so its selector is not asked for there
	_passes(all_pass_low)
}

test_ato_expiry_days_typed_when_sent if {
	every bad in ["400", "30", true, [], {}] {
		inp := _set(all_pass_moderate, ["authorization", "ato_expiry_days"], bad)
		not _passes(inp)
		some v in _violations(inp)
		startswith(v, "FedRAMP CA-6: evidence invalid — input.authorization.ato_expiry_days is not a number")
	}
	_passes(_drop(all_pass_moderate, ["authorization", "ato_expiry_days"]))
	not _passes(_set(all_pass_moderate, ["authorization", "ato_expiry_days"], 30))
}

test_algorithm_inventory_must_name_algorithms if {
	not _passes(_set(all_pass_low, ["cryptography", "algorithms_in_use"], []))
	not _passes(_set(all_pass_low, ["cryptography", "algorithms_in_use"], "AES-256"))
	not _passes(_set(all_pass_low, ["cryptography", "algorithms_in_use"], ["AES-256", 7]))
	not _passes(_set(all_pass_low, ["cryptography", "algorithms_in_use"], ["AES-256", {"usage": "hmac"}]))
	not _passes(_set(all_pass_low, ["cryptography", "algorithms_in_use"], ["AES-256", ""]))
	not _passes(object.union(all_pass_low, {"cryptography": {"fips_140_validated": true, "nsa_approved": "false", "algorithms_in_use": ["AES-256"]}}))
}

test_personnel_records_must_be_objects_and_present if {
	not _passes(_set(all_pass_low, ["personnel"], []))
	not _passes(_set(all_pass_low, ["personnel"], ["ops1"]))
	not _passes(_set(all_pass_high, ["personnel", 2], null))
}

test_kev_dates_and_flags_are_typed if {
	# unremediated and past due: a finding
	not _passes(_set(all_pass_high, ["continuous_monitoring", "kev_findings", 0, "remediated"], false))

	# a due date that is not a date used to silence the past-due rule
	bad_date := _set(_set(all_pass_high, ["continuous_monitoring", "kev_findings", 0, "remediated"], false), ["continuous_monitoring", "kev_findings", 0, "due_date"], "01/10/2026")
	not _passes(bad_date)
	not _passes(_set(all_pass_high, ["continuous_monitoring", "kev_findings", 0, "due_date"], "soon"))
	not _passes(_set(all_pass_high, ["continuous_monitoring", "kev_findings", 1], "CVE-2024-0002"))

	# so did an assessment_date that is not a date
	not _passes(_set(all_pass_high, ["assessment_date"], "24 November 2026"))
	not _passes(_set(all_pass_high, ["assessment_date"], 20261124))

	# without KEV findings assessment_date is report metadata only
	_passes(_set(all_pass_moderate, ["assessment_date"], "unknown"))
}
