package cfr_part_11.main_test

import data.cfr_part_11.main
import rego.v1

# Every fact the module reads, all true, every optional section declared in use.
all_pass := {
	"system_validation": {
		"validated": true,
		"revalidation": {"on_change": true},
	},
	"records": {
		"human_readable": {"capable": true},
		"electronic_copy": {"capable": true},
		"retention": {"protected_during_retention_period": true},
		"backup": {"regular_and_tested": true},
	},
	"access_control": {
		"authorized_users": {"only": true},
		"unique_user_ids": {"enforced": true},
	},
	"audit_trail": {
		"computer_generated": true,
		"timestamps": {"accurate": true},
		"captures_record_changes": true,
		"protected_from_modification": true,
		"previous_entries_not_obscured": true,
		"retention": {"at_least_as_long_as_record": true},
	},
	"operational_checks": {"sequence_enforcement": true},
	"authority_checks": {"enabled": true},
	"device_checks": {"input_validation": true},
	"personnel": {"training": {
		"system_specific": true,
		"records": {"maintained": true},
	}},
	"policies": {"individual_accountability": {"documented": true}},
	"documentation": {
		"distribution": {"controlled": true},
		"revision": {"controlled": true},
	},
	"open_systems": {
		"encryption": {"records_in_transit": true},
		"digital_signatures": {"where_appropriate": true},
		"in_use": true,
	},
	"electronic_signatures": {
		"manifestation": {
			"printed_name": true,
			"date_time": true,
			"meaning": true,
			"human_readable": true,
		},
		"record_linking": {
			"cryptographically_bound": true,
			"tamper_evident": true,
		},
		"uniqueness": {"guaranteed": true},
		"identity_verification": {"before_assignment": true},
		"fda_certification": {"filed": true},
		"non_biometric": {
			"two_distinct_components": true,
			"single_session_reauth": true,
			"different_session_full_auth": true,
			"genuine_owner_only": true,
			"misuse_requires_collaboration": true,
			"in_use": true,
		},
		"biometric": {
			"designed_exclusively_for_individual": true,
			"in_use": true,
		},
	},
	"identification_codes": {
		"uniqueness": {"maintained": true},
		"periodic_revision": true,
		"loss_management": {"procedures": true},
		"transaction_safeguards": true,
		"unauthorized_use": {"detection": true},
		"device_testing": {"initial_and_periodic": true},
		"in_use": true,
		"devices": {"in_use": true},
	},
	"entity_name": "Example Pharma",
	"system_name": "LIMS",
	"assessment_date": "2026-11-23",
}

_report(inp) := r if {
	r := main.compliance_report with input as inp
}

_set(inp, path, value) := json.patch(inp, [{"op": "add", "path": concat("/", array.concat([""], path)), "value": value}])

_ids(report) := {id | some v in report.violations; id := split(v, ":")[0]}

test_compliance_report_defined_on_empty_input if {
	r := _report({})
	r.framework == "FDA 21 CFR Part 11"

	# empty input must fail closed: every check is a violation, nothing is exempt
	r.compliant == false
	r.violation_count == r.total_controls
	r.failed_controls == r.total_controls
	count(r.not_applicable) == 0
}

test_non_compliant_on_empty_input if {
	not main.compliant with input as {}
}

test_defaults_for_metadata if {
	r := _report({})
	r.entity_name == "unknown"
	r.system_name == "unknown"
}

test_metadata_picked_up_from_input if {
	r := _report(object.union(all_pass, {"entity_type": "pharmaceutical"}))
	r.entity_name == "Example Pharma"
	r.entity_type == "pharmaceutical"
	r.system_name == "LIMS"
	r.assessed_at == "2026-11-23"
	_report(all_pass).entity_type == "unknown"
}

test_all_pass_fixture_is_compliant if {
	r := _report(all_pass)
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
	count(r.not_applicable) == 0
}

# Audit 2026-11-23, finding 1: the module declared 43 controls and implemented 42.
# The declared total is the number of checks: an empty input fails every one of them, once each.
test_declared_total_equals_implemented_checks if {
	r := _report({})
	r.total_controls == 50
	count(r.violations) == 50
	sum([count(bucket) | some bucket in r.section_summary]) == 50
}

# The same holds for null sections and for every fact as a string: nothing passes, nothing is exempt.
test_null_and_string_inputs_fail_every_check if {
	nulls := {k: null | some k, _ in all_pass}
	_report(nulls).failed_controls == 50
	as_strings := json.patch(all_pass, [{"op": "replace", "path": concat("/", array.concat([""], split(path, "."))), "value": "true"} |
		some path in (object.keys(_fact_citations) | _scope_facts)
	])
	rs := _report(as_strings)
	rs.failed_controls == 50
	count(rs.not_applicable) == 0
}

_scope_facts := {
	"open_systems.in_use",
	"electronic_signatures.non_biometric.in_use",
	"electronic_signatures.biometric.in_use",
	"identification_codes.in_use",
	"identification_codes.devices.in_use",
}

# A scope declaration that is missing or not a boolean is its own violation, cited to the section it scopes.
test_scope_declarations_must_be_booleans if {
	expected := {
		"open_systems.in_use": "21 CFR 11.30",
		"electronic_signatures.non_biometric.in_use": "21 CFR 11.200(a)",
		"electronic_signatures.biometric.in_use": "21 CFR 11.200(b)",
		"identification_codes.in_use": "21 CFR 11.300",
		"identification_codes.devices.in_use": "21 CFR 11.300",
	}
	object.keys(expected) == _scope_facts
	every path, citation in expected {
		every bad in ["true", "false", 0, null, {}] {
			r := _report(_set(all_pass, split(path, "."), bad))
			r.failed_controls == 1
			_ids(r) == {citation}
			count(r.not_applicable) == 0
			some v in r.violations
			contains(v, "evidence missing or invalid")
		}
		rm := _report(json.remove(all_pass, [concat("/", array.concat([""], split(path, ".")))]))
		_ids(rm) == {citation}
	}
}

test_section_summary_buckets_do_not_overlap if {
	r := _report({})
	count(r.section_summary.s11_10_closed_systems) == 22
	count(r.section_summary.s11_30_open_systems) == 3
	count(r.section_summary.s11_50_manifestations) == 4
	count(r.section_summary.s11_70_record_linking) == 2
	count(r.section_summary.s11_100_general_esig) == 3
	count(r.section_summary.s11_200_esig_components) == 8
	count(r.section_summary.s11_300_id_codes) == 8
}

# Each fact fails exactly one check, and failed_controls is counted, not clamped.
test_each_fact_fails_exactly_one_check if {
	every path, _ in _fact_citations {
		r := _report(_set(all_pass, split(path, "."), false))
		r.compliant == false
		r.violation_count == 1
		r.failed_controls == 1
	}
}

# Audit finding 2: citations checked against the eCFR text of 21 CFR Part 11 (version of 2026-01-01).
_fact_citations := {
	"system_validation.validated": "21 CFR 11.10(a)",
	"system_validation.revalidation.on_change": "21 CFR 11.10(a)",
	"records.human_readable.capable": "21 CFR 11.10(b)",
	"records.electronic_copy.capable": "21 CFR 11.10(b)",
	"records.retention.protected_during_retention_period": "21 CFR 11.10(c)",
	"records.backup.regular_and_tested": "21 CFR 11.10(c)",
	"access_control.authorized_users.only": "21 CFR 11.10(d)",
	"access_control.unique_user_ids.enforced": "21 CFR 11.10(d)",
	"audit_trail.computer_generated": "21 CFR 11.10(e)",
	"audit_trail.timestamps.accurate": "21 CFR 11.10(e)",
	"audit_trail.captures_record_changes": "21 CFR 11.10(e)",
	"audit_trail.protected_from_modification": "21 CFR 11.10(e)",
	"audit_trail.previous_entries_not_obscured": "21 CFR 11.10(e)",
	"audit_trail.retention.at_least_as_long_as_record": "21 CFR 11.10(e)",
	"operational_checks.sequence_enforcement": "21 CFR 11.10(f)",
	"authority_checks.enabled": "21 CFR 11.10(g)",
	"device_checks.input_validation": "21 CFR 11.10(h)",
	"personnel.training.system_specific": "21 CFR 11.10(i)",
	"personnel.training.records.maintained": "21 CFR 11.10(i)",
	"policies.individual_accountability.documented": "21 CFR 11.10(j)",
	"documentation.distribution.controlled": "21 CFR 11.10(k)(1)",
	"documentation.revision.controlled": "21 CFR 11.10(k)(2)",
	"open_systems.encryption.records_in_transit": "21 CFR 11.30",
	"open_systems.digital_signatures.where_appropriate": "21 CFR 11.30",
	"electronic_signatures.manifestation.printed_name": "21 CFR 11.50(a)(1)",
	"electronic_signatures.manifestation.date_time": "21 CFR 11.50(a)(2)",
	"electronic_signatures.manifestation.meaning": "21 CFR 11.50(a)(3)",
	"electronic_signatures.manifestation.human_readable": "21 CFR 11.50(b)",
	"electronic_signatures.record_linking.cryptographically_bound": "21 CFR 11.70",
	"electronic_signatures.record_linking.tamper_evident": "21 CFR 11.70",
	"electronic_signatures.uniqueness.guaranteed": "21 CFR 11.100(a)",
	"electronic_signatures.identity_verification.before_assignment": "21 CFR 11.100(b)",
	"electronic_signatures.fda_certification.filed": "21 CFR 11.100(c)",
	"electronic_signatures.non_biometric.two_distinct_components": "21 CFR 11.200(a)(1)",
	# was cited as 11.200(a)(2) and (a)(3); those paragraphs are the two checks that follow
	"electronic_signatures.non_biometric.single_session_reauth": "21 CFR 11.200(a)(1)(i)",
	"electronic_signatures.non_biometric.different_session_full_auth": "21 CFR 11.200(a)(1)(ii)",
	"electronic_signatures.non_biometric.genuine_owner_only": "21 CFR 11.200(a)(2)",
	"electronic_signatures.non_biometric.misuse_requires_collaboration": "21 CFR 11.200(a)(3)",
	"electronic_signatures.biometric.designed_exclusively_for_individual": "21 CFR 11.200(b)",
	"identification_codes.uniqueness.maintained": "21 CFR 11.300(a)",
	"identification_codes.periodic_revision": "21 CFR 11.300(b)",
	# loss management was cited as (d), transaction safeguards as (e), detection as (c)
	"identification_codes.loss_management.procedures": "21 CFR 11.300(c)",
	"identification_codes.transaction_safeguards": "21 CFR 11.300(d)",
	"identification_codes.unauthorized_use.detection": "21 CFR 11.300(d)",
	"identification_codes.device_testing.initial_and_periodic": "21 CFR 11.300(e)",
}

test_citation_table_covers_every_check if {
	count(_fact_citations) + count(_scope_facts) == _report({}).total_controls
}

test_each_fact_is_cited_to_its_paragraph if {
	every path, citation in _fact_citations {
		_ids(_report(_set(all_pass, split(path, "."), false))) == {citation}
	}
}

# Missing, null and wrong-typed evidence is never a pass. On main every fact as the string "no" was compliant.
test_non_boolean_evidence_fails if {
	every path, citation in _fact_citations {
		every bad in ["true", "no", 1, null, {}, ["true"]] {
			_ids(_report(_set(all_pass, split(path, "."), bad))) == {citation}
		}
	}
}

test_missing_fact_fails if {
	r := _report(json.remove(all_pass, ["/audit_trail/previous_entries_not_obscured"]))
	_ids(r) == {"21 CFR 11.10(e)"}
	r2 := _report(json.remove(all_pass, ["/audit_trail"]))
	r2.failed_controls == 6
}

# Audit finding 2: IQ/OQ/PQ is not regulation text. It is an advisory and does not score.
test_iq_oq_pq_is_an_advisory_not_a_violation if {
	r := _report(all_pass)
	r.compliant == true
	count(r.advisories) == 1
	count(_report(_set(all_pass, ["system_validation", "iq_oq_pq"], {"documented": true})).advisories) == 0
	every value in [false, null, "yes"] {
		rv := _report(_set(all_pass, ["system_validation", "iq_oq_pq"], {"documented": value}))
		rv.compliant == true
		rv.violation_count == 0
		count(rv.advisories) == 1
	}
	some a in r.advisories
	contains(a, "IQ/OQ/PQ")
	contains(a, "not a 21 CFR Part 11 requirement")
}

test_no_violation_names_iq_oq_pq if {
	every v in _report({}).violations {
		not contains(v, "IQ")
		not contains(v, "Qualification")
	}
}

test_validation_itself_still_scores_as_11_10_a if {
	r := _report(_set(all_pass, ["system_validation", "validated"], false))
	some v in r.violations
	startswith(v, "21 CFR 11.10(a): System not validated to ensure accuracy, reliability, consistent intended performance")
}

# Applicability: only the boolean false exempts a section.
test_closed_system_exempts_11_30_only_on_boolean_false if {
	closed := json.patch(all_pass, [{"op": "replace", "path": "/open_systems", "value": {"in_use": false}}])
	r := _report(closed)
	r.compliant == true
	count(r.not_applicable) == 1
	_report(json.remove(all_pass, ["/open_systems"])).failed_controls == 3

	every bad in ["false", null, 0, "no"] {
		rb := _report(json.patch(all_pass, [{"op": "replace", "path": "/open_systems", "value": {"in_use": bad}}]))
		_ids(rb) == {"21 CFR 11.30"}
		rb.failed_controls == 3
		count(rb.not_applicable) == 0
	}
}

test_biometric_not_in_use_exempts_11_200_b if {
	r := _report(json.patch(all_pass, [{"op": "replace", "path": "/electronic_signatures/biometric", "value": {"in_use": false}}]))
	r.compliant == true
	rm := _report(json.patch(all_pass, [{"op": "replace", "path": "/electronic_signatures/biometric", "value": {}}]))
	_ids(rm) == {"21 CFR 11.200(b)"}
	rm.failed_controls == 2
}

test_non_biometric_exemption_needs_biometric_in_use if {
	nb := [{"op": "replace", "path": "/electronic_signatures/non_biometric", "value": {"in_use": false}}]
	_report(json.patch(all_pass, nb)).compliant == true

	# declaring neither kind in use exempts 11.200(b) only; the five 11.200(a) checks still apply
	neither := array.concat(nb, [{"op": "replace", "path": "/electronic_signatures/biometric", "value": {"in_use": false}}])
	r := _report(json.patch(all_pass, neither))
	r.failed_controls == 5
	every id in _ids(r) {
		startswith(id, "21 CFR 11.200(a)")
	}
}

test_identification_code_applicability if {
	no_devices := [{"op": "replace", "path": "/identification_codes/devices", "value": {"in_use": false}}]
	base := json.remove(all_pass, ["/identification_codes/loss_management", "/identification_codes/device_testing"])
	_ids(_report(base)) == {"21 CFR 11.300(c)", "21 CFR 11.300(e)"}
	_report(json.patch(base, no_devices)).compliant == true

	none := json.patch(all_pass, [{"op": "replace", "path": "/identification_codes", "value": {"in_use": false}}])
	r := _report(none)
	r.compliant == true
	count(r.not_applicable) == 1
	count(_report(json.patch(all_pass, [{"op": "replace", "path": "/identification_codes", "value": {"in_use": "false"}}])).section_summary.s11_300_id_codes) == 8
}
