package nist.sp800_53.pii_processing_transparency_logic_test

import rego.v1

# Logic tests for pii_processing_transparency/pt_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass_base := {"pt_controls": {"policy": {"documented": true, "official_designated": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "procedures": {"documented": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "processing_authority": {"authority_documented": true, "processing_restricted_to_authorized": true}, "processing_purposes": {"purposes_documented": true, "described_in_public_notices": true, "processing_restricted_to_purposes": true, "changes_monitored": true}, "consent": {"mechanism_implemented": true, "obtained_before_collection": true}, "privacy_notice": {"available_at_first_interaction": true, "plain_language": true, "identifies_authority": true, "identifies_purposes": true, "days_since_last": 100, "odp": {"frequency_days": 365}}, "system_of_records_notice": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "specific_categories": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "computer_matching": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.pii_processing_transparency.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.pii_processing_transparency.compliance_report with input as {}
	count(r.violations) == count(data.nist.sp800_53.pii_processing_transparency.evaluated_controls)
	every id in data.nist.sp800_53.pii_processing_transparency.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.pii_processing_transparency.evaluated_controls == {"PT-1", "PT-2", "PT-3", "PT-4", "PT-5", "PT-6", "PT-7", "PT-8", "PT-5(2)", "PT-6(1)", "PT-6(2)", "PT-7(1)", "PT-7(2)"}
}

test_pt1_policy_not_documented_fails if {
	inp := object.union(_pass, {"pt_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_pt1_no_official_fails if {
	inp := object.union(_pass, {"pt_controls": {"policy": {"official_designated": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-1")
	count(f) == 1
	contains(f[0], "official")
}

test_pt1_procedures_review_overdue_fails if {
	inp := object.union(_pass, {"pt_controls": {"procedures": {"days_since_last": 400}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-1")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_pt1_policy_review_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"pt_controls": {"policy": {"odp": {"frequency_days": null}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt1_procedures_documented_string_fails if {
	inp := object.union(_pass, {"pt_controls": {"procedures": {"documented": "true"}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt2_authority_not_documented_fails if {
	inp := object.union(_pass, {"pt_controls": {"processing_authority": {"authority_documented": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-2")
	count(f) == 1
	contains(f[0], "authority")
}

test_pt2_restricted_null_is_evidence_missing if {
	inp := object.union(_pass, {"pt_controls": {"processing_authority": {"processing_restricted_to_authorized": null}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-2")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt3_not_in_public_notice_fails if {
	inp := object.union(_pass, {"pt_controls": {"processing_purposes": {"described_in_public_notices": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-3")
	count(f) == 1
	contains(f[0], "public privacy notices")
}

test_pt3_changes_monitored_string_true_fails if {
	inp := object.union(_pass, {"pt_controls": {"processing_purposes": {"changes_monitored": "true"}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt4_no_mechanism_fails if {
	inp := object.union(_pass, {"pt_controls": {"consent": {"mechanism_implemented": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-4")
	count(f) == 1
	contains(f[0], "consent")
}

test_pt4_consent_after_collection_fails if {
	inp := object.union(_pass, {"pt_controls": {"consent": {"obtained_before_collection": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-4")
	count(f) == 1
	contains(f[0], "before PII is collected")
}

test_pt5_notice_overdue_fails if {
	inp := object.union(_pass, {"pt_controls": {"privacy_notice": {"days_since_last": 400}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-5")
	count(f) == 1
	contains(f[0], "privacy notice provided last 400 days ago")
}

test_pt5_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"pt_controls": {"privacy_notice": {"days_since_last": "1"}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt5_odp_null_is_evidence_missing if {
	inp := object.union(_pass, {"pt_controls": {"privacy_notice": {"odp": {"frequency_days": null}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_pt5_not_plain_language_fails if {
	inp := object.union(_pass, {"pt_controls": {"privacy_notice": {"plain_language": false}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-5")
	count(f) == 1
	contains(f[0], "plain language")
}

test_pt6_attestation_missing_fails if {
	inp := object.union(_pass, {"pt_controls": {"system_of_records_notice": {"attestation": null}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-6")
	count(f) == 1
	contains(f[0], "attestation")
}

test_pt6_attested_string_true_fails if {
	inp := object.union(_pass, {"pt_controls": {"system_of_records_notice": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-6")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_pt6_attestation_empty_by_fails if {
	inp := object.union(_pass, {"pt_controls": {"system_of_records_notice": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-6")
	count(f) == 1
	contains(f[0], "attestation")
}

test_pt7_attestation_missing_fails if {
	inp := object.union(_pass, {"pt_controls": {"specific_categories": {"attestation": null}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-7")
	count(f) == 1
	contains(f[0], "attestation")
}

test_pt7_attested_string_true_fails if {
	inp := object.union(_pass, {"pt_controls": {"specific_categories": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-7")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_pt7_attestation_empty_by_fails if {
	inp := object.union(_pass, {"pt_controls": {"specific_categories": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-7")
	count(f) == 1
	contains(f[0], "attestation")
}

test_pt8_attestation_missing_fails if {
	inp := object.union(_pass, {"pt_controls": {"computer_matching": {"attestation": null}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-8")
	count(f) == 1
	contains(f[0], "attestation")
}

test_pt8_attested_string_true_fails if {
	inp := object.union(_pass, {"pt_controls": {"computer_matching": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-8")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_pt8_attestation_empty_by_fails if {
	inp := object.union(_pass, {"pt_controls": {"computer_matching": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	count(v) == 1
	f := _flagged(v, "PT-8")
	count(f) == 1
	contains(f[0], "attestation")
}

# The all-pass fixture with the facts of the Privacy-baseline enhancements.
_pass := object.union(_pass_base, {"pt_controls": {"privacy_notice": {"privacy_act_statements": {"forms_without_statement": 0}}, "system_of_records_notice": {"routine_uses": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "exemptions": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}}, "specific_categories": {"social_security_numbers": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "first_amendment": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}}}})

# --- Privacy-baseline enhancements and count type traps: each case flips exactly one id ---

test_privacy_pt5_2_fails_1 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"privacy_notice": {"privacy_act_statements": {"forms_without_statement": 3}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-5(2)"}
	some x in v
	contains(x, "no Privacy Act statement")
}

test_privacy_pt5_2_evidence_missing_2 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"privacy_notice": {"privacy_act_statements": {"forms_without_statement": "0"}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-5(2)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_pt6_1_attested_passes if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as _pass
	count(_flagged(v, "PT-6(1)")) == 0
}

test_privacy_pt6_1_fails_1 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"routine_uses": {"attestation": {"attested": false}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(1)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt6_1_malformed_attestation_fails if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"routine_uses": {"attestation": {"attested": "true", "date": 20261101}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(1)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt6_1_evidence_missing_2 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"routine_uses": {"attestation": null}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(1)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_pt6_1_old_review_facts_do_not_pass if {
	inp := {"pt_controls": {"system_of_records_notice": {"routine_uses": {"days_since_last": 100, "odp": {"frequency_days": 365}, "compatible_with_collection_purpose": true}}}}
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as inp
	f := _flagged(v, "PT-6(1)")
	count(f) == 1
	contains(f[0], "not attested")
}

test_privacy_pt6_2_attested_passes if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as _pass
	count(_flagged(v, "PT-6(2)")) == 0
}

test_privacy_pt6_2_fails_1 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"exemptions": {"attestation": {"attested": false}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(2)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt6_2_malformed_attestation_fails if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"exemptions": {"attestation": {"by": "   "}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(2)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt6_2_evidence_missing_2 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"system_of_records_notice": {"exemptions": {"attestation": "yes"}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-6(2)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_pt7_1_fails_1 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"specific_categories": {"social_security_numbers": {"attestation": {"attested": false}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-7(1)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt7_1_evidence_missing_2 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"specific_categories": {"social_security_numbers": {"attestation": null}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-7(1)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_pt7_2_fails_1 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"specific_categories": {"first_amendment": {"attestation": {"by": ""}}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-7(2)"}
	some x in v
	contains(x, "not attested")
}

test_privacy_pt7_2_evidence_missing_2 if {
	v := data.nist.sp800_53.pii_processing_transparency.violation with input as object.union(_pass, {"pt_controls": {"specific_categories": {"first_amendment": {"attestation": null}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"PT-7(2)"}
	some x in v
	contains(x, "evidence missing")
}
