package exceptions_test

import rego.v1

import data.exceptions

# Expiry dates deliberately far in the future / past so tests need no clock mocking.
active_entry := {
	"host": "web01",
	"framework": "cis_rhel9",
	"control_id": "5.2.1",
	"reason": "Compensating control in place",
	"approver": "sec-officer@example.com",
	"expires": "2200-01-01",
}

expired_entry := object.union(active_entry, {"expires": "2000-01-01"})

wildcard_entry := object.union(active_entry, {"host": "*", "framework": "*"})

violations_in := [
	"CIS 5.2.1: SSH PermitRootLogin must be disabled",
	"CIS 1.1.1: cramfs must be disabled",
]

test_active_waiver_filters_matching_violation if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}
	d.waived_count == 1
	d.active_violations == ["CIS 1.1.1: cramfs must be disabled"]
	count(d.waived) == 1
}

test_waived_set_carries_full_waiver_record if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}
	some w in d.waived
	w.waiver.approver == "sec-officer@example.com"
	w.waiver.reason == "Compensating control in place"
}

test_expired_waiver_does_not_filter_and_is_surfaced if {
	d := exceptions.decision with data.waivers as {"entries": [expired_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}
	d.waived_count == 0
	count(d.active_violations) == 2
	count(d.expired_matches) == 1
}

test_wrong_host_does_not_match if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "db01", "framework": "cis_rhel9", "violations": violations_in}
	d.waived_count == 0
	count(d.active_violations) == 2
}

test_wrong_framework_does_not_match if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "nerc_cip", "violations": violations_in}
	d.waived_count == 0
}

test_wildcard_host_and_framework_match if {
	d := exceptions.decision with data.waivers as {"entries": [wildcard_entry]}
		with input as {"host": "anything", "framework": "nerc_cip", "violations": violations_in}
	d.waived_count == 1
}

test_object_violations_match_on_serialized_content if {
	obj_violations := [{"control": "CIS 5.2.1", "detail": "PermitRootLogin yes"}]
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": obj_violations}
	d.waived_count == 1
	d.active_violations == []
}

test_no_waiver_data_loaded_is_a_noop if {
	d := exceptions.decision with data.waivers as {}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}
	d.waived_count == 0
	count(d.active_violations) == 2
	d.waiver_entries_loaded == 0
}

test_entry_without_expiry_never_matches if {
	no_expiry := object.remove(active_entry, ["expires"])
	d := exceptions.decision with data.waivers as {"entries": [no_expiry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}
	d.waived_count == 0
}

test_empty_violations_yields_empty_decision if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": []}
	d.waived_count == 0
	d.active_violations == []
}

# Semantic review 2026-11-13: a waiver for a control id must not waive longer ids that contain it.
test_waiver_does_not_match_longer_control_ids if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": [
			"CIS 5.2.10: other control",
			"CIS 15.2.1: other control",
			"CIS 5.2.1.3: other control",
			"CIS 5.2.1: SSH PermitRootLogin must be disabled",
		]}
	d.waived_count == 1
	count(d.active_violations) == 3
}

test_waiver_matches_id_followed_by_sentence_period if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]}
		with input as {"host": "web01", "framework": "cis_rhel9", "violations": ["Failed CIS 5.2.1. Fix it"]}
	d.waived_count == 1
}

# ── Site settings: required fields, maximum time to live, expiring soon ──────

# 2026-11-20T00:00:00Z
now_ns := 1795132800000000000

near_entry := object.union(active_entry, {"expires": "2026-12-20"})

mitigated_entry := object.union(near_entry, {"mitigation": "WAF rule 4411", "evidence_ref": "CR-2201"})

in_web01 := {"host": "web01", "framework": "cis_rhel9", "violations": violations_in}

test_no_settings_changes_nothing if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry]} with input as in_web01
	d.waived_count == 1
	d.rejected_count == 0
	count(d.rejected) == 0
}

test_required_mitigation_rejects_entry_without_one if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"required_fields": ["reason", "approver", "mitigation"]}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
	d.rejected_count == 1
	count(d.active_violations) == 2
	some r in d.rejected
	r.problems == ["required field mitigation is missing or empty"]
}

test_blank_mitigation_counts_as_missing if {
	d := exceptions.decision with data.waivers as {"entries": [object.union(near_entry, {"mitigation": "   "})], "settings": {"required_fields": ["mitigation"]}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
	d.rejected_count == 1
}

test_non_string_mitigation_counts_as_missing if {
	d := exceptions.decision with data.waivers as {"entries": [object.union(near_entry, {"mitigation": true})], "settings": {"required_fields": ["mitigation"]}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
}

test_required_mitigation_accepts_entry_with_one if {
	d := exceptions.decision with data.waivers as {"entries": [mitigated_entry], "settings": {"required_fields": ["reason", "approver", "mitigation"]}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 1
	d.rejected_count == 0
	some w in d.waived
	w.waiver.mitigation == "WAF rule 4411"
	w.waiver.evidence_ref == "CR-2201"
}

test_max_ttl_rejects_far_expiry if {
	d := exceptions.decision with data.waivers as {"entries": [active_entry], "settings": {"max_ttl_days": 180}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
	d.rejected_count == 1
	some r in d.rejected
	r.problems == ["expires more than 180 days ahead (maximum time to live)"]
}

test_max_ttl_accepts_expiry_inside_the_limit if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"max_ttl_days": 180}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 1
	d.rejected_count == 0
}

test_max_ttl_boundary_exactly_at_limit_is_accepted if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"max_ttl_days": 30}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 1
}

test_max_ttl_one_day_over_is_rejected if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"max_ttl_days": 29}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
}

test_malformed_max_ttl_rejects_every_entry if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"max_ttl_days": "180"}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
	some r in d.rejected
	"setting max_ttl_days is not a positive number" in r.problems
}

test_malformed_required_fields_rejects_every_entry if {
	d := exceptions.decision with data.waivers as {"entries": [mitigated_entry], "settings": {"required_fields": "mitigation"}}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 0
	d.rejected_count == 1
}

test_expired_entry_is_reported_as_expired_not_rejected if {
	d := exceptions.decision with data.waivers as {"entries": [expired_entry], "settings": {"required_fields": ["mitigation"]}}
		with input as in_web01
		with time.now_ns as now_ns
	d.rejected_count == 0
	count(d.expired_matches) == 1
}

test_expiring_soon_lists_waiver_inside_the_window if {
	d := exceptions.decision with data.waivers as {"entries": [object.union(near_entry, {"expires": "2026-11-27"})]}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 1
	some e in d.expiring_soon
	e.days_left == 7
}

test_expiring_soon_empty_outside_the_window if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry]}
		with input as in_web01
		with time.now_ns as now_ns
	d.waived_count == 1
	count(d.expiring_soon) == 0
}

test_expiring_window_setting_is_honoured if {
	d := exceptions.decision with data.waivers as {"entries": [near_entry], "settings": {"expiring_within_days": 45}}
		with input as in_web01
		with time.now_ns as now_ns
	count(d.expiring_soon) == 1
}
