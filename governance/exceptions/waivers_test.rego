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
