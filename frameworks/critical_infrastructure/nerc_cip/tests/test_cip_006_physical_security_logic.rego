package nerc_cip.cip_006_test

import rego.v1

import data.nerc_cip.cip_006 as c

# Validation 2026-10-17: ISO-8601 review dates and missing roster.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

person(d) := {"person_id": "p1", "access_level": "authorized_unescorted_physical_access", "physical_access_authorization": {"last_review_date": d}}

test_recent_iso_review_passes if {
	c.physical_access_authorization_reviewed with input as {"personnel": [person(now_rfc)]}
}

test_old_iso_review_fails if {
	not c.physical_access_authorization_reviewed with input as {"personnel": [person("2019-01-01T00:00:00Z")]}
}

test_missing_review_date_fails if {
	p := {"person_id": "p1", "access_level": "authorized_unescorted_physical_access"}
	not c.physical_access_authorization_reviewed with input as {"personnel": [p]}
}

test_no_roster_fails if {
	not c.physical_access_authorization_reviewed with input as {}
	not c.physical_access_authorization_reviewed with input as {"personnel": []}
}

test_violation_listed_for_old_review if {
	v := c.violations with input as {"personnel": [person("2019-01-01T00:00:00Z")]}
	count([x | some x in v; x.requirement == "R3"]) == 1
}

test_standalone_low_asset_out_of_scope if {
	assets := [
		{"impact_categorization": "high", "physical_protection_documented": true, "access_controlled": true},
		{"impact_categorization": "low"},
	]
	c.standalone_assets_protected with input as {"standalone_bes_cyber_assets": assets}
}
