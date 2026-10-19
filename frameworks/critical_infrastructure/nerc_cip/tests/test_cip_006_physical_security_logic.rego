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

# decisions 2026-10-19: PCA and standalone-asset protection are required and produce violations.
test_pca_unprotected_violation_and_not_compliant if {
	i := {"protected_cyber_assets": [{"physical_protection": {"in_psp": true, "access_logged": false}}]}
	not c.pca_physically_protected with input as i
	count([x | some x in c.violations with input as i; x.requirement == "R2"; contains(x.description, "Protected Cyber Assets")]) == 1
	not c.compliant with input as i
}

test_pca_explicit_false_not_applicable if {
	c.pca_physically_protected with input as {"protected_cyber_assets": false}
}

test_standalone_unprotected_violation if {
	i := {"standalone_bes_cyber_assets": [{"impact_categorization": "high", "physical_protection_documented": false, "access_controlled": true}]}
	count([x | some x in c.violations with input as i; x.requirement == "R1.5"]) == 1
}

test_standalone_explicit_false_not_applicable if {
	c.standalone_assets_protected with input as {"standalone_bes_cyber_assets": false}
}

test_report_lists_pca_and_standalone if {
	r := c.report with input as {}
	r.requirements.R2_pca_protected == false
	r.requirements.R1_5_standalone_protected == false
}
