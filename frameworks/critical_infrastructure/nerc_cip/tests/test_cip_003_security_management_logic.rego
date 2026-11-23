package nerc_cip.cip_003_test

import rego.v1

import data.nerc_cip.cip_003 as c

# Fixed evaluation clock for every date test.
now := time.parse_rfc3339_ns("2026-11-23T00:00:00Z")

low_only := [{"system_id": "S1", "impact_categorization": "low"}]

high_only := [{"system_id": "S1", "impact_categorization": "high"}]

# A complete CIP-003-9 fact set for an entity with high and low impact systems.
good := {
	"bes_cyber_systems": [
		{"system_id": "H1", "impact_categorization": "high"},
		{"system_id": "L1", "impact_categorization": "low"},
	],
	"cybersecurity_organization": {
		"senior_manager": {
			"designated": true,
			"name": "A. Manager",
			"title": "VP Operations",
			"authority_documented": true,
			"responsibilities_defined": true,
			"accountability_documented": true,
		},
		"delegated_authority": false,
	},
	"cybersecurity_policies": {
		"documented": true,
		"approved": true,
		"cip_senior_manager_approved": true,
		"last_review_date": "2026-06-01T00:00:00Z",
		"areas": {
			"personnel_and_training": true,
			"electronic_security_perimeters": true,
			"physical_security": true,
			"systems_security_management": true,
			"incident_response": true,
			"recovery_plans": true,
			"configuration_management": true,
			"information_protection": true,
			"cip_exceptional_circumstances": true,
		},
		"low_impact_areas": {
			"cyber_security_awareness": true,
			"physical_security_controls": true,
			"electronic_access_controls": true,
			"cyber_security_incident_response": true,
			"transient_cyber_assets_and_removable_media": true,
			"vendor_electronic_remote_access": true,
			"cip_exceptional_circumstances": true,
		},
	},
	"low_impact_plan": {
		"documented": true,
		"approved": true,
		"last_review_date": "2026-06-01T00:00:00Z",
		"cyber_security_awareness": true,
		"physical_security_controls": true,
		"electronic_access_controls": true,
		"cyber_security_incident_response": true,
		"transient_cyber_asset_controls": true,
		"vendor_electronic_remote_access": {
			"allowed": true,
			"determine_method": true,
			"disable_method": true,
			"malicious_communications_detection": true,
		},
	},
	"transient_cyber_assets": {
		"policy_documented": true,
		"asset_management": {"inventory_maintained": true, "authorization_required": true},
		"controls": {"malicious_code_prevention": true, "security_patches": {"applied": true, "documented": true}},
	},
	"removable_media": {
		"policy_documented": true,
		"authorization_required": true,
		"scanning_before_use": true,
		"encryption_when_applicable": true,
	},
}

reqs(vs) := {v.requirement | some v in vs}

test_complete_facts_are_compliant if {
	c.compliant with input as good with time.now_ns as now
	count(c.violations) == 0 with input as good with time.now_ns as now
	c.report.standard == "CIP-003-9" with input as good with time.now_ns as now
}

# ---- applicability -----------------------------------------------------------

# An absent BES Cyber System inventory does not waive R2 (validation 2026-10-17).
test_no_inventory_does_not_waive_low_impact_plan if {
	not c.low_impact_plan_implemented with input as {}
	not c.low_impact_plan_reviewed with input as {}
	not c.low_impact_vendor_remote_access_controlled with input as {}
	not c.low_impact_policy_areas_covered with input as {}
}

test_inventory_without_low_systems_waives_r2 if {
	i := {"bes_cyber_systems": high_only}
	c.low_impact_plan_implemented with input as i
	c.low_impact_plan_reviewed with input as i
	c.low_impact_vendor_remote_access_controlled with input as i
	c.low_impact_policy_areas_covered with input as i
	c.transient_cyber_asset_policy with input as i
	c.removable_media_controls with input as i
	not "R2" in reqs(c.violations) with input as i
}

test_inventory_without_high_medium_waives_part_1_1 if {
	c.required_policy_areas_covered with input as {"bes_cyber_systems": low_only}
	not c.required_policy_areas_covered with input as {"bes_cyber_systems": high_only}
}

test_low_system_requires_plan if {
	not c.low_impact_plan_implemented with input as {"bes_cyber_systems": low_only}
}

# ---- requirement labels follow CIP-003-9 ---------------------------------------

test_labels_follow_the_standard if {
	vs := c.violations with input as {}
	rs := reqs(vs)

	# R1 policies, R2 low impact plan, R3 CIP Senior Manager, R4 delegation.
	{"R1", "R2", "R3", "R4"} & rs == {"R1", "R2", "R3", "R4"}

	# CIP-003-9 has no R5.
	not "R5" in rs
	some v in vs
	v.requirement == "R3"
	contains(v.description, "CIP Senior Manager")
}

test_every_missing_policy_topic_is_named_by_part if {
	vs := c.violations with input as {}
	rs := reqs(vs)
	every part in {"R1.1.1", "R1.1.8", "R1.1.9", "R1.2.1", "R1.2.6", "R1.2.7"} {
		part in rs
	}
}

test_information_sharing_plan_is_advisory_only if {
	c.report.advisory.information_sharing_plan == false with input as good with time.now_ns as now
	c.compliant with input as good with time.now_ns as now
	not "information_sharing_plan" in object.keys(c.report.requirements) with input as good with time.now_ns as now
}

# ---- new in version 9: vendor electronic remote access (low impact) -----------

test_part_1_2_6_vendor_remote_access_policy_topic if {
	i := json.patch(good, [{"op": "replace", "path": "/cybersecurity_policies/low_impact_areas/vendor_electronic_remote_access", "value": false}])
	vs := c.violations with input as i with time.now_ns as now
	reqs(vs) == {"R1.2.6"}
	not c.compliant with input as i with time.now_ns as now
}

test_section_6_each_method_required if {
	every method in ["determine_method", "disable_method", "malicious_communications_detection"] {
		i := json.patch(good, [{"op": "replace", "path": sprintf("/low_impact_plan/vendor_electronic_remote_access/%s", [method]), "value": false}])
		vs := c.violations with input as i with time.now_ns as now
		count(vs) == 1
		some v in vs
		v.requirement == "R2"
		contains(v.description, method)
		contains(v.description, "Section 6")
		not c.compliant with input as i with time.now_ns as now
	}
}

test_section_6_explicit_not_allowed_is_not_applicable if {
	i := json.patch(good, [{"op": "replace", "path": "/low_impact_plan/vendor_electronic_remote_access", "value": {"allowed": false}}])
	c.low_impact_vendor_remote_access_controlled with input as i
	c.compliant with input as i with time.now_ns as now
}

test_section_6_absent_or_untyped_statement_is_evidence_missing if {
	absent := json.remove(good, ["/low_impact_plan/vendor_electronic_remote_access"])
	untyped := json.patch(good, [{"op": "replace", "path": "/low_impact_plan/vendor_electronic_remote_access", "value": {"allowed": "no"}}])
	every i in [absent, untyped] {
		not c.low_impact_vendor_remote_access_controlled with input as i
		vs := c.violations with input as i with time.now_ns as now
		count(vs) == 1
		some v in vs
		startswith(v.description, "evidence missing")
		contains(v.description, "Section 6")
	}
}

test_section_1_awareness_required_in_plan if {
	i := json.patch(good, [{"op": "replace", "path": "/low_impact_plan/cyber_security_awareness", "value": false}])
	not c.low_impact_plan_implemented with input as i
}

# ---- R4 delegation ------------------------------------------------------------

test_delegation_absent_is_evidence_missing_not_exempt if {
	i := json.remove(good, ["/cybersecurity_organization/delegated_authority"])
	not c.delegation_documented with input as i
	vs := c.violations with input as i with time.now_ns as now
	count(vs) == 1
	some v in vs
	v.requirement == "R4"
	startswith(v.description, "evidence missing")
}

test_delegation_explicit_none_and_documented_pass if {
	c.delegation_documented with input as good
	d := {"exists": true, "documented": true, "current": true, "delegate_name": "B. Delegate", "scope_defined": true}
	c.delegation_documented with input as json.patch(good, [{"op": "replace", "path": "/cybersecurity_organization/delegated_authority", "value": d}])
	c.delegation_documented with input as json.patch(good, [{"op": "replace", "path": "/cybersecurity_organization/delegated_authority", "value": {"exists": false}}])
}

test_undocumented_delegation_has_a_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/cybersecurity_organization/delegated_authority", "value": {"exists": true, "documented": false}}])
	vs := c.violations with input as i with time.now_ns as now
	count(vs) == 1
	some v in vs
	v.requirement == "R4"
	not startswith(v.description, "evidence missing")
}

# ---- dates: stale, future, missing --------------------------------------------

with_policy_review(d) := json.patch(good, [{"op": "replace", "path": "/cybersecurity_policies/last_review_date", "value": d}])

test_policy_review_within_15_months_passes if {
	c.policy_review_current with input as with_policy_review("2025-09-01T00:00:00Z") with time.now_ns as now
}

test_policy_review_older_than_15_months_fails if {
	i := with_policy_review("2025-07-01T00:00:00Z")
	not c.policy_review_current with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	{v.description | some v in vs} == {"Cybersecurity policies not reviewed within 15 calendar months"}
}

test_future_policy_review_date_is_a_finding if {
	i := with_policy_review("2027-01-01T00:00:00Z")
	not c.policy_review_current with input as i with time.now_ns as now
	not c.compliant with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	some v in vs
	v.requirement == "R1"
	contains(v.description, "later than the evaluation time")
	contains(v.description, "cybersecurity_policies.last_review_date")
}

test_unparseable_or_missing_policy_review_date_is_evidence_missing if {
	every i in [with_policy_review("last spring"), with_policy_review(true), json.remove(good, ["/cybersecurity_policies/last_review_date"])] {
		not c.policy_review_current with input as i with time.now_ns as now
		vs := c.violations with input as i with time.now_ns as now
		some v in vs
		v.description == "evidence missing — input.cybersecurity_policies.last_review_date not collected or not an RFC 3339 date"
	}
}

test_future_low_impact_plan_review_date_is_a_finding if {
	i := json.patch(good, [{"op": "replace", "path": "/low_impact_plan/last_review_date", "value": "2031-01-01T00:00:00Z"}])
	not c.low_impact_plan_reviewed with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	some v in vs
	v.requirement == "R2"
	contains(v.description, "later than the evaluation time")
}

test_future_information_sharing_review_does_not_pass_advisory if {
	plan := {"documented": true, "nerc_contact_included": true, "regional_entity_contact_included": true, "contacts_current": true}
	ok := object.union(good, {"information_sharing_plan": object.union(plan, {"last_review_date": "2026-01-01T00:00:00Z"})})
	future := object.union(good, {"information_sharing_plan": object.union(plan, {"last_review_date": "2028-01-01T00:00:00Z"})})
	c.information_sharing_plan_exists with input as ok with time.now_ns as now
	not c.information_sharing_plan_exists with input as future with time.now_ns as now
}

# ---- Attachment 1 Section 5 (was mislabelled "R4") ----------------------------

test_removable_media_violation_alone_is_r2 if {
	i := json.remove(good, ["/removable_media"])
	vs := c.violations with input as i with time.now_ns as now
	count(vs) == 1
	some v in vs
	v.requirement == "R2"
	contains(v.description, "Section 5.3")
}
