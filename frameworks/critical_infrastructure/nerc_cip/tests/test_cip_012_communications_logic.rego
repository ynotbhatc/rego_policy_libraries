package nerc_cip.cip_012_test

import rego.v1

import data.nerc_cip.cip_012 as c

# Validation 2026-10-17: backup links are checked even without backup_links_exist.

insecure := {"same_protection_level": false, "encryption_enabled": false, "authentication_implemented": false}

secure := {"same_protection_level": true, "encryption_enabled": true, "authentication_implemented": true}

test_insecure_backup_links_without_flag_fail if {
	not c.backup_communication_protected with input as {"communication_contingency": {"backup_links": [insecure]}}
}

test_insecure_backup_links_with_flag_fail if {
	not c.backup_communication_protected with input as {"communication_contingency": {"backup_links_exist": true, "backup_links": [insecure]}}
}

test_secure_backup_links_pass if {
	c.backup_communication_protected with input as {"communication_contingency": {"backup_links": [secure]}}
}

test_explicit_no_backup_links_passes if {
	c.backup_communication_protected with input as {"communication_contingency": {"backup_links_exist": false}}
}

test_missing_contingency_evidence_fails if {
	not c.backup_communication_protected with input as {}
	not c.backup_communication_protected with input as {"communication_contingency": {}}
}

# ---- CIP-012-2 (audit 2026-11-23): parts 1.1-1.5, availability, fixed clock ----

now := time.parse_rfc3339_ns("2026-11-23T00:00:00Z")

good_link := {
	"data_types_identified": true,
	"real_time_assessment_data_flag": true,
	"real_time_monitoring_data_flag": true,
	"encryption_enabled": true,
	"authentication_implemented": true,
	"integrity_protection": true,
	"availability_protection": true,
	"encryption": {"algorithm_documented": true, "key_management_documented": true, "minimum_strength_adequate": true},
	"authentication": {"method_documented": true, "bidirectional": true},
	"other_entity_operated": true,
	"responsibilities_documented": true,
}

good := {
	"control_center_communications": {
		"inventory_maintained": true,
		"criticality_assessed": true,
		"protection_requirements_defined": true,
		"links": [good_link],
		"last_review_date": "2026-03-01T00:00:00Z",
		"last_test_date": "2026-03-01T00:00:00Z",
		"test_documented": true,
	},
	"communication_monitoring": {
		"enabled": true,
		"logging_implemented": true,
		"anomaly_detection": true,
		"alerting_configured": true,
		"last_review_date": "2026-11-10T00:00:00Z",
	},
	"communication_contingency": {
		"plans_documented": true,
		"backup_communications": true,
		"testing_performed": true,
		"recovery_procedures": true,
		"backup_links_exist": false,
	},
}

link_patch(path, value) := json.patch(good, [{"op": "add", "path": sprintf("/control_center_communications/links/0/%s", [path]), "value": value}])

only_requirements(i) := {v.requirement | some v in c.violations with input as i with time.now_ns as now}

test_complete_facts_compliant_and_versioned if {
	c.compliant with input as good with time.now_ns as now
	count(c.violations) == 0 with input as good with time.now_ns as now
	c.report.standard == "CIP-012-2" with input as good with time.now_ns as now
}

# CIP-012-2 has one requirement, R1, with Parts 1.1-1.5.
test_no_label_outside_r1 if {
	every r in only_requirements({}) {
		r in {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5"}
	}
}

test_every_part_reports_on_empty_input if {
	{"R1.1", "R1.2", "R1.3", "R1.4", "R1.5"} & only_requirements({}) == {"R1.1", "R1.2", "R1.3", "R1.4", "R1.5"}
}

# Part 1.2 (new): loss of the ability to communicate.
test_link_without_availability_method_is_part_1_2 if {
	i := link_patch("availability_protection", false)
	not c.communication_availability_protected with input as i
	only_requirements(i) == {"R1.2"}
	not c.compliant with input as i with time.now_ns as now

	# Availability no longer hides inside the Part 1.1 protection check.
	c.communication_protection_implemented with input as i
}

test_availability_needs_a_link_inventory if {
	not c.communication_availability_protected with input as {}
	not c.communication_availability_protected with input as {"control_center_communications": {"links": []}}
}

# Part 1.3 (new): recovery of communication links.
test_missing_recovery_method_is_part_1_3 if {
	i := json.patch(good, [{"op": "replace", "path": "/communication_contingency/recovery_procedures", "value": false}])
	only_requirements(i) == {"R1.3"}
	c.communication_contingency_plans_established with input as i
}

# Part 1.5: responsibilities when another Responsible Entity operates the far end.
test_part_1_5_responsibilities if {
	c.communication_responsibilities_identified with input as good
	c.communication_responsibilities_identified with input as json.patch(good, [
		{"op": "replace", "path": "/control_center_communications/links/0/other_entity_operated", "value": false},
		{"op": "remove", "path": "/control_center_communications/links/0/responsibilities_documented"},
	])
	undocumented := link_patch("responsibilities_documented", false)
	only_requirements(undocumented) == {"R1.5"}
}

test_part_1_5_undeclared_is_not_same_entity if {
	undeclared := json.remove(good, ["/control_center_communications/links/0/other_entity_operated"])
	only_requirements(undeclared) == {"R1.5"}
	untyped := link_patch("other_entity_operated", "no")
	only_requirements(untyped) == {"R1.5"}
}

# Dates: a future review or test date is a finding; an unusable one is evidence missing.
test_future_dates_are_findings if {
	paths := [
		"/communication_monitoring/last_review_date",
		"/control_center_communications/last_review_date",
		"/control_center_communications/last_test_date",
	]
	every path in paths {
		i := json.patch(good, [{"op": "replace", "path": path, "value": "2027-06-01T00:00:00Z"}])
		not c.compliant with input as i with time.now_ns as now
		vs := c.violations with input as i with time.now_ns as now
		count([v | some v in vs; contains(v.description, "later than the evaluation time")]) == 1
	}
}

test_future_log_review_date_fails_the_rule if {
	c.communication_log_review with input as good with time.now_ns as now
	i := json.patch(good, [{"op": "replace", "path": "/communication_monitoring/last_review_date", "value": "2027-06-01T00:00:00Z"}])
	not c.communication_log_review with input as i with time.now_ns as now
}

test_unparseable_date_is_evidence_missing if {
	i := json.patch(good, [{"op": "replace", "path": "/control_center_communications/last_review_date", "value": "01/03/2026"}])
	not c.communication_plan_current with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	"evidence missing — input.control_center_communications.last_review_date not collected or not an RFC 3339 date" in {v.description | some v in vs}
}

test_stale_dates_still_fail if {
	i := json.patch(good, [{"op": "replace", "path": "/communication_monitoring/last_review_date", "value": "2026-10-01T00:00:00Z"}])
	not c.communication_log_review with input as i with time.now_ns as now
	vs := c.violations with input as i with time.now_ns as now
	count(vs) == 1
}
