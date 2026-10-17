package nerc_cip_cip015_test

import rego.v1

import data.nerc_cip_cip015 as c

# Validation 2026-10-17: scope filter, AND-ed sub-requirements, evidence required.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

good_system := {
	"system_id": "S1",
	"esp_name": "ESP-1",
	"impact_categorization": "high",
	"has_external_routable_connectivity": true,
	"network_baseline": {"established": true, "documented": true},
	"anomaly_detection": {"implemented": true, "covers_esp": true},
	"malicious_comm_detection": {"capability_documented": true, "tools": ["ids"]},
	"response_process": {"documented": true, "includes_notification": true, "includes_investigation": true},
}

base := {"insm": {
	"systems": [good_system],
	"categorization_review_date": now_rfc,
	"documentation_review": {"documented": true, "reviewer": "r", "last_review_date": now_rfc},
}}

test_good_inventory_compliant if {
	c.cip_015_compliant with input as base
	c.cip_015_score == 100 with input as base
}

test_low_impact_system_does_not_fail_r1 if {
	low := {"system_id": "L1", "impact_categorization": "low"}
	i := json.patch(base, [{"op": "add", "path": "/insm/systems/-", "value": low}])
	c.r1_systems_identified with input as i
	c.cip_015_compliant with input as i
}

test_no_erc_system_does_not_fail_r1 if {
	noerc := {"system_id": "N1", "impact_categorization": "medium", "has_external_routable_connectivity": false}
	i := json.patch(base, [{"op": "add", "path": "/insm/systems/-", "value": noerc}])
	c.r1_systems_identified with input as i
}

test_applicable_system_without_esp_name_fails_r1 if {
	i := json.remove(base, ["insm/systems/0/esp_name"])
	not c.r1_systems_identified with input as i
}

test_baseline_documented_but_not_established_is_not_met if {
	i := json.patch(base, [{"op": "replace", "path": "/insm/systems/0/network_baseline/established", "value": false}])
	not c.r2_1_compliant with input as i
	not c.cip_015_compliant with input as i
	c.cip_015_score < 100 with input as i
}

test_established_but_not_documented_baseline_is_a_violation if {
	i := json.patch(base, [{"op": "replace", "path": "/insm/systems/0/network_baseline/documented", "value": false}])
	not c.r2_1_compliant with input as i
	not c.r2_compliant with input as i
	v := c.r2_violations with input as i
	count(v) == 1
}

test_anomaly_detection_must_cover_esp if {
	i := json.patch(base, [{"op": "replace", "path": "/insm/systems/0/anomaly_detection/covers_esp", "value": false}])
	not c.r2_2_compliant with input as i
	not c.r2_compliant with input as i
}

test_malicious_comm_tools_required if {
	i := json.patch(base, [{"op": "replace", "path": "/insm/systems/0/malicious_comm_detection/tools", "value": []}])
	not c.r2_3_compliant with input as i
}

test_response_process_needs_all_elements if {
	i := json.patch(base, [{"op": "replace", "path": "/insm/systems/0/response_process/includes_investigation", "value": false}])
	not c.r2_4_compliant with input as i
	not c.r2_compliant with input as i
}

test_no_systems_r2_not_compliant if {
	not c.r2_compliant with input as {}
	not c.r2_compliant with input as {"insm": {"systems": []}}
}
