package digital_sovereignty.network_sovereignty_fixes_test

import rego.v1

ns := data.digital_sovereignty.network_sovereignty

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_transit_flag_absent_not_protected if {
	not ns.sensitive_traffic_protected with input as {"traffic_routing": {}}
	has_control(ns.violations, "NS-006") with input as {"traffic_routing": {}}
}

test_transit_flag_missing_section_not_protected if not ns.sensitive_traffic_protected with input as {}

test_transit_false_protected if ns.sensitive_traffic_protected with input as {"traffic_routing": {"sensitive_traffic_transits_foreign_country": false}}

test_transit_true_unencrypted_not_protected if not ns.sensitive_traffic_protected with input as {"traffic_routing": {"sensitive_traffic_transits_foreign_country": true, "encrypted_if_transits_foreign": false}}

test_transit_true_encrypted_protected if ns.sensitive_traffic_protected with input as {"traffic_routing": {"sensitive_traffic_transits_foreign_country": true, "encrypted_if_transits_foreign": true}}

test_regulated_segment_without_location_violates if {
	inp := {"approved_jurisdictions": ["DE"], "network_segments": [{"segment_id": "s1", "handles_regulated_data": true}]}
	not ns.segments_in_approved_jurisdictions with input as inp
	has_control(ns.violations, "NS-011") with input as inp
}

test_regulated_segment_in_approved_ok if {
	inp := {"approved_jurisdictions": ["DE"], "network_segments": [{"segment_id": "s1", "handles_regulated_data": true, "location_country": "DE"}]}
	ns.segments_in_approved_jurisdictions with input as inp
}

test_unregulated_segment_without_location_ok if {
	inp := {"approved_jurisdictions": ["DE"], "network_segments": [{"segment_id": "s1", "handles_regulated_data": false}]}
	ns.segments_in_approved_jurisdictions with input as inp
}

test_report_defined_when_segment_fails if {
	r := ns.report with input as {"approved_jurisdictions": ["DE"], "network_segments": [{"segment_id": "s1", "handles_regulated_data": true, "location_country": "US"}]}
	r.compliant == false
	r.controls["NS-011_segments_in_jurisdiction"] == false
	r.violation_count > 0
}

test_dns_logs_string_value_not_retained if not ns.dns_logs_retained with input as {"dns_configuration": {"dns_logs_retained_days": "30"}}

test_dns_logs_90_retained if ns.dns_logs_retained with input as {"dns_configuration": {"dns_logs_retained_days": 90}}

test_netflow_string_retention_not_ok if not ns.netflow_monitoring with input as {"network_monitoring": {"netflow_collection_enabled": true, "retention_days": "7"}}

test_netflow_numeric_retention_ok if ns.netflow_monitoring with input as {"network_monitoring": {"netflow_collection_enabled": true, "retention_days": 120}}

test_missing_resolver_country_still_reports_ns002 if has_control(ns.violations, "NS-002") with input as {"approved_jurisdictions": ["DE"], "dns_configuration": {}}

test_missing_egress_country_still_reports_ns008 if has_control(ns.violations, "NS-008") with input as {"approved_jurisdictions": ["DE"], "internet_egress": {}}
