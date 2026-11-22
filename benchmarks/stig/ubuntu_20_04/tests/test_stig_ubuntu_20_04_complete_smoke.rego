package stig.ubuntu_20_04_test

import rego.v1

# Smoke and rule tests for benchmarks/stig/ubuntu_20_04/stig_ubuntu_20_04_complete.rego, against the V2R4 check
# text (2026-11-21). Missing evidence is Open with an "evidence missing" detail, never Not_a_Finding.

test_stig_ubuntu_20_04_complete_loads_on_empty_input if {
	m := data.stig.ubuntu_20_04 with input as {}
	is_object(m)
}

test_findings_open_without_evidence if {
	data.stig.ubuntu_20_04.vendor_supported_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.dod_root_ca_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.password_history_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.password_length_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.compliant == false with input as {"x": 1}
}

test_evidence_missing_details if {
	every d in [
		data.stig.ubuntu_20_04.vendor_supported_detail,
		data.stig.ubuntu_20_04.dod_root_ca_detail,
		data.stig.ubuntu_20_04.password_history_detail,
		data.stig.ubuntu_20_04.password_length_detail,
	] {
		contains(d, "evidence missing")
	}
}

test_all_pass_with_evidence if {
	inp := {
		"attest": {"ubuntu_20_04_vendor_supported": true},
		"certificates": {"dod_root_ca_installed": true},
		"password_policy": {"password_history_size": 5, "minimum_password_length": 15},
	}
	data.stig.ubuntu_20_04.compliant == true with input as inp
	r := data.stig.ubuntu_20_04.stig_assessment with input as inp
	count(r.rule_results) == 4
}

test_disa_thresholds if {
	data.stig.ubuntu_20_04.password_length_status == "Open" with input as {"password_policy": {"minimum_password_length": 14}}
	data.stig.ubuntu_20_04.password_history_status == "Open" with input as {"password_policy": {"password_history_size": 4}}
	data.stig.ubuntu_20_04.password_history_status == "Not_a_Finding" with input as {"password_policy": {"password_history_size": 5}}
}

test_non_boolean_evidence_open if {
	data.stig.ubuntu_20_04.dod_root_ca_status == "Open" with input as {"certificates": {"dod_root_ca_installed": "true"}}
	data.stig.ubuntu_20_04.vendor_supported_status == "Open" with input as {"attest": {"ubuntu_20_04_vendor_supported": "yes"}}
	d := data.stig.ubuntu_20_04.vendor_supported_detail with input as {"attest": {"ubuntu_20_04_vendor_supported": false}}
	contains(d, "check failed")
}
