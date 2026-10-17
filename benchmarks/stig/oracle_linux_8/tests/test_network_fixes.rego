package stig.oracle_linux_8.network_test

import rego.v1

# Validation fixes 2026-10-17: missing interface lists are Open, and compliant requires evidence.

test_network_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.network.compliant with input as {}
}

test_network_missing_wireless_list_is_open if {
	data.stig.oracle_linux_8.network.status_ol08_00_040110 == "Open" with input as {"kernel_params": {}}
}

test_network_empty_wireless_list_is_not_a_finding if {
	data.stig.oracle_linux_8.network.status_ol08_00_040110 == "Not_a_Finding" with input as {"wireless_interfaces": []}
}

test_network_wireless_disabled_flag_is_not_a_finding if {
	data.stig.oracle_linux_8.network.status_ol08_00_040110 == "Not_a_Finding" with input as {"network_config": {"wireless_disabled": true}}
}

test_network_missing_promiscuous_list_is_open if {
	data.stig.oracle_linux_8.network.status_ol08_00_040330 == "Open" with input as {"kernel_params": {}}
}

test_network_empty_promiscuous_list_is_not_a_finding if {
	data.stig.oracle_linux_8.network.status_ol08_00_040330 == "Not_a_Finding" with input as {"promiscuous_interfaces": []}
}

test_network_promiscuous_interface_is_open if {
	data.stig.oracle_linux_8.network.status_ol08_00_040330 == "Open" with input as {"promiscuous_interfaces": ["eth0"]}
}

test_network_compliant_when_facts_collected_and_no_cat_i_open if {
	data.stig.oracle_linux_8.network.compliant with input as {"kernel_params": {}}
}

test_network_report_populated_on_empty_input if {
	r := data.stig.oracle_linux_8.network.compliance_report with input as {}
	r.compliant == false
	r.open_findings == count(r.findings)
}
