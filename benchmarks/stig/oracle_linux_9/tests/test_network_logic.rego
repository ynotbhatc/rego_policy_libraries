package stig.oracle_linux_9.network_test

import rego.v1

import data.stig.oracle_linux_9.network

# Validation 2026-10-17: missing evidence is not a pass.

test_missing_wireless_evidence_is_open if {
	network.status_ol09_00_006001 == "Open" with input as {}
}

test_wireless_present_is_open if {
	network.status_ol09_00_006001 == "Open" with input as {"wireless_interfaces": ["wlan0"]}
	network.status_ol09_00_006001 == "Open" with input as {"wireless_interfaces": {"interfaces": ["wlan0"], "count": 1, "has_wireless": true}}
}

test_missing_promiscuous_evidence_is_open if {
	network.status_ol09_00_006004 == "Open" with input as {}
}

test_promiscuous_lists if {
	network.status_ol09_00_006004 == "Not_a_Finding" with input as {"promiscuous_interfaces": []}
	network.status_ol09_00_006004 == "Open" with input as {"promiscuous_interfaces": ["eth0"]}
}
