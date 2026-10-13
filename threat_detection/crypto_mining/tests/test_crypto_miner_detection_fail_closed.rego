package security.crypto_miner_detection_test

import rego.v1

test_not_clean_without_facts if {
	c := object.get(data.security.crypto_miner_detection, "compliant", false) with input as {}
	not c == true
}

test_clean_host_with_facts_is_compliant if {
	data.security.crypto_miner_detection.compliant with input as {"running_processes": [], "network_connections": []}
}
