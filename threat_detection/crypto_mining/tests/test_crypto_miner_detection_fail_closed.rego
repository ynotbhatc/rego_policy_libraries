package security.crypto_miner_detection_test

import rego.v1

test_not_clean_without_facts if {
	c := object.get(data.security.crypto_miner_detection, "compliant", false) with input as {}
	not c == true
}

test_clean_host_with_facts_is_compliant if {
	data.security.crypto_miner_detection.compliant with input as {"running_processes": [], "network_connections": []}
}

# Semantic review 2026-11-13: a detection must not be dropped because a name/pid field is absent.
test_miner_process_without_name_still_violates if {
	inp := {"running_processes": [{"cmdline": "./xmrig -o pool.minexmr.com", "pid": 123}]}
	v := data.security.crypto_miner_detection.violations with input as inp
	count(v) > 0
	not data.security.crypto_miner_detection.compliant with input as inp
}
