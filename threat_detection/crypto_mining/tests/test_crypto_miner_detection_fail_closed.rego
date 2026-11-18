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

# Audit 2026-11-17 finding 18: the default is false, so empty input is an
# explicit false (not merely "not true"), a clean host is true, and a host
# with a detection is false.
test_empty_input_compliant_is_false if {
	data.security.crypto_miner_detection.compliant == false with input as {}
}

test_clean_host_compliant_is_true if {
	data.security.crypto_miner_detection.compliant == true with input as {"running_processes": [{"name": "sshd", "cmdline": "/usr/sbin/sshd -D", "pid": 1}]}
}

test_miner_host_compliant_is_false if {
	data.security.crypto_miner_detection.compliant == false with input as {"running_processes": [{"name": "xmrig", "cmdline": "./xmrig", "pid": 9}]}
}
