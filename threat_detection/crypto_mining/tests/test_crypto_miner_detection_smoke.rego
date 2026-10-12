package security.crypto_miner_detection_test

import rego.v1

# Generated smoke test for threat_detection/crypto_mining/crypto_miner_detection.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_crypto_miner_detection_loads_on_empty_input if {
	m := data.security.crypto_miner_detection with input as {}
	is_object(m)
}

