package iso27001.cryptography_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string FIPS level passed `>= 2`.
test_string_fips_level_not_hsm_usage if {
	not data.iso27001.cryptography.hsm_usage with input as {"hsm": {"available": true, "key_generation": true, "key_storage": true, "cryptographic_operations": true, "tamper_protection": true, "fips_140_2_level": "1"}}
}

test_null_fips_level_not_hsm_usage if {
	not data.iso27001.cryptography.hsm_usage with input as {"hsm": {"available": true, "key_generation": true, "key_storage": true, "cryptographic_operations": true, "tamper_protection": true, "fips_140_2_level": null}}
}

test_text_fips_level_not_hsm_usage if {
	not data.iso27001.cryptography.hsm_usage with input as {"hsm": {"available": true, "key_generation": true, "key_storage": true, "cryptographic_operations": true, "tamper_protection": true, "fips_140_2_level": "x"}}
}

test_numeric_fips_level_unchanged if {
	data.iso27001.cryptography.hsm_usage with input as {"hsm": {"available": true, "key_generation": true, "key_storage": true, "cryptographic_operations": true, "tamper_protection": true, "fips_140_2_level": 3}}
}
