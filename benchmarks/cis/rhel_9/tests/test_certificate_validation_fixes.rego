package cis_rhel9.certificate_validation_test

import rego.v1

# Validation fixes 2026-10-17: certificate records missing expiry / key size are violations.

base := {"certificates": {"ca_bundle_intact": true, "crypto_policy": "DEFAULT", "system_certs": [{"subject": "CN=a", "days_until_expiry": 365, "key_type": "RSA", "key_bits": 4096, "signature_algorithm": "sha256WithRSAEncryption"}]}}

test_cert_good_input_compliant if {
	data.cis_rhel9.certificate_validation.compliant with input as base
}

test_cert_missing_expiry_is_violation if {
	i := json.remove(base, ["/certificates/system_certs/0/days_until_expiry"])
	not data.cis_rhel9.certificate_validation.compliant with input as i
}

test_cert_missing_key_bits_is_violation if {
	i := json.remove(base, ["/certificates/system_certs/0/key_bits"])
	not data.cis_rhel9.certificate_validation.compliant with input as i
}
