package stig.oracle_linux_8.pki_crypto_test

import rego.v1

# Validation fixes 2026-10-17: missing crypto-policy evidence is Open; null cert mapping is not a mapping.

test_pki_crypto_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.pki_crypto.compliant with input as {}
}

test_pki_crypto_missing_overrides_is_open if {
	data.stig.oracle_linux_8.pki_crypto.status_ol08_00_010183 == "Open" with input as {"pam_config": {"piv_enabled": true}}
}

test_pki_crypto_empty_overrides_is_not_a_finding if {
	data.stig.oracle_linux_8.pki_crypto.status_ol08_00_010183 == "Not_a_Finding" with input as {"crypto_policy_overrides": []}
}

test_pki_crypto_overrides_present_is_open if {
	data.stig.oracle_linux_8.pki_crypto.status_ol08_00_010183 == "Open" with input as {"crypto_policy_overrides": ["/etc/app.conf"]}
}

test_pki_crypto_compliant_with_overrides_collected_empty if {
	data.stig.oracle_linux_8.pki_crypto.cat_i_compliant with input as {"crypto_policy_overrides": []}
}

test_pki_crypto_null_cert_mapping_is_open if {
	data.stig.oracle_linux_8.pki_crypto.status_ol08_00_020090 == "Open" with input as {"sssd_config": {"cert_user_mapping": null}}
}

test_pki_crypto_nonempty_cert_mapping_is_not_a_finding if {
	data.stig.oracle_linux_8.pki_crypto.status_ol08_00_020090 == "Not_a_Finding" with input as {"sssd_config": {"cert_user_mapping": "ldap:(cn=%{subject_cn})"}}
}
