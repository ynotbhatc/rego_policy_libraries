package cis_rhel9.storage_encryption_test

import rego.v1

# Validation fixes 2026-10-17: an empty storage_encryption object is not evidence; FIPS policy message is not dropped.

good := {"storage_encryption": {
	"fips_enabled": true, "fips_mode_required": true, "crypto_policy": "FIPS",
	"luks_volumes": [], "unencrypted_data_partitions": [], "crypttab_entries": [], "crypttab_missing_devices": [],
	"fstab_unencrypted_data_mounts": [], "swap_present": false,
}}

test_storage_good_input_compliant if {
	data.cis_rhel9.storage_encryption.compliant with input as good
}

test_storage_empty_object_not_compliant if {
	not data.cis_rhel9.storage_encryption.compliant with input as {"storage_encryption": {}}
}

test_storage_each_missing_fact_is_violation if {
	every key in ["fips_enabled", "crypto_policy", "luks_volumes", "unencrypted_data_partitions", "crypttab_entries", "crypttab_missing_devices", "fstab_unencrypted_data_mounts", "swap_present"] {
		not data.cis_rhel9.storage_encryption.compliant with input as json.remove(good, [concat("", ["/storage_encryption/", key])])
	}
}

test_storage_fips_required_without_crypto_policy_reports_policy_violation if {
	i := json.remove(good, ["/storage_encryption/crypto_policy"])
	some v in data.cis_rhel9.storage_encryption.violations with input as i
	startswith(v, "STIG RHEL-09-672020: Crypto policy")
}

test_storage_data_encryption_required_needs_fstab_entries if {
	i := json.patch(good, [{"op": "add", "path": "/storage_encryption/data_encryption_required", "value": true}])
	not data.cis_rhel9.storage_encryption.compliant with input as i
}
