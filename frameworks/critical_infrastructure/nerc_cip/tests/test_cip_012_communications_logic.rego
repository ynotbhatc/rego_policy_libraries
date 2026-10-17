package nerc_cip.cip_012_test

import rego.v1

import data.nerc_cip.cip_012 as c

# Validation 2026-10-17: backup links are checked even without backup_links_exist.

insecure := {"same_protection_level": false, "encryption_enabled": false, "authentication_implemented": false}

secure := {"same_protection_level": true, "encryption_enabled": true, "authentication_implemented": true}

test_insecure_backup_links_without_flag_fail if {
	not c.backup_communication_protected with input as {"communication_contingency": {"backup_links": [insecure]}}
}

test_insecure_backup_links_with_flag_fail if {
	not c.backup_communication_protected with input as {"communication_contingency": {"backup_links_exist": true, "backup_links": [insecure]}}
}

test_secure_backup_links_pass if {
	c.backup_communication_protected with input as {"communication_contingency": {"backup_links": [secure]}}
}

test_explicit_no_backup_links_passes if {
	c.backup_communication_protected with input as {"communication_contingency": {"backup_links_exist": false}}
}

test_missing_contingency_evidence_fails if {
	not c.backup_communication_protected with input as {}
	not c.backup_communication_protected with input as {"communication_contingency": {}}
}
