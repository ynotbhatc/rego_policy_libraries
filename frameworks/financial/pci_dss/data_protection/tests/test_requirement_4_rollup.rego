package pci_dss.data_protection.requirement_4_test

import rego.v1

# Roll-up behaviour (validation 2026-10-17). Controls are mocked with `with ... as` so these tests
# pin the aggregation logic independent of the evidence schema. The control under test is left
# unmocked and evaluated against an empty input, i.e. it is genuinely failing.

test_all_controls_pass_is_compliant_and_full_score if {
	data.pci_dss.data_protection.requirement_4.pci_requirement_4_compliant with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.pos_terminal_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
	data.pci_dss.data_protection.requirement_4.pci_requirement_4_score == 100 with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.pos_terminal_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
}

test_one_failing_control_gives_partial_score_and_populated_findings if {
	score := data.pci_dss.data_protection.requirement_4.pci_requirement_4_score with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
	score > 0
	score < 100
	f := data.pci_dss.data_protection.requirement_4.pci_requirement_4_findings with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
	count(f) > 0
	not data.pci_dss.data_protection.requirement_4.pci_requirement_4_compliant with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
}

test_failing_wireless_pan_transmission_secure_blocks_compliance if {
	not data.pci_dss.data_protection.requirement_4.pci_requirement_4_compliant with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.pos_terminal_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.pan_in_messaging_secured as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
}

test_failing_pan_in_messaging_secured_blocks_compliance if {
	not data.pci_dss.data_protection.requirement_4.pci_requirement_4_compliant with data.pci_dss.data_protection.requirement_4.transmission_security_policies_established as true with data.pci_dss.data_protection.requirement_4.transmission_security_roles_defined as true with data.pci_dss.data_protection.requirement_4.strong_cryptography_for_pan as true with data.pci_dss.data_protection.requirement_4.accepted_cryptography_standards as true with data.pci_dss.data_protection.requirement_4.certificate_management_secure as true with data.pci_dss.data_protection.requirement_4.payment_page_encryption as true with data.pci_dss.data_protection.requirement_4.pos_terminal_encryption as true with data.pci_dss.data_protection.requirement_4.api_transmission_encrypted as true with data.pci_dss.data_protection.requirement_4.trusted_keys_certificates_managed as true with data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure as true with data.pci_dss.data_protection.requirement_4.weak_protocols_inventory_current as true
}

test_payment_page_encryption_missing_scope_flag_does_not_pass if {
	not data.pci_dss.data_protection.requirement_4.payment_page_encryption with input as {}
}

test_payment_page_encryption_explicit_not_in_scope_passes if {
	data.pci_dss.data_protection.requirement_4.payment_page_encryption with input as {"pci": {"ecommerce": {"in_scope": false}}}
}

test_pos_terminal_encryption_missing_scope_flag_does_not_pass if {
	not data.pci_dss.data_protection.requirement_4.pos_terminal_encryption with input as {}
}

test_pos_terminal_encryption_explicit_not_in_scope_passes if {
	data.pci_dss.data_protection.requirement_4.pos_terminal_encryption with input as {"pci": {"pos": {"in_scope": false}}}
}

test_wireless_pan_transmission_secure_missing_scope_flag_does_not_pass if {
	not data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure with input as {}
}

test_wireless_pan_transmission_secure_explicit_not_in_scope_passes if {
	data.pci_dss.data_protection.requirement_4.wireless_pan_transmission_secure with input as {"pci": {"wireless": {"transmits_pan": false}}}
}
