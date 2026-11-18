package stig.oracle_linux_8.audit_logging_test

import rego.v1

# Validation fixes 2026-10-17: a module with no facts collected is not compliant.

test_audit_logging_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.audit_logging.compliant with input as {}
}

test_audit_logging_empty_collections_not_compliant if {
	not data.stig.oracle_linux_8.audit_logging.compliant with input as {"auditd_config": null}
}

test_audit_logging_compliant_when_facts_collected_and_no_cat_i_open if {
	data.stig.oracle_linux_8.audit_logging.cat_i_compliant with input as {"auditd_config": {"admin_space_left_action": "single"}, "audit_rules": []}
}
