package stig.oracle_linux_8.decisions_scope_test

import rego.v1

# Decisions 2026-10-19 (theme A): `compliant` = no open finding at any category;
# `cat_i_compliant` keeps the former CAT-I-only meaning.

test_audit_logging_cat_ii_open_not_compliant if {
	i := {"auditd_config": {"admin_space_left_action": "single"}, "audit_rules": []}
	data.stig.oracle_linux_8.audit_logging.cat_i_compliant with input as i
	not data.stig.oracle_linux_8.audit_logging.compliant with input as i
}

test_network_cat_ii_open_not_compliant if {
	i := {"kernel_params": {}}
	data.stig.oracle_linux_8.network.cat_i_compliant with input as i
	not data.stig.oracle_linux_8.network.compliant with input as i
}

test_software_integrity_cat_ii_open_not_compliant if {
	i := {"services": {"rsyslog": "active"}}
	data.stig.oracle_linux_8.software_integrity.cat_i_compliant with input as i
	not data.stig.oracle_linux_8.software_integrity.compliant with input as i
}

test_pki_crypto_cat_ii_open_not_compliant if {
	i := {"crypto_policy_overrides": []}
	data.stig.oracle_linux_8.pki_crypto.cat_i_compliant with input as i
	not data.stig.oracle_linux_8.pki_crypto.compliant with input as i
}

test_report_exposes_cat_i_compliant if {
	r := data.stig.oracle_linux_8.services.compliance_report with input as {}
	r.cat_i_compliant == false
	r.compliant == false
}
