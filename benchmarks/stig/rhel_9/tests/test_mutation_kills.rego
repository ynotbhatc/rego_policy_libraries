package stig.rhel_9.mutation_kill_test

# Tests that kill mutants scripts/mutation_test.py found surviving in benchmarks/stig/rhel_9 (#306): the per-section
# roll-ups (open findings, cat_i_compliant), the severity counts and compliance flags of stig_rhel9_complete.rego,
# the stig_rhel9 bridge, and the integer check in the shared _str helper. Findings are mocked with `with`, so the
# roll-up logic is pinned independent of any rule's evidence. Hand-written; the generator never writes this file.

import rego.v1

_open := {"stig_id": "RHEL-09-000001", "severity": "CAT I", "status": "Open"}

_closed := {"stig_id": "RHEL-09-000002", "severity": "CAT I", "status": "Not_a_Finding"}

test_account_auth_violations_list_only_open_findings if {
	data.stig.rhel_9.account_auth.violations == {"RHEL-09-000001"} with data.stig.rhel_9.account_auth.findings as [_open, _closed]
}

test_account_auth_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.account_auth.cat_i_compliant with data.stig.rhel_9.account_auth.cat_i_findings as [_open, _closed]
}

test_account_auth_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.account_auth.cat_i_compliant with data.stig.rhel_9.account_auth.cat_i_findings as [_closed]
}

test_audit_logging_violations_list_only_open_findings if {
	data.stig.rhel_9.audit_logging.violations == {"RHEL-09-000001"} with data.stig.rhel_9.audit_logging.findings as [_open, _closed]
}

test_audit_logging_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.audit_logging.cat_i_compliant with data.stig.rhel_9.audit_logging.cat_i_findings as [_open, _closed]
}

test_audit_logging_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.audit_logging.cat_i_compliant with data.stig.rhel_9.audit_logging.cat_i_findings as [_closed]
}

test_configuration_management_violations_list_only_open_findings if {
	data.stig.rhel_9.configuration_management.violations == {"RHEL-09-000001"} with data.stig.rhel_9.configuration_management.findings as [_open, _closed]
}

test_configuration_management_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.configuration_management.cat_i_compliant with data.stig.rhel_9.configuration_management.cat_i_findings as [_open, _closed]
}

test_configuration_management_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.configuration_management.cat_i_compliant with data.stig.rhel_9.configuration_management.cat_i_findings as [_closed]
}

test_file_permissions_violations_list_only_open_findings if {
	data.stig.rhel_9.file_permissions.violations == {"RHEL-09-000001"} with data.stig.rhel_9.file_permissions.findings as [_open, _closed]
}

test_file_permissions_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.file_permissions.cat_i_compliant with data.stig.rhel_9.file_permissions.cat_i_findings as [_open, _closed]
}

test_file_permissions_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.file_permissions.cat_i_compliant with data.stig.rhel_9.file_permissions.cat_i_findings as [_closed]
}

test_network_violations_list_only_open_findings if {
	data.stig.rhel_9.network.violations == {"RHEL-09-000001"} with data.stig.rhel_9.network.findings as [_open, _closed]
}

test_network_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.network.cat_i_compliant with data.stig.rhel_9.network.cat_i_findings as [_open, _closed]
}

test_network_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.network.cat_i_compliant with data.stig.rhel_9.network.cat_i_findings as [_closed]
}

test_pki_crypto_violations_list_only_open_findings if {
	data.stig.rhel_9.pki_crypto.violations == {"RHEL-09-000001"} with data.stig.rhel_9.pki_crypto.findings as [_open, _closed]
}

test_pki_crypto_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.pki_crypto.cat_i_compliant with data.stig.rhel_9.pki_crypto.cat_i_findings as [_open, _closed]
}

test_pki_crypto_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.pki_crypto.cat_i_compliant with data.stig.rhel_9.pki_crypto.cat_i_findings as [_closed]
}

test_services_violations_list_only_open_findings if {
	data.stig.rhel_9.services.violations == {"RHEL-09-000001"} with data.stig.rhel_9.services.findings as [_open, _closed]
}

test_services_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.services.cat_i_compliant with data.stig.rhel_9.services.cat_i_findings as [_open, _closed]
}

test_services_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.services.cat_i_compliant with data.stig.rhel_9.services.cat_i_findings as [_closed]
}

test_software_integrity_violations_list_only_open_findings if {
	data.stig.rhel_9.software_integrity.violations == {"RHEL-09-000001"} with data.stig.rhel_9.software_integrity.findings as [_open, _closed]
}

test_software_integrity_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.software_integrity.cat_i_compliant with data.stig.rhel_9.software_integrity.cat_i_findings as [_open, _closed]
}

test_software_integrity_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.software_integrity.cat_i_compliant with data.stig.rhel_9.software_integrity.cat_i_findings as [_closed]
}

test_ssh_config_violations_list_only_open_findings if {
	data.stig.rhel_9.ssh_config.violations == {"RHEL-09-000001"} with data.stig.rhel_9.ssh_config.findings as [_open, _closed]
}

test_ssh_config_cat_i_open_blocks_cat_i_compliant if {
	not data.stig.rhel_9.ssh_config.cat_i_compliant with data.stig.rhel_9.ssh_config.cat_i_findings as [_open, _closed]
}

test_ssh_config_cat_i_closed_is_cat_i_compliant if {
	data.stig.rhel_9.ssh_config.cat_i_compliant with data.stig.rhel_9.ssh_config.cat_i_findings as [_closed]
}

_mixed := [
	{"severity": "CAT I", "status": "Open"},
	{"severity": "CAT II", "status": "Open"},
	{"severity": "CAT II", "status": "Not_Applicable"},
	{"severity": "CAT III", "status": "Not_Reviewed"},
	{"severity": "CAT III", "status": "Not_a_Finding"},
]

test_complete_severity_and_status_counts if {
	count(data.stig.rhel_9.cat_i_open_findings) == 1 with data.stig.rhel_9.all_findings as _mixed
	count(data.stig.rhel_9.cat_ii_open_findings) == 1 with data.stig.rhel_9.all_findings as _mixed
	count(data.stig.rhel_9.cat_iii_open_findings) == 0 with data.stig.rhel_9.all_findings as _mixed
	data.stig.rhel_9.open_findings_count == 2 with data.stig.rhel_9.all_findings as _mixed
	data.stig.rhel_9.not_applicable_count == 1 with data.stig.rhel_9.all_findings as _mixed
	data.stig.rhel_9.not_reviewed_count == 1 with data.stig.rhel_9.all_findings as _mixed
	data.stig.rhel_9.not_a_finding_count == 1 with data.stig.rhel_9.all_findings as _mixed
}

test_complete_cat_iii_open_is_counted if {
	count(data.stig.rhel_9.cat_iii_open_findings) == 1 with data.stig.rhel_9.all_findings as [{"severity": "CAT III", "status": "Open"}]
}

test_complete_open_cat_i_is_not_overall_compliant if {
	not data.stig.rhel_9.overall_compliant with data.stig.rhel_9.all_findings as _mixed
	not data.stig.rhel_9.fully_compliant with data.stig.rhel_9.all_findings as _mixed
}

test_complete_open_cat_ii_only_is_overall_but_not_fully_compliant if {
	fs := [{"severity": "CAT II", "status": "Open"}, {"severity": "CAT I", "status": "Not_a_Finding"}]
	data.stig.rhel_9.overall_compliant with data.stig.rhel_9.all_findings as fs
	not data.stig.rhel_9.fully_compliant with data.stig.rhel_9.all_findings as fs
}

test_complete_nothing_open_is_fully_compliant if {
	fs := [{"severity": "CAT I", "status": "Not_a_Finding"}, {"severity": "CAT II", "status": "Not_Applicable"}]
	data.stig.rhel_9.overall_compliant with data.stig.rhel_9.all_findings as fs
	data.stig.rhel_9.fully_compliant with data.stig.rhel_9.all_findings as fs
}

# stig_rhel9 bridge (stig_rhel9_main.rego): the bridge's own finding or the upstream one, never both
_fail_closed(v) if v.control == "FAIL-CLOSED"

_fail_closed(v) if startswith(object.get(v, "rule_title", ""), "FAIL-CLOSED")

test_bridge_no_facts_is_not_compliant_with_one_fail_closed_finding if {
	r := data.stig_rhel9.main.compliance_report with input as {}
	r.compliant == false
	r.facts_supplied == false
	fc := [v | some v in r.violations; _fail_closed(v)]
	count(fc) == 1
}

test_bridge_compliant_target_with_facts_is_compliant if {
	r := data.stig_rhel9.main.compliance_report with input as {"fips": {"fips_enabled": "1"}}
		with data.stig.rhel_9.main.compliant as true
		with data.stig.rhel_9.main.violations as []
	r.compliant == true
	r.violation_count == 0
}

test_bridge_non_compliant_target_is_not_compliant if {
	r := data.stig_rhel9.main.compliance_report with input as {"fips": {"fips_enabled": "1"}}
		with data.stig.rhel_9.main.compliant as false
		with data.stig.rhel_9.main.violations as []
	r.compliant == false
}

test_bridge_target_violation_is_not_compliant if {
	r := data.stig_rhel9.main.compliance_report with input as {"fips": {"fips_enabled": "1"}}
		with data.stig.rhel_9.main.compliant as true
		with data.stig.rhel_9.main.violations as [{"rule_title": "x"}]
	r.compliant == false
}

test_bridge_does_not_repeat_upstream_fail_closed if {
	r := data.stig_rhel9.main.compliance_report with input as {}
		with data.stig.rhel_9.main.violations as [{"rule_title": "FAIL-CLOSED: no facts"}]
	r.violation_count == 1
}

test_bridge_adds_fail_closed_when_upstream_has_other_findings_only if {
	r := data.stig_rhel9.main.compliance_report with input as {}
		with data.stig.rhel_9.main.violations as [{"rule_title": "RHEL-09-671010"}]
	r.violation_count == 2
}

# _str: a number counts only when it is an integer (1.5 is not the value "1")
test_str_helper_rejects_non_integer_number if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213010 == "Open" with input as {"kernel_params": {"kernel.dmesg_restrict": 1.5}}
}

test_str_helper_accepts_integer_number if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213010 == "Not_a_Finding" with input as {"kernel_params": {"kernel.dmesg_restrict": 1}}
}
