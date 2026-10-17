package cis_fortinet_fortigate_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_fortinet_fortigate.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_missing_ssl_versions_flagged if has("1.1:", {"fortigate_config": {"system": {"global": {}}}})
test_wrong_ssl_versions_flagged if has("1.1:", {"fortigate_config": {"system": {"global": {"admin_https_ssl_versions": "tlsv1-1"}}}})
test_good_ssl_versions_ok if not has("1.1:", {"fortigate_config": {"system": {"global": {"admin_https_ssl_versions": "tlsv1-2"}}}})

test_missing_fortiguard_log_flagged if has("3.1:", {"fortigate_config": {"log": {}}})
test_enabled_fortiguard_log_ok if not has("3.1:", {"fortigate_config": {"log": {"fortiguard": {"status": "enable"}}}})

vpn(p) := {"fortigate_config": {"vpn": {"ipsec": {"phase1_interface": [p]}}}}

test_mixed_proposal_flagged if has("6.1:", vpn({"proposal": "aes256-sha256 3des-sha1"}))
test_missing_proposal_flagged if has("6.1:", vpn({"name": "v1"}))
test_aes_only_proposal_ok if not has("6.1:", vpn({"proposal": "aes256-sha256 aes128-sha1"}))

test_missing_antispam_flagged if has("8.1:", {"fortigate_config": {"system": {"fortiguard": {}}}})
test_absent_fortiguard_flagged if has("8.1:", {"fortigate_config": {"system": {}}})
test_enabled_antispam_ok if not has("8.1:", {"fortigate_config": {"system": {"fortiguard": {"antispam": "enable"}}}})

test_compliant_false_on_empty if data.cis_fortinet_fortigate.compliant == false with input as {}

test_summary_total_matches_sections if {
	s := data.cis_fortinet_fortigate.compliance_summary with input as {}
	s.total_controls == sum([x.total | some x in s.sections])
}
