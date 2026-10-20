package cis_fortinet_fortigate_test

import rego.v1

# Regression tests from the 2026-10-17 validation pass, re-pointed at the CIS FortiGate 7.4.x Benchmark v1.0.1
# rewrite (2026-10-20). The test names are kept; each body now exercises the 7.4.x recommendation that covers the
# same setting: admin GUI TLS version (2.1.10), central logging (7.2.1), SSL-VPN protocol versions (6.1.2) and the
# FortiGuard sandbox service (4.2.6).

g := data.cis_fortinet_fortigate_test.green

has(prefix, inp) if {
	v := data.cis_fortinet_fortigate.violations with input as inp
	some x in v
	startswith(x, prefix)
}

glob(o) := json.patch(g, [{"op": "add", "path": "/fortigate_config/system/global", "value": o}])

test_missing_ssl_versions_flagged if has("2.1.10:", {"fortigate_config": {"system": {"global": {}}}})

test_wrong_ssl_versions_flagged if has("2.1.10:", json.patch(g, [{"op": "add", "path": "/fortigate_config/system/global/admin_https_ssl_versions", "value": "tlsv1-1"}]))

test_good_ssl_versions_ok if not has("2.1.10:", g)

test_missing_fortiguard_log_flagged if has("7.2.1:", {"fortigate_config": {"log": {}}})

test_enabled_fortiguard_log_ok if not has("7.2.1:", g)

vpn(p) := json.patch(g, [{"op": "add", "path": "/fortigate_config/vpn/ssl/settings", "value": p}])

test_mixed_proposal_flagged if has("6.1.2:", vpn({"ssl_max_proto_ver": "tls1-3", "ssl_min_proto_ver": "tls1-1", "algorithm": "high"}))

test_missing_proposal_flagged if has("6.1.2:", vpn({"servercert": "vpn.example.com"}))

test_aes_only_proposal_ok if not has("6.1.2:", vpn({"ssl_max_proto_ver": "tls1-3", "ssl_min_proto_ver": "tls1-2", "algorithm": "high"}))

test_missing_antispam_flagged if has("4.2.6:", json.patch(g, [{"op": "add", "path": "/fortigate_config/system/fortiguard", "value": {}}]))

test_absent_fortiguard_flagged if has("4.2.6:", json.patch(g, [{"op": "remove", "path": "/fortigate_config/system/fortiguard"}]))

test_enabled_antispam_ok if not has("4.2.6:", g)

test_compliant_false_on_empty if data.cis_fortinet_fortigate.compliant == false with input as {}

test_summary_total_matches_sections if {
	s := data.cis_fortinet_fortigate.compliance_summary with input as {}
	s.total_controls == sum([x.total | some x in s.sections])
}
