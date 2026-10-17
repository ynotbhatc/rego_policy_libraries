package cis_pfsense_test

import rego.v1

wan_rule(src, dst) := {"filter": {"rule": [{"interface": "wan", "type": "pass", "source": src, "destination": dst}]}}

has(prefix, inp) if {
	v := data.cis_pfsense.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_wan_pass_any_present_objects_flagged if has("2.1.3", wan_rule({"any": ""}, {"any": ""}))

test_wan_pass_absent_sides_flagged if has("2.1.3", {"filter": {"rule": [{"interface": "wan", "type": "pass"}]}})

test_wan_pass_specific_source_not_flagged if not has("2.1.3", wan_rule({"network": "lan"}, {"any": ""}))

test_wan_pass_specific_destination_not_flagged if not has("2.1.3", wan_rule({"any": ""}, {"address": "10.0.0.5"}))

test_vuln_scan_missing_package_list_not_misleading if {
	inp := {"vulnerability_scan": {"performed": true}}
	not has("5.1.1 Packages with known", inp)
	has("5.1.1 UNABLE TO VERIFY", inp)
}

test_vuln_scan_with_packages_flagged if has("5.1.1 Packages with known", {"vulnerability_scan": {"performed": true}, "vulnerable_packages": ["openssl"]})

test_vuln_scan_clean_ok if {
	inp := {"vulnerability_scan": {"performed": true}, "vulnerable_packages": []}
	not has("5.1.1", inp)
}
