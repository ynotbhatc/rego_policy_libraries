package cis_palo_alto_panos_test

import rego.v1

# Hand-written tests (not touched by tools/cis_generators/gen_palo_alto.py): license gating, rule scoping and
# the .main bridge, the cases the generated pass/fail/evidence-missing tests cannot express.

g := data.cis_palo_alto_panos_test.green

has(id, inp) if {
	v := data.cis_palo_alto_panos.violations with input as inp
	some x in v
	startswith(x, concat("", [id, ":"]))
}

p(ops) := json.patch(g, ops)

_unlicensed := [{"op": "add", "path": "/panos_config/licenses", "value": [{"feature": "PAN-DB URL Filtering", "expired": "no"}]}]

test_unlicensed_inline_cloud_items_pass if {
	inp := p(array.concat(_unlicensed, [
		{"op": "add", "path": "/panos_config/profiles/vulnerability/0/cloud_inline_analysis", "value": "no"},
		{"op": "add", "path": "/panos_config/profiles/spyware/0/cloud_inline_analysis", "value": "no"},
		{"op": "add", "path": "/panos_config/profiles/url_filtering/0/cloud_inline_cat", "value": "no"},
		{"op": "remove", "path": "/panos_config/profiles/spyware/0/botnet_domains/dns_security_categories"},
	]))
	not has("6.22", inp)
	not has("6.23", inp)
	not has("6.24", inp)
	not has("6.25", inp)
}

test_expired_license_counts_as_unlicensed if {
	inp := p([
		{"op": "add", "path": "/panos_config/licenses/1/expired", "value": "yes"},
		{"op": "add", "path": "/panos_config/profiles/vulnerability/0/cloud_inline_analysis", "value": "no"},
	])
	not has("6.22", inp)
	has("6.8", p([{"op": "add", "path": "/panos_config/licenses/0/expired", "value": "yes"}]))
}

test_disabled_allow_rule_is_ignored if {
	inp := p([{"op": "add", "path": "/panos_config/rulebase/security/-", "value": {
		"name": "old", "from": ["trust"], "to": ["untrust"], "application": ["any"], "service": ["any"],
		"action": "allow", "disabled": "yes",
	}}])
	not has("7.2", inp)
	not has("6.2", inp)
}

test_any_destination_zone_counts_as_internet if {
	inp := p([{"op": "add", "path": "/panos_config/rulebase/security/-", "value": {
		"name": "lab", "from": ["trust"], "to": ["any"], "application": ["ssh"], "service": ["application-default"],
		"action": "allow", "profile_setting": {"profiles": {"virus": ["av-strict"], "vulnerability": ["vp-strict"], "wildfire_analysis": ["wf-strict"]}},
	}}])
	has("6.5", inp)
	has("6.12", inp)
	not has("6.2", inp)
}

test_unknown_profile_group_gives_no_profile if {
	has("6.7", p([{"op": "add", "path": "/panos_config/rulebase/security/1/profile_setting/group", "value": ["no-such-group"]}]))
}

test_empty_site_list_is_evidence_missing if {
	v := data.cis_palo_alto_panos.violations with input as p([{"op": "add", "path": "/panos_config/site/untrusted_zones", "value": []}])
	"2.3: evidence missing — panos_config.{zone,site.untrusted_zones} not collected" in v
}

test_untrusted_zone_missing_from_config_fails if has("6.15", p([{"op": "add", "path": "/panos_config/site/untrusted_zones/-", "value": "partner"}]))

test_lockout_time_zero_fails if has("1.4.2", p([{"op": "add", "path": "/panos_config/shared/authentication_profile/0/lockout/lockout_time", "value": 0}]))

test_vulnerability_rule_allowing_critical_fails if {
	has("6.6", p([{"op": "add", "path": "/panos_config/profiles/vulnerability/0/rules/0", "value": {"name": "allow-crit", "severity": ["critical"], "action": "allow"}}]))
}

test_main_bridge_on_green if {
	r := data.cis_palo_alto_panos.main.compliance_report with input as g
	r.total_controls == 79
	r.failed_controls == 0
	r.compliant == true
	r.compliance_percentage == 100
	count(r.violations) == 0
}

test_main_bridge_fails_closed_on_empty if {
	r := data.cis_palo_alto_panos.main.compliance_report with input as {}
	r.failed_controls == r.total_controls
	r.compliant == false
	some v in r.violations
	startswith(v, "FAIL-CLOSED:")
}
