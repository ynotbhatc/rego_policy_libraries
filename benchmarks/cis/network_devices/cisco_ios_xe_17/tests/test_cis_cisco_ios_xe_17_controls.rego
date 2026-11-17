package cis_cisco_ios_xe_17_test

import rego.v1

# Hand-written tests (not touched by tools/cis_generators/gen_cisco_ios_xe_17.py): matching traps and the
# .main bridge, the cases the generated pass/fail/evidence-missing tests cannot express.

g := data.cis_cisco_ios_xe_17_test.green

has(id, inp) if {
	v := data.cis_cisco_ios_xe_17.violations with input as inp
	some x in v
	startswith(x, concat("", [id, ":"]))
}

with_lines(ls) := object.union(g, {"ios_xe_config": {"lines": ls}})

without(ls, drop) := [l | some l in ls; l != drop]

test_commented_line_does_not_satisfy if {
	ls := array.concat(without(g.ios_xe_config.lines, "aaa new-model"), ["! aaa new-model"])
	has("1.1.1", with_lines(ls))
}

test_negated_command_does_not_satisfy if {
	ls := array.concat(without(g.ios_xe_config.lines, "aaa new-model"), ["no aaa new-model"])
	has("1.1.1", with_lines(ls))
}

test_longer_token_does_not_satisfy if {
	ls := array.concat(without(g.ios_xe_config.lines, "service tcp-keepalives-in"), ["service tcp-keepalives-in-extra"])
	has("2.1.5", with_lines(ls))
}

test_indented_line_is_not_top_level if {
	ls := array.concat(without(g.ios_xe_config.lines, "service password-encryption"), [" service password-encryption"])
	has("1.4.2", with_lines(ls))
}

test_exec_timeout_zero_never_times_out if {
	inp := json.patch(g, [{"op": "replace", "path": "/ios_xe_config/sections/5/lines/0", "value": "exec-timeout 0 0"}])
	has("1.2.8", inp)
}

test_exec_timeout_over_ten_minutes_fails if {
	inp := json.patch(g, [{"op": "replace", "path": "/ios_xe_config/sections/5/lines/0", "value": "exec-timeout 10 1"}])
	has("1.2.8", inp)
}

test_exec_timeout_seconds_only_form_passes if {
	inp := json.patch(g, [{"op": "replace", "path": "/ios_xe_config/sections/5/lines/0", "value": "exec-timeout 9 59"}])
	not has("1.2.8", inp)
}

test_vty_block_without_ssh_only_fails if {
	inp := json.patch(g, [{"op": "remove", "path": "/ios_xe_config/sections/6/lines/3"}])
	has("1.2.2", inp)
}

test_no_aux_line_passes_when_line_sections_collected if {
	inp := json.patch(g, [{"op": "remove", "path": "/ios_xe_config/sections/4"}])
	not has("1.2.3", inp)
	not has("1.2.6", inp)
}

test_http_off_skips_http_checks if {
	ls := [l | some l in g.ios_xe_config.lines; not startswith(l, "ip http")]
	inp := with_lines(array.concat(ls, ["no ip http server"]))
	not has("1.1.5", inp)
	not has("1.2.9", inp)
	not has("1.2.10", inp)
}

test_snmp_community_named_rw_is_not_rw_access if {
	ls := array.concat(g.ios_xe_config.lines, ["snmp-server community rw RO 10"])
	not has("1.5.4", with_lines(ls))
}

test_snmp_community_view_then_rw_fails if {
	ls := array.concat(g.ios_xe_config.lines, ["snmp-server community abc view v1 RW 10"])
	has("1.5.4", with_lines(ls))
}

test_snmp_community_without_acl_fails if {
	ls := array.concat(g.ios_xe_config.lines, ["snmp-server community abc RO"])
	has("1.5.5", with_lines(ls))
}

test_snmp_community_acl_without_mode_passes if {
	ls := array.concat(g.ios_xe_config.lines, ["snmp-server community abc 10"])
	not has("1.5.5", with_lines(ls))
}

test_enable_secret_type_0_fails if {
	inp := with_lines(array.concat(without(g.ios_xe_config.lines, "enable secret 9 $9$abcdef"), ["enable secret 0 plain"]))
	has("1.4.1", inp)
}

test_ssh_retries_unset_is_default_and_passes if {
	ls := [l | some l in g.ios_xe_config.lines; not startswith(l, "ip ssh authentication-retries")]
	not has("2.1.1.1.5", with_lines(ls))
}

test_ssh_retries_zero_fails if {
	ls := array.concat([l | some l in g.ios_xe_config.lines; not startswith(l, "ip ssh authentication-retries")], ["ip ssh authentication-retries 0"])
	has("2.1.1.1.5", with_lines(ls))
}

test_hostname_prefix_token_not_matched if {
	ls := array.concat(without(g.ios_xe_config.lines, "hostname edge-r1"), ["hostnames edge"])
	has("2.1.1.1.1", with_lines(ls))
}

test_logging_host_by_name_is_not_an_ip if {
	ls := array.concat(without(g.ios_xe_config.lines, "logging host 10.20.30.40"), ["logging host syslog.example.net"])
	has("2.2.4", with_lines(ls))
}

test_empty_banner_text_fails if {
	inp := json.patch(g, [{"op": "replace", "path": "/ios_xe_config/banners/motd", "value": ""}])
	has("1.3.3", inp)
}

test_level_2_proxy_arp_skipped_at_level_1 if {
	inp := json.patch(g, [
		{"op": "add", "path": "/cis_profile", "value": {"level": 1}},
		{"op": "replace", "path": "/ios_xe_config/sections/2/lines/1", "value": "ip proxy-arp"},
	])
	not has("3.1.2", inp)
}

test_main_report_on_empty_input_is_fail_closed if {
	r := data.cis_cisco_ios_xe_17.main.compliance_report with input as {}
	r.compliant == false
	r.facts_supplied == false
	r.total_controls == 84
	r.failed_controls == 84
	r.violation_count > 0
}

test_main_report_on_green_input_is_compliant if {
	r := data.cis_cisco_ios_xe_17.main.compliance_report with input as g
	r.compliant == true
	r.failed_controls == 0
	r.total_controls == 84
}
