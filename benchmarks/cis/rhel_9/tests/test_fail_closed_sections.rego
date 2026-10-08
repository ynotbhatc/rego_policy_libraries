package cis_rhel9_fail_closed_test

import rego.v1

import data.cis_rhel9
import data.cis_rhel9.filesystem
import data.cis_rhel9.network
import data.cis_rhel9.user_group

# Measured before this fix: on empty input, filesystem, network and user_group
# reported compliant while the other 11 sections failed, so an assessment that
# evaluated nothing scored 21.4% with 3/14 sections compliant. Absent facts are
# unevaluated, and unevaluated is reported as non-compliant.

test_filesystem_fails_closed_on_empty_input if {
	not filesystem.compliant with input as {}
	some v in filesystem.violations with input as {}
	contains(v, "FAIL-CLOSED")
}

test_network_fails_closed_on_empty_input if {
	not network.compliant with input as {}
	some v in network.violations with input as {}
	contains(v, "FAIL-CLOSED")
}

test_user_group_fails_closed_on_empty_input if {
	not user_group.compliant with input as {}
	some v in user_group.violations with input as {}
	contains(v, "FAIL-CLOSED")
}

test_assessment_reports_no_compliant_sections_on_empty_input if {
	a := cis_rhel9.compliance_assessment with input as {}
	a.compliant == false
	a.sections_compliant == 0
	a.score == 0
}

# The guard fires per missing key, and only for missing keys: supplying every
# required fact object (here, with nothing non-compliant inside) clears it.
filesystem_facts := {
	"disabled_filesystem_modules": {"modules": []},
	"separate_partitions": {"analysis": []},
	"mount_options": {"tmp": {}, "dev_shm": {}},
	"sticky_bit": {"world_writable_without_sticky": []},
	"usb_storage": {"status": "disabled", "loaded": false, "disabled": true},
}

test_filesystem_guard_clears_when_facts_supplied if {
	vs := filesystem.violations with input as filesystem_facts
	count([v | some v in vs; contains(v, "FAIL-CLOSED")]) == 0
}

test_filesystem_guard_names_each_missing_key if {
	vs := filesystem.violations with input as object.remove(filesystem_facts, ["usb_storage"])
	missing := [v | some v in vs; contains(v, "FAIL-CLOSED")]
	count(missing) == 1
	contains(missing[0], "usb_storage")
}

network_facts := {
	"sysctl_parameters": {"analysis": [], "non_compliant_params": []},
	"ip_forwarding": {"ipv4_enabled": false, "ipv6_enabled": false},
	"ipv6": {"enabled": false},
	"firewall": {"type": "firewalld", "active": true},
	"wireless_interfaces": {"has_wireless": false, "count": 0},
}

test_network_guard_clears_when_facts_supplied if {
	vs := network.violations with input as network_facts
	count([v | some v in vs; contains(v, "FAIL-CLOSED")]) == 0
}

test_user_group_guard_clears_when_facts_supplied if {
	vs := user_group.violations with input as {"user_group": {}}
	count([v | some v in vs; contains(v, "FAIL-CLOSED")]) == 0
}
