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
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# In v3 every Automated recommendation carries its own "evidence missing" violation (the v2 section-level
# FAIL-CLOSED guard lines are gone); the guard tests below assert that per-recommendation form.

test_filesystem_fails_closed_on_empty_input if {
	not filesystem.compliant with input as {}
	some v in filesystem.violations with input as {}
	contains(v, "evidence missing")
}

test_network_fails_closed_on_empty_input if {
	not network.compliant with input as {}
	some v in network.violations with input as {}
	contains(v, "evidence missing")
}

test_user_group_fails_closed_on_empty_input if {
	not user_group.compliant with input as {}
	some v in user_group.violations with input as {}
	contains(v, "evidence missing")
}

test_assessment_reports_no_compliant_sections_on_empty_input if {
	a := cis_rhel9.compliance_assessment with input as {}
	a.compliant == false
	a.sections_compliant == 0
	a.score == 0
}

filesystem_facts := {"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "disabled": true, "loaded": false}, {"module": "freevxfs", "disabled": true, "loaded": false}, {"module": "hfs", "disabled": true, "loaded": false}, {"module": "hfsplus", "disabled": true, "loaded": false}, {"module": "jffs2", "disabled": true, "loaded": false}, {"module": "overlay", "disabled": true, "loaded": false}, {"module": "squashfs", "disabled": true, "loaded": false}, {"module": "udf", "disabled": true, "loaded": false}, {"module": "firewire-core", "disabled": true, "loaded": false}, {"module": "usb-storage", "disabled": true, "loaded": false}]}, "attest": {"unused_filesystem_modules_reviewed": true}, "mount_options": {"tmp": {"exists": true, "has_nodev": true, "has_nosuid": true, "has_noexec": true}, "dev_shm": {"exists": true, "has_nodev": true, "has_nosuid": true, "has_noexec": true}}, "ansible_facts": {"ansible_mounts": [{"mount": "/", "fstype": "xfs", "options": "rw"}, {"mount": "/home", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/home", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/tmp", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/tmp", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log/audit", "fstype": "tmpfs", "options": "rw,nodev,nosuid,noexec"}, {"mount": "/var/log/audit", "fstype": "xfs", "options": "rw,nodev,nosuid,noexec"}]}}

test_filesystem_guard_clears_when_facts_supplied if {
	vs := filesystem.violations with input as filesystem_facts
	count([v | some v in vs; contains(v, "evidence missing")]) == 0
}

test_filesystem_guard_names_each_missing_key if {
	vs := filesystem.violations with input as object.remove(filesystem_facts, ["mount_options"])
	missing := [v | some v in vs; contains(v, "evidence missing")]
	count(missing) == 8
	every m in missing { contains(m, "mount_options") }
}

network_facts := {"attest": {"ipv6_status_identified": true, "firewalld_loopback_traffic_configured": true, "firewalld_loopback_source_traffic_configured": true, "firewalld_services_ports_reviewed": true, "firewalld_default_zone_drop": true}, "wireless_interfaces": {"has_wireless": true, "modules": [{"module": "iwlwifi", "disabled": true, "loaded": false}]}, "packages": {"bluez": false, "firewalld": true, "iptables-services": false, "ufw": false}, "disabled_network_modules": {"modules": [{"module": "dccp", "disabled": true, "loaded": false}, {"module": "tipc", "disabled": true, "loaded": false}, {"module": "rds", "disabled": true, "loaded": false}, {"module": "sctp", "disabled": true, "loaded": false}, {"module": "atm", "disabled": true, "loaded": false}, {"module": "can", "disabled": true, "loaded": false}]}, "sysctl_parameters": {"analysis": [{"parameter": "net.ipv4.ip_forward", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.forwarding", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.forwarding", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"}, {"parameter": "net.ipv4.icmp_ignore_bogus_error_responses", "current_value": "1"}, {"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.secure_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.secure_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"}, {"parameter": "net.ipv4.conf.default.rp_filter", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"}, {"parameter": "net.ipv4.conf.default.log_martians", "current_value": "1"}, {"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.route_localnet", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.route_localnet", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.forwarding", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.forwarding", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_ra", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_ra", "current_value": "0"}], "persisted": {"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.forwarding": "0", "net.ipv4.conf.default.forwarding": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv4.icmp_ignore_bogus_error_responses": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1", "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0", "net.ipv4.conf.all.secure_redirects": "0", "net.ipv4.conf.default.secure_redirects": "0", "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.conf.default.rp_filter": "1", "net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.default.accept_source_route": "0", "net.ipv4.conf.all.log_martians": "1", "net.ipv4.conf.default.log_martians": "1", "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.route_localnet": "0", "net.ipv4.conf.default.route_localnet": "0", "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.forwarding": "0", "net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0", "net.ipv6.conf.all.accept_source_route": "0", "net.ipv6.conf.default.accept_source_route": "0", "net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0"}}, "firewall": {"backend": "nftables", "zones": [{"name": "public", "interfaces": ["eth0"], "target": "default", "permanent_target": "default", "icmp_block_inversion": false, "icmp_blocks": ["timestamp-reply", "timestamp-request"]}, {"name": "trusted", "interfaces": ["lo"], "target": "ACCEPT", "permanent_target": "ACCEPT", "icmp_block_inversion": false, "icmp_blocks": []}], "log_denied": "unicast"}, "services": {"sshd.service": {"state": "running", "status": "enabled"}, "firewalld.service": {"state": "running", "status": "enabled"}, "nftables.service": {"state": "inactive", "status": "not-found"}}}

test_network_guard_clears_when_facts_supplied if {
	vs := network.violations with input as network_facts
	count([v | some v in vs; contains(v, "evidence missing")]) == 0
}

test_user_group_guard_clears_when_facts_supplied if {
	vs := user_group.violations with input as {"user_group": {"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [], "duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {}, "users_without_home_directory": [], "users_not_owning_home": [], "home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [], "dotfiles_group_or_world_writable": []}}
	count([v | some v in vs; contains(v, "evidence missing")]) == 0
}
