package cis.docker.host_test

import rego.v1

# Validation fix pass 2026-10-17.

test_trusted_users_fails_without_member_list if {
	not data.cis.docker.host.trusted_docker_users with input as {"docker_partition": {"exists": true, "mount_point": "/var/lib/docker"}}
}

test_trusted_users_passes_with_empty_member_list if {
	data.cis.docker.host.trusted_docker_users with input as {"docker_group_members": [], "trusted_users": []}
}

test_trusted_users_fails_for_untrusted_member if {
	not data.cis.docker.host.trusted_docker_users with input as {"docker_group_members": ["mallory"], "trusted_users": ["root"]}
}

test_report_fully_populated_on_failing_input if {
	r := data.cis.docker.host.docker_host_compliance with input as {}
	r.overall_compliant == false
	r.trusted_docker_users == false
	count(r) == 15
}
