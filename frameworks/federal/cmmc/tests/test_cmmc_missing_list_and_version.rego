package cmmc_missing_list_and_version_test

import data.cmmc_level_2_pass_test.level_2_facts
import rego.v1

# `count(input.audit.x) == 0` and `input.scp.tls_min_version != "1.2"` are undefined when the field is missing,
# so the finding used to vanish. Starting from the all-pass Level 2 fixture, a missing field must produce it.

_without(path) := json.patch(level_2_facts, [{"op": "remove", "path": path}])

test_fixture_has_none_of_these_findings if {
	data.cmmc.audit_accountability.violation_3_3_2 == set() with input as level_2_facts
	data.cmmc.audit_accountability.violation_3_3_7 == set() with input as level_2_facts
	data.cmmc.audit_accountability.violation_3_3_9 == set() with input as level_2_facts
	data.cmmc.system_communications_protection.violation_3_13_8 == set() with input as level_2_facts
}

test_missing_privileged_command_rules_is_a_finding if {
	v := data.cmmc.audit_accountability.violation_3_3_2 with input as _without(["audit", "privileged_command_rules"])
	"3.3.2: No audit rules configured for privileged command execution" in v
}

test_string_privileged_command_rules_is_a_finding if {
	i := json.patch(level_2_facts, [{"op": "replace", "path": ["audit", "privileged_command_rules"], "value": "all"}])
	v := data.cmmc.audit_accountability.violation_3_3_2 with input as i
	"3.3.2: No audit rules configured for privileged command execution" in v
}

test_missing_ntp_servers_is_a_finding if {
	v := data.cmmc.audit_accountability.violation_3_3_7 with input as _without(["audit", "ntp_servers"])
	"3.3.7: No authoritative NTP time sources configured" in v
}

test_missing_audit_admins_is_a_finding if {
	v := data.cmmc.audit_accountability.violation_3_3_9 with input as _without(["audit", "audit_admins"])
	"3.3.9: No designated privileged users for audit management" in v
}

test_missing_tls_min_version_is_a_finding if {
	v := data.cmmc.system_communications_protection.violation_3_13_8 with input as _without(["scp", "tls_min_version"])
	"3.13.8: TLS minimum version is not collected (must be TLS 1.2 or higher)" in v
}
