package corporate.access.control_test

import rego.v1

import data.corporate.access.control as c

# Validation 2026-10-17.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

test_missing_job_function_is_excessive if {
	u := {"u1": {"id": "u1", "status": "active", "roles": [{"name": "system_admin"}]}}
	not c.roles_follow_least_privilege with input as {"users": u}
	v := c.rbac_violations with input as {"users": u}
	count(v) == 1
}

test_matching_job_function_is_not_excessive if {
	u := {"u1": {"id": "u1", "status": "active", "roles": [{"name": "developer"}], "job_function": "developer"}}
	c.roles_follow_least_privilege with input as {"users": u}
}

test_separated_financial_process_passes if {
	p := {"name": "close", "criticality_level": "normal", "participants": [{"user_id": "a", "role": "preparer"}, {"user_id": "b", "role": "approver"}]}
	c.financial_process_separation with input as {"financial_processes": [p]}
}

test_same_person_preparer_and_approver_fails if {
	p := {"name": "close", "criticality_level": "normal", "participants": [{"user_id": "a", "role": "preparer"}, {"user_id": "a", "role": "approver"}]}
	not c.financial_process_separation with input as {"financial_processes": [p]}
}

test_separated_it_process_passes if {
	p := {"name": "rel", "environment": "production", "participants": [{"user_id": "d", "role": "developer"}, {"user_id": "e", "role": "deployer"}, {"user_id": "f", "role": "approver"}]}
	c.it_process_separation with input as {"it_processes": [p]}
}

test_developer_deploying_to_production_fails if {
	p := {"name": "rel", "environment": "production", "participants": [{"user_id": "d", "role": "developer"}, {"user_id": "d", "role": "deployer"}]}
	not c.it_process_separation with input as {"it_processes": [p]}
}

test_missing_access_review_is_overdue if {
	u := {"u1": {"id": "u1", "status": "active", "roles": []}}
	not c.account_maintenance_performed with input as {"users": u}
}

test_iso_old_access_review_is_overdue if {
	u := {"u1": {"id": "u1", "status": "active", "roles": [], "last_access_review": "2019-01-01T00:00:00Z"}}
	not c.account_maintenance_performed with input as {"users": u}
}

test_recent_iso_access_review_ok if {
	u := {"u1": {"id": "u1", "status": "active", "roles": [], "last_access_review": now_rfc}}
	c.account_maintenance_performed with input as {"users": u}
}

test_sox_only_financial_users_in_scope if {
	users := {
		"f": {"id": "f", "system_access": ["financial_reporting"], "quarterly_access_review": true},
		"n": {"id": "n", "system_access": ["wiki"]},
	}
	c.sox_access_control_compliant with input as {"users": users} with c.access_control_compliant as true with c.segregation_of_duties_enforced as true
}

test_sox_financial_user_without_review_fails if {
	users := {"f": {"id": "f", "system_access": ["financial_reporting"], "quarterly_access_review": false}}
	not c.sox_access_control_compliant with input as {"users": users} with c.access_control_compliant as true with c.segregation_of_duties_enforced as true
}

test_pci_only_cardholder_users_in_scope if {
	users := {
		"c": {"id": "c", "data_access": ["cardholder_data"], "mfa_enabled": true, "unique_user_id": true},
		"n": {"id": "n", "data_access": ["wiki"]},
	}
	c.pci_dss_access_control_compliant with input as {"users": users} with c.access_control_compliant as true
}

test_unknown_manager_is_orphan if {
	users := {"u1": {"id": "u1", "status": "active", "manager_id": "M-999"}}
	not c.orphaned_accounts_managed with input as {"users": users}
}

test_known_active_manager_not_orphan if {
	users := {
		"u1": {"id": "u1", "status": "active", "manager_id": "m1"},
		"m1": {"id": "m1", "status": "active", "manager_id": "m1"},
	}
	c.orphaned_accounts_managed with input as {"users": users}
}

test_score_not_zeroed_by_undefined_check if {
	# One failing roll-up (the unmanaged privileged user breaks mfa) must not zero the score.
	u := {"p": {"id": "p", "status": "active", "roles": [{"name": "root"}], "job_function": "admin"}}
	c.access_control_score > 0 with input as {"users": u}
	c.access_control_score < 100 with input as {"users": u}
}

test_no_users_not_compliant if {
	not c.access_control_compliant with input as {}
}
