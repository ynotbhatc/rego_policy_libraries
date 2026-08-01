# Tests for the AAP job policy set.
#
# Every decision returns {"allowed": bool, "violations": [string]} — the
# contract Ansible Automation Platform's policy enforcement expects.
package aac.aap.policy_test

import data.aac.aap.policy
import rego.v1

# A Tuesday, 23:00 UTC.
_base_input := {
	"id": 4242,
	"name": "PROD-web - Deploy",
	"created": "2026-07-28T23:00:00Z",
	"created_by": {"id": 7, "username": "alice", "is_superuser": false, "teams": ["app-team"]},
	"credentials": [{"id": 5, "name": "prod-ssh", "organization": 1, "managed": false, "kind": "ssh"}],
	"inventory": {"id": 2, "name": "prod-web", "organization": 1},
	"job_template": {"id": 9, "name": "PROD-web - Deploy", "organization": 1},
	"project": {"scm_url": "https://github.com/acme/automation.git", "scm_branch": "main"},
	"labels": [{"id": 1, "name": "change-ticket:CHG0012345"}],
	"extra_vars": {"app_version": "2.1.4"},
}

_with(overrides) := object.union(_base_input, overrides)

# ---------------------------------------------------------------------------
# 1. Time of day / change window
# ---------------------------------------------------------------------------
test_window_allows_inside_hours if {
	r := policy.maintenance_window with input as _base_input
		with data.aac.aap.config as {"maintenance_window": {"start_hour": 22, "end_hour": 4}}
	r.allowed
	count(r.violations) == 0
}

test_window_blocks_outside_hours if {
	r := policy.maintenance_window with input as _with({"created": "2026-07-28T14:00:00Z"})
		with data.aac.aap.config as {"maintenance_window": {"start_hour": 22, "end_hour": 4}}
	not r.allowed
	count(r.violations) == 1
}

test_window_wraps_midnight if {
	r := policy.maintenance_window with input as _with({"created": "2026-07-29T02:00:00Z"})
		with data.aac.aap.config as {"maintenance_window": {"start_hour": 22, "end_hour": 4}}
	r.allowed
}

test_window_blocks_disallowed_day if {
	# 2026-08-01 is a Saturday.
	r := policy.maintenance_window with input as _with({"created": "2026-08-01T23:00:00Z"})
		with data.aac.aap.config as {"maintenance_window": {"allowed_days": ["Monday"]}}
	not r.allowed
}

test_window_blocks_on_freeze_date if {
	r := policy.maintenance_window with input as _base_input
		with data.aac.aap.config as {"maintenance_window": {"freeze_dates": ["2026-07-28"]}}
	not r.allowed
}

test_window_break_glass_label_overrides if {
	r := policy.maintenance_window with input as _with({
		"created": "2026-07-28T14:00:00Z",
		"labels": [{"name": "break-glass"}],
	})
		with data.aac.aap.config as {"maintenance_window": {"start_hour": 22, "end_hour": 4}}
	r.allowed
}

# ---------------------------------------------------------------------------
# 2. Maintenance mode
# ---------------------------------------------------------------------------
test_maintenance_mode_inactive_allows if {
	r := policy.maintenance_mode with input as _base_input
	r.allowed
}

test_maintenance_mode_blocks_scoped_inventory if {
	r := policy.maintenance_mode with input as _base_input
		with data.aac.aap.config as {"maintenance_mode": {
			"active": true,
			"inventories": ["prod-web"],
			"reason": "DB migration",
		}}
	not r.allowed
	contains(r.violations[0], "DB migration")
}

test_maintenance_mode_ignores_other_inventory if {
	r := policy.maintenance_mode with input as _with({"inventory": {"name": "dev-web", "organization": 1}})
		with data.aac.aap.config as {"maintenance_mode": {"active": true, "inventories": ["prod-web"]}}
	r.allowed
}

test_maintenance_mode_platform_wide_when_list_empty if {
	r := policy.maintenance_mode with input as _base_input
		with data.aac.aap.config as {"maintenance_mode": {"active": true}}
	not r.allowed
}

# ---------------------------------------------------------------------------
# 3. Owner -> environment / inventory
# ---------------------------------------------------------------------------
test_owner_scope_allows_bound_pattern if {
	r := policy.owner_scope with input as _base_input
		with data.aac.aap.config as {"owner_scope": {"bindings": {"alice": ["prod-*"]}}}
	r.allowed
}

test_owner_scope_blocks_unbound_pattern if {
	r := policy.owner_scope with input as _base_input
		with data.aac.aap.config as {"owner_scope": {"bindings": {"alice": ["dev-*"]}}}
	not r.allowed
}

test_owner_scope_team_binding_grants_access if {
	r := policy.owner_scope with input as _base_input
		with data.aac.aap.config as {"owner_scope": {"team_bindings": {"app-team": ["prod-*"]}}}
	r.allowed
}

test_owner_scope_blocks_unbound_user_when_disabled if {
	r := policy.owner_scope with input as _base_input
		with data.aac.aap.config as {"owner_scope": {"unbound_users_allowed": false}}
	not r.allowed
}

test_owner_scope_blocks_org_mismatch if {
	r := policy.owner_scope with input as _with({"inventory": {"name": "prod-web", "organization": 99}})
		with data.aac.aap.config as {"owner_scope": {"bindings": {"alice": ["prod-*"]}}}
	not r.allowed
}

# ---------------------------------------------------------------------------
# 4. Labels
# ---------------------------------------------------------------------------
test_labels_allows_when_required_present if {
	r := policy.required_labels with input as _base_input
		with data.aac.aap.config as {"labels": {"required": ["change-ticket:CHG0012345"]}}
	r.allowed
}

test_labels_blocks_missing_required if {
	r := policy.required_labels with input as _base_input
		with data.aac.aap.config as {"labels": {"required": ["peer-reviewed"]}}
	not r.allowed
}

test_labels_blocks_forbidden if {
	r := policy.required_labels with input as _with({"labels": [{"name": "quarantined"}]})
		with data.aac.aap.config as {"labels": {"forbidden": ["quarantined"]}}
	not r.allowed
}

test_labels_required_for_matching_inventory if {
	r := policy.required_labels with input as _base_input
		with data.aac.aap.config as {"labels": {"required_for_inventories": {"prod-*": ["peer-reviewed"]}}}
	not r.allowed
}

test_labels_one_of_requires_exactly_one if {
	r := policy.required_labels with input as _with({"labels": [{"name": "env-dev"}, {"name": "env-prod"}]})
		with data.aac.aap.config as {"labels": {"one_of": [["env-dev", "env-prod"]]}}
	not r.allowed
}

test_labels_value_pattern_enforced if {
	r := policy.required_labels with input as _with({"labels": [{"name": "change-ticket:oops"}]})
		with data.aac.aap.config as {"labels": {"pattern_requirements": {"change-ticket": "^CHG[0-9]{7}$"}}}
	not r.allowed
}

test_labels_value_pattern_passes if {
	r := policy.required_labels with input as _base_input
		with data.aac.aap.config as {"labels": {"pattern_requirements": {"change-ticket": "^CHG[0-9]{7}$"}}}
	r.allowed
}

# ---------------------------------------------------------------------------
# 5. Superuser
# ---------------------------------------------------------------------------
test_superuser_blocked_by_default if {
	r := policy.superuser_restriction with input as _with({"created_by": {"username": "root", "is_superuser": true}})
	not r.allowed
}

test_superuser_exempt_user_allowed if {
	r := policy.superuser_restriction with input as _with({"created_by": {"username": "root", "is_superuser": true}})
		with data.aac.aap.config as {"superuser": {"exempt_users": ["root"]}}
	r.allowed
}

test_non_superuser_allowed if {
	r := policy.superuser_restriction with input as _base_input
	r.allowed
}

# ---------------------------------------------------------------------------
# 6. Credential scope
# ---------------------------------------------------------------------------
test_credential_scope_allows_matching_prefix if {
	r := policy.credential_scope with input as _base_input
	r.allowed
}

test_credential_scope_blocks_prefix_mismatch if {
	r := policy.credential_scope with input as _with({"credentials": [{"name": "dev-ssh", "organization": 1, "managed": false}]})
	not r.allowed
}

test_credential_scope_blocks_global_credential if {
	r := policy.credential_scope with input as _with({"credentials": [{"name": "prod-ssh", "organization": null, "managed": false}]})
	not r.allowed
}

# ---------------------------------------------------------------------------
# 7. extra_vars
# ---------------------------------------------------------------------------
test_extra_vars_allows_listed_key if {
	r := policy.extra_vars_control with input as _base_input
		with data.aac.aap.config as {"extra_vars": {"allowlist": ["app_version"], "allow_unlisted": false}}
	r.allowed
}

test_extra_vars_blocks_unlisted_key if {
	r := policy.extra_vars_control with input as _with({"extra_vars": {"rm_rf": true}})
		with data.aac.aap.config as {"extra_vars": {"allowlist": ["app_version"], "allow_unlisted": false}}
	not r.allowed
}

test_extra_vars_blocks_secret_like_key if {
	r := policy.extra_vars_control with input as _with({"extra_vars": {"db_password": "hunter2"}})
	not r.allowed
}

test_extra_vars_value_pattern_enforced if {
	r := policy.extra_vars_control with input as _with({"extra_vars": {"target_env": "banana"}})
		with data.aac.aap.config as {"extra_vars": {"value_patterns": {"target_env": "^(dev|stage|prod)$"}}}
	not r.allowed
}

test_extra_vars_accepts_json_string_form if {
	r := policy.extra_vars_control with input as _with({"extra_vars": "{\"db_password\": \"x\"}"})
	not r.allowed
}

test_team_extra_vars_blocks_unpermitted_key if {
	r := policy.team_extra_vars with input as _base_input
		with data.aac.aap.config as {"team_extra_vars": {"teams": {"app-team": ["other_key"]}}}
	not r.allowed
}

test_team_extra_vars_allows_permitted_key if {
	r := policy.team_extra_vars with input as _base_input
		with data.aac.aap.config as {"team_extra_vars": {"teams": {"app-team": ["app_version"]}}}
	r.allowed
}

# ---------------------------------------------------------------------------
# 8. Naming
# ---------------------------------------------------------------------------
test_naming_allows_conforming_name if {
	r := policy.naming_standard with input as _base_input
		with data.aac.aap.config as {"naming": {"pattern": "^(PROD|STAGE|DEV)-.+ - .+$"}}
	r.allowed
}

test_naming_blocks_nonconforming_name if {
	r := policy.naming_standard with input as _with({"job_template": {"name": "my test job"}})
		with data.aac.aap.config as {"naming": {"pattern": "^(PROD|STAGE|DEV)-.+ - .+$"}}
	not r.allowed
}

test_naming_blocks_forbidden_term if {
	r := policy.naming_standard with input as _with({"job_template": {"name": "PROD-web - copy of Deploy"}})
		with data.aac.aap.config as {"naming": {"forbid_terms": ["copy of"]}}
	not r.allowed
}

# ---------------------------------------------------------------------------
# 9. Source control
# ---------------------------------------------------------------------------
test_source_allows_approved_repo_and_branch if {
	r := policy.source_control with input as _base_input
		with data.aac.aap.config as {"source_control": {
			"allowed_repos": ["github.com/acme/*"],
			"allowed_branches": ["main", "release/*"],
		}}
	r.allowed
}

test_source_blocks_unapproved_repo if {
	r := policy.source_control with input as _with({"project": {"scm_url": "https://github.com/rando/x.git", "scm_branch": "main"}})
		with data.aac.aap.config as {"source_control": {"allowed_repos": ["github.com/acme/*"]}}
	not r.allowed
}

test_source_blocks_unapproved_branch if {
	r := policy.source_control with input as _with({"project": {"scm_url": "https://github.com/acme/automation.git", "scm_branch": "wip"}})
		with data.aac.aap.config as {"source_control": {"allowed_branches": ["main"]}}
	not r.allowed
}

test_source_blocks_ssh_when_https_required if {
	r := policy.source_control with input as _with({"project": {"scm_url": "git@github.com:acme/automation.git", "scm_branch": "main"}})
	not r.allowed
}

test_source_blocks_detached_head if {
	r := policy.source_control with input as _with({"project": {
		"scm_url": "https://github.com/acme/automation.git",
		"scm_branch": "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0",
	}})
	not r.allowed
}

# ---------------------------------------------------------------------------
# 10. Blanket deny
# ---------------------------------------------------------------------------
test_deny_all_inactive_allows if {
	r := policy.deny_all with input as _base_input
	r.allowed
}

test_deny_all_active_blocks if {
	r := policy.deny_all with input as _base_input
		with data.aac.aap.config as {"deny_all": {"active": true, "reason": "SEV1 in progress"}}
	not r.allowed
}

test_deny_all_exempt_label_allows if {
	r := policy.deny_all with input as _with({"labels": [{"name": "incident-response"}]})
		with data.aac.aap.config as {"deny_all": {"active": true}}
	r.allowed
}

# ---------------------------------------------------------------------------
# Contract — every decision must return the PAC shape
# ---------------------------------------------------------------------------
test_all_decisions_return_pac_contract if {
	every d in [
		policy.maintenance_window,
		policy.maintenance_mode,
		policy.owner_scope,
		policy.superuser_restriction,
		policy.credential_scope,
		policy.required_labels,
		policy.extra_vars_control,
		policy.team_extra_vars,
		policy.naming_standard,
		policy.source_control,
		policy.deny_all,
	] {
		is_boolean(d.allowed)
		is_array(d.violations)
	} with input as _base_input
}
