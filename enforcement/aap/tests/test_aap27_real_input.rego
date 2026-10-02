# Tests against a REAL Ansible Automation Platform 2.7 policy input.
#
# _aap27_input is the document AAP 2.7 POSTed to OPA for one job launch,
# captured from OPA's console decision log (decision_logs.console=true) on
# AAP 2.7 (controller 4.8.6), 2026-10-02. It is built by
# awx/main/tasks/policy.py (JobSerializer). Only these values were changed:
# the EE registry host and the project's branch, to neutral examples. Every
# field name, nesting and type is exactly as AAP sent it.
#
# The launch: a non-superuser who is a member of one team, on a job template
# carrying one organization-scoped credential. Shapes the hand-written
# fixture in test_aap_policy.rego does not have:
#
#   created_by.teams         [{"id": 1, "name": "app-team"}]   objects, not names
#   credentials[].organization  {"id": 3, "name": ...}         object, not an id
#   organization             top level {"id", "name"} — the job's organization
#   job_template, inventory  carry NO organization field at all
#
# Because every policy reads input through object.get with a default, a shape
# mismatch does not error — the rule silently does not fire, which looks
# exactly like "allowed". These tests pin each shape so that cannot recur.
package aac.aap.policy_test

import data.aac.aap.policy
import rego.v1

_aap27_input := {
	"created": "2026-10-02T20:18:56.193051Z",
	"created_by": {"id": 5, "is_superuser": false, "teams": [{"id": 1, "name": "app-team"}], "username": "policy-demo"},
	"credentials": [{
		"cloud": false,
		"credential_type": 8,
		"description": "Vault password for playbooks/group_vars/all/secrets.yml (vault_id: sales.demos)",
		"id": 7,
		"kind": "vault",
		"kubernetes": false,
		"managed": false,
		"name": "Sales Demos - Vault",
		"organization": {"id": 3, "name": "IT Service Automation"},
	}],
	"execution_environment": {"id": 5, "image": "registry.example.com/sales_demos_ee:v1.2.0", "name": "Sales Demos - OCP Virt EE", "pull": "missing"},
	"extra_vars": {"greeting": "if you can read this, the canary did NOT block"},
	"forks": 0,
	"hosts_count": 0,
	"id": 133,
	"instance_group": {"capacity": 0, "id": 2, "jobs_running": 1, "jobs_total": 116, "max_concurrent_jobs": 0, "max_forks": 0, "name": "default"},
	"inventory": {
		"description": "Control hosts synced from inventory/hosts.yml, plus the demo VMs registered by playbooks/provision_vm.yml.",
		"has_active_failures": false,
		"has_inventory_sources": true,
		"hosts_with_active_failures": 0,
		"id": 3,
		"inventory_sources": [{"id": 11, "name": "sales.demos repo inventory", "source": "scm", "status": "successful"}],
		"kind": "",
		"name": "Sales Demo VMs",
		"total_groups": 7,
		"total_hosts": 5,
		"total_inventory_sources": 1,
	},
	"job_template": {"id": 68, "job_type": "run", "name": "Policy as Code - Canary"},
	"job_type": "run",
	"job_type_name": "job",
	"labels": [{"id": 15, "name": "policy", "organization": {"id": 3, "name": "IT Service Automation"}}],
	"launch_type": "manual",
	"launched_by": {"id": 5, "name": "policy-demo", "type": "user", "url": "/api/v2/users/5/"},
	"limit": "sandbox",
	"name": "Policy as Code - Canary",
	"organization": {"id": 3, "name": "IT Service Automation"},
	"playbook": "playbooks/policy_demo_hello.yml",
	"project": {
		"id": 10,
		"name": "Sales Demos",
		"scm_branch": "main",
		"scm_clean": true,
		"scm_delete_on_update": false,
		"scm_refspec": "",
		"scm_track_submodules": false,
		"scm_type": "git",
		"scm_url": "https://github.com/ericcames/sales.demos.git",
		"status": "successful",
	},
	# The JOB's branch override, empty unless the template allows one at
	# launch — not the project's branch above.
	"scm_branch": "",
	# Empty at decision time: the job has not checked out anything yet.
	"scm_revision": "",
	"workflow_job": null,
	"workflow_job_template": null,
}

_aap27_with(overrides) := object.union(_aap27_input, overrides)

# ---------------------------------------------------------------------------
# Contract — every decision returns AAP's shape against the real input
# ---------------------------------------------------------------------------
test_aap27_every_decision_returns_contract if {
	results := [
		policy.maintenance_window, policy.maintenance_mode,
		policy.owner_scope, policy.superuser_restriction, policy.credential_scope,
		policy.required_labels, policy.extra_vars_control, policy.team_extra_vars,
		policy.naming_standard, policy.source_control, policy.deny_all,
	] with input as _aap27_input
	count(results) == 11
	every r in results {
		is_boolean(r.allowed)
		is_array(r.violations)
	}
}

# ---------------------------------------------------------------------------
# Teams arrive as {"id", "name"} objects
# ---------------------------------------------------------------------------
test_aap27_team_binding_grants_access if {
	r := policy.owner_scope with input as _aap27_input
		with data.aac.aap.config as {"owner_scope": {
			"team_bindings": {"app-team": ["sales demo*"]},
			"unbound_users_allowed": false,
		}}
	r.allowed
	count(r.violations) == 0
}

test_aap27_team_binding_restricts_access if {
	r := policy.owner_scope with input as _aap27_input
		with data.aac.aap.config as {"owner_scope": {
			"team_bindings": {"app-team": ["dev-*"]},
			"unbound_users_allowed": false,
		}}
	not r.allowed
	count(r.violations) == 1
}

test_aap27_team_extra_vars_permits_team_key if {
	r := policy.team_extra_vars with input as _aap27_input
		with data.aac.aap.config as {"team_extra_vars": {
			"teams": {"app-team": ["greeting"]},
			"unbound_teams_allowed": false,
		}}
	r.allowed
}

test_aap27_team_extra_vars_blocks_key_outside_team if {
	r := policy.team_extra_vars with input as _aap27_input
		with data.aac.aap.config as {"team_extra_vars": {"teams": {"app-team": ["app_version"]}}}
	not r.allowed
	count(r.violations) == 1
}

# Bare team names, as in test_aap_policy.rego, keep working.
test_aap27_bare_team_names_still_accepted if {
	r := policy.owner_scope with input as _aap27_with({"created_by": {"username": "policy-demo", "is_superuser": false, "teams": ["app-team"]}})
		with data.aac.aap.config as {"owner_scope": {
			"team_bindings": {"app-team": ["sales demo*"]},
			"unbound_users_allowed": false,
		}}
	r.allowed
}

# ---------------------------------------------------------------------------
# Credentials carry organization as an object
# ---------------------------------------------------------------------------
test_aap27_org_scoped_credential_is_not_global if {
	r := policy.credential_scope with input as _aap27_input
		with data.aac.aap.config as {"credential_scope": {"require_prefix_match": false}}
	r.allowed
}

test_aap27_global_credential_is_denied if {
	cred := object.union(_aap27_input.credentials[0], {"organization": null})
	r := policy.credential_scope with input as _aap27_with({"credentials": [cred]})
		with data.aac.aap.config as {"credential_scope": {"require_prefix_match": false}}
	not r.allowed
	count(r.violations) == 1
}

# ---------------------------------------------------------------------------
# Known gap, pinned rather than hidden: AAP 2.7 sends no organization on
# job_template or inventory, so enforce_org_match has nothing to compare and
# cannot fire. This test documents today's behaviour; change it together
# with the rule if the inventory's organization becomes available.
# ---------------------------------------------------------------------------
test_aap27_org_match_has_no_inventory_org_to_compare if {
	not "organization" in object.keys(_aap27_input.job_template)
	not "organization" in object.keys(_aap27_input.inventory)
	r := policy.owner_scope with input as _aap27_input
		with data.aac.aap.config as {"owner_scope": {"enforce_org_match": true}}
	r.allowed
}

# ---------------------------------------------------------------------------
# Superuser and canary behave on the real shape
# ---------------------------------------------------------------------------
test_aap27_non_superuser_allowed if {
	r := policy.superuser_restriction with input as _aap27_input
	r.allowed
}

test_aap27_superuser_denied if {
	r := policy.superuser_restriction with input as _aap27_with({"created_by": {"id": 1, "username": "admin", "is_superuser": true, "teams": [{"id": 1, "name": "app-team"}]}})
	not r.allowed
}

test_aap27_deny_all_blocks_when_active if {
	r := policy.deny_all with input as _aap27_input
		with data.aac.aap.config as {"deny_all": {"active": true, "reason": "wiring canary"}}
	not r.allowed
	count(r.violations) == 1
}
