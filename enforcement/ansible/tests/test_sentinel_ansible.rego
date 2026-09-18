# Tests for the Sentinel-equivalent Ansible playbook enforcement policy.
#
# One test per violation path (each isolated so only that rule fires), a
# compliant case where nothing denies and `allow` is true, and a test pinning
# that the aggregate `result` object is populated on empty input.

package sentinel.ansible_test

import data.sentinel.ansible
import rego.v1

# ── helpers ──────────────────────────────────────────────────────────────────

has(violations, code) if {
	some v in violations
	startswith(v, code)
}

# ── SENTINEL-ANS-001 — plays must have a name ────────────────────────────────

test_play_without_name_violates if {
	v := ansible.violations with input as {"plays": [{"hosts": "webservers"}]}
	has(v, "SENTINEL-ANS-001")
	count(v) == 1
}

test_play_with_empty_name_violates if {
	v := ansible.violations with input as {"plays": [{"name": "", "hosts": "webservers"}]}
	has(v, "SENTINEL-ANS-001")
	count(v) == 1
}

# ── SENTINEL-ANS-002 — no bare 'all' hosts in production ─────────────────────

test_bare_all_hosts_in_production_violates if {
	v := ansible.violations with input as {"plays": [{"name": "deploy", "hosts": "all"}]}
	has(v, "SENTINEL-ANS-002")
	count(v) == 1
}

# boolean-true hosts (YAML 1.1 parsers) is treated the same as string "all"
test_bare_all_hosts_boolean_true_violates if {
	v := ansible.violations with input as {"plays": [{"name": "deploy", "hosts": true}]}
	has(v, "SENTINEL-ANS-002")
	count(v) == 1
}

# same play is fine outside production
test_bare_all_hosts_allowed_outside_production if {
	v := ansible.violations with input as {
		"sentinel_environment": "development",
		"plays": [{"name": "deploy", "hosts": "all"}],
	}
	count(v) == 0
}

# ── SENTINEL-ANS-003 — no hardcoded secrets in vars ──────────────────────────

test_hardcoded_secret_in_vars_violates if {
	v := ansible.violations with input as {"plays": [{
		"name": "deploy",
		"hosts": "webservers",
		"vars": {"db_password": "hunter2"},
	}]}
	has(v, "SENTINEL-ANS-003")
	count(v) == 1
}

# a vault reference ({{ ... }}) is not a hardcoded secret
test_vault_reference_var_is_allowed if {
	v := ansible.violations with input as {"plays": [{
		"name": "deploy",
		"hosts": "webservers",
		"vars": {"db_password": "{{ vault_db_password }}"},
	}]}
	count(v) == 0
}

# ── SENTINEL-ANS-004 — tasks must have tags ──────────────────────────────────

test_task_without_tags_violates if {
	v := ansible.violations with input as {"plays": [{
		"name": "deploy",
		"hosts": "webservers",
		"tasks": [{"name": "install nginx"}],
	}]}
	has(v, "SENTINEL-ANS-004")
	count(v) == 1
}

# ── Compliant input — nothing denies, allow is true ──────────────────────────

test_compliant_playbook_allows if {
	clean := {
		"sentinel_environment": "production",
		"plays": [{
			"name": "deploy web tier",
			"hosts": "webservers",
			"vars": {"db_password": "{{ vault_db_password }}"},
			"tasks": [{"name": "install nginx", "tags": ["web"]}],
		}],
	}
	v := ansible.violations with input as clean
	count(v) == 0
	ansible.allow with input as clean
}

# default allow is false when a violation exists
test_allow_false_when_violation if {
	not ansible.allow with input as {"plays": [{"hosts": "all"}]}
}

# ── Aggregate report — populated object on empty input {} ────────────────────

test_result_is_populated_object_on_empty_input if {
	r := ansible.result with input as {}
	r.policy == "Sentinel — Ansible Playbook"
	r.allow == true
	r.violation_count == 0
	r.violations == []
	count(r) == 4
}
