# METADATA
# title: "Sentinel-equivalent policy for Ansible playbooks"
# custom:
#   class: enforcement
#   framework: enforcement_ansible
#   source: aac
#   domains: [ansible]
#   coverage:
#     checks: 5
#     cited: 4
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sentinel.ansible

import rego.v1

# Sentinel-equivalent policy for Ansible playbooks
# Playbook YAML is converted to JSON before evaluation (via `from_yaml | to_json`)
# OPA endpoint: POST http://localhost:8181/v1/data/sentinel/ansible/result
#
# Input shape:
#   input.plays[].name          — play name (required)
#   input.plays[].hosts         — target hosts (must not be bare "all" in production)
#   input.plays[].vars          — play vars (checked for hardcoded secrets)
#   input.plays[].tasks[]       — task list
#   input.plays[].tasks[].name  — task name
#   input.plays[].tasks[].tags  — task tags (required for auditability)
#   input.environment           — "production" | "staging" | "development"

#
# A document that is not a readable playbook is denied, never waved through (SENTINEL-ANS-000): the gate
# judges input.plays, so that list must be there and every play, task list, vars map and tag list must
# have the shape the rules below read.

# =============================================================================
# PLAYBOOK SHAPE (SENTINEL-ANS-000)
# =============================================================================

violations contains msg if {
	not is_array(object.get(input, "plays", null))
	msg := sprintf("SENTINEL-ANS-000: Malformed playbook: input.plays must be a list of plays, got %v; nothing was evaluated", [_type(object.get(input, "plays", null))])
}

violations contains msg if {
	some i, play in input.plays
	problem := _play_problems(play)[_]
	msg := sprintf("SENTINEL-ANS-000: Malformed playbook: play [%v] %v", [i, problem])
}

_type(v) := "nothing" if v == null

_type(v) := type_name(v) if v != null

_play_problems(play) := {"is not a mapping"} if not is_object(play)

_play_problems(play) := {p |
	some p, bad in {
		"has a name that is not a string": _set_and_not(play, "name", {"string"}),
		"has vars that are not a mapping": _set_and_not(play, "vars", {"object"}),
		"has tasks that are not a list": _set_and_not(play, "tasks", {"array"}),
		"has a task that is not a mapping": _bad_task(play),
		"has a task whose tags are not a string or a list": _bad_task_tags(play),
	}
	bad
} if is_object(play)

# the key is set (present and not null) and its value is of none of the allowed types
_set_and_not(o, key, types) if {
	v := object.get(o, key, null)
	v != null
	not type_name(v) in types
} else := false

_bad_task(play) if {
	some task in play.tasks
	not is_object(task)
} else := false

_bad_task_tags(play) if {
	some task in play.tasks
	_set_and_not(task, "tags", {"string", "array"})
} else := false

# =============================================================================
# PLAYS MUST HAVE A NAME
# =============================================================================

violations contains msg if {
	some i, play in input.plays

	# a null name is no name (`not play.name` is false for null)
	not is_string(object.get(play, "name", null))
	msg := sprintf(
		"SENTINEL-ANS-001: Play [%v] has no 'name' field — all plays must be named for auditability",
		[i],
	)
}

violations contains msg if {
	some play in input.plays
	play.name == ""
	msg := sprintf(
		"SENTINEL-ANS-001: Play '%v' has an empty 'name' field",
		[object.get(play, "name", "(unnamed)")],
	)
}

# =============================================================================
# NO BARE 'all' HOSTS IN PRODUCTION
# =============================================================================

# Helper: "all" can arrive as string "all" (standard YAML) or as boolean true
# (some YAML 1.1 parsers). Handle both to be safe.
hosts_targets_all(hosts) if {
	is_string(hosts)
	lower(hosts) == "all"
}

hosts_targets_all(hosts) if {
	hosts == true
}

violations contains msg if {
	some play in input.plays
	hosts_targets_all(play.hosts)

	# Use sentinel_environment (not 'environment' which is an Ansible reserved keyword)
	object.get(input, "sentinel_environment", "production") == "production"
	msg := sprintf(
		"SENTINEL-ANS-002: Play '%v' targets all hosts — use an explicit group or limit in production",
		[object.get(play, "name", "(unnamed)")],
	)
}

# =============================================================================
# NO HARDCODED SECRETS IN VARS
# =============================================================================

secret_patterns := {"password", "secret", "api_key", "token", "private_key", "passwd", "credentials"}

violations contains msg if {
	some play in input.plays
	vars := object.get(play, "vars", {})
	some var_key in object.keys(vars)
	some pattern in secret_patterns
	contains(lower(var_key), pattern)
	var_value := vars[var_key]
	is_string(var_value)
	not startswith(var_value, "{{") # vault references are allowed
	msg := sprintf(
		"SENTINEL-ANS-003: Play '%v' has potential hardcoded secret in var '%v' — use Ansible Vault",
		[object.get(play, "name", "(unnamed)"), var_key],
	)
}

# =============================================================================
# TASKS MUST HAVE TAGS
# =============================================================================

violations contains msg if {
	some play in input.plays
	some task in object.get(play, "tasks", [])
	task_name := object.get(task, "name", "(unnamed task)")
	_no_tags(object.get(task, "tags", null))
	msg := sprintf(
		"SENTINEL-ANS-004: Task '%v' in play '%v' has no tags — tags required for selective execution and audit",
		[task_name, object.get(play, "name", "(unnamed)")],
	)
}

# no tags: the key is absent, null, or an empty string or list
_no_tags(tags) if tags == null

_no_tags(tags) if count(tags) == 0

# =============================================================================
# ALLOW / RESULT
# =============================================================================

default allow := false

allow if {
	count(violations) == 0
}

result := {
	"policy": "Sentinel — Ansible Playbook",
	"allow": allow,
	"violation_count": count(violations),
	"violations": [v | some v in violations],
}
