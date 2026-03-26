package sentinel.ansible

import rego.v1

# Sentinel-equivalent policy for Ansible playbooks
# Playbook YAML is converted to JSON before evaluation (via `from_yaml | to_json`)
# OPA endpoint: POST http://192.168.4.62:8182/v1/data/sentinel/ansible/result
#
# Input shape:
#   input.plays[].name          — play name (required)
#   input.plays[].hosts         — target hosts (must not be bare "all" in production)
#   input.plays[].vars          — play vars (checked for hardcoded secrets)
#   input.plays[].tasks[]       — task list
#   input.plays[].tasks[].name  — task name
#   input.plays[].tasks[].tags  — task tags (required for auditability)
#   input.environment           — "production" | "staging" | "development"

# =============================================================================
# PLAYS MUST HAVE A NAME
# =============================================================================

violations contains msg if {
    some i, play in input.plays
    not play.name
    msg := sprintf(
        "SENTINEL-ANS-001: Play [%v] has no 'name' field — all plays must be named for auditability",
        [i]
    )
}

violations contains msg if {
    some play in input.plays
    play.name == ""
    msg := sprintf(
        "SENTINEL-ANS-001: Play '%v' has an empty 'name' field",
        [play.name]
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
        [play.name]
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
    not startswith(var_value, "{{")    # vault references are allowed
    msg := sprintf(
        "SENTINEL-ANS-003: Play '%v' has potential hardcoded secret in var '%v' — use Ansible Vault",
        [play.name, var_key]
    )
}

# =============================================================================
# TASKS MUST HAVE TAGS
# =============================================================================

violations contains msg if {
    some play in input.plays
    some task in object.get(play, "tasks", [])
    task_name := object.get(task, "name", "(unnamed task)")
    task_tags := object.get(task, "tags", [])
    count(task_tags) == 0
    msg := sprintf(
        "SENTINEL-ANS-004: Task '%v' in play '%v' has no tags — tags required for selective execution and audit",
        [task_name, play.name]
    )
}

# =============================================================================
# ALLOW / RESULT
# =============================================================================

default allow := false

allow if {
    count(violations) == 0
}

result := {
    "policy":          "Sentinel — Ansible Playbook",
    "allow":           allow,
    "violation_count": count(violations),
    "violations":      [v | some v in violations],
}
