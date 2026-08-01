# AAP job policy — what variables may enter automation.
#
# extra_vars are the widest injection surface on a job. This constrains which
# keys may be set, what values they may take, and who may set them.
#
# Query paths:
#   /v1/data/aac/aap/policy/extra_vars_control
#   /v1/data/aac/aap/policy/team_extra_vars
#
# Covers PAC examples: extra_vars_allowlist, extra_vars_validation,
# team_based_extra_vars_restriction
package aac.aap.policy

import rego.v1

# ---------------------------------------------------------------------------
# Configuration — override via data.aac.aap.config.extra_vars
#
#   {"allowlist": ["app_version", "target_env"],
#    "denylist": ["ansible_become_password"],
#    "allow_unlisted": false,
#    "value_patterns": {"target_env": "^(dev|stage|prod)$"},
#    "forbid_secret_like_keys": true}
# ---------------------------------------------------------------------------
_ev_defaults := {
	"allowlist": [],
	"denylist": [],
	# When false, any key outside the allowlist is rejected.
	"allow_unlisted": true,
	"value_patterns": {},
	"forbid_secret_like_keys": true,
	"secret_key_pattern": "(?i)(pass|passwd|password|secret|token|api_?key|private_?key)",
}

_ev_cfg := object.union(_ev_defaults, _override) if {
	_override := data.aac.aap.config.extra_vars
	is_object(_override)
} else := _ev_defaults

# extra_vars may arrive as an object or as a JSON string.
_extra_vars := ev if {
	is_object(input.extra_vars)
	ev := input.extra_vars
} else := ev if {
	is_string(input.extra_vars)
	ev := json.unmarshal(input.extra_vars)
} else := {}

_ev_keys := {lower(k) | some k, _ in _extra_vars}

_ev_allowlist := {lower(k) | some k in _ev_cfg.allowlist}

_ev_denylist := {lower(k) | some k in _ev_cfg.denylist}

# --- explicit denylist -----------------------------------------------------
_ev_violations contains msg if {
	some k in _ev_keys
	k in _ev_denylist
	msg := sprintf("extra_var '%s' is explicitly denied.", [k])
}

# --- allowlist enforcement -------------------------------------------------
_ev_violations contains msg if {
	not _ev_cfg.allow_unlisted
	count(_ev_allowlist) > 0
	some k in _ev_keys
	not k in _ev_allowlist
	msg := sprintf(
		"extra_var '%s' is not in the approved allowlist %v.",
		[k, _ev_cfg.allowlist],
	)
}

# --- secret-shaped keys ----------------------------------------------------
_ev_violations contains msg if {
	_ev_cfg.forbid_secret_like_keys
	some k in _ev_keys
	regex.match(_ev_cfg.secret_key_pattern, k)
	msg := sprintf(
		"extra_var '%s' looks like a secret — pass it through a credential or Ansible Vault, not extra_vars.",
		[k],
	)
}

# --- value validation ------------------------------------------------------
_ev_violations contains msg if {
	some key, pattern in _ev_cfg.value_patterns
	some k, v in _extra_vars
	lower(k) == lower(key)
	sv := _as_string(v)
	not regex.match(pattern, sv)
	msg := sprintf(
		"extra_var '%s' value '%s' does not match the required format %s.",
		[k, sv, pattern],
	)
}

_as_string(v) := v if is_string(v)

_as_string(v) := sprintf("%v", [v]) if not is_string(v)

extra_vars_control := {
	"allowed": count(_ev_violations) == 0,
	"violations": [v | some v in _ev_violations],
}

# ---------------------------------------------------------------------------
# Team-scoped extra_vars — override via data.aac.aap.config.team_extra_vars
#
#   {"teams": {"app-team": ["app_version"], "dba": ["db_schema_version"]},
#    "unbound_teams_allowed": false}
#
# A user may only set keys permitted to at least one of their teams.
# ---------------------------------------------------------------------------
_tev_defaults := {"teams": {}, "unbound_teams_allowed": true}

_tev_cfg := object.union(_tev_defaults, _override) if {
	_override := data.aac.aap.config.team_extra_vars
	is_object(_override)
} else := _tev_defaults

_user_teams := {lower(t) | some t in object.get(input, ["created_by", "teams"], [])}

_team_permitted := {lower(k) |
	some team in _user_teams
	some k in object.get(_tev_cfg.teams, team, [])
}

_has_team_binding if {
	some team in _user_teams
	object.get(_tev_cfg.teams, team, null) != null
}

_tev_violations contains msg if {
	count(_extra_vars) > 0
	_has_team_binding
	some k in _ev_keys
	not k in _team_permitted
	msg := sprintf(
		"extra_var '%s' is not permitted for teams %v (permitted: %v).",
		[k, _user_teams, _team_permitted],
	)
}

_tev_violations contains msg if {
	count(_extra_vars) > 0
	not _has_team_binding
	not _tev_cfg.unbound_teams_allowed
	msg := sprintf(
		"User's teams %v have no extra_vars binding and unbound use is disabled.",
		[_user_teams],
	)
}

team_extra_vars := {
	"allowed": count(_tev_violations) == 0,
	"violations": [v | some v in _tev_violations],
}
