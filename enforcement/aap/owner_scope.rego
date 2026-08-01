# AAP job policy — who may automate what.
#
# Binds launching users (and their teams) to the inventories and environments
# they are permitted to target, and constrains privileged launches.
#
# Query paths:
#   /v1/data/aac/aap/policy/owner_scope           — owner -> inventory/environment
#   /v1/data/aac/aap/policy/superuser_restriction  — deny superuser launches
#   /v1/data/aac/aap/policy/credential_scope       — credential/inventory coherence
#
# Covers PAC examples: restrict_inv_use_to_org, superuser_allowed_false,
# mismatch_prefix_allowed_false, global_credential_allowed_false
package aac.aap.policy

import rego.v1

# ---------------------------------------------------------------------------
# Configuration — override via data.aac.aap.config.owner_scope
#
#   {"bindings": {"alice": ["prod-*", "stage-*"], "bob": ["dev-*"]},
#    "team_bindings": {"platform-sre": ["*"]},
#    "unbound_users_allowed": false,
#    "enforce_org_match": true}
# ---------------------------------------------------------------------------
_os_defaults := {
	"bindings": {},
	"team_bindings": {},
	# When false, a user with no binding cannot launch anything.
	"unbound_users_allowed": true,
	# Require the inventory's organization to match the job template's.
	"enforce_org_match": true,
}

_os_cfg := object.union(_os_defaults, _override) if {
	_override := data.aac.aap.config.owner_scope
	is_object(_override)
} else := _os_defaults

_username := lower(object.get(input, ["created_by", "username"], ""))

_inv_name := lower(object.get(input, ["inventory", "name"], ""))

_teams := {lower(t) | some t in object.get(input, ["created_by", "teams"], [])}

# Patterns this launcher is permitted to target, from user and team bindings.
_allowed_patterns := patterns if {
	user_pats := object.get(_os_cfg.bindings, _username, [])
	team_pats := [p |
		some team in _teams
		some p in object.get(_os_cfg.team_bindings, team, [])
	]
	patterns := array.concat(user_pats, team_pats)
}

_has_binding if {
	count(_allowed_patterns) > 0
}

_matches_any if {
	some pattern in _allowed_patterns
	glob.match(lower(pattern), [], _inv_name)
}

_os_violations contains msg if {
	_inv_name != ""
	_has_binding
	not _matches_any
	msg := sprintf(
		"User '%s' is not permitted to target inventory '%s' (permitted: %v).",
		[_username, _inv_name, _allowed_patterns],
	)
}

_os_violations contains msg if {
	_inv_name != ""
	not _has_binding
	not _os_cfg.unbound_users_allowed
	msg := sprintf(
		"User '%s' has no inventory binding and unbound launches are disabled.",
		[_username],
	)
}

# Inventory must belong to the same organization as the job template.
_jt_org := object.get(input, ["job_template", "organization"], null)

_inv_org := object.get(input, ["inventory", "organization"], null)

_os_violations contains msg if {
	_os_cfg.enforce_org_match
	is_number(_jt_org)
	is_number(_inv_org)
	_jt_org != _inv_org
	msg := sprintf(
		"Inventory organization (%d) does not match the job template's organization (%d).",
		[_inv_org, _jt_org],
	)
}

owner_scope := {
	"allowed": count(_os_violations) == 0,
	"violations": [v | some v in _os_violations],
}

# ---------------------------------------------------------------------------
# Superuser restriction — override via data.aac.aap.config.superuser
#
#   {"deny": true, "exempt_users": ["break-glass-svc"]}
# ---------------------------------------------------------------------------
_su_defaults := {"deny": true, "exempt_users": []}

_su_cfg := object.union(_su_defaults, _override) if {
	_override := data.aac.aap.config.superuser
	is_object(_override)
} else := _su_defaults

_su_exempt if {
	some u in _su_cfg.exempt_users
	lower(u) == _username
}

_su_violations contains msg if {
	_su_cfg.deny
	object.get(input, ["created_by", "is_superuser"], false) == true
	not _su_exempt
	msg := sprintf(
		"Superuser '%s' may not launch automation directly — use a scoped service account so the action is attributable.",
		[_username],
	)
}

superuser_restriction := {
	"allowed": count(_su_violations) == 0,
	"violations": [v | some v in _su_violations],
}

# ---------------------------------------------------------------------------
# Credential scope — override via data.aac.aap.config.credential_scope
#
#   {"deny_global_credentials": true,
#    "require_prefix_match": true,
#    "prefix_separator": "-"}
#
# require_prefix_match guards the classic mistake of pointing a production
# credential at a development inventory (or vice versa) by comparing the
# leading token of each name.
# ---------------------------------------------------------------------------
_cs_defaults := {
	"deny_global_credentials": true,
	"require_prefix_match": true,
	"prefix_separator": "-",
	"exempt_credentials": [],
}

_cs_cfg := object.union(_cs_defaults, _override) if {
	_override := data.aac.aap.config.credential_scope
	is_object(_override)
} else := _cs_defaults

_credentials := object.get(input, "credentials", [])

_cred_exempt(name) if {
	some e in _cs_cfg.exempt_credentials
	lower(e) == lower(name)
}

# A credential with no owning organization is global.
_cs_violations contains msg if {
	_cs_cfg.deny_global_credentials
	some cred in _credentials
	cred.organization == null
	not cred.managed
	not _cred_exempt(cred.name)
	msg := sprintf(
		"Credential '%s' is global (no owning organization) — scope it to an organization before use.",
		[cred.name],
	)
}

_prefix(name) := p if {
	parts := split(lower(name), _cs_cfg.prefix_separator)
	p := parts[0]
}

_cs_violations contains msg if {
	_cs_cfg.require_prefix_match
	_inv_name != ""
	some cred in _credentials
	not _cred_exempt(cred.name)
	cp := _prefix(cred.name)
	ip := _prefix(_inv_name)
	cp != ip
	msg := sprintf(
		"Credential '%s' (prefix '%s') does not match inventory '%s' (prefix '%s') — likely an environment mismatch.",
		[cred.name, cp, _inv_name, ip],
	)
}

credential_scope := {
	"allowed": count(_cs_violations) == 0,
	"violations": [v | some v in _cs_violations],
}
