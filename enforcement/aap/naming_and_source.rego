# AAP job policy — naming standards and trusted automation sources.
#
# Query paths:
#   /v1/data/aac/aap/policy/naming_standard   — job template naming
#   /v1/data/aac/aap/policy/source_control    — approved repo and branch
#   /v1/data/aac/aap/policy/deny_all          — break-glass blanket deny
#
# Covers PAC examples: jt_naming_validation, github_repo_validation,
# project_scm_branch, allowed_false
package aac.aap.policy

import rego.v1

# ---------------------------------------------------------------------------
# Job-template naming — override via data.aac.aap.config.naming
#
#   {"pattern": "^(PROD|STAGE|DEV)-[A-Za-z0-9]+ - .+$",
#    "max_length": 80, "forbid_terms": ["test", "tmp", "copy of"]}
# ---------------------------------------------------------------------------
_nm_defaults := {
	"pattern": "",
	"max_length": 0,
	"forbid_terms": [],
}

_nm_cfg := object.union(_nm_defaults, _override) if {
	_override := data.aac.aap.config.naming
	is_object(_override)
} else := _nm_defaults

_jt_name := object.get(input, ["job_template", "name"], object.get(input, "name", ""))

_nm_violations contains msg if {
	_nm_cfg.pattern != ""
	_jt_name != ""
	not regex.match(_nm_cfg.pattern, _jt_name)
	msg := sprintf(
		"Job template name '%s' does not match the required convention %s.",
		[_jt_name, _nm_cfg.pattern],
	)
}

_nm_violations contains msg if {
	_nm_cfg.max_length > 0
	count(_jt_name) > _nm_cfg.max_length
	msg := sprintf(
		"Job template name is %d characters; the maximum is %d.",
		[count(_jt_name), _nm_cfg.max_length],
	)
}

_nm_violations contains msg if {
	some term in _nm_cfg.forbid_terms
	contains(lower(_jt_name), lower(term))
	msg := sprintf(
		"Job template name '%s' contains the forbidden term '%s'.",
		[_jt_name, term],
	)
}

naming_standard := {
	"allowed": count(_nm_violations) == 0,
	"violations": [v | some v in _nm_violations],
}

# ---------------------------------------------------------------------------
# Source control — override via data.aac.aap.config.source_control
#
#   {"allowed_repos": ["github.com/acme/*"],
#    "allowed_branches": ["main", "release/*"],
#    "forbid_detached_head": true,
#    "require_https": true}
# ---------------------------------------------------------------------------
_sc_defaults := {
	"allowed_repos": [],
	"allowed_branches": [],
	"forbid_detached_head": true,
	"require_https": true,
}

_sc_cfg := object.union(_sc_defaults, _override) if {
	_override := data.aac.aap.config.source_control
	is_object(_override)
} else := _sc_defaults

_scm_url := lower(object.get(input, ["project", "scm_url"], ""))

_scm_branch := object.get(input, ["project", "scm_branch"], "")

# Normalise git@host:org/repo and https://host/org/repo to host/org/repo
_repo_id := id if {
	startswith(_scm_url, "git@")
	trimmed := trim_prefix(_scm_url, "git@")
	id := replace(trim_suffix(trimmed, ".git"), ":", "/")
} else := id if {
	regex.match("^https?://", _scm_url)
	stripped := regex.replace(_scm_url, "^https?://", "")
	id := trim_suffix(stripped, ".git")
} else := ""

_sc_violations contains msg if {
	_sc_cfg.require_https
	_scm_url != ""
	startswith(_scm_url, "git@")
	msg := sprintf(
		"Project source '%s' uses SSH — HTTPS is required so access is brokered by a managed credential.",
		[_scm_url],
	)
}

_sc_violations contains msg if {
	count(_sc_cfg.allowed_repos) > 0
	_repo_id != ""
	not _repo_allowed
	msg := sprintf(
		"Project repository '%s' is not an approved automation source (allowed: %v).",
		[_repo_id, _sc_cfg.allowed_repos],
	)
}

_repo_allowed if {
	some pattern in _sc_cfg.allowed_repos
	glob.match(lower(pattern), ["/"], _repo_id)
}

_sc_violations contains msg if {
	count(_sc_cfg.allowed_branches) > 0
	_scm_branch != ""
	not _branch_allowed
	msg := sprintf(
		"Project branch '%s' is not approved for execution (allowed: %v).",
		[_scm_branch, _sc_cfg.allowed_branches],
	)
}

_branch_allowed if {
	some pattern in _sc_cfg.allowed_branches
	glob.match(pattern, ["/"], _scm_branch)
}

_sc_violations contains msg if {
	_sc_cfg.forbid_detached_head
	regex.match("^[0-9a-f]{40}$", lower(_scm_branch))
	msg := sprintf(
		"Project is pinned to commit %s rather than a named branch — automation must run from a reviewable ref.",
		[_scm_branch],
	)
}

source_control := {
	"allowed": count(_sc_violations) == 0,
	"violations": [v | some v in _sc_violations],
}

# ---------------------------------------------------------------------------
# Blanket deny — the incident switch. Associate with an organization to halt
# all automation. Override via data.aac.aap.config.deny_all.
#
#   {"active": true, "reason": "SEV1 in progress", "exempt_labels": ["incident-response"]}
# ---------------------------------------------------------------------------
_da_defaults := {
	"active": false,
	"reason": "automation is administratively halted",
	"exempt_labels": ["incident-response"],
}

_da_cfg := object.union(_da_defaults, _override) if {
	_override := data.aac.aap.config.deny_all
	is_object(_override)
} else := _da_defaults

_da_labels := {lower(l.name) | some l in object.get(input, "labels", [])}

_da_exempt if {
	some e in _da_cfg.exempt_labels
	lower(e) in _da_labels
}

_da_violations contains msg if {
	_da_cfg.active
	not _da_exempt
	msg := sprintf("All automation is blocked: %s.", [_da_cfg.reason])
}

deny_all := {
	"allowed": count(_da_violations) == 0,
	"violations": [v | some v in _da_violations],
}
