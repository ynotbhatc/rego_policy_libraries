# AAP job policy — label-driven gating.
#
# Labels are the cheapest way to carry governance intent on a job: a change
# ticket, an approval, an environment marker, a quarantine flag. This policy
# makes them enforceable.
#
# Query path:
#   /v1/data/aac/aap/policy/required_labels
#
# No PAC example covers this — it is an AAC addition.
package aac.aap.policy

import rego.v1

# ---------------------------------------------------------------------------
# Configuration — override via data.aac.aap.config.labels
#
#   {"required": ["change-ticket"],
#    "forbidden": ["quarantined", "do-not-run"],
#    "required_for_inventories": {"prod-*": ["change-approved", "peer-reviewed"]},
#    "one_of": [["env-dev", "env-stage", "env-prod"]],
#    "pattern_requirements": {"change-ticket": "^CHG[0-9]{7}$"}}
# ---------------------------------------------------------------------------
_lbl_defaults := {
	"required": [],
	"forbidden": [],
	"required_for_inventories": {},
	"one_of": [],
	"pattern_requirements": {},
}

_lbl_cfg := object.union(_lbl_defaults, _override) if {
	_override := data.aac.aap.config.labels
	is_object(_override)
} else := _lbl_defaults

_label_list := object.get(input, "labels", [])

_label_names := {lower(l.name) | some l in _label_list}

_inventory := lower(object.get(input, ["inventory", "name"], ""))

# --- forbidden -------------------------------------------------------------
_lbl_violations contains msg if {
	some f in _lbl_cfg.forbidden
	lower(f) in _label_names
	msg := sprintf(
		"Job carries the forbidden label '%s' — execution is blocked.",
		[f],
	)
}

# --- globally required -----------------------------------------------------
_lbl_violations contains msg if {
	some r in _lbl_cfg.required
	not lower(r) in _label_names
	msg := sprintf("Required label '%s' is missing.", [r])
}

# --- required for matching inventories -------------------------------------
_lbl_violations contains msg if {
	some pattern, required in _lbl_cfg.required_for_inventories
	glob.match(lower(pattern), [], _inventory)
	some r in required
	not lower(r) in _label_names
	msg := sprintf(
		"Inventory '%s' matches '%s', which requires the label '%s'.",
		[_inventory, pattern, r],
	)
}

# --- exactly-one-of groups (e.g. an environment marker) --------------------
_lbl_violations contains msg if {
	some group in _lbl_cfg.one_of
	present := [g | some g in group; lower(g) in _label_names]
	count(present) == 0
	msg := sprintf("Exactly one of %v must be present; none were.", [group])
}

_lbl_violations contains msg if {
	some group in _lbl_cfg.one_of
	present := [g | some g in group; lower(g) in _label_names]
	count(present) > 1
	msg := sprintf(
		"Exactly one of %v must be present; found %v.",
		[group, present],
	)
}

# --- value format ----------------------------------------------------------
# Enforces "key:value" labels, e.g. change-ticket:CHG0012345
_lbl_violations contains msg if {
	some key, pattern in _lbl_cfg.pattern_requirements
	values := [v |
		some l in _label_list
		parts := split(l.name, ":")
		count(parts) == 2
		lower(parts[0]) == lower(key)
		v := parts[1]
	]
	count(values) > 0
	some v in values
	not regex.match(pattern, v)
	msg := sprintf(
		"Label '%s' value '%s' does not match the required format %s.",
		[key, v, pattern],
	)
}

_lbl_violations contains msg if {
	some key, pattern in _lbl_cfg.pattern_requirements
	values := [v |
		some l in _label_list
		parts := split(l.name, ":")
		count(parts) == 2
		lower(parts[0]) == lower(key)
		v := parts[1]
	]
	count(values) == 0
	msg := sprintf(
		"Label '%s' is required in 'key:value' form matching %s, but no value was supplied.",
		[key, pattern],
	)
}

required_labels := {
	"allowed": count(_lbl_violations) == 0,
	"violations": [v | some v in _lbl_violations],
}
