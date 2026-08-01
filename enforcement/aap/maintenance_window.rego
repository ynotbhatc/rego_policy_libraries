# AAP job policy — time-of-day windows, change freezes, and maintenance mode.
#
# Consumes the Ansible Automation Platform Policy as Code job-context input and
# returns the documented decision contract:
#
#   {"allowed": bool, "violations": [string]}
#
# Query paths (associate with an organization, inventory, or job template):
#   /v1/data/aac/aap/policy/maintenance_window
#   /v1/data/aac/aap/policy/maintenance_mode
#
# Covers PAC example: maintenance_window
package aac.aap.policy

import rego.v1

# ---------------------------------------------------------------------------
# Configuration — override via data.aac.aap.config.maintenance_window
# ---------------------------------------------------------------------------
_mw_defaults := {
	"timezone": "UTC",
	# Days on which automation may run at all.
	"allowed_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
	# Permitted window, 24h clock. Wraps midnight when start > end.
	"start_hour": 0,
	"end_hour": 24,
	# Full-day freezes, "YYYY-MM-DD".
	"freeze_dates": [],
	# A job carrying this label bypasses the window (audited by its presence).
	"break_glass_label": "break-glass",
}

_mw_cfg := object.union(_mw_defaults, _override) if {
	_override := data.aac.aap.config.maintenance_window
	is_object(_override)
} else := _mw_defaults

# ---------------------------------------------------------------------------
# Evaluation time — prefer the job's own timestamp so decisions are
# reproducible when replayed; fall back to wall clock.
# ---------------------------------------------------------------------------
_eval_ns := ns if {
	is_string(input.created)
	ns := time.parse_rfc3339_ns(input.created)
} else := time.now_ns()

_tz := _mw_cfg.timezone

_weekday := time.weekday([_eval_ns, _tz])

_hour := h if {
	clock := time.clock([_eval_ns, _tz])
	h := clock[0]
}

_date := sprintf("%04d-%02d-%02d", [y, m, d]) if {
	parts := time.date([_eval_ns, _tz])
	y := parts[0]
	m := parts[1]
	d := parts[2]
}

_labels := {lower(l.name) | some l in object.get(input, "labels", [])}

_break_glass if {
	lower(_mw_cfg.break_glass_label) in _labels
}

# ---------------------------------------------------------------------------
# Window logic
# ---------------------------------------------------------------------------
_in_hours if {
	_mw_cfg.start_hour <= _mw_cfg.end_hour
	_hour >= _mw_cfg.start_hour
	_hour < _mw_cfg.end_hour
}

# Window wraps midnight, e.g. 22:00 -> 04:00
_in_hours if {
	_mw_cfg.start_hour > _mw_cfg.end_hour
	_hour >= _mw_cfg.start_hour
}

_in_hours if {
	_mw_cfg.start_hour > _mw_cfg.end_hour
	_hour < _mw_cfg.end_hour
}

_day_allowed if {
	_weekday in _mw_cfg.allowed_days
}

_frozen if {
	_date in _mw_cfg.freeze_dates
}

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------
_mw_violations contains msg if {
	not _break_glass
	_frozen
	msg := sprintf(
		"Change freeze in effect for %s — automation is blocked. Apply the '%s' label with an approved change record to override.",
		[_date, _mw_cfg.break_glass_label],
	)
}

_mw_violations contains msg if {
	not _break_glass
	not _day_allowed
	msg := sprintf(
		"%s is not an approved day for automation (allowed: %v).",
		[_weekday, _mw_cfg.allowed_days],
	)
}

_mw_violations contains msg if {
	not _break_glass
	not _in_hours
	msg := sprintf(
		"%02d:00 %s is outside the approved change window %02d:00-%02d:00.",
		[_hour, _tz, _mw_cfg.start_hour, _mw_cfg.end_hour],
	)
}

# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------
maintenance_window := {
	"allowed": count(_mw_violations) == 0,
	"violations": [v | some v in _mw_violations],
}

# ---------------------------------------------------------------------------
# Maintenance mode — a named freeze on specific inventories or the whole
# platform. Override via data.aac.aap.config.maintenance_mode.
#
#   {"active": true, "inventories": ["prod-web"], "reason": "DB migration",
#    "break_glass_label": "break-glass"}
#
# An empty "inventories" list means platform-wide.
# ---------------------------------------------------------------------------
_mm_defaults := {
	"active": false,
	"inventories": [],
	"reason": "unspecified",
	"break_glass_label": "break-glass",
}

_mm_cfg := object.union(_mm_defaults, _override) if {
	_override := data.aac.aap.config.maintenance_mode
	is_object(_override)
} else := _mm_defaults

_mm_break_glass if {
	lower(_mm_cfg.break_glass_label) in _labels
}

_inventory_name := lower(object.get(input, ["inventory", "name"], ""))

_mm_scoped if {
	count(_mm_cfg.inventories) == 0
}

_mm_scoped if {
	some inv in _mm_cfg.inventories
	lower(inv) == _inventory_name
}

_mm_violations contains msg if {
	_mm_cfg.active
	_mm_scoped
	not _mm_break_glass
	msg := sprintf(
		"Maintenance mode is active for inventory '%s' (reason: %s). Automation is blocked until it is cleared.",
		[_inventory_name, _mm_cfg.reason],
	)
}

maintenance_mode := {
	"allowed": count(_mm_violations) == 0,
	"violations": [v | some v in _mm_violations],
}
