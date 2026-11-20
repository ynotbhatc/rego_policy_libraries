# Security exception waivers — waived, never hidden.
#
# A waiver moves a finding from active violations to a waived set; it never
# deletes it. Consumers must store and report the waived set alongside the
# active one so an assessor sees a documented exception (justification,
# approver, expiry), not an absence. Expired waivers stop matching
# automatically — the finding reverts to an active violation with no
# configuration change.
#
# Waiver entries are plain data, loaded at data.waivers.entries (e.g.
# PUT /v1/data/waivers). Each entry:
#
#   {
#     "host":       "web01.example.com",   # or "*" for any host
#     "framework":  "cis_rhel9",           # or "*" for any framework
#     "control_id": "5.2.1",               # substring matched against the violation text
#     "reason":     "Compensating control: ...",
#     "approver":   "security-officer@example.com",
#     "expires":    "2026-12-31"           # YYYY-MM-DD; entries without a date never match.
#                                          # Dates must be before year 2262 (int64 ns limit) —
#                                          # a far-future date fails to parse and the entry
#                                          # silently never matches (fails toward reporting).
#     "mitigation":   "WAF rule 4411 blocks the path",   # optional: what reduces the risk while the gap is open
#     "evidence_ref": "CR-2201"                         # optional: where the approval / mitigation evidence lives
#   }
#
# Optional site settings, loaded at data.waivers.settings:
#
#   {
#     "required_fields":      ["reason", "approver", "mitigation"],  # each must be a non-empty string
#     "max_ttl_days":         180,   # a waiver may not expire further ahead than this (time to live)
#     "expiring_within_days": 14     # waivers this close to expiry are listed in expiring_soon (default 14)
#   }
#
# With no settings the behaviour is unchanged. An entry that matches a finding
# but breaks a setting is NOT applied: the finding stays active and the entry is
# listed in `rejected` with the reasons, so a gap cannot be warranted without a
# reason, a mitigation or an end date the site accepts. A setting that is
# present but malformed rejects every entry (fails toward reporting).
#
# Query: POST /v1/data/exceptions/decision with
#   input: {"host": "...", "framework": "...", "violations": [...]}
# Violations may be strings or objects; objects are matched against their
# JSON serialization, so a control ID anywhere in the object matches.

# METADATA
# title: "Security exception waivers — waived, never hidden"
# custom:
#   class: governance
#   framework: exceptions
#   source: aac
#   domains: [exceptions]
#   coverage:
#     checks: 5
#     cited: 0
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package exceptions

import rego.v1

# Narrow reference (never object.get(data, ...)) — depending on the whole data
# document would include this package's own rules and trip recursion checks.
default waiver_entries := []

waiver_entries := data.waivers.entries

input_violations := object.get(input, "violations", [])

input_host := object.get(input, "host", "")

input_framework := object.get(input, "framework", "")

# ── Matching ──────────────────────────────────────────────────────────────────

violation_text(v) := v if is_string(v)

violation_text(v) := json.marshal(v) if not is_string(v)

entry_active(entry) if {
	exp := object.get(entry, "expires", "")
	exp != ""
	time.now_ns() < time.parse_ns("2006-01-02", exp)
}

entry_matches(entry, v) if {
	object.get(entry, "host", "*") in {input_host, "*"}
	object.get(entry, "framework", "*") in {input_framework, "*"}
	cid := object.get(entry, "control_id", "")
	cid != ""
	_contains_id(violation_text(v), cid)
}

# Token-boundary match: the control id must not be a fragment of a longer id
# (a waiver for 5.2.1 must not waive 5.2.10, 15.2.1 or 5.2.1.3).
_contains_id(text, cid) if {
	esc := regex.replace(cid, `[.\\+*?()|\[\]{}^$]`, `\$0`)
	regex.match(sprintf(`(^|[^0-9A-Za-z.])%s($|[^0-9A-Za-z.]|\.($|[^0-9A-Za-z]))`, [esc]), text)
}

# ── Site settings: required fields and maximum time to live ──────────────────

default waiver_settings := {}

waiver_settings := data.waivers.settings

_ns_per_day := 86400000000000

_required_fields := object.get(waiver_settings, "required_fields", [])

_setting_problems contains "setting required_fields is not a list of field names" if {
	not is_array(_required_fields)
}

_setting_problems contains "setting required_fields is not a list of field names" if {
	some f in _required_fields
	not is_string(f)
}

_setting_problems contains "setting max_ttl_days is not a positive number" if {
	"max_ttl_days" in object.keys(waiver_settings)
	not _positive_number(waiver_settings.max_ttl_days)
}

_setting_problems contains "setting expiring_within_days is not a positive number" if {
	"expiring_within_days" in object.keys(waiver_settings)
	not _positive_number(waiver_settings.expiring_within_days)
}

_positive_number(x) if {
	is_number(x)
	x > 0
}

_filled(entry, field) if {
	v := object.get(entry, field, "")
	is_string(v)
	trim_space(v) != ""
}

# Problems that stop an unexpired entry from being applied. Empty for every
# entry when no settings are loaded.
entry_problems(entry) := problems if {
	missing := {sprintf("required field %s is missing or empty", [f]) |
		is_array(_required_fields)
		some f in _required_fields
		is_string(f)
		not _filled(entry, f)
	}
	too_long := {sprintf("expires more than %v days ahead (maximum time to live)", [waiver_settings.max_ttl_days]) |
		_positive_number(object.get(waiver_settings, "max_ttl_days", 0))
		exp_ns := time.parse_ns("2006-01-02", object.get(entry, "expires", ""))
		exp_ns - time.now_ns() > waiver_settings.max_ttl_days * _ns_per_day
	}
	problems := (missing | too_long) | _setting_problems
}

entry_accepted(entry) if count(entry_problems(entry)) == 0

# ── Decision sets ─────────────────────────────────────────────────────────────

waived contains {"violation": v, "waiver": entry} if {
	some v in input_violations
	some entry in waiver_entries
	entry_active(entry)
	entry_accepted(entry)
	entry_matches(entry, v)
}

# Unexpired entries that match a finding but are not applied, with the reasons.
# The finding stays in active_violations.
rejected contains {"violation": v, "waiver": entry, "problems": sort(entry_problems(entry))} if {
	some v in input_violations
	some entry in waiver_entries
	entry_active(entry)
	not entry_accepted(entry)
	entry_matches(entry, v)
}

_expiring_days := d if {
	d := object.get(waiver_settings, "expiring_within_days", 14)
	_positive_number(d)
} else := 14

# Applied waivers that run out soon: the finding returns to active on that date.
expiring_soon contains {"violation": w.violation, "waiver": w.waiver, "days_left": days} if {
	some w in waived
	left_ns := time.parse_ns("2006-01-02", w.waiver.expires) - time.now_ns()
	left_ns <= _expiring_days * _ns_per_day
	days := ceil(left_ns / _ns_per_day)
}

waived_violations contains v if {
	some w in waived
	v := w.violation
}

active_violations := [v |
	some v in input_violations
	not v in waived_violations
]

# Matching entries that no longer apply because their expiry passed — surfaced
# so reports can flag findings that were waived and have silently reverted.
expired_matches contains {"violation": v, "waiver": entry} if {
	some v in input_violations
	some entry in waiver_entries
	not entry_active(entry)
	entry_matches(entry, v)
}

decision := {
	"active_violations": active_violations,
	"waived": waived,
	"waived_count": count(waived_violations),
	"expired_matches": expired_matches,
	"rejected": rejected,
	"rejected_count": count({r.violation | some r in rejected}),
	"expiring_soon": expiring_soon,
	"waiver_entries_loaded": count(waiver_entries),
}
