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
#   }
#
# Query: POST /v1/data/exceptions/decision with
#   input: {"host": "...", "framework": "...", "violations": [...]}
# Violations may be strings or objects; objects are matched against their
# JSON serialization, so a control ID anywhere in the object matches.

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
	contains(violation_text(v), cid)
}

# ── Decision sets ─────────────────────────────────────────────────────────────

waived contains {"violation": v, "waiver": entry} if {
	some v in input_violations
	some entry in waiver_entries
	entry_active(entry)
	entry_matches(entry, v)
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
	"waiver_entries_loaded": count(waiver_entries),
}
