# METADATA
# title: "AAC estate continuity: every expected asset is evaluated, explained or retired"
# custom:
#   class: governance
#   framework: estate_continuity
#   source: aac
#   domains: [assurance, it-governance]
#   coverage:
#     checks: 7
#     cited: 0
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package estate_continuity.main

import rego.v1

# Estate continuity: tells a device that was retired on purpose from one that
# has gone quiet or disappeared.
#
# Silence is never treated as retirement. A host leaves the estate cleanly only
# when a decommission record names who retired it, under what reference and
# when. Anything else that stops answering, or vanishes from the inventory or
# its provider, is a finding. This is the same fail-closed rule the library
# applies to attestations: an absent declaration is a failure, never a pass.
#
# INPUT CONTRACT (assembled by the collector; all ages are hours, computed by
# the collector so this policy does no clock arithmetic):
#
#   {
#     "config": {                        # optional; defaults shown
#       "freshness_hours":   26,         # evaluated within this = active
#       "stale_after_hours": 52,         # beyond this = stale (finding); between = late
#       "stopped_in_scope":  true        # powered-off hosts are flagged, not failed
#     },
#     "hosts": [{
#       "name":                  "web-01",           # required, unique
#       "in_inventory":          true,               # required boolean: still in the AAP inventory
#       "provider":              "aws_ec2",          # optional: aws_ec2 | vmware | none ...
#       "provider_state":        "running",          # running | stopped | terminated | absent | unknown
#       "hours_since_evaluated": 3.2,                # null/absent = never evaluated
#       "hours_since_first_seen": 400,               # when the registry first saw it
#       "last_attempt": {"outcome": "ok", "hours_ago": 3.0},   # ok | unreachable | failed
#       "retirement":   {"declared": true, "ref": "CHG0012", "by": "J. Smith", "hours_ago": 30},
#       "removal_event":{"source": "user", "by": "admin", "hours_ago": 20}
#     }]
#   }
#
# States, and whether each is a finding:
#
#   active                 evaluated within freshness_hours                       no
#   late                   last evaluation between freshness and stale_after      advisory
#   new                    never evaluated, first seen within stale_after         advisory
#   stopped                provider says powered off, in scope                    advisory
#   stopped_out_of_scope   powered off, and config says stopped is out of scope   no
#   retired                decommission record, and gone from inventory/provider  no
#   retirement_incomplete  decommission record, but still in inventory            advisory
#   stale_unreachable      no evaluation beyond stale_after; last attempt unreachable   FINDING
#   stale_failing          ... last attempt connected but failed                        FINDING
#   stale_no_evidence      ... last attempt succeeded, but no evidence was stored       FINDING
#   stale_not_targeted     ... no run has tried it                                      FINDING
#   removed_unrecorded     removed by a named actor, with no decommission record        FINDING
#   missing                gone from inventory/provider, no record of any kind          FINDING
#   unmanaged_running      provider says running, but it is in no inventory checked     FINDING
#   zombie                 recorded as retired, but answered after the retirement        FINDING
#   invalid_record         the host record is malformed and cannot be classified        FINDING

default_config := {"freshness_hours": 26, "stale_after_hours": 52, "stopped_in_scope": true}

supplied_config := c if {
	c := input.config
	is_object(c)
} else := {}

cfg_number(key) := n if {
	n := supplied_config[key]
	is_number(n)
	n > 0
} else := default_config[key]

freshness_hours := cfg_number("freshness_hours")

stale_after_hours := s if {
	s := cfg_number("stale_after_hours")
	s >= freshness_hours
} else := max([freshness_hours, default_config.stale_after_hours])

# Only an explicit false takes stopped hosts out of scope.
default stopped_in_scope := true

stopped_in_scope := false if supplied_config.stopped_in_scope == false

config_problem contains msg if {
	some key in ["freshness_hours", "stale_after_hours"]
	v := supplied_config[key]
	not positive_number(v)
	msg := sprintf("AAC estate continuity: config.%s must be a positive number, got %v — the default is used", [key, v])
}

config_problem contains msg if {
	v := supplied_config.stopped_in_scope
	not is_boolean(v)
	msg := sprintf("AAC estate continuity: config.stopped_in_scope must be a boolean, got %v — stopped hosts stay in scope", [v])
}

positive_number(v) if {
	is_number(v)
	v > 0
}

# ── Host records ─────────────────────────────────────────────────────────────

# A helper rule, not `not is_array(input.hosts)`: OPA does not treat a built-in
# called on an undefined argument as false, so that negation never fires when
# `hosts` is missing altogether — the fail-open case this guard exists for.
hosts_supplied if is_array(input.hosts)

hosts := input.hosts if hosts_supplied

else := []

valid_host(h) if {
	is_object(h)
	is_string(h.name)
	h.name != ""
	is_boolean(h.in_inventory)
}

known_provider_states := {"running", "stopped", "terminated", "absent", "unknown"}

provider_state(h) := s if {
	s := h.provider_state
	s in known_provider_states
} else := "unknown"

evaluated_hours(h) := n if {
	n := h.hours_since_evaluated
	is_number(n)
}

first_seen_hours(h) := n if {
	n := h.hours_since_first_seen
	is_number(n)
}

outcome(h) := o if {
	o := h.last_attempt.outcome
	o in {"ok", "unreachable", "failed"}
} else := "none"

# A decommission record counts only when it names the reference, the person and
# the time. A bare `declared: true` is not a record.
declared(h) if {
	h.retirement.declared == true
	non_empty_string(h.retirement.ref)
	non_empty_string(h.retirement.by)
	is_number(h.retirement.hours_ago)
}

non_empty_string(s) if {
	is_string(s)
	s != ""
}

# The provider is the authority on whether a machine exists. Inventory absence
# alone means gone only when the provider cannot vouch for the machine: an
# inventory sync that drops stopped instances must not turn them into
# disappearances.
gone(h) if provider_state(h) in {"terminated", "absent"}

gone(h) if {
	h.in_inventory == false
	not provider_state(h) in {"running", "stopped"}
}

unmanaged_running(h) if {
	h.in_inventory == false
	provider_state(h) == "running"
}

answered_after_retirement(h) if {
	outcome(h) == "ok"
	is_number(h.last_attempt.hours_ago)
	h.last_attempt.hours_ago < h.retirement.hours_ago
}

removed_by_actor(h) if non_empty_string(h.removal_event.by)

# ── Classification (first match wins) ───────────────────────────────────────

state(h) := "invalid_record" if {
	not valid_host(h)
} else := "zombie" if {
	declared(h)
	answered_after_retirement(h)
} else := "retired" if {
	declared(h)
	gone(h)
} else := "retirement_incomplete" if {
	declared(h)
} else := "removed_unrecorded" if {
	gone(h)
	removed_by_actor(h)
} else := "missing" if {
	gone(h)
} else := "unmanaged_running" if {
	unmanaged_running(h)
} else := "stopped" if {
	provider_state(h) == "stopped"
	stopped_in_scope
} else := "stopped_out_of_scope" if {
	provider_state(h) == "stopped"
} else := "active" if {
	evaluated_hours(h) <= freshness_hours
} else := "new" if {
	not evaluated_hours(h)
	first_seen_hours(h) <= stale_after_hours
} else := "late" if {
	evaluated_hours(h) <= stale_after_hours
} else := "stale_unreachable" if {
	outcome(h) == "unreachable"
} else := "stale_failing" if {
	outcome(h) == "failed"
} else := "stale_no_evidence" if {
	outcome(h) == "ok"
} else := "stale_not_targeted"

finding_states := {
	"invalid_record", "zombie", "removed_unrecorded", "missing", "unmanaged_running",
	"stale_unreachable", "stale_failing", "stale_no_evidence", "stale_not_targeted",
}

advisory_states := {"late", "new", "stopped", "retirement_incomplete"}

all_states := (finding_states | advisory_states) | {"active", "retired", "stopped_out_of_scope"}

# ── Human-readable reasons (these are what an auditor reads) ────────────────

host_label(h, i) := h.name if non_empty_string(h.name)

else := sprintf("record #%d", [i])

age(h) := sprintf("%v h ago", [evaluated_hours(h)]) if evaluated_hours(h)

else := "never"

reason(h, i, "invalid_record") := sprintf(
	"AAC estate continuity: %s is malformed (needs a non-empty name and a boolean in_inventory) — it cannot be classified, so it is a finding",
	[host_label(h, i)],
)

reason(h, i, "zombie") := sprintf(
	"CIS Controls v8 1.2 / NIST SP 800-53 CM-8: %s is recorded as retired (%s, by %s) but answered an assessment %v h after the retirement — an asset believed gone is still running",
	[h.name, h.retirement.ref, h.retirement.by, h.retirement.hours_ago - h.last_attempt.hours_ago],
)

reason(h, i, "retired") := sprintf(
	"%s retired under %s by %s; gone from inventory/provider (%s) — closed out, history kept",
	[h.name, h.retirement.ref, h.retirement.by, provider_state(h)],
)

reason(h, i, "retirement_incomplete") := sprintf(
	"%s is recorded as retired (%s) but is still in the inventory — finish the removal or withdraw the record",
	[h.name, h.retirement.ref],
)

reason(h, i, "removed_unrecorded") := sprintf(
	"NIST SP 800-53 CM-8(1) / CIS Controls v8 1.1: %s was removed by %s (via %v, %v h ago) but there is no decommission record — the removal is unauthorised until one is filed",
	[h.name, h.removal_event.by, object.get(h.removal_event, "source", "unknown"), object.get(h.removal_event, "hours_ago", "?")],
)

reason(h, i, "missing") := sprintf(
	"NIST SP 800-53 CM-8 / CIS Controls v8 1.1: %s is no longer in the inventory or its provider (in_inventory=%v, provider_state=%s) and there is no record of who removed it or why — unexplained disappearance",
	[h.name, h.in_inventory, provider_state(h)],
)

reason(h, i, "unmanaged_running") := sprintf(
	"CIS Controls v8 1.1 / NIST SP 800-53 CM-8: %s is running (%v) but is in no inventory being checked — it exists, and nothing is managing or assessing it",
	[h.name, object.get(h, "provider", "provider")],
)

reason(h, i, "stopped") := sprintf(
	"%s is powered off (%v) — in scope but not being evaluated; last evaluation: %s",
	[h.name, object.get(h, "provider", "provider"), age(h)],
)

reason(h, i, "stopped_out_of_scope") := sprintf("%s is powered off; stopped hosts are out of scope here", [h.name])

reason(h, i, "active") := sprintf("%s last evaluated %s", [h.name, age(h)])

reason(h, i, "new") := sprintf("%s first seen %v h ago and not yet evaluated", [h.name, first_seen_hours(h)])

reason(h, i, "late") := sprintf(
	"%s last evaluated %s (expected within %v h; a finding after %v h); last attempt: %s",
	[h.name, age(h), freshness_hours, stale_after_hours, outcome(h)],
)

reason(h, i, "stale_unreachable") := sprintf(
	"NIST SP 800-53 CA-7: %s has no evaluation within the last %v h (last evaluation: %s); the last attempt could not reach it — check its address, network path and credentials",
	[h.name, stale_after_hours, age(h)],
)

reason(h, i, "stale_failing") := sprintf(
	"NIST SP 800-53 CA-7: %s has no evaluation within the last %v h (last evaluation: %s); the last attempt reached it but failed",
	[h.name, stale_after_hours, age(h)],
)

reason(h, i, "stale_no_evidence") := sprintf(
	"NIST SP 800-53 CA-7: %s has no evaluation within the last %v h (last evaluation: %s), although the last attempt succeeded — collection ran but no evidence was stored",
	[h.name, stale_after_hours, age(h)],
)

reason(h, i, "stale_not_targeted") := sprintf(
	"NIST SP 800-53 CA-7: %s has no evaluation within the last %v h (last evaluation: %s) and no run has tried to assess it — it is outside every assessment's scope",
	[h.name, stale_after_hours, age(h)],
)

# ── Results ─────────────────────────────────────────────────────────────────

host_results := [r |
	some i, h in hosts
	s := state(h)
	r := {
		"name": host_label(h, i),
		"state": s,
		"finding": s in finding_states,
		"advisory": s in advisory_states,
		"provider": object.get(h, "provider", "none"),
		"provider_state": provider_state(h),
		"reason": reason(h, i, s),
	}
]

host_names := [h.name | some h in hosts; non_empty_string(h.name)]

duplicate_names := {n |
	some n in host_names
	count([m | some m in host_names; m == n]) > 1
}

violation contains r.reason if {
	some r in host_results
	r.finding
}

violation contains msg if {
	not hosts_supplied
	msg := "AAC estate continuity: input.hosts must be an array of host records — nothing can be classified"
}

violation contains msg if {
	hosts_supplied
	count(input.hosts) == 0
	msg := "AAC estate continuity: no hosts supplied — the collector returned nothing to classify, which is never a clean estate"
}

violation contains msg if {
	some n in duplicate_names
	msg := sprintf("AAC estate continuity: %s appears more than once in the input — each asset must be one record", [n])
}

advisory contains r.reason if {
	some r in host_results
	r.advisory
}

advisory contains msg if some msg in config_problem

default compliant := false

compliant if count(violation) == 0

state_counts := {s: n |
	some s in all_states
	n := count([1 | some r in host_results; r.state == s])
}

compliance_report := {
	"framework": "estate_continuity",
	"name": "Estate continuity — every expected asset is evaluated, explained or retired",
	"version": "1.0.0",
	"total_controls": count(hosts),
	"hosts_evaluated": count(hosts),
	"states": state_counts,
	"hosts": host_results,
	"violations": sort([v | some v in violation]),
	"violation_count": count(violation),
	"advisories": sort([a | some a in advisory]),
	"advisory_count": count(advisory),
	"compliant": compliant,
	"config": {
		"freshness_hours": freshness_hours,
		"stale_after_hours": stale_after_hours,
		"stopped_in_scope": stopped_in_scope,
	},
}
