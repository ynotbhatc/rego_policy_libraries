package git_audit.playbook_documentation

import rego.v1

# =============================================================================
# Git Repository Audit — Ansible Playbook Documentation Quality
#
# Validates that every playbook in the repository has adequate documentation
# so that anyone can understand what it does, who owns it, and when it was
# last reviewed — without reading the implementation.
#
# OPA endpoint (when loaded):
#   POST http://<opa-host>:8182/v1/data/git_audit/playbook_documentation/report
#
# Input shape:
#   input.repository         — e.g. "ynotbhatc/compliance"
#   input.branch             — e.g. "main"
#   input.commit             — short SHA
#   input.playbooks[]
#     .path                  — relative path in repo
#     .metadata
#       .author              — "Jane Smith <jane@company.com>" or "Jane Smith"
#       .purpose             — one-sentence description of what the playbook does
#       .version             — semver string, e.g. "1.2.0"
#       .date_modified       — ISO-8601 date, e.g. "2026-01-15"
#       .owner_team          — (optional) team responsible
#       .contact             — (optional) email or Slack channel
#       .last_reviewed       — (optional) ISO-8601 date
#     .plays[]
#       .name                — play name
#       .hosts               — target pattern
#       .tasks[]
#         .name              — task name
#         .tags[]            — task tags (optional for this policy)
#
# Collector: ansible/playbooks/git_audit_collect.yml converts playbook YAML
# to this JSON shape and posts it to OPA for evaluation.
# =============================================================================

# -----------------------------------------------------------------------------
# Configuration — thresholds and allowed values
# -----------------------------------------------------------------------------

# Minimum word count for a useful purpose description
min_purpose_words := 5

# Minimum character length for a play name to be considered descriptive
min_play_name_length := 10

# Minimum character length for a task name to be considered descriptive
min_task_name_length := 5

# Minimum percentage of tasks that must have names (0–100)
min_task_naming_coverage := 90

# Maximum days since last modification before flagging as stale
max_stale_days := 365

# Placeholder strings that indicate unfilled documentation
placeholder_patterns := {
	"TODO",
	"FIXME",
	"TBD",
	"your name",
	"your team",
	"placeholder",
	"example",
	"n/a",
	"none",
	"unknown",
	"fill in",
}

# Valid semver pattern (major.minor.patch, with optional pre-release)
semver_regex := `^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`

# -----------------------------------------------------------------------------
# Per-playbook violation rules
# Each produces a set of violation messages for a single playbook object.
# -----------------------------------------------------------------------------

# --- Metadata presence ---

metadata_violations(playbook) := violations if {
	violations := {msg |
		some check in _metadata_checks(playbook)
		check != null
		msg := check
	}
}

_metadata_checks(playbook) := [
	_check_field_present(playbook, "author"),
	_check_field_present(playbook, "purpose"),
	_check_field_present(playbook, "version"),
	_check_field_present(playbook, "date_modified"),
]

_check_field_present(playbook, field) := msg if {
	not playbook.metadata[field]
	msg := sprintf("DOC-001: Missing required metadata field '%s'", [field])
} else := null

# --- Metadata quality ---

quality_violations(playbook) := violations if {
	violations := {msg |
		some rule in [
			_check_placeholder(playbook, "author"),
			_check_placeholder(playbook, "purpose"),
			_check_purpose_length(playbook),
			_check_author_contact(playbook),
			_check_version_format(playbook),
			_check_date_format(playbook),
		]
		rule != null
		msg := rule
	}
}

# Field must not contain a placeholder value
_check_placeholder(playbook, field) := msg if {
	value := playbook.metadata[field]
	is_string(value)
	some pattern in placeholder_patterns
	contains(lower(value), pattern)
	msg := sprintf(
		"DOC-002: Metadata field '%s' contains placeholder text ('%s')",
		[field, value],
	)
} else := null

# Purpose must be descriptive — at least min_purpose_words words
_check_purpose_length(playbook) := msg if {
	purpose := playbook.metadata.purpose
	is_string(purpose)
	word_count := count(split(trim_space(purpose), " "))
	word_count < min_purpose_words
	msg := sprintf(
		"DOC-003: 'purpose' is too brief (%d word(s)) — use at least %d words to describe what this playbook does",
		[word_count, min_purpose_words],
	)
} else := null

# Author should include a way to contact them (email address or @handle)
_check_author_contact(playbook) := msg if {
	author := playbook.metadata.author
	is_string(author)
	not contains(author, "@")
	not playbook.metadata.contact
	not playbook.metadata.owner_team
	msg := "DOC-004: 'author' has no contact info — include an email (<user@domain>) or set 'contact' / 'owner_team'"
} else := null

# Version must follow semver (x.y.z)
_check_version_format(playbook) := msg if {
	version := playbook.metadata.version
	is_string(version)
	not regex.match(semver_regex, version)
	msg := sprintf(
		"DOC-005: 'version' value '%s' is not valid semver — use format MAJOR.MINOR.PATCH (e.g. 1.0.0)",
		[version],
	)
} else := null

# date_modified must look like an ISO-8601 date (YYYY-MM-DD)
_check_date_format(playbook) := msg if {
	date := playbook.metadata.date_modified
	is_string(date)
	not regex.match(`^\d{4}-\d{2}-\d{2}$`, date)
	msg := sprintf(
		"DOC-006: 'date_modified' value '%s' is not a valid ISO-8601 date (YYYY-MM-DD)",
		[date],
	)
} else := null

# --- Play naming ---

play_violations(playbook) := violations if {
	violations := {msg |
		some i, play in playbook.plays
		some msg in _play_checks(playbook.path, i, play)
	}
}

_play_checks(path, idx, play) := violations if {
	violations := {msg |
		some check in [
			_check_play_named(path, idx, play),
			_check_play_name_descriptive(path, idx, play),
		]
		check != null
		msg := check
	}
}

_check_play_named(path, idx, play) := msg if {
	not play.name
	msg := sprintf(
		"DOC-010: Play [%d] in '%s' has no 'name' field — every play must be named",
		[idx, path],
	)
} else if {
	play.name == ""
	msg := sprintf(
		"DOC-010: Play [%d] in '%s' has an empty 'name' field",
		[idx, path],
	)
} else := null

_check_play_name_descriptive(path, idx, play) := msg if {
	play.name
	play.name != ""
	count(play.name) < min_play_name_length
	msg := sprintf(
		"DOC-011: Play [%d] '%s' in '%s' is too short — use a descriptive name (at least %d chars)",
		[idx, play.name, path, min_play_name_length],
	)
} else := null

# --- Task naming coverage ---

task_violations(playbook) := violations if {
	violations := {msg |
		some msg in _task_coverage_checks(playbook)
	}
}

_task_coverage_checks(playbook) := violations if {
	all_tasks := [task |
		some play in playbook.plays
		some task in object.get(play, "tasks", [])
	]
	total := count(all_tasks)
	total > 0

	unnamed := [task |
		some task in all_tasks
		name := object.get(task, "name", "")
		name == ""
	]
	unnamed_count := count(unnamed)

	coverage := ((total - unnamed_count) * 100) / total
	coverage < min_task_naming_coverage

	violations := {sprintf(
		"DOC-020: Task naming coverage is %d%% (%d of %d tasks named) — minimum is %d%%",
		[coverage, total - unnamed_count, total, min_task_naming_coverage],
	)}
} else := set()

short_task_violations(playbook) := violations if {
	violations := {msg |
		some play in playbook.plays
		some task in object.get(play, "tasks", [])
		task_name := object.get(task, "name", "")
		task_name != ""
		count(task_name) < min_task_name_length
		msg := sprintf(
			"DOC-021: Task '%s' in play '%s' has a very short name — be more descriptive",
			[task_name, object.get(play, "name", "(unnamed play)")],
		)
	}
}

# --- Stale documentation warning ---

staleness_violations(playbook) := violations if {
	date_str := playbook.metadata.date_modified
	is_string(date_str)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, date_str)

	# Parse YYYY-MM-DD
	parts := split(date_str, "-")
	year := to_number(parts[0])
	month := to_number(parts[1])
	day := to_number(parts[2])

	# Approximate days since modified (compare against audit date in input)
	audit_year := object.get(input, "audit_year", 2026)
	audit_month := object.get(input, "audit_month", 3)

	age_months := ((audit_year - year) * 12) + (audit_month - month)
	age_days := age_months * 30

	age_days > max_stale_days

	violations := {sprintf(
		"DOC-030: '%s' has not been updated in approximately %d days (modified: %s) — review and update if still current",
		[playbook.path, age_days, date_str],
	)}
} else := set()

# -----------------------------------------------------------------------------
# Per-playbook summary
# -----------------------------------------------------------------------------

playbook_report(playbook) := report if {
	m_viols := metadata_violations(playbook)
	q_viols := quality_violations(playbook)
	p_viols := play_violations(playbook)
	t_viols := task_violations(playbook)
	st_viols := short_task_violations(playbook)
	stale_viols := staleness_violations(playbook)

	all_viols := array.concat(
		array.concat(
			[v | some v in m_viols],
			[v | some v in q_viols],
		),
		array.concat(
			array.concat([v | some v in p_viols], [v | some v in t_viols]),
			array.concat([v | some v in st_viols], [v | some v in stale_viols]),
		),
	)

	report := {
		"path": playbook.path,
		"compliant": count(all_viols) == 0,
		"violation_count": count(all_viols),
		"violations": all_viols,
		"metadata_score": _metadata_score(playbook),
	}
}

_metadata_score(playbook) := score if {
	fields := ["author", "purpose", "version", "date_modified", "owner_team", "contact", "last_reviewed"]
	present := [f | some f in fields; playbook.metadata[f]]
	score := (count(present) * 100) / count(fields)
}

# -----------------------------------------------------------------------------
# Repository-level report
# -----------------------------------------------------------------------------

default audit_passed := false

audit_passed if {
	every playbook in input.playbooks {
		count(metadata_violations(playbook)) == 0
		count(quality_violations(playbook)) == 0
		count(play_violations(playbook)) == 0
		count(task_violations(playbook)) == 0
	}
}

# Playbooks that are fully compliant
compliant_playbooks := [p.path |
	some p in input.playbooks
	playbook_report(p).compliant == true
]

# Playbooks that have violations
non_compliant_playbooks := [p.path |
	some p in input.playbooks
	playbook_report(p).compliant == false
]

# All violations across the entire repo, annotated with playbook path
all_violations := [entry |
	some playbook in input.playbooks
	some v in playbook_report(playbook).violations
	entry := {"playbook": playbook.path, "violation": v}
]

# Violations by code prefix (DOC-001, DOC-010, etc.)
violations_by_category := {category: msgs |
	some category in {"DOC-001", "DOC-002", "DOC-003", "DOC-004", "DOC-005", "DOC-006", "DOC-010", "DOC-011", "DOC-020", "DOC-021", "DOC-030"}
	msgs := [v.violation |
		some v in all_violations
		startswith(v.violation, category)
	]
	count(msgs) > 0
}

# Average metadata completeness score across all playbooks
average_metadata_score := score if {
	count(input.playbooks) > 0
	total := sum([playbook_report(p).metadata_score | some p in input.playbooks])
	score := total / count(input.playbooks)
} else := 0

report := {
	"repository": object.get(input, "repository", "unknown"),
	"branch": object.get(input, "branch", "unknown"),
	"commit": object.get(input, "commit", "unknown"),
	"audit_passed": audit_passed,
	"summary": {
		"total_playbooks": count(input.playbooks),
		"compliant": count(compliant_playbooks),
		"non_compliant": count(non_compliant_playbooks),
		"total_violations": count(all_violations),
		"average_metadata_score_pct": average_metadata_score,
	},
	"playbooks": [playbook_report(p) | some p in input.playbooks],
	"violations_by_category": violations_by_category,
	"compliant_playbooks": compliant_playbooks,
	"non_compliant_playbooks": non_compliant_playbooks,
}
