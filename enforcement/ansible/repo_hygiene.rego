# AAC repository hygiene — policy the delivery layer is gated by
#
# The policy library has 492 tests and CI gates. The 221 playbooks a customer
# installs had none, and the cost was concrete: two documented entry points sat
# in main unable to run, and 32 files carried lab-specific addresses that reach
# a customer and read as "this was never meant for me".
#
# These rules express those checks as policy rather than as shell. Three
# reasons that is better than a grep:
#
#   1. Structure, not text. `walk` reaches every value at any depth, so a rule
#      reports "the login_host of task 0" rather than "line 116". A hardcoded
#      address in a connection parameter is not the same finding as one in a
#      comment, and only a structural check can tell them apart.
#   2. The rules are testable. Every rule below has unit tests, which is the
#      discipline the delivery layer has never had.
#   3. One rule, two enforcement points. The same policy gates CI and, through
#      AAP's Policy as Code, job launch.
#
# WHAT THIS DELIBERATELY DOES NOT DO
#   Parsing. Rego evaluates data, so YAML must be loaded first (`from_yaml` in
#   Ansible, `yaml.safe_load` in CI). Generic lint is `ansible-lint`'s job and
#   is not reimplemented here. Module and collection resolution needs Ansible
#   itself. This file covers only the rules that are specifically ours.
#
# Input shape (one playbook per evaluation):
#   input.path           string  — repo-relative path, for the message
#   input.plays[]        array   — the parsed playbook
#   input.lab_addresses  array   — optional; addresses to treat as lab-specific
#
# OPA query path: /v1/data/aac/repo/hygiene/violation

package aac.repo.hygiene

import rego.v1

# Overridable so a deployment can supply its own list without editing policy.
default lab_addresses := ["192.168.4.62", "192.168.4.26"]

lab_addresses := input.lab_addresses

path_label := input.path

default path_label := "<playbook>"

# Tasks in every block a play can carry. `tasks` alone misses handlers and
# pre/post tasks, which is where a rule of this kind usually leaks.
all_tasks(play) := ts if {
	ts := array.concat(
		array.concat(
			[t | some t in object.get(play, "tasks", [])],
			[t | some t in object.get(play, "pre_tasks", [])],
		),
		array.concat(
			[t | some t in object.get(play, "post_tasks", [])],
			[t | some t in object.get(play, "handlers", [])],
		),
	)
}

task_name(task) := object.get(task, "name", "<unnamed>")

# ── AAC-ANS-001 — loop_var belongs under loop_control ────────────────────────
# Ansible rejects the play outright: "conflicting action statements". Found in
# cip_008_incident_response.yml, which is AAP template 117 and documented in
# CLAUDE.md — a named entry point that could not run.
violation contains msg if {
	some play in input.plays
	some task in all_tasks(play)
	task.loop_var
	msg := sprintf(
		"AAC-ANS-001: %s: task '%s' sets loop_var at task level — it belongs under loop_control, and Ansible refuses the play as written",
		[path_label, task_name(task)],
	)
}

# ── AAC-ANS-002 — every play is named ────────────────────────────────────────
# An unnamed play produces unattributable output, which is the same
# evidence-quality problem the platform exists to solve.
violation contains msg if {
	some i, play in input.plays
	not play.name
	msg := sprintf("AAC-ANS-002: %s: play %d has no name", [path_label, i])
}

violation contains msg if {
	some i, play in input.plays
	play.name == ""
	msg := sprintf("AAC-ANS-002: %s: play %d has an empty name", [path_label, i])
}

# ── AAC-ANS-003 — no environment-specific addresses ──────────────────────────
# The structural path is reported, not a line number, so the reader can see
# whether it is a connection parameter or an incidental string.
violation contains msg if {
	some play in input.plays
	walk(play, [p, value])
	is_string(value)
	some addr in lab_addresses
	contains(value, addr)
	msg := sprintf(
		"AAC-ANS-003: %s: lab address %s at %v — resolve through site_config (opa_*_url, pg_host, grafana_url, aac_host)",
		[path_label, addr, p],
	)
}

# ── AAC-ANS-004 — a task that writes evidence names its framework ────────────
# compliance_results.framework was nullable for seven months and 906 rows
# landed without it, so "which standard is this evidence for" was unanswerable.
# The column is NOT NULL now; this stops a playbook reaching the gate at all.
writes_evidence(task) if {
	some k, v in task
	endswith(k, "postgresql_query")
	q := object.get(v, "query", "")
	contains(lower(q), "insert into compliance_results")
}

violation contains msg if {
	some play in input.plays
	some task in all_tasks(play)
	writes_evidence(task)
	some k, v in task
	endswith(k, "postgresql_query")
	not framework_supplied(v)
	msg := sprintf(
		"AAC-ANS-004: %s: task '%s' writes to compliance_results without naming a framework — evidence that cannot say which standard it is for is not evidence",
		[path_label, task_name(task)],
	)
}

framework_supplied(v) if contains(lower(object.get(v, "query", "")), "framework")

framework_supplied(v) if {
	some arg in object.get(v, "positional_args", [])
	is_string(arg)
	contains(lower(arg), "framework")
}

# ── Report ───────────────────────────────────────────────────────────────────

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"policy": "AAC repository hygiene",
	"path": path_label,
	"plays_evaluated": count(input.plays),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
