# Tests for the repository hygiene policy.
#
# Every rule has a violating case, a passing case, and where the rule has an
# edge that could silently under-report, a test pinning that edge. The failures
# these rules describe are real ones from this repository, so the fixtures are
# modelled on the actual defects rather than invented.

package aac.repo.hygiene_test

import data.aac.repo.hygiene
import rego.v1

# ── helpers ──────────────────────────────────────────────────────────────────

pb(tasks) := {"path": "example.yml", "plays": [{
	"name": "Example play",
	"hosts": "localhost",
	"tasks": tasks,
}]}

has(violations, code) if {
	some v in violations
	contains(v, code)
}

# ── AAC-ANS-001 — loop_var placement ─────────────────────────────────────────
# Modelled on cip_008_incident_response.yml, AAP template 117.

test_loop_var_at_task_level_violates if {
	v := hygiene.violation with input as pb([{
		"name": "Capture system state",
		"shell": "lastb -n 20",
		"loop": "{{ affected_systems }}",
		"loop_var": "affected_host",
	}])
	has(v, "AAC-ANS-001")
}

test_loop_var_under_loop_control_passes if {
	v := hygiene.violation with input as pb([{
		"name": "Capture system state",
		"shell": "lastb -n 20",
		"loop": "{{ affected_systems }}",
		"loop_control": {"loop_var": "affected_host"},
	}])
	not has(v, "AAC-ANS-001")
}

# The rule must reach handlers and pre/post tasks, not just `tasks`. A rule
# that only walks `tasks` looks correct and silently under-reports.
test_loop_var_is_caught_in_handlers if {
	v := hygiene.violation with input as {"path": "h.yml", "plays": [{
		"name": "p",
		"hosts": "localhost",
		"handlers": [{"name": "restart", "shell": "x", "loop_var": "i"}],
	}]}
	has(v, "AAC-ANS-001")
}

test_loop_var_is_caught_in_pre_tasks if {
	v := hygiene.violation with input as {"path": "p.yml", "plays": [{
		"name": "p",
		"hosts": "localhost",
		"pre_tasks": [{"name": "prep", "shell": "x", "loop_var": "i"}],
	}]}
	has(v, "AAC-ANS-001")
}

# ── AAC-ANS-002 — plays are named ────────────────────────────────────────────

test_unnamed_play_violates if {
	v := hygiene.violation with input as {"path": "u.yml", "plays": [{"hosts": "all", "tasks": []}]}
	has(v, "AAC-ANS-002")
}

test_empty_play_name_violates if {
	v := hygiene.violation with input as {"path": "e.yml", "plays": [{"name": "", "hosts": "all", "tasks": []}]}
	has(v, "AAC-ANS-002")
}

test_named_play_passes if {
	v := hygiene.violation with input as pb([])
	not has(v, "AAC-ANS-002")
}

# ── AAC-ANS-003 — no lab addresses ───────────────────────────────────────────
# Modelled on caf_assessment.yml, which carried the address in both a play var
# and a connection parameter.

test_lab_address_in_play_vars_violates if {
	v := hygiene.violation with input as {"path": "caf.yml", "plays": [{
		"name": "CAF",
		"hosts": "localhost",
		"vars": {"opa_server_url": "http://192.168.4.62:8182"},
	}]}
	has(v, "AAC-ANS-003")
}

test_lab_address_in_connection_param_violates if {
	v := hygiene.violation with input as pb([{
		"name": "Store",
		"community.postgresql.postgresql_query": {"login_host": "192.168.4.62"},
	}])
	has(v, "AAC-ANS-003")
}

# Depth is the point: grep finds text, this must find values wherever they sit.
test_lab_address_found_at_depth if {
	v := hygiene.violation with input as pb([{
		"name": "Nested",
		"uri": {"body": {"config": {"syslog": {"host": "192.168.4.26"}}}},
	}])
	has(v, "AAC-ANS-003")
}

test_templated_endpoint_passes if {
	v := hygiene.violation with input as {"path": "ok.yml", "plays": [{
		"name": "CAF",
		"hosts": "localhost",
		"vars": {"opa_server_url": "{{ opa_compliance_url }}"},
	}]}
	not has(v, "AAC-ANS-003")
}

test_lab_address_list_is_overridable if {
	v := hygiene.violation with input as {
		"path": "x.yml",
		"lab_addresses": ["10.0.0.1"],
		"plays": [{"name": "p", "hosts": "localhost", "vars": {"h": "10.0.0.1"}}],
	}
	has(v, "AAC-ANS-003")
}

# ── AAC-ANS-004 — evidence names its framework ───────────────────────────────

test_evidence_write_without_framework_violates if {
	v := hygiene.violation with input as pb([{
		"name": "Store results",
		"community.postgresql.postgresql_query": {"query": "INSERT INTO compliance_results (hostname, total_controls) VALUES (%s, %s)"},
	}])
	has(v, "AAC-ANS-004")
}

test_framework_in_query_passes if {
	v := hygiene.violation with input as pb([{
		"name": "Store results",
		"community.postgresql.postgresql_query": {"query": "INSERT INTO compliance_results (hostname, framework) VALUES (%s, %s)"},
	}])
	not has(v, "AAC-ANS-004")
}

test_framework_in_positional_args_passes if {
	v := hygiene.violation with input as pb([{
		"name": "Store results",
		"community.postgresql.postgresql_query": {
			"query": "INSERT INTO compliance_results (hostname, fw) VALUES (%s, %s)",
			"positional_args": ["{{ inventory_hostname }}", "{{ aac_result_framework }}"],
		},
	}])
	not has(v, "AAC-ANS-004")
}

test_non_evidence_query_is_not_flagged if {
	v := hygiene.violation with input as pb([{
		"name": "Read something",
		"community.postgresql.postgresql_query": {"query": "SELECT 1"},
	}])
	not has(v, "AAC-ANS-004")
}

# ── report ───────────────────────────────────────────────────────────────────

test_clean_playbook_is_compliant if {
	r := hygiene.compliance_report with input as pb([{"name": "Do a thing", "debug": {"msg": "ok"}}])
	r.compliant == true
	r.violation_count == 0
	r.plays_evaluated == 1
}

test_report_survives_a_playbook_with_no_path if {
	# A caller that forgets `path` must still get a usable report rather than
	# an empty object — the undefined-field trap that collapses reports to {}.
	r := hygiene.compliance_report with input as {"plays": [{"name": "p", "hosts": "localhost"}]}
	r.path == "<playbook>"
	count(r) > 0
}
