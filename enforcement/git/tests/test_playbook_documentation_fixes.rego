package git_audit.playbook_documentation_test

import rego.v1

# Regression tests for the 2026-10-17 validation findings. Each fails on the pre-fix module.


good_playbook := {
	"path": "playbooks/site.yml",
	"metadata": {
		"author": "ops@acme.io",
		"purpose": "Configure the web tier with hardened defaults for production",
		"version": "1.2.0",
		"date_modified": "2026-10-01",
	},
	"plays": [{"name": "Configure web tier", "tasks": [{"name": "Install nginx"}]}],
}

# Violation messages for one playbook, through the public all_violations rule
violations_for(pb) := vs if {
	vs := {v.violation | some v in data.git_audit.playbook_documentation.all_violations} with input as {"playbooks": [pb], "audit_year": 2026, "audit_month": 10}
}

with_meta(field, value) := object.union(good_playbook, {"metadata": object.union(good_playbook.metadata, {field: value})})

test_baseline_playbook_passes if {
	data.git_audit.playbook_documentation.audit_passed with input as {"playbooks": [good_playbook], "audit_year": 2026, "audit_month": 10}
}

test_uppercase_placeholder_flagged if {
	pb := with_meta("purpose", "TODO: describe what this playbook does for ops")
	some v in violations_for(pb)
	startswith(v, "DOC-002")
}

test_empty_playbook_list_fails_closed if {
	not data.git_audit.playbook_documentation.audit_passed with input as {"playbooks": []}
}

test_missing_playbook_list_fails_closed if {
	not data.git_audit.playbook_documentation.audit_passed with input as {}
}

test_stale_playbook_fails_audit if {
	pb := with_meta("date_modified", "2020-01-01")
	not data.git_audit.playbook_documentation.audit_passed with input as {"playbooks": [pb], "audit_year": 2026, "audit_month": 10}
}

test_short_task_name_fails_audit if {
	pb := object.union(good_playbook, {"plays": [{"name": "Configure web tier", "tasks": [{"name": "x"}]}]})
	not data.git_audit.playbook_documentation.audit_passed with input as {"playbooks": [pb], "audit_year": 2026, "audit_month": 10}
}

test_staleness_defaults_to_today if {
	# No audit date in the input: the reference date is now, so a 2025-06 date is over a year old after 2026-06.
	pb := with_meta("date_modified", "2025-06-01")
	vs := [v.violation | some v in data.git_audit.playbook_documentation.all_violations] with input as {"playbooks": [pb]}
		with time.now_ns as time.parse_rfc3339_ns("2026-10-17T00:00:00Z")
	some v in vs
	startswith(v, "DOC-030")
}

test_task_coverage_message_is_an_integer if {
	pb := object.union(good_playbook, {"plays": [{"name": "Configure web tier", "tasks": [{"name": "Install nginx"}, {"name": "Start nginx"}, {}]}]})
	some v in violations_for(pb)
	contains(v, "coverage is 67%")
}

test_empty_author_is_missing if {
	pb := with_meta("author", "")
	"DOC-001: Missing required metadata field 'author'" in violations_for(pb)
}

test_empty_play_name_message if {
	pb := object.union(good_playbook, {"plays": [{"name": "", "tasks": [{"name": "Install nginx"}]}]})
	"DOC-010: Play [0] in 'playbooks/site.yml' has an empty 'name' field" in violations_for(pb)
}
