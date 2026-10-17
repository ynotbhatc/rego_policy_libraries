package aac.repo.hygiene_fixes_test

import data.aac.repo.hygiene
import rego.v1

pb(tasks) := {"path": "example.yml", "plays": [{"name": "Example play", "hosts": "localhost", "tasks": tasks}]}

has(violations, code) if {
	some v in violations
	contains(v, code)
}

test_empty_input_not_compliant if not hygiene.compliant with input as {}

test_empty_plays_not_compliant if not hygiene.compliant with input as {"path": "x.yml", "plays": []}

test_plays_wrong_shape_not_compliant if not hygiene.compliant with input as {"path": "x.yml", "plays": "oops"}

test_missing_plays_reports_violation if has(hygiene.violation, "AAC-ANS-000") with input as {}

test_clean_playbook_compliant if hygiene.compliant with input as pb([{"name": "ok", "debug": {"msg": "hi"}}])

test_string_shorthand_without_framework_violates if {
	v := hygiene.violation with input as pb([{
		"name": "Write evidence",
		"community.postgresql.postgresql_query": "INSERT INTO compliance_results (host, result) VALUES ('a', 'pass')",
	}])
	has(v, "AAC-ANS-004")
}

test_string_shorthand_with_framework_passes if {
	v := hygiene.violation with input as pb([{
		"name": "Write evidence",
		"community.postgresql.postgresql_query": "INSERT INTO compliance_results (host, framework, result) VALUES ('a', 'cis', 'pass')",
	}])
	not has(v, "AAC-ANS-004")
}

test_framework_only_in_where_clause_violates if {
	v := hygiene.violation with input as pb([{
		"name": "Write evidence",
		"community.postgresql.postgresql_query": {"query": "INSERT INTO compliance_results (host, result) SELECT h, r FROM t WHERE framework = 'cis'"},
	}])
	has(v, "AAC-ANS-004")
}
