package aac.repo.install_hygiene_test

import rego.v1

import data.aac.repo.install_hygiene as ih

# Validation 2026-10-17: absent scan input is not a pass; *_pass fallbacks are caught.

test_missing_lines_not_compliant if {
	not ih.compliant with input as {"path": "x"}
}

test_empty_lines_compliant if {
	ih.compliant with input as {"path": "x", "lines": []}
}

test_missing_tracked_files_not_compliant if {
	not ih.tracking_compliant with input as {}
	ih.tracking_compliant with input as {"tracked_files": [], "must_be_untracked": ["config.yml"]}
}

test_tracked_operator_file_violates if {
	not ih.tracking_compliant with input as {"tracked_files": ["config.yml"], "must_be_untracked": ["config.yml"]}
}

test_ansible_pass_fallback_flagged if {
	v := ih.violation with input as {"path": "play.yml", "lines": [{"n": 3, "text": "ansible_ssh_pass: \"{{ ssh_pass | default('hunter2') }}\""}]}
	count(v) == 1
	not ih.compliant with input as {"path": "play.yml", "lines": [{"n": 3, "text": "ansible_ssh_pass: \"{{ ssh_pass | default('hunter2') }}\""}]}
}

test_bypass_name_not_flagged if {
	count(ih.violation) == 0 with input as {"path": "play.yml", "lines": [{"n": 1, "text": "bypass: \"{{ x | default('abc') }}\""}]}
}

test_pwd_and_credential_flagged if {
	count(ih.violation) == 2 with input as {"path": "p.yml", "lines": [
		{"n": 1, "text": "db_pwd: \"{{ a | default('x1') }}\""},
		{"n": 2, "text": "api_credential: \"{{ b | default('y1') }}\""},
	]}
}
