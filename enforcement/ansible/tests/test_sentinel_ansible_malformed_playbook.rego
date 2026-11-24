# A malformed playbook is denied (SENTINEL-ANS-000): the gate never allows a document it could not read
# as a list of plays.

package sentinel.ansible_malformed_test

import rego.v1

import data.sentinel.ansible as gate
import data.sentinel_ansible.main

good_playbook := {
	"sentinel_environment": "production",
	"plays": [{
		"name": "Deploy the web tier",
		"hosts": "webservers",
		"vars": {"app_port": 8443, "db_password": "{{ vault_db_password }}"},
		"tasks": [
			{"name": "Install the package", "tags": ["install"]},
			{"name": "Start the service", "tags": "service"},
		],
	}],
}

_allowed(inp) if {
	gate.allow with input as inp
	main.compliance_report.compliant == true with input as inp
}

_denied(inp) if {
	not gate.allow with input as inp
	main.compliance_report.compliant == false with input as inp
}

_ans000(inp) if {
	some msg in gate.violations with input as inp
	startswith(msg, "SENTINEL-ANS-000: Malformed playbook")
}

test_good_playbook_is_allowed if _allowed(good_playbook)

test_empty_input_is_denied if {
	_denied({})
	_ans000({})
}

test_document_that_is_not_a_playbook_is_denied if {
	every inp in [{"foo": "bar"}, {"plays": null}, {"plays": "true"}, {"plays": "1"}, {"plays": {"name": "x"}}, {"sentinel_environment": "development"}] {
		_denied(inp)
		_ans000(inp)
	}
}

test_plays_null_or_removed_is_denied if {
	_denied(json.patch(good_playbook, [{"op": "remove", "path": "/plays"}]))
	_denied(json.patch(good_playbook, [{"op": "replace", "path": "/plays", "value": null}]))
}

test_play_of_the_wrong_shape_is_denied if {
	cases := [
		["/plays/0", "play"], ["/plays/0", 1], ["/plays/0", null],
		["/plays/0/name", 7], ["/plays/0/name", true],
		["/plays/0/vars", "db_password=hunter2"], ["/plays/0/vars", ["a"]],
		["/plays/0/tasks", "install"], ["/plays/0/tasks", {"name": "t"}],
		["/plays/0/tasks/0", "install"], ["/plays/0/tasks/0", null],
		["/plays/0/tasks/0/tags", 5], ["/plays/0/tasks/0/tags", true], ["/plays/0/tasks/0/tags", {"a": 1}],
	]
	every c in cases {
		inp := json.patch(good_playbook, [{"op": "replace", "path": c[0], "value": c[1]}])
		_denied(inp)
		_ans000(inp)
	}
}

# The existing rules still decide a readable playbook.
test_readable_playbook_is_judged_by_the_rules if {
	_denied(json.patch(good_playbook, [{"op": "remove", "path": "/plays/0/name"}]))
	_denied(json.patch(good_playbook, [{"op": "replace", "path": "/plays/0/name", "value": null}]))
	_denied(json.patch(good_playbook, [{"op": "replace", "path": "/plays/0/hosts", "value": "all"}]))
	_denied(json.patch(good_playbook, [{"op": "replace", "path": "/plays/0/vars/db_password", "value": "hunter2"}]))
	_denied(json.patch(good_playbook, [{"op": "remove", "path": "/plays/0/tasks/0/tags"}]))
	_denied(json.patch(good_playbook, [{"op": "replace", "path": "/plays/0/tasks/0/tags", "value": null}]))
}

# An empty playbook has nothing to run and nothing to violate.
test_empty_play_list_is_allowed if _allowed({"plays": []})
