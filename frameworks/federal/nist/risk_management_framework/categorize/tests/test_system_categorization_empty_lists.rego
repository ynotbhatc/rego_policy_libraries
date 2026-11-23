package nist.rmf.categorize_empty_lists_test

import rego.v1

# Weekly audit 2026-11-23 follow-up: external_dependencies was guarded by `count(x) >= 0`, true for any collection.
# NIST SP 800-53 Rev 5 PL-2a: describe "any dependencies on or connections to other systems or system components".

_dep := {"service_provider": "Example Cloud", "categorization_level": "moderate", "risk_assessment_completed": true}

_ok(facts) if data.nist.rmf.categorize.external_dependencies_identified with input as {"system_categorization": facts}

test_empty_external_dependencies_need_explicit_statement if {
	not _ok({"external_dependencies": []})
	not _ok({"external_dependencies": [], "has_external_dependencies": true})
	not _ok({"external_dependencies": [], "has_external_dependencies": "false"})
	not _ok({"external_dependencies": [], "has_external_dependencies": null})
	_ok({"external_dependencies": [], "has_external_dependencies": false})
}

test_external_dependencies_must_be_an_array_and_consistent if {
	_ok({"external_dependencies": [_dep]})
	_ok({"external_dependencies": [_dep], "has_external_dependencies": true})
	not _ok({"external_dependencies": [_dep], "has_external_dependencies": false})
	not _ok({})
	not _ok({"has_external_dependencies": false})
	not _ok({"external_dependencies": null, "has_external_dependencies": false})
	not _ok({"external_dependencies": {}, "has_external_dependencies": false})
	not _ok({"external_dependencies": [object.union(_dep, {"service_provider": 3})]})
	not _ok({"external_dependencies": [object.remove(_dep, ["risk_assessment_completed"])]})
}

test_empty_input_is_not_identified if {
	not data.nist.rmf.categorize.external_dependencies_identified with input as {}
}
