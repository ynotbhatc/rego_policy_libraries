# Tests for cisa_tic3.main — CISA TIC 3.0 Security Capabilities Catalog v3.3.
package cisa_tic3.main_test

import rego.v1

import data.cisa_tic3.main

_all := {id: true | some id, _ in main.capabilities}

_universal := {id: true | some id, c in main.capabilities; c.group == "universal"}

_count(g) := count({id | some id, c in main.capabilities; c.group == g})

test_row_counts_pinned if {
	count(main.capabilities) == 116
	count(main.groups) == 13
	_count("universal") == 25
	_count("files") == 4
	_count("email") == 20
	_count("web") == 13
	_count("networking") == 6
	_count("resiliency") == 3
	_count("dns") == 5
	_count("intrusion_detection") == 6
	_count("enterprise") == 6
	_count("ucc") == 8
	_count("data_protection") == 7
	_count("services") == 5
	_count("identity") == 8
}

test_every_row_has_a_known_group_and_csf_mapping if {
	count({id | some id, c in main.capabilities; not main.groups[c.group]}) == 0
	count({id | some id, c in main.capabilities; count(c.csf) == 0}) == 0
}

test_normalised_ids_keep_printed_form if {
	main.capabilities["3.UNL.SCRMA"].printed_id == "3 UNL.SCRMA"
	main.capabilities["3.PEP.EM.EDRPR"].printed_id == "3.PE P.EM.EDRPR"
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + all 116 capabilities in scope
	r.violation_count == 117
}

test_all_attested_is_compliant if {
	inp := {"cisa_tic3": {"capabilities": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.capabilities_evaluated == 116
	r.capabilities_attested == 116
}

test_all_attested_with_declared_scope_is_compliant if {
	inp := {"cisa_tic3": {"pep_groups_in_scope": ["web", "email", "dns"], "capabilities": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.capabilities_evaluated == 63
	r.groups.files.in_scope == false
}

test_empty_scope_needs_universal_only if {
	inp := {"cisa_tic3": {"pep_groups_in_scope": [], "capabilities": _universal}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.capabilities_evaluated == 25
	r.pep_groups_in_scope == []
}

test_scope_opens_one_group if {
	inp := {"cisa_tic3": {"pep_groups_in_scope": ["resiliency"], "capabilities": _universal}}
	r := main.compliance_report with input as inp
	r.violation_count == 3
	r.groups.resiliency.gaps == ["3.PEP.RE.DDSPR", "3.PEP.RE.EEXPS", "3.PEP.RE.RDELI"]
}

test_one_false_is_named if {
	inp := {"cisa_tic3": {"capabilities": object.union(_all, {"3.PEP.WE.BINSP": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "3.PEP.WE.BINSP")
	contains(m, "Break and Inspect")
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"cisa_tic3": {"capabilities": object.union(_all, {"3.UNI.TSYNC": "true", "3.UNI.SCRMA": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "3.UNI.TSYNC")
	some m2 in v
	contains(m2, "unknown capability id 3.UNI.SCRMA")
}

test_malformed_scope_is_a_violation_and_evaluates_all if {
	inp := {"cisa_tic3": {"pep_groups_in_scope": ["web", "wifi"], "capabilities": _universal}}
	r := main.compliance_report with input as inp
	r.capabilities_evaluated == 116
	some m in r.violations
	contains(m, "pep_groups_in_scope")

	# 91 PEP gaps + the scope violation
	r.violation_count == 92
}

test_scope_not_an_array_is_a_violation if {
	inp := {"cisa_tic3": {"pep_groups_in_scope": "web", "capabilities": _all}}
	v := main.violations with input as inp
	count(v) == 1
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"cisa_tic3": {"capabilities": ["3.UNI.BRECO"]}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_non_object_namespace_fails_closed if {
	v := main.violations with input as {"cisa_tic3": "x"}
	some m in v
	contains(m, "FAIL-CLOSED")
	r := main.compliance_report with input as {"cisa_tic3": "x"}
	r.compliant == false
}
