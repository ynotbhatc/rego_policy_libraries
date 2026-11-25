package iso27001_advisory_evidence_test

import rego.v1

import data.iso27001

# Audit 2026-11-24, round 2. The 85 facts read only by the checks in unmapped_fact_rules decide no Annex A
# control. Removing one, or sending false, changes no verdict (by design, 2026-11-17). Sending one with the
# wrong type is a collection error: it is listed in advisory_evidence_findings, and the Annex A verdict
# still does not move.

green := data.iso27001_annex_a_test._green

types := iso27001.advisory_fact_types

_ptr(path) := concat("/", array.concat([""], split(path, ".")))

_set(path, value) := json.patch(green, [{"op": "replace", "path": _ptr(path), "value": value}])

_bad("boolean") := ["false", "true", "no", 0, 1, null, [], {}]

_bad("number") := ["2", "two", true, false, null, []]

# every advisory fact holds `value` (paths are two to four levels deep)
_bulk(value) := object.union_n(array.concat(
	[green],
	array.concat(
		[{p[0]: {p[1]: value}} | some path, _ in types; p := split(path, "."); count(p) == 2],
		array.concat(
			[{p[0]: {p[1]: {p[2]: value}}} | some path, _ in types; p := split(path, "."); count(p) == 3],
			[{p[0]: {p[1]: {p[2]: {p[3]: value}}}} | some path, _ in types; p := split(path, "."); count(p) == 4],
		),
	),
))

test_table_size_and_depth if {
	count(types) == 85
	every path, want in types {
		want in {"boolean", "number"}
		count(split(path, ".")) in {2, 3, 4}
	}
}

test_green_fixture_carries_every_advisory_fact_with_its_type if {
	every path, want in types {
		type_name(object.get(green, split(path, "."), null)) == want
	}
}

test_green_fixture_has_no_findings_and_passes if {
	count(iso27001.advisory_evidence_findings) == 0 with input as green
	r := data.iso27001.main.compliance_report with input as green
	r.compliant == true
	r.advisory_evidence_findings == []
	r.advisory_evidence_finding_count == 0
}

# The facts are checked in 8 slices (index of the sorted path modulo 8), so that no test runs long enough to meet the
# suite's per-test timeout on the oldest supported OPA. Every fact is in exactly one slice.
_type_slice(i) := {path: types[path] | some j, path in sort([k | some k, _ in types]); j % 8 == i}

test_the_slices_cover_every_advisory_fact if {
	sum([count(_type_slice(i)) | some i in numbers.range(0, 7)]) == count(types)
	every path, _ in types {
		count([i | some i in numbers.range(0, 7); path in object.keys(_type_slice(i))]) == 1
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_0 if {
	every path, want in _type_slice(0) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_1 if {
	every path, want in _type_slice(1) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_2 if {
	every path, want in _type_slice(2) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_3 if {
	every path, want in _type_slice(3) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_4 if {
	every path, want in _type_slice(4) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_5 if {
	every path, want in _type_slice(5) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_6 if {
	every path, want in _type_slice(6) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_each_mistyped_advisory_fact_is_reported_once_and_named_slice_7 if {
	every path, want in _type_slice(7) {
		every bad in _bad(want) {
			f := iso27001.advisory_evidence_findings with input as _set(path, bad)
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not a %v (got %v) — the fact feeds only checks listed in unmapped_fact_rules", [path, want, type_name(bad)])}
		}
	}
}

test_removed_or_false_advisory_fact_is_not_a_finding if {
	every path, _ in types {
		count(iso27001.advisory_evidence_findings) == 0 with input as json.remove(green, [_ptr(path)])
	}
	every path in [q | some q, w in types; w == "boolean"] {
		count(iso27001.advisory_evidence_findings) == 0 with input as _set(path, false)
	}
}

# the Annex A verdict never moves on an advisory fact, mistyped or not; the report shows the findings
test_all_advisory_facts_mistyped_verdict_unchanged_findings_listed if {
	every bad in ["false", "true", "no", null] {
		r := data.iso27001.main.compliance_report with input as _bulk(bad)
		r.compliant == true
		r.violation_count == 0
		r.controls_satisfied == 93
		r.advisory_evidence_finding_count == 85
		count(r.advisory_evidence_findings) == 85
	}
}

test_all_advisory_facts_false_verdict_unchanged_no_findings if {
	r := data.iso27001.main.compliance_report with input as _bulk(false)
	r.compliant == true

	# the two number facts are now booleans, which is a type finding; the 83 booleans are plain false
	r.advisory_evidence_finding_count == 2
}

test_advisory_section_of_the_wrong_type_is_reported if {
	every section in ["api", "certificates", "database", "digital_signatures", "dns_security", "hsm", "pki"] {
		every bad in [null, "true", 1, []] {
			inp := object.union(green, {section: bad})
			f := iso27001.advisory_evidence_findings with input as inp
			f == {sprintf("ISO/IEC 27001 Input Contract (advisory, not scored): input.%v is not an object (got %v) — the facts under it feed only checks listed in unmapped_fact_rules", [section, type_name(bad)])}
			iso27001.compliant with input as inp
		}
	}
}

test_advisory_section_removed_is_not_a_finding if {
	every section in ["api", "certificates", "database", "digital_signatures", "dns_security", "hsm", "pki"] {
		inp := json.remove(green, [concat("", ["/", section])])
		count(iso27001.advisory_evidence_findings) == 0 with input as inp
		iso27001.compliant with input as inp
	}
}

test_empty_and_non_object_input_report_defined_and_failing if {
	every bad in [{}, "true", null, 1, []] {
		r := data.iso27001.main.compliance_report with input as bad
		r.compliant == false
		r.advisory_evidence_finding_count == 0
	}
}

# A.5.14 is decided by three communications_security fact checks; its attestation is accepted but does not
# decide it (module header, "How a control is evaluated"). Removing it changes nothing; a wrong-typed one is
# an Input Contract violation.
test_a514_attestation_does_not_decide_a_fact_evaluated_control if {
	inp := json.remove(green, ["/iso27001/annex_a/A.5.14"])
	r := data.iso27001.main.compliance_report with input as inp
	r.compliant == true
	r.annex_a["A.5.14"].basis == "facts"
	r.annex_a["A.5.14"].satisfied == true
	bad := json.patch(green, [{"op": "replace", "path": "/iso27001/annex_a/A.5.14", "value": "true"}])
	not iso27001.compliant with input as bad
}
