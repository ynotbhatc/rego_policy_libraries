# Tests for owasp_top10.main.

package owasp_top10.main_test

import rego.v1

import data.owasp_top10.main

all_true := {"owasp_top10": {"categories": {"A01:2025": true, "A02:2025": true, "A03:2025": true, "A04:2025": true, "A05:2025": true, "A06:2025": true, "A07:2025": true, "A08:2025": true, "A09:2025": true, "A10:2025": true}}}

test_fully_compliant if {
	main.compliant with input as all_true
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some msg in r.violations
	contains(msg, "FAIL-CLOSED")
	r.violation_count == 11 # the FAIL-CLOSED message plus one per unattested category
}

test_non_object_container_fails_closed if {
	r := main.compliance_report with input as {"owasp_top10": {"categories": [true]}}
	r.compliant == false
	some msg in r.violations
	contains(msg, "FAIL-CLOSED")
}

test_one_false_named if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/owasp_top10/categories/A05:2025", "value": false}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "A05:2025")
	contains(msg, "Injection")
}

test_missing_row_is_violation if {
	inp := json.patch(all_true, [{"op": "remove", "path": "/owasp_top10/categories/A10:2025"}])
	v := main.violations with input as inp
	count(v) == 1
}

test_string_true_is_violation if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/owasp_top10/categories/A01:2025", "value": "true"}])
	not main.compliant with input as inp
}

test_unknown_id_is_violation if {
	inp := json.patch(all_true, [{"op": "add", "path": "/owasp_top10/categories/A11:2025", "value": true}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown category id A11:2025")
}

test_row_counts_pinned if {
	count(main.category_rows) == 10
	count(main.categories) == 10
	count(main.mapping_2021) == 10
	sum([count(r.cwes) | some r in main.category_rows]) == 249
	count(main.categories["A01:2025"].cwes) == 40
	count(main.categories["A09:2025"].cwes) == 5
}

test_every_row_has_url_and_cwes if {
	every r in main.category_rows {
		startswith(r.url, "https://owasp.org/Top10/2025/")
		count(r.cwes) > 0
		r.title != ""
	}
}

test_report_rollup if {
	r := main.compliance_report with input as all_true
	r.categories_total == 10
	r.categories_attested == 10
	r.cwe_mappings_total == 249
	r.categories["A03:2025"].attested == true
}
