# A row that lacks the field a rule selects on must produce a finding, not drop out of the check
# (`row.field == "public"` is undefined when the field is absent, so the row used to pass).
package cis_oci.missing_row_fields_test

import rego.v1

import data.cis_oci.main
import data.cis_oci.main_test.green

# [path removed, recommendation that must report evidence missing]
_cases := [
	["/oci/integration_instances/0/network_access", "2.6"],
	["/oci/analytics_instances/0/network_access", "2.7"],
	["/oci/autonomous_databases/0/network_access", "2.8"],
	["/oci/network/security_lists/0/ingress/0/source", "2.1"],
	["/oci/network/security_lists/0/ingress/0/protocol", "2.1"],
	["/oci/network/security_lists/0/ingress", "2.1"],
	["/oci/network/security_groups/0/ingress/0/source", "2.3"],
	["/oci/network/security_groups/0/ingress/0/protocol", "2.3"],
	["/oci/network/security_groups/0/ingress", "2.3"],
]

test_a_row_without_the_field_is_a_finding if {
	every c in _cases {
		r := main.compliance_report with input as json.patch(green, [{"op": "remove", "path": c[0]}])
		r.compliant == false
		some v in r.violations
		startswith(v, sprintf("%s: ", [c[1]]))
		contains(v, "evidence missing")
	}
}

test_a_non_text_source_is_a_finding if {
	r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": "/oci/network/security_lists/0/ingress/0/source", "value": 5}])
	r.compliant == false
}

test_the_default_security_list_without_vcn_still_reports if {
	inp := json.patch(green, [
		{"op": "remove", "path": "/oci/network/security_lists/0/vcn"},
		{"op": "replace", "path": "/oci/network/security_lists/0/is_default", "value": true},
		{"op": "add", "path": "/oci/network/security_lists/0/ingress/-", "value": {"source": "10.0.0.0/8", "protocol": "6"}},
	])
	r := main.compliance_report with input as inp
	some v in r.violations
	startswith(v, "2.5:")
}
