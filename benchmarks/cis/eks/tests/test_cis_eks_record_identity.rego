# A record that lacks the field a control scopes or matches it by must not leave the check
# (CIS Amazon EKS v2.0.0). In Rego `not f(row.field) in S` is undefined, not true, when the field is absent,
# so before this test a workload without metadata, a namespace without a name or a service account without a
# name dropped out of every list and the control passed. Each case removes one field from the all-pass
# fixture and names a control that must then report invalid evidence.

package cis_eks.record_identity_test

import rego.v1

_green := data.cis_eks.main_test.compliant_input

_report := data.cis_eks.main.compliance_report

# [path removed, a control that reads the inventory, text the finding carries]
_cases := [
	["/cis_eks/workloads/0/metadata", "4.4.1", "workloads[0].metadata.name is missing or not a string"],
	["/cis_eks/workloads/0/metadata/name", "4.1.6", "workloads[0].metadata.name is missing or not a string"],
	["/cis_eks/workloads/0/spec", "4.1.5", "workloads[0] has no pod spec"],
	["/cis_eks/workloads/1/spec", "4.2.1", "workloads[1] has no pod spec"],
	["/cis_eks/workloads/2/spec/jobTemplate", "5.2.1", "workloads[2] has no pod spec"],
	["/cis_eks/namespaces/1/metadata", "4.2.1", "namespaces[1].metadata.name is missing or not a string"],
	["/cis_eks/namespaces/1/metadata/name", "4.2.5", "namespaces[1].metadata.name is missing or not a string"],
	["/cis_eks/service_accounts/0/metadata", "5.2.1", "service_accounts[0].metadata.name is missing or not a string"],
	["/cis_eks/service_accounts/1/metadata/name", "4.1.6", "service_accounts[1].metadata.name is missing or not a string"],
	["/cis_eks/role_bindings/0/subjects/0/kind", "4.1.5", "role_bindings[0].subjects[0].kind is missing or not a string"],
	["/cis_eks/role_bindings/0/subjects/0/name", "4.1.5", "role_bindings[0].subjects[0].name is missing or not a string"],
]

_without(path) := json.patch(_green, [{"op": "remove", "path": path}])

_invalid(r, id, text) if {
	some msg in r.violations
	startswith(msg, sprintf("CIS EKS %s: evidence invalid", [id]))
	contains(msg, text)
}

test_fixture_passes if _report.compliant == true with input as _green

test_record_without_its_identity_is_invalid_evidence if {
	every c in _cases {
		r := _report with input as _without(c[0])
		r.compliant == false
		_invalid(r, c[1], c[2])
	}
}

# A name that is present but not text is the same problem.
test_record_name_of_the_wrong_type_is_invalid_evidence if {
	every bad in [null, 7, true, "", " ", []] {
		r := _report with input as json.patch(_green, [{"op": "replace", "path": "/cis_eks/namespaces/1/metadata/name", "value": bad}])
		r.compliant == false
		_invalid(r, "4.2.1", "namespaces[1].metadata.name is missing or not a string")
	}
}

# The finding a broken record used to hide: a workload that reads a secret from its environment and has no
# metadata was left out of the 4.4.1 list. It is now reported, and the counts still add up.
test_unnamed_workload_no_longer_hides_from_the_control if {
	patched := json.patch(_green, [
		{"op": "remove", "path": "/cis_eks/workloads/0/metadata"},
		{"op": "add", "path": "/cis_eks/workloads/0/spec/template/spec/containers/0/envFrom", "value": [{"secretRef": {"name": "s"}}]},
	])
	r := _report with input as patched
	r.compliant == false
	_invalid(r, "4.4.1", "workloads[0].metadata.name")
	r.passed_controls + r.failed_controls == r.total_controls
}
