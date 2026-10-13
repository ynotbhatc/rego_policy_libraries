package cis_openshift_4_test

import rego.v1

test_not_compliant_without_facts if {
	c := object.get(data.cis_openshift_4, "compliant", false) with input as {}
	not c == true
}
