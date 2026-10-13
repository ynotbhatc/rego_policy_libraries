package cis_vcenter_8_test

import rego.v1

test_not_compliant_without_facts if {
	c := object.get(data.cis_vcenter_8, "compliant", false) with input as {}
	not c == true
}
