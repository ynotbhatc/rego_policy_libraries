package cis_nginx_1_20_test

import rego.v1

test_not_compliant_without_facts if {
	c := object.get(data.cis_nginx_1_20, "compliant", false) with input as {}
	not c == true
}
