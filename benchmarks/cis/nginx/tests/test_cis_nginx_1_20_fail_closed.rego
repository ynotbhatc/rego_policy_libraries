package cis_nginx_1_20_test

import rego.v1

test_not_compliant_without_facts if {
	c := data.cis_nginx_1_20.compliant with input as {}
	c == false
}
