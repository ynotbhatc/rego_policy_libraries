package stig.rhel_9.decisions_scope_test

import rego.v1

# Decisions 2026-10-19 (theme A): `compliant` = no open finding at any category.

test_services_cat_ii_open_not_compliant if {
	i := {"packages": {"telnet-server": false, "rsh-server": false, "ypserv": false, "tftp-server": false, "vsftpd": false}}
	data.stig.rhel_9.services.cat_i_compliant with input as i
	not data.stig.rhel_9.services.compliant with input as i
}

test_report_exposes_cat_i_compliant if {
	r := data.stig.rhel_9.network.compliance_report with input as {}
	r.cat_i_compliant == false
	r.compliant == false
}
