package stig.rhel_9.services_fixes_test

import rego.v1

sv := data.stig.rhel_9.services

test_empty_input_not_compliant if not sv.compliant with input as {}

test_empty_input_all_open if sv.compliance_report.open_findings == sv.compliance_report.total_findings with input as {}

test_missing_package_key_is_open if sv.status_rhel_09_291010 == "Open" with input as {"packages": {}}

test_explicit_absent_is_ok if sv.status_rhel_09_291020 == "Not_a_Finding" with input as {"packages": {"ypserv": false}}

test_installed_is_open if sv.status_rhel_09_291020 == "Open" with input as {"packages": {"ypserv": true}}

test_telnet_alias_installed_is_open if sv.status_rhel_09_291010 == "Open" with input as {"packages": {"telnet-server": false, "telnetd": true}}

test_telnet_both_absent_ok if sv.status_rhel_09_291010 == "Not_a_Finding" with input as {"packages": {"telnet-server": false, "telnetd": false}}

test_telnet_one_alias_reported_absent_ok if sv.status_rhel_09_291010 == "Not_a_Finding" with input as {"packages": {"telnet-server": false}}

test_inactive_service_with_package_installed_is_open if sv.status_rhel_09_291070 == "Open" with input as {"services": {"named": "inactive"}, "packages": {"bind": true}}

test_package_removed_ok if sv.status_rhel_09_291070 == "Not_a_Finding" with input as {"packages": {"bind": false}}

test_snmp_inactive_but_installed_open if sv.status_rhel_09_291055 == "Open" with input as {"services": {"snmpd": "inactive"}, "packages": {"net-snmp": true}}

test_rsync_inactive_but_installed_open if sv.status_rhel_09_291095 == "Open" with input as {"services": {"rsyncd": "masked"}, "packages": {"rsync-daemon": true}}

test_ftpd_inactive_vsftpd_installed_open if sv.status_rhel_09_291030 == "Open" with input as {"services": {"ftpd": "inactive"}, "packages": {"vsftpd": true}}

test_service_missing_state_open if sv.status_rhel_09_291035 == "Open" with input as {"services": {}}

test_service_inactive_ok if sv.status_rhel_09_291035 == "Not_a_Finding" with input as {"services": {"autofs": "inactive"}}

test_service_active_open if sv.status_rhel_09_291035 == "Open" with input as {"services": {"autofs": "active"}}

test_all_cat_i_absent_compliant if sv.compliant with input as {"packages": {"telnet-server": false, "rsh-server": false, "ypserv": false, "tftp-server": false, "vsftpd": false}}
