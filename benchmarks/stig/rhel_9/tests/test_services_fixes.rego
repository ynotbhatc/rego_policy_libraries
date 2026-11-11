package stig.rhel_9.services_fixes_test

import rego.v1

sv := data.stig.rhel_9.services

test_empty_input_not_compliant if not sv.compliant with input as {}

test_empty_input_all_open if sv.compliance_report.open_findings == sv.compliance_report.total_findings with input as {}

test_missing_package_key_is_open if sv.status_rhel_09_215040 == "Open" with input as {"packages": {}}

test_telnet_alias_installed_is_open if sv.status_rhel_09_215040 == "Open" with input as {"packages": {"telnet-server": false, "telnetd": true}}

test_telnet_both_absent_ok if sv.status_rhel_09_215040 == "Not_a_Finding" with input as {"packages": {"telnet-server": false, "telnetd": false}}

test_telnet_one_alias_reported_absent_ok if sv.status_rhel_09_215040 == "Not_a_Finding" with input as {"packages": {"telnet-server": false}}

test_ftpd_inactive_vsftpd_installed_open if sv.status_rhel_09_215015 == "Open" with input as {"services": {"ftpd": "inactive"}, "packages": {"vsftpd": true}}

test_service_missing_state_open if sv.status_rhel_09_231040 == "Open" with input as {"services": {}}

test_service_inactive_ok if sv.status_rhel_09_231040 == "Not_a_Finding" with input as {"services": {"autofs": "inactive"}}

test_service_active_open if sv.status_rhel_09_231040 == "Open" with input as {"services": {"autofs": "active"}}

# CAT I in V2R10: tftp-server (RHEL-09-215060) and the FTP server (RHEL-09-215015); telnet-server is CAT II.
test_all_cat_i_absent_compliant if sv.cat_i_compliant with input as {"packages": {"tftp-server": false, "vsftpd": false}}

test_telnet_installed_not_compliant if not sv.compliant with input as {"packages": {"telnet-server": true, "tftp-server": false, "vsftpd": false}}
