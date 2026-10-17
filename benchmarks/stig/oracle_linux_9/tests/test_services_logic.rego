package stig.oracle_linux_9.services_test

import rego.v1

import data.stig.oracle_linux_9.services

# Validation 2026-10-17: no evidence is not a pass; ftp needs vsftpd gone.

test_empty_input_cat_i_open if {
	services.status_ol09_00_000135 == "Open" with input as {}
	services.status_ol09_00_000130 == "Open" with input as {}
	not services.compliant with input as {}
}

test_empty_input_nfs_open if {
	services.status_ol09_00_000100 == "Open" with input as {}
}

test_running_vsftpd_with_ftpd_absent_is_open if {
	services.status_ol09_00_000130 == "Open" with input as {"services": {"vsftpd": "active", "sshd": "active"}, "packages": {"vsftpd": true}}
}

test_ftp_clean_host_passes if {
	services.status_ol09_00_000130 == "Not_a_Finding" with input as {"services": {"sshd": "active"}, "packages": {"vsftpd": false}}
}

test_tftp_installed_is_open if {
	services.status_ol09_00_000135 == "Open" with input as {"packages": {"tftp-server": true}}
	services.status_ol09_00_000135 == "Not_a_Finding" with input as {"packages": {"tftp-server": false}}
}

test_nfs_active_is_open if {
	services.status_ol09_00_000100 == "Open" with input as {"services": {"nfs-server": "active"}}
	services.status_ol09_00_000100 == "Not_a_Finding" with input as {"services": {"nfs-server": "inactive", "nfsd": "inactive"}}
}

test_telnet_server_installed_is_open if {
	services.status_ol09_00_000110 == "Open" with input as {"packages": {"telnet-server": true}}
	services.status_ol09_00_000110 == "Not_a_Finding" with input as {"packages": {"telnet-server": false}}
}
