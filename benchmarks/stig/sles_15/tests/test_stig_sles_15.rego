package stig.sles_15_test

import rego.v1
import data.stig.sles_15

test_report_wellformed_on_empty_input if {
	report := sles_15.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings
}

green_fixture := {
	 "os": {
	  "vendor_supported": true
	 },
	 "packages": [
	  "crypto-policies"
	 ],
	 "crypto_policy": {
	  "policy": "FIPS",
	  "overridden": false,
	  "opensshserver_ciphers": "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr",
	  "opensshserver_macs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
	 },
	 "grub": {
	  "password_required": true,
	  "uefi_password_required": true
	 },
	 "sshd_config": {
	  "PermitRootLogin": "no",
	  "X11Forwarding": "no",
	  "PermitEmptyPasswords": "no"
	 },
	 "storage": {
	  "persistent_partitions_encrypted": true
	 },
	 "repos": {
	  "gpgcheck": true
	 },
	 "sudo": {
	  "nopasswd_or_noauthenticate_present": false
	 },
	 "fips": {
	  "enabled": true
	 },
	 "services": {
	  "sshd": {
	   "active": true
	  }
	 },
	 "accounts": {
	  "root_only_uid0": true
	 },
	 "passwd": {
	  "blank_password_accounts": []
	 },
	 "pam": {
	  "nullok_present": false
	 },
	 "forbidden_files": {
	  "shosts_present": false,
	  "shosts_equiv_present": false
	 },
	 "systemd": {
	  "ctrl_alt_del_masked": true,
	  "ctrl_alt_del_burst_disabled": true
	 },
	 "gdm": {
	  "ctrl_alt_del_disabled": true,
	  "automatic_login_enabled": false
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := sles_15.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
	report.summary.cat_i_open == 0
}
