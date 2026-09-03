package stig.ubuntu_22_04_test

import rego.v1
import data.stig.ubuntu_22_04

test_report_wellformed_on_empty_input if {
	report := ubuntu_22_04.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings
}

green_fixture := {
	 "os": {
	  "vendor_supported": true
	 },
	 "systemd": {
	  "ctrl_alt_del_masked": true
	 },
	 "grub": {
	  "password_required": true
	 },
	 "sysctl": {
	  "kernel.dmesg_restrict": 1
	 },
	 "services": {
	  "kdump-tools": {
	   "masked": true
	  },
	  "ssh": {
	   "active": true
	  }
	 },
	 "packages": [
	  "openssh-server"
	 ],
	 "sshd_config": {
	  "PermitEmptyPasswords": "no",
	  "PermitUserEnvironment": "no",
	  "ClientAliveCountMax": 1,
	  "ClientAliveInterval": 600,
	  "X11Forwarding": "no",
	  "X11UseLocalhost": "yes",
	  "Ciphers": "aes256-ctr,aes256-gcm@openssh.com,aes128-ctr,aes128-gcm@openssh.com",
	  "MACs": "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com"
	 },
	 "gdm": {
	  "ctrl_alt_del_disabled": true
	 },
	 "sudo": {
	  "only_required_members": true
	 },
	 "pam": {
	  "nullok_present": false
	 },
	 "passwd": {
	  "blank_password_accounts": []
	 },
	 "sssd": {
	  "pki_mapping_configured": true
	 },
	 "fips": {
	  "enabled": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := ubuntu_22_04.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
	report.summary.cat_i_open == 0
}
