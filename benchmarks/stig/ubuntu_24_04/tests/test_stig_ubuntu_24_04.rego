package stig.ubuntu_24_04_test

import data.stig.ubuntu_24_04
import rego.v1

test_report_wellformed_on_empty_input if {
	report := ubuntu_24_04.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings
}

green_fixture := {
	"packages": ["openssh-server"],
	"services": {
		"ssh": {"active": true},
		"kdump-tools": {"masked": true},
	},
	"sshd_config": {
		"Ciphers": "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr",
		"MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
		"X11Forwarding": "no",
		"X11UseLocalhost": "yes",
		"PermitEmptyPasswords": "no",
		"PermitUserEnvironment": "no",
		"ClientAliveCountMax": 1,
		"ClientAliveInterval": 600,
	},
	"grub": {"password_required": true},
	"gdm": {"ctrl_alt_del_disabled": true},
	"systemd": {"ctrl_alt_del_masked": true},
	"passwd": {"blank_password_accounts": []},
	"pam": {"nullok_present": false},
	"sssd": {"pki_mapping_configured": true},
	"fips": {"enabled": true},
	"sudo": {"only_required_members": true},
	"sysctl": {"kernel.dmesg_restrict": 1},
	"os": {"vendor_supported": true},
}

test_fully_compliant_on_green_fixture if {
	report := ubuntu_24_04.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
	report.summary.cat_i_open == 0
}
