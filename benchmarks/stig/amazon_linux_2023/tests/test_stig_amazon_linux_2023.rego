package stig.amazon_linux_2023_test

import rego.v1
import data.stig.amazon_linux_2023

test_report_wellformed_on_empty_input if {
	report := amazon_linux_2023.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings
}

green_fixture := {
	 "fips": {
	  "enabled": true
	 },
	 "storage": {
	  "persistent_partitions_encrypted": true
	 },
	 "repos": {
	  "localpkg_gpgcheck": true,
	  "gpgcheck": true,
	  "all_repos_gpgcheck": true
	 },
	 "os": {
	  "vendor_supported": true
	 },
	 "sysctl": {
	  "kernel.dmesg_restrict": 1,
	  "kernel.randomize_va_space": 2
	 },
	 "packages": [
	  "openssh-server",
	  "crypto-policies"
	 ],
	 "services": {
	  "sshd": {
	   "active": true
	  }
	 },
	 "crypto_policy": {
	  "opensshserver_ciphers": "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr",
	  "openssh_client_ciphers": "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr",
	  "opensshserver_macs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
	  "openssh_client_macs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
	  "policy": "FIPS",
	  "overridden": false
	 },
	 "sshd_config": {
	  "RekeyLimit": "1G 1h",
	  "PermitEmptyPasswords": "no",
	  "PermitRootLogin": "no",
	  "UsePAM": "yes"
	 },
	 "selinux": {
	  "enforcing": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := amazon_linux_2023.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
	report.summary.cat_i_open == 0
}
