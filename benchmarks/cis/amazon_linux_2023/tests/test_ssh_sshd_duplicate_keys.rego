package cis_amazon_linux_2023.ssh_test

import rego.v1


# Regression: `sshd -T` repeats hostkey / listenaddress. Before this test the
# module's sshd_config comprehension raised eval_conflict_error ("object keys
# must be unique") on every real host, which the orchestrator surfaced as an
# OPA 500 and the playbook correctly refused to score (lab job 6106).
_raw := "port 22\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ecdsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\npermitrootlogin no\nmaxauthtries 4\nloglevel INFO\n"

test_sshd_config_tolerates_repeated_directives if {
	cfg := data.cis_amazon_linux_2023.ssh.sshd_config with input as {"ssh": {"sshd_config_raw": _raw}}
	cfg["permitrootlogin"] == "no"
	contains(cfg["hostkey"], "ssh_host_rsa_key")
	contains(cfg["hostkey"], "ssh_host_ed25519_key")
	count(split(cfg["listenaddress"], ",")) == 2
}

test_module_evaluates_with_repeated_directives if {
	v := data.cis_amazon_linux_2023.ssh.violations with input as {"ssh": {"sshd_config_raw": _raw}}
	count(v) >= 0
}
