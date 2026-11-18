package cis_rhel9.ssh_test

import rego.v1

# Regression: `sshd -T` repeats hostkey / listenaddress. Before this test the
# module's sshd_config comprehension raised eval_conflict_error ("object keys
# must be unique") on every real host, which the orchestrator surfaced as an
# OPA 500 and the playbook correctly refused to score (lab job 6106).
_raw := "port 22\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ecdsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\npermitrootlogin no\nmaxauthtries 4\nloglevel INFO\n"

test_sshd_config_tolerates_repeated_directives if {
	cfg := data.cis_rhel9.ssh.sshd_config with input as {"ssh": {"sshd_config_raw": _raw}}
	cfg.permitrootlogin == "no"
	contains(cfg.hostkey, "ssh_host_rsa_key")
	contains(cfg.hostkey, "ssh_host_ed25519_key")
	count(split(cfg.listenaddress, ",")) == 2
}

_has(v, id) if {
	some x in v
	startswith(x, concat("", [id, ":"]))
}

# The module still evaluates with the repeated directives, decides the three settings the config carries
# (5.1.16 loglevel, 5.1.17 maxauthtries, 5.1.21 permitrootlogin pass, so none is reported) and still fails closed on
# everything the config does not carry (5.1.10 clientalive is missing evidence).
test_module_evaluates_with_repeated_directives if {
	v := data.cis_rhel9.ssh.violations with input as {"ssh": {"sshd_config_raw": _raw}}
	count(v) > 0
	not _has(v, "5.1.16")
	not _has(v, "5.1.17")
	not _has(v, "5.1.21")
	_has(v, "5.1.10")
}

test_repeated_directives_do_not_hide_a_bad_setting if {
	raw := replace(_raw, "permitrootlogin no", "permitrootlogin yes")
	v := data.cis_rhel9.ssh.violations with input as {"ssh": {"sshd_config_raw": raw}}
	_has(v, "5.1.21")
}
