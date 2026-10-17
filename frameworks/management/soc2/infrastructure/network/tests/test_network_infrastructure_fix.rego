package soc2.infrastructure.network_test

import rego.v1

# Validation fix pass 2026-10-17: a failing control must not make the score or findings undefined.

test_network_infrastructure_score_defined_when_every_control_fails if {
	s := data.soc2.infrastructure.network.network_infrastructure_score with input as {}
	s == 0
}

test_network_infrastructure_findings_fully_populated_when_every_control_fails if {
	r := data.soc2.infrastructure.network.network_infrastructure_findings with input as {}
	r.overall_score == 0
	leaves := [v | walk(r, [path, v]); not is_object(v); path != ["overall_score"]]
	count(leaves) > 1
	every v in leaves {
		v == false
	}
}

net_enc(v) := {"network": {"encryption": {"in_transit": {"tls_minimum_version": v, "perfect_forward_secrecy": true}, "ipsec": {"configured": true}, "macsec": {"enabled": true}}}}

test_tls_minimum_version_forms if {
	every v in [1.2, "TLSv1.2", "1.3"] {
		data.soc2.infrastructure.network.network_encryption_compliant with input as net_enc(v)
	}
}

test_old_tls_minimum_version_fails_including_strings if {
	every v in [1.0, "TLSv1.0", "1.1", "SSLv3"] {
		not data.soc2.infrastructure.network.network_encryption_compliant with input as net_enc(v)
	}
}
