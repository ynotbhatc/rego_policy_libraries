package soc2.confidentiality.data_confidentiality_test

import rego.v1

# Validation fix pass 2026-10-17: a failing control must not make the score or findings undefined.

test_data_confidentiality_score_defined_when_every_control_fails if {
	s := data.soc2.confidentiality.data_confidentiality.confidentiality_score with input as {}
	s == 0
}

test_data_confidentiality_findings_fully_populated_when_every_control_fails if {
	r := data.soc2.confidentiality.data_confidentiality.confidentiality_findings with input as {}
	r.overall_score == 0
	leaves := [v | walk(r, [path, v]); not is_object(v); path != ["overall_score"]]
	count(leaves) > 1
	every v in leaves {
		v == false
	}
}

transit(v) := {"encryption": {"in_transit": {"enabled": true, "protocols": {"tls_version": v}, "cipher_suites": {"strong_only": true}, "certificate_management": {"automated": true}}}}

test_tls_version_forms if {
	every v in [1.2, 1.3, "1.2", "TLSv1.2", "TLSv1.3", "TLS 1.3"] {
		data.soc2.confidentiality.data_confidentiality.encryption_in_transit with input as transit(v)
	}
}

test_old_tls_versions_fail_including_strings if {
	every v in [1.0, 1.1, "1.0", "TLSv1.0", "TLSv1.1", "SSLv3", "bogus"] {
		not data.soc2.confidentiality.data_confidentiality.encryption_in_transit with input as transit(v)
	}
}
