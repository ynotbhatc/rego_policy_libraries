# Closed vocabularies are allow-lists: an unknown word is an evidence invalid finding, never a pass (round 4).
package cis_aws.closed_vocabularies_test

import rego.v1

import data.cis_aws as b

green := data.cis_aws.v7_controls_test.green

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

_has_text(vs, id, t) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
	contains(v, t)
}

# Console user without MFA: 2.10 fires, whatever the letter case of the AWS CSV word.
test_2_10_fires_for_any_case_of_true if {
	every w in ["true", "TRUE", " True "] {
		inp := json.patch(green, [
			{"op": "replace", "path": "/credential_report/1/password_enabled", "value": w},
			{"op": "replace", "path": "/credential_report/1/mfa_active", "value": "false"},
		])
		vs := b.violations with input as inp
		_has_id(vs, "2.10")
	}
}

# An unknown password_enabled word must not mean "no console password".
test_2_10_unknown_password_enabled_word_is_evidence_invalid if {
	every w in ["yes", "enabled", "no", "1"] {
		inp := json.patch(green, [
			{"op": "replace", "path": "/credential_report/1/password_enabled", "value": w},
			{"op": "replace", "path": "/credential_report/1/mfa_active", "value": "false"},
		])
		vs := b.violations with input as inp
		_has_text(vs, "2.10", "evidence invalid, got string")
	}
}

test_2_10_unknown_mfa_active_word_is_evidence_invalid if {
	inp := json.patch(green, [{"op": "replace", "path": "/credential_report/1/mfa_active", "value": "maybe"}])
	vs := b.violations with input as inp
	_has_text(vs, "2.10", "mfa_active")
}

test_2_10_documented_words_are_accepted if {
	every w in ["TRUE", "FALSE", "not_supported"] {
		inp := json.patch(green, [{"op": "replace", "path": "/credential_report/0/password_enabled", "value": w}])
		vs := b.violations with input as inp
		not _has_text(vs, "2.10", "evidence invalid")
	}
}

# 6.3: an unrecognised IpProtocol is not a portless protocol that clears the rule.
test_6_3_unknown_protocol_is_a_finding if {
	every p in ["false", "ssh", "TCPX", "300", "-2"] {
		inp := json.patch(green, [{"op": "add", "path": "/security_groups/0/IpPermissions/-", "value": {"IpProtocol": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}}])
		vs := b.violations with input as inp
		_has_text(vs, "6.3", "not a recognised EC2 protocol")
	}
}

test_6_3_known_portless_protocols_still_collected if {
	every p in ["icmp", "icmpv6", "ICMP", "1", "50", "58", "-1"] {
		inp := json.patch(green, [{"op": "add", "path": "/security_groups/0/IpPermissions/-", "value": {"IpProtocol": p, "FromPort": 0, "ToPort": 0, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}}])
		vs := b.violations with input as inp
		not _has_text(vs, "6.3", "not a recognised EC2 protocol")
	}
}
