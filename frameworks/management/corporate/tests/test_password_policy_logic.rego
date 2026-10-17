package corporate.password_test

import rego.v1

import data.corporate.password as p

# Validation 2026-10-17.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

old_rfc := "2019-01-01T00:00:00Z"

inp(role, value, changed) := {
	"user": {"role": role, "last_password_change": changed, "password_history": []},
	"password": {"value": value, "length": count(split(value, "")), "value_hash": "h"},
}

# 3 days ago, in RFC3339
recent := time.format([time.now_ns() - (3 * 24 * 60 * 60 * 1000000000), "UTC", "2006-01-02T15:04:05Z07:00"])

test_unlisted_role_old_password_is_expired if {
	not p.age_requirements_met with input as inp("developer", "Zk3!mQw9xLp2", old_rfc)
	p.password_expired with input as inp("developer", "Zk3!mQw9xLp2", old_rfc)
}

test_unlisted_role_recent_password_ok if {
	p.age_requirements_met with input as inp("developer", "Zk3!mQw9xLp2", recent)
}

test_iso_last_change_old_fails_age if {
	not p.age_requirements_met with input as inp("standard", "Zk3!mQw9xLp2", old_rfc)
}

test_iso_last_change_recent_passes_age if {
	p.age_requirements_met with input as inp("standard", "Zk3!mQw9xLp2", recent)
}

test_missing_last_change_fails_age if {
	i := json.remove(inp("standard", "Zk3!mQw9xLp2", recent), ["user/last_password_change"])
	not p.age_requirements_met with input as i
}

test_sequential_chars_detected if {
	p.contains_sequential_chars with input as inp("standard", "abcdefgh12345!Qz", recent)
	p.contains_forbidden_patterns with input as inp("standard", "xxQ!abc9Zk", recent)
}

test_no_sequence_in_clean_password if {
	not p.contains_sequential_chars with input as inp("standard", "Zk3!mQw9xLp2", recent)
}

test_repeated_chars_detected if {
	p.contains_repeated_chars with input as inp("standard", "aaaaXbcd1!Qz9mKp", recent)
	not p.contains_repeated_chars with input as inp("standard", "Zk3!mQw9xLp2", recent)
}

test_violations_reported_for_failing_password if {
	v := p.password_violations with input as inp("standard", "short", recent)
	count([x | some x in v; x.type == "length"]) == 1
	count([x | some x in v; x.type == "complexity"]) == 1
}

test_violations_defined_for_unknown_role if {
	v := p.password_violations with input as inp("developer", "short", recent)
	count([x | some x in v; x.type == "complexity"]) == 1
}

test_password_policy_score_defined_when_check_fails if {
	s := p.password_policy_score with input as inp("standard", "short", recent)
	s < 100
}

test_service_account_entropy_counts_characters if {
	p.service_account_entropy_met with input as inp("service_account", "Zk3!mQw9xLp2Zk3!mQw9xLp2", recent)
}

test_predictable_triple_repeat if {
	p.contains_predictable_patterns with input as inp("service_account", "Zk3!mQQQ9xLp2", recent)
}
