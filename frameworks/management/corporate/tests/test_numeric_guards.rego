package corporate.numeric_guards_test

import rego.v1

# null sorts below every number: a null session timeout passed `<= 480`.
test_null_session_timeout_not_enforced if {
	not data.corporate.access.control.mfa_policy_enforced with input as {"mfa_policy": {"enforcement_mode": "enforced", "bypass_allowed": false, "session_timeout_minutes": null}}
}

test_string_session_timeout_not_enforced if {
	not data.corporate.access.control.mfa_policy_enforced with input as {"mfa_policy": {"enforcement_mode": "enforced", "bypass_allowed": false, "session_timeout_minutes": "1"}}
}

test_text_session_timeout_not_enforced if {
	not data.corporate.access.control.mfa_policy_enforced with input as {"mfa_policy": {"enforcement_mode": "enforced", "bypass_allowed": false, "session_timeout_minutes": "x"}}
}

test_numeric_session_timeout_unchanged if {
	data.corporate.access.control.mfa_policy_enforced with input as {"mfa_policy": {"enforcement_mode": "enforced", "bypass_allowed": false, "session_timeout_minutes": 60}}
}

# "1" sorts above every number: a string SLA passed `>= 99.9`.
test_string_vendor_sla_not_compliant if {
	not data.corporate.backup.offsite_vendor_compliant with input as {"backup_vendors": [{"certifications": ["SOC 2"], "sla": {"availability": "1"}, "contract": {"data_residency_compliant": true}}]}
}

test_null_vendor_sla_not_compliant if {
	not data.corporate.backup.offsite_vendor_compliant with input as {"backup_vendors": [{"certifications": ["SOC 2"], "sla": {"availability": null}, "contract": {"data_residency_compliant": true}}]}
}

test_text_vendor_sla_not_compliant if {
	not data.corporate.backup.offsite_vendor_compliant with input as {"backup_vendors": [{"certifications": ["SOC 2"], "sla": {"availability": "x"}, "contract": {"data_residency_compliant": true}}]}
}

test_numeric_vendor_sla_unchanged if {
	data.corporate.backup.offsite_vendor_compliant with input as {"backup_vendors": [{"certifications": ["SOC 2"], "sla": {"availability": 99.99}, "contract": {"data_residency_compliant": true}}]}
}

# A string password length passed `>= 20`.
test_string_password_length_not_met if {
	not data.corporate.password.service_account_length_met with input as {"password": {"length": "1"}}
}

test_null_password_length_not_met if {
	not data.corporate.password.service_account_length_met with input as {"password": {"length": null}}
}

test_text_password_length_not_met if {
	not data.corporate.password.service_account_length_met with input as {"password": {"length": "x"}}
}

test_numeric_password_length_unchanged if {
	data.corporate.password.service_account_length_met with input as {"password": {"length": 24}}
}
