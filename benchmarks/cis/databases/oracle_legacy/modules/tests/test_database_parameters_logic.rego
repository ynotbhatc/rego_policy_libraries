package cis_oracle.database_parameters_test

import rego.v1

# Validation fix 2026-10-17: a missing parameters section / key produced no violation.

good_params := {
	"AUDIT_SYS_OPERATIONS": "TRUE",
	"AUDIT_TRAIL": "DB",
	"GLOBAL_NAMES": "TRUE",
	"OS_ROLES": "FALSE",
	"REMOTE_LOGIN_PASSWORDFILE": "NONE",
	"REMOTE_OS_AUTHENT": "FALSE",
	"REMOTE_OS_ROLES": "FALSE",
	"SEC_CASE_SENSITIVE_LOGON": "TRUE",
	"SEC_RETURN_SERVER_RELEASE_BANNER": "FALSE",
	"SQL92_SECURITY": "TRUE",
	"O7_DICTIONARY_ACCESSIBILITY": "FALSE",
	"SEC_PROTOCOL_ERROR_FURTHER_ACTION": "DROP,3",
}

good_input := {
	"parameters": good_params,
	"oracle_version": {"major": 19},
	"unified_auditing": {"enabled": true},
	"network_encryption": {"enabled": true, "crypto_checksumming": "REQUIRED"},
}

test_missing_parameters_section_not_compliant if {
	inp := object.remove(good_input, ["parameters"])
	not data.cis_oracle.database_parameters.compliant with input as inp
}

test_missing_single_key_not_compliant if {
	inp := {"parameters": object.remove(good_params, ["GLOBAL_NAMES"]), "oracle_version": {"major": 19}, "unified_auditing": {"enabled": true}, "network_encryption": {"enabled": true, "crypto_checksumming": "REQUIRED"}}
	not data.cis_oracle.database_parameters.compliant with input as inp
}

test_missing_version_not_compliant if {
	inp := object.remove(good_input, ["oracle_version"])
	not data.cis_oracle.database_parameters.compliant with input as inp
}

test_good_input_compliant if {
	data.cis_oracle.database_parameters.compliant with input as good_input
}
