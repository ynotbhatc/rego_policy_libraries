package stig.postgresql_16_test

import rego.v1
import data.stig.postgresql_16

test_report_wellformed_on_empty_input if {
	report := postgresql_16.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "pg": {
	  "org_level_auth_integrated": true,
	  "authorizations_enforced": true,
	  "install_account_restricted": true,
	  "pki_keys_access_enforced": true,
	  "fips_modules_in_use": true,
	  "data_at_rest_protected": true,
	  "nsa_crypto_for_classified": true,
	  "crypto_integrity_mechanisms": true,
	  "vendor_supported_version": true,
	  "audit_successful_object_access": true,
	  "audit_unsuccessful_object_access": true
	 },
	 "pg_settings": {
	  "password_encryption": "scram-sha-256",
	  "ssl": "on"
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := postgresql_16.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.postgresql_16.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}
