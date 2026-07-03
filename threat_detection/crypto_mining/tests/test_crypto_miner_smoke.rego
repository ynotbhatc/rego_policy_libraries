# Phase 1 contract smoke test — Crypto Miner Detection aggregate assessment.
# Contract: data.security.crypto_miner_detection.compliance_assessment must
# return a well-formed, non-empty object on empty input (never undefined -> {}).
package security.crypto_miner_detection_test

import rego.v1

import data.security.crypto_miner_detection

test_report_wellformed_on_empty_input if {
	result := crypto_miner_detection.compliance_assessment with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
