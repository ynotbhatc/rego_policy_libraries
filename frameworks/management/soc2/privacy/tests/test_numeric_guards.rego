package soc2.privacy.data_privacy_numeric_guards_test

import rego.v1

# null sorts below every number: a null response timeline passed `<= 30`.
test_string_data_subject_request_handling_is_false if {
	not data.soc2.privacy.data_privacy.data_subject_request_handling with input as {"privacy": {"data_subject_requests": {"automated_workflow": true, "identity_verification": true, "response_timeline": "1", "request_logging": true}}}
}

test_null_data_subject_request_handling_is_false if {
	not data.soc2.privacy.data_privacy.data_subject_request_handling with input as {"privacy": {"data_subject_requests": {"automated_workflow": true, "identity_verification": true, "response_timeline": null, "request_logging": true}}}
}

test_text_data_subject_request_handling_is_false if {
	not data.soc2.privacy.data_privacy.data_subject_request_handling with input as {"privacy": {"data_subject_requests": {"automated_workflow": true, "identity_verification": true, "response_timeline": "x", "request_logging": true}}}
}

test_numeric_data_subject_request_handling_unchanged if {
	data.soc2.privacy.data_privacy.data_subject_request_handling with input as {"privacy": {"data_subject_requests": {"automated_workflow": true, "identity_verification": true, "response_timeline": 20, "request_logging": true}}}
}
