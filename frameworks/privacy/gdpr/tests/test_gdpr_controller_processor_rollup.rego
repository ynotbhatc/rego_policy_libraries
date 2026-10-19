package gdpr.controller_processor_test

import rego.v1

# Controls other than `failing` are mocked true; `failing` is left unmocked and evaluated against empty input.
test_all_controls_true_is_compliant if {
	data.gdpr.controller_processor.compliant with input as {}
		with data.gdpr.controller_processor.controller_accountability as true
		with data.gdpr.controller_processor.joint_controller_arrangement as true
		with data.gdpr.controller_processor.data_protection_policies as true
		with data.gdpr.controller_processor.privacy_by_design_technical as true
		with data.gdpr.controller_processor.privacy_by_default as true
		with data.gdpr.controller_processor.processor_due_diligence as true
		with data.gdpr.controller_processor.processor_contract as true
		with data.gdpr.controller_processor.sub_processor_management as true
		with data.gdpr.controller_processor.controller_records as true
		with data.gdpr.controller_processor.processor_records as true
		with data.gdpr.controller_processor.security_of_processing as true
		with data.gdpr.controller_processor.supervisory_authority_cooperation as true
		with data.gdpr.controller_processor.processor_staff_obligations as true
}

test_supervisory_authority_failure_blocks_compliance if {
	not data.gdpr.controller_processor.compliant with input as {}
		with data.gdpr.controller_processor.controller_accountability as true
		with data.gdpr.controller_processor.joint_controller_arrangement as true
		with data.gdpr.controller_processor.data_protection_policies as true
		with data.gdpr.controller_processor.privacy_by_design_technical as true
		with data.gdpr.controller_processor.privacy_by_default as true
		with data.gdpr.controller_processor.processor_due_diligence as true
		with data.gdpr.controller_processor.processor_contract as true
		with data.gdpr.controller_processor.sub_processor_management as true
		with data.gdpr.controller_processor.controller_records as true
		with data.gdpr.controller_processor.processor_records as true
		with data.gdpr.controller_processor.security_of_processing as true
		with data.gdpr.controller_processor.processor_staff_obligations as true
}

test_processor_staff_obligations_failure_blocks_compliance if {
	not data.gdpr.controller_processor.compliant with input as {}
		with data.gdpr.controller_processor.controller_accountability as true
		with data.gdpr.controller_processor.joint_controller_arrangement as true
		with data.gdpr.controller_processor.data_protection_policies as true
		with data.gdpr.controller_processor.privacy_by_design_technical as true
		with data.gdpr.controller_processor.privacy_by_default as true
		with data.gdpr.controller_processor.processor_due_diligence as true
		with data.gdpr.controller_processor.processor_contract as true
		with data.gdpr.controller_processor.sub_processor_management as true
		with data.gdpr.controller_processor.controller_records as true
		with data.gdpr.controller_processor.processor_records as true
		with data.gdpr.controller_processor.security_of_processing as true
		with data.gdpr.controller_processor.supervisory_authority_cooperation as true
}

test_joint_controllers_absent_flag_does_not_pass if {
	not data.gdpr.controller_processor.joint_controller_arrangement with input as {"gdpr": {"joint_controllers": {}}}
}

test_joint_controllers_explicitly_not_applicable_passes if {
	data.gdpr.controller_processor.joint_controller_arrangement with input as {"gdpr": {"joint_controllers": {"arrangement_exists": false}}}
}

# decisions 2026-10-19: Art. 26 joint-controller arrangement gates compliance.
test_joint_controller_failure_blocks_compliance if {
	not data.gdpr.controller_processor.compliant with input as {}
		with data.gdpr.controller_processor.controller_accountability as true
		with data.gdpr.controller_processor.data_protection_policies as true
		with data.gdpr.controller_processor.privacy_by_design_technical as true
		with data.gdpr.controller_processor.privacy_by_default as true
		with data.gdpr.controller_processor.processor_due_diligence as true
		with data.gdpr.controller_processor.processor_contract as true
		with data.gdpr.controller_processor.sub_processor_management as true
		with data.gdpr.controller_processor.controller_records as true
		with data.gdpr.controller_processor.processor_records as true
		with data.gdpr.controller_processor.security_of_processing as true
		with data.gdpr.controller_processor.supervisory_authority_cooperation as true
		with data.gdpr.controller_processor.processor_staff_obligations as true
}

test_joint_controller_explicit_false_is_not_applicable if {
	data.gdpr.controller_processor.joint_controller_arrangement with input as {"gdpr": {"joint_controllers": {"arrangement_exists": false}}}
}

test_joint_controller_undeclared_fails_closed if {
	not data.gdpr.controller_processor.joint_controller_arrangement with input as {}
}
