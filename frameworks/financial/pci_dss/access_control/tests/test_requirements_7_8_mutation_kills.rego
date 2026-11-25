# Mutation-killing tests for PCI DSS v4.0.1 Requirements 7 and 8 (#306). scripts/mutation_test.py found that
# deleting or inverting most conditions in requirement_7.rego / requirement_8.rego went unnoticed: no test
# started from a configuration that meets every sub-requirement and broke one element. Each test below does
# exactly that and expects the control that reads the element to fail and the requirement roll-up to be
# non-compliant. Requirement numbers are cited; PCI DSS text is not quoted.
package pci_dss_tests.access_control.mutation_kill_test
import rego.v1

_green := {"pci": {"access_control": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}, "accountability": {"established": true}}, "access_model": {"least_privilege": {"implemented": true}, "need_to_know": {"enforced": true}, "default_deny": {"configured": true}, "access_rules": {"documented": true}}, "rbac": {"enabled": true, "roles": {"defined": true, "cde_access": {"restricted": true}}, "privilege_assignment": {"approved": true}, "conflicting_duties": {"prevented": true}}, "access_assignment": {"job_functions": {"documented": true}, "access_required": {"justified": true}, "approval_required": true, "manager_approval": true}, "privileged_access": {"inventory": {"maintained": true}, "assignment": {"approved": true}, "separation_from_normal": {"enforced": true}, "just_in_time": {"available": true}, "monitoring": {"enabled": true}}, "third_party_access": {"inventory": {"maintained": true}, "need_to_know": {"enforced": true}, "time_limited": true, "mfa": {"required": true}, "monitoring": {"enabled": true}}, "access_review": {"performed": true, "all_accounts": {"included": true}, "results": {"documented": true}, "inappropriate_access": {"removed": true}, "frequency_months": 6}, "system_accounts": {"inventory": {"maintained": true}, "access": {"limited_to_functions_needed": true}, "interactive_login": {"disabled_unless_needed": true}, "review": {"annually": true, "performed_periodically": true}, "interactive_use": {"prohibited_unless_exceptional": true}, "authentication": {"managed": true}, "credentials": {"in_vault": true, "rotation": {"automated": true}}}, "acs": {"implemented": true, "all_cde_system_components": {"covered": true}, "default_deny": {"configured": true}, "settings": {"restriction_unless_specifically_allowed": true}}, "authentication": {"policies": {"documented": true, "approved": true, "current": true}, "roles": {"defined": true}, "responsibilities": {"assigned": true}}, "user_ids": {"shared_accounts": {"prohibited": true}, "generic_accounts": {"prohibited_in_cde": true}, "group_accounts": {"prohibited": true}, "unique_per_user": true}, "account_lifecycle": {"provisioning": {"approval_required": true}, "modification": {"approval_required": true}, "termination": {"immediate_revocation": true}, "inactive_accounts": {"disabled_after_90_days": true}}, "vendor_accounts": {"disabled_when_not_in_use": true, "monitored_when_active": true, "time_limited": true}, "sessions": {"reauthentication_required": true, "idle_timeout_minutes": 15}, "passwords": {"numeric_and_alpha": {"required": true}, "first_use": {"change_required": true}, "reset": {"immediate_change_required": true}, "temporary": {"single_use": true}, "minimum_length": 12, "history": {"count": 4}, "lockout": {"after_attempts": 10, "duration_minutes": 30}, "single_factor_only": true, "max_age_days": 90, "customer_accounts": {"single_factor_only": true, "max_age_days": 90}}, "auth_factors": {"stored": {"encrypted": true}, "transmission": {"encrypted": true}, "service_providers": {"different_from_customers": true}}, "mfa": {"cde_admin_access": {"required": true}, "non_console_admin": {"required": true}, "factors": {"at_least_two": true, "different_categories": true, "cannot_be_same_type": true}, "remote_access": {"required": true}, "all_cde_access": {"required": true}, "user_cde_access": {"enforced": true}, "replay_attacks": {"prevented": true}, "bypass": {"not_possible_by_any_single_admin": true}, "all_factors_required": true, "vpn": {"mfa_enforced": true}, "remote_desktop": {"mfa_enforced": true}}, "entity": {"service_provider": true}}}

test_green_configuration_meets_requirement_7 if {
	data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as _green
	data.pci_dss.access_control.requirement_7.pci_requirement_7_score == 100 with input as _green
}

test_green_configuration_meets_requirement_8 if {
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as _green
	data.pci_dss.access_control.requirement_8.pci_requirement_8_score == 100 with input as _green
}

test_r7_access_control_policies_established_access_control_policies_documented_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"policies": {"documented": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_policies_established with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_policies_established_access_control_policies_approved_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"policies": {"approved": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_policies_established with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_policies_established_access_control_policies_current_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"policies": {"current": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_policies_established with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_roles_defined_access_control_roles_defined_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"roles": {"defined": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_roles_defined with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_roles_defined_access_control_responsibilities_assigned_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"responsibilities": {"assigned": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_roles_defined with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_roles_defined_access_control_accountability_established_false_fails if {
	fx := object.union(_green, {"pci": {"access_control": {"accountability": {"established": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_roles_defined with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_least_privilege_access_model_access_model_least_privilege_implemented_false_fails if {
	fx := object.union(_green, {"pci": {"access_model": {"least_privilege": {"implemented": false}}}})
	not data.pci_dss.access_control.requirement_7.least_privilege_access_model with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_least_privilege_access_model_access_model_need_to_know_enforced_false_fails if {
	fx := object.union(_green, {"pci": {"access_model": {"need_to_know": {"enforced": false}}}})
	not data.pci_dss.access_control.requirement_7.least_privilege_access_model with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_least_privilege_access_model_access_model_default_deny_configured_false_fails if {
	fx := object.union(_green, {"pci": {"access_model": {"default_deny": {"configured": false}}}})
	not data.pci_dss.access_control.requirement_7.least_privilege_access_model with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_least_privilege_access_model_access_model_access_rules_documented_false_fails if {
	fx := object.union(_green, {"pci": {"access_model": {"access_rules": {"documented": false}}}})
	not data.pci_dss.access_control.requirement_7.least_privilege_access_model with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_rbac_implemented_rbac_enabled_false_fails if {
	fx := object.union(_green, {"pci": {"rbac": {"enabled": false}}})
	not data.pci_dss.access_control.requirement_7.rbac_implemented with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_rbac_implemented_rbac_roles_defined_false_fails if {
	fx := object.union(_green, {"pci": {"rbac": {"roles": {"defined": false}}}})
	not data.pci_dss.access_control.requirement_7.rbac_implemented with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_rbac_implemented_rbac_roles_cde_access_restricted_false_fails if {
	fx := object.union(_green, {"pci": {"rbac": {"roles": {"cde_access": {"restricted": false}}}}})
	not data.pci_dss.access_control.requirement_7.rbac_implemented with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_rbac_implemented_rbac_privilege_assignment_approved_false_fails if {
	fx := object.union(_green, {"pci": {"rbac": {"privilege_assignment": {"approved": false}}}})
	not data.pci_dss.access_control.requirement_7.rbac_implemented with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_rbac_implemented_rbac_conflicting_duties_prevented_false_fails if {
	fx := object.union(_green, {"pci": {"rbac": {"conflicting_duties": {"prevented": false}}}})
	not data.pci_dss.access_control.requirement_7.rbac_implemented with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_job_function_based_access_access_assignment_job_functions_documented_false_fails if {
	fx := object.union(_green, {"pci": {"access_assignment": {"job_functions": {"documented": false}}}})
	not data.pci_dss.access_control.requirement_7.job_function_based_access with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_job_function_based_access_access_assignment_access_required_justified_false_fails if {
	fx := object.union(_green, {"pci": {"access_assignment": {"access_required": {"justified": false}}}})
	not data.pci_dss.access_control.requirement_7.job_function_based_access with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_job_function_based_access_access_assignment_approval_required_false_fails if {
	fx := object.union(_green, {"pci": {"access_assignment": {"approval_required": false}}})
	not data.pci_dss.access_control.requirement_7.job_function_based_access with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_job_function_based_access_access_assignment_manager_approval_false_fails if {
	fx := object.union(_green, {"pci": {"access_assignment": {"manager_approval": false}}})
	not data.pci_dss.access_control.requirement_7.job_function_based_access with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_privileged_access_managed_privileged_access_inventory_maintained_false_fails if {
	fx := object.union(_green, {"pci": {"privileged_access": {"inventory": {"maintained": false}}}})
	not data.pci_dss.access_control.requirement_7.privileged_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_privileged_access_managed_privileged_access_assignment_approved_false_fails if {
	fx := object.union(_green, {"pci": {"privileged_access": {"assignment": {"approved": false}}}})
	not data.pci_dss.access_control.requirement_7.privileged_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_privileged_access_managed_privileged_access_separation_from_normal_enforced_false_fails if {
	fx := object.union(_green, {"pci": {"privileged_access": {"separation_from_normal": {"enforced": false}}}})
	not data.pci_dss.access_control.requirement_7.privileged_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_privileged_access_managed_privileged_access_just_in_time_available_false_fails if {
	fx := object.union(_green, {"pci": {"privileged_access": {"just_in_time": {"available": false}}}})
	not data.pci_dss.access_control.requirement_7.privileged_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_privileged_access_managed_privileged_access_monitoring_enabled_false_fails if {
	fx := object.union(_green, {"pci": {"privileged_access": {"monitoring": {"enabled": false}}}})
	not data.pci_dss.access_control.requirement_7.privileged_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_third_party_access_managed_third_party_access_inventory_maintained_false_fails if {
	fx := object.union(_green, {"pci": {"third_party_access": {"inventory": {"maintained": false}}}})
	not data.pci_dss.access_control.requirement_7.third_party_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_third_party_access_managed_third_party_access_need_to_know_enforced_false_fails if {
	fx := object.union(_green, {"pci": {"third_party_access": {"need_to_know": {"enforced": false}}}})
	not data.pci_dss.access_control.requirement_7.third_party_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_third_party_access_managed_third_party_access_time_limited_false_fails if {
	fx := object.union(_green, {"pci": {"third_party_access": {"time_limited": false}}})
	not data.pci_dss.access_control.requirement_7.third_party_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_third_party_access_managed_third_party_access_mfa_required_false_fails if {
	fx := object.union(_green, {"pci": {"third_party_access": {"mfa": {"required": false}}}})
	not data.pci_dss.access_control.requirement_7.third_party_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_third_party_access_managed_third_party_access_monitoring_enabled_false_fails if {
	fx := object.union(_green, {"pci": {"third_party_access": {"monitoring": {"enabled": false}}}})
	not data.pci_dss.access_control.requirement_7.third_party_access_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_user_access_reviews_access_review_performed_false_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"performed": false}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_user_access_reviews_access_review_all_accounts_included_false_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"all_accounts": {"included": false}}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_user_access_reviews_access_review_results_documented_false_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"results": {"documented": false}}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_user_access_reviews_access_review_inappropriate_access_removed_false_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"inappropriate_access": {"removed": false}}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_application_system_accounts_managed_system_accounts_inventory_maintained_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"inventory": {"maintained": false}}}})
	not data.pci_dss.access_control.requirement_7.application_system_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_application_system_accounts_managed_system_accounts_access_limited_to_functions_needed_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"access": {"limited_to_functions_needed": false}}}})
	not data.pci_dss.access_control.requirement_7.application_system_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_application_system_accounts_managed_system_accounts_interactive_login_disabled_unless_needed_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"interactive_login": {"disabled_unless_needed": false}}}})
	not data.pci_dss.access_control.requirement_7.application_system_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_application_system_accounts_managed_system_accounts_review_annually_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"review": {"annually": false}}}})
	not data.pci_dss.access_control.requirement_7.application_system_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_system_acs_implemented_false_fails if {
	fx := object.union(_green, {"pci": {"acs": {"implemented": false}}})
	not data.pci_dss.access_control.requirement_7.access_control_system with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_system_acs_all_cde_system_components_covered_false_fails if {
	fx := object.union(_green, {"pci": {"acs": {"all_cde_system_components": {"covered": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_system with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_system_acs_default_deny_configured_false_fails if {
	fx := object.union(_green, {"pci": {"acs": {"default_deny": {"configured": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_system with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_access_control_system_acs_settings_restriction_unless_specifically_allowed_false_fails if {
	fx := object.union(_green, {"pci": {"acs": {"settings": {"restriction_unless_specifically_allowed": false}}}})
	not data.pci_dss.access_control.requirement_7.access_control_system with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r8_authentication_policies_established_authentication_policies_documented_false_fails if {
	fx := object.union(_green, {"pci": {"authentication": {"policies": {"documented": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_policies_established with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_policies_established_authentication_policies_approved_false_fails if {
	fx := object.union(_green, {"pci": {"authentication": {"policies": {"approved": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_policies_established with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_policies_established_authentication_policies_current_false_fails if {
	fx := object.union(_green, {"pci": {"authentication": {"policies": {"current": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_policies_established with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_roles_defined_authentication_roles_defined_false_fails if {
	fx := object.union(_green, {"pci": {"authentication": {"roles": {"defined": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_roles_defined with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_roles_defined_authentication_responsibilities_assigned_false_fails if {
	fx := object.union(_green, {"pci": {"authentication": {"responsibilities": {"assigned": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_roles_defined with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8__shared_generic_group_ok_user_ids_shared_accounts_prohibited_false_fails if {
	fx := object.union(_green, {"pci": {"user_ids": {"shared_accounts": {"prohibited": false}}}})
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8__shared_generic_group_ok_user_ids_generic_accounts_prohibited_in_cde_false_fails if {
	fx := object.union(_green, {"pci": {"user_ids": {"generic_accounts": {"prohibited_in_cde": false}}}})
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8__shared_generic_group_ok_user_ids_group_accounts_prohibited_false_fails if {
	fx := object.union(_green, {"pci": {"user_ids": {"group_accounts": {"prohibited": false}}}})
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_unique_user_ids_user_ids_unique_per_user_false_fails if {
	fx := object.union(_green, {"pci": {"user_ids": {"unique_per_user": false}}})
	not data.pci_dss.access_control.requirement_8.unique_user_ids with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_account_lifecycle_managed_account_lifecycle_provisioning_approval_required_false_fails if {
	fx := object.union(_green, {"pci": {"account_lifecycle": {"provisioning": {"approval_required": false}}}})
	not data.pci_dss.access_control.requirement_8.account_lifecycle_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_account_lifecycle_managed_account_lifecycle_modification_approval_required_false_fails if {
	fx := object.union(_green, {"pci": {"account_lifecycle": {"modification": {"approval_required": false}}}})
	not data.pci_dss.access_control.requirement_8.account_lifecycle_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_account_lifecycle_managed_account_lifecycle_termination_immediate_revocation_false_fails if {
	fx := object.union(_green, {"pci": {"account_lifecycle": {"termination": {"immediate_revocation": false}}}})
	not data.pci_dss.access_control.requirement_8.account_lifecycle_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_account_lifecycle_managed_account_lifecycle_inactive_accounts_disabled_after_90_days_false_fails if {
	fx := object.union(_green, {"pci": {"account_lifecycle": {"inactive_accounts": {"disabled_after_90_days": false}}}})
	not data.pci_dss.access_control.requirement_8.account_lifecycle_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_vendor_accounts_managed_vendor_accounts_disabled_when_not_in_use_false_fails if {
	fx := object.union(_green, {"pci": {"vendor_accounts": {"disabled_when_not_in_use": false}}})
	not data.pci_dss.access_control.requirement_8.vendor_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_vendor_accounts_managed_vendor_accounts_monitored_when_active_false_fails if {
	fx := object.union(_green, {"pci": {"vendor_accounts": {"monitored_when_active": false}}})
	not data.pci_dss.access_control.requirement_8.vendor_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_vendor_accounts_managed_vendor_accounts_time_limited_false_fails if {
	fx := object.union(_green, {"pci": {"vendor_accounts": {"time_limited": false}}})
	not data.pci_dss.access_control.requirement_8.vendor_accounts_managed with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_idle_session_reauthentication_sessions_reauthentication_required_false_fails if {
	fx := object.union(_green, {"pci": {"sessions": {"reauthentication_required": false}}})
	not data.pci_dss.access_control.requirement_8.idle_session_reauthentication with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_passwords_numeric_and_alpha_required_false_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"numeric_and_alpha": {"required": false}}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_first_use_password_change_passwords_first_use_change_required_false_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"first_use": {"change_required": false}}}})
	not data.pci_dss.access_control.requirement_8.first_use_password_change with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_first_use_password_change_passwords_reset_immediate_change_required_false_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"reset": {"immediate_change_required": false}}}})
	not data.pci_dss.access_control.requirement_8.first_use_password_change with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_first_use_password_change_passwords_temporary_single_use_false_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"temporary": {"single_use": false}}}})
	not data.pci_dss.access_control.requirement_8.first_use_password_change with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_factors_protected_auth_factors_stored_encrypted_false_fails if {
	fx := object.union(_green, {"pci": {"auth_factors": {"stored": {"encrypted": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_factors_protected with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_factors_protected_auth_factors_transmission_encrypted_false_fails if {
	fx := object.union(_green, {"pci": {"auth_factors": {"transmission": {"encrypted": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_factors_protected with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_cde_admin_mfa_cde_admin_access_required_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"cde_admin_access": {"required": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_cde_admin with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_cde_admin_mfa_non_console_admin_required_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"non_console_admin": {"required": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_cde_admin with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_cde_admin_mfa_factors_at_least_two_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"factors": {"at_least_two": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_cde_admin with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_cde_admin_mfa_factors_different_categories_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"factors": {"different_categories": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_cde_admin with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_remote_access_mfa_remote_access_required_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"remote_access": {"required": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_remote_access with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_all_cde_access_mfa_all_cde_access_required_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"all_cde_access": {"required": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_all_cde_access with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_all_cde_access_mfa_user_cde_access_enforced_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"user_cde_access": {"enforced": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_all_cde_access with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_system_secure_mfa_replay_attacks_prevented_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"replay_attacks": {"prevented": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_system_secure with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_system_secure_mfa_bypass_not_possible_by_any_single_admin_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"bypass": {"not_possible_by_any_single_admin": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_system_secure with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_system_secure_mfa_factors_cannot_be_same_type_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"factors": {"cannot_be_same_type": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_system_secure with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_not_susceptible_to_replay_mfa_replay_attacks_prevented_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"replay_attacks": {"prevented": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_not_susceptible_to_replay with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_not_susceptible_to_replay_mfa_all_factors_required_false_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"all_factors_required": false}}})
	not data.pci_dss.access_control.requirement_8.mfa_not_susceptible_to_replay with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_system_application_accounts_system_accounts_interactive_use_prohibited_unless_exceptional_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"interactive_use": {"prohibited_unless_exceptional": false}}}})
	not data.pci_dss.access_control.requirement_8.system_application_accounts with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_system_application_accounts_system_accounts_authentication_managed_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"authentication": {"managed": false}}}})
	not data.pci_dss.access_control.requirement_8.system_application_accounts with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_system_application_accounts_system_accounts_review_performed_periodically_false_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"review": {"performed_periodically": false}}}})
	not data.pci_dss.access_control.requirement_8.system_application_accounts with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r7_user_access_reviews_review_every_7_months_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"frequency_months": 7}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r7_user_access_reviews_review_frequency_as_string_fails if {
	fx := object.union(_green, {"pci": {"access_review": {"frequency_months": "6"}}})
	not data.pci_dss.access_control.requirement_7.user_access_reviews with input as fx
	not data.pci_dss.access_control.requirement_7.pci_requirement_7_compliant with input as fx
}

test_r8_idle_session_reauthentication_idle_16_minutes_fails if {
	fx := object.union(_green, {"pci": {"sessions": {"idle_timeout_minutes": 16}}})
	not data.pci_dss.access_control.requirement_8.idle_session_reauthentication with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_idle_session_reauthentication_idle_0_minutes_fails if {
	fx := object.union(_green, {"pci": {"sessions": {"idle_timeout_minutes": 0}}})
	not data.pci_dss.access_control.requirement_8.idle_session_reauthentication with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_idle_session_reauthentication_idle_1_minute_passes if {
	fx := object.union(_green, {"pci": {"sessions": {"idle_timeout_minutes": 1}}})
	data.pci_dss.access_control.requirement_8.idle_session_reauthentication with input as fx
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_length_11_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"minimum_length": 11}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_history_3_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"history": {"count": 3}}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_lockout_after_11_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"lockout": {"after_attempts": 11}}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_lockout_after_0_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"lockout": {"after_attempts": 0}}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_lockout_after_1_passes if {
	fx := object.union(_green, {"pci": {"passwords": {"lockout": {"after_attempts": 1}}}})
	data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_password_requirements_lockout_29_minutes_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"lockout": {"duration_minutes": 29}}}})
	not data.pci_dss.access_control.requirement_8.password_requirements with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_single_factor_password_lifetime_single_factor_91_days_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"max_age_days": 91}}})
	not data.pci_dss.access_control.requirement_8.single_factor_password_lifetime with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_single_factor_password_lifetime_single_factor_0_days_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"max_age_days": 0}}})
	not data.pci_dss.access_control.requirement_8.single_factor_password_lifetime with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_single_factor_password_lifetime_single_factor_1_day_passes if {
	fx := object.union(_green, {"pci": {"passwords": {"max_age_days": 1}}})
	data.pci_dss.access_control.requirement_8.single_factor_password_lifetime with input as fx
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_single_factor_password_lifetime_mfa_everywhere_no_rotation_passes if {
	fx := object.union(_green, {"pci": {"passwords": {"single_factor_only": false}}})
	data.pci_dss.access_control.requirement_8.single_factor_password_lifetime with input as fx
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_service_provider_customer_password_lifetime_customer_91_days_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"customer_accounts": {"max_age_days": 91}}}})
	not data.pci_dss.access_control.requirement_8.service_provider_customer_password_lifetime with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_service_provider_customer_password_lifetime_customer_0_days_fails if {
	fx := object.union(_green, {"pci": {"passwords": {"customer_accounts": {"max_age_days": 0}}}})
	not data.pci_dss.access_control.requirement_8.service_provider_customer_password_lifetime with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_service_provider_customer_password_lifetime_customer_mfa_no_rotation_passes if {
	fx := object.union(_green, {"pci": {"passwords": {"customer_accounts": {"single_factor_only": false}}}})
	data.pci_dss.access_control.requirement_8.service_provider_customer_password_lifetime with input as fx
	data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_authentication_factors_protected_service_provider_shared_factors_fails if {
	fx := object.union(_green, {"pci": {"auth_factors": {"service_providers": {"different_from_customers": false}}}})
	not data.pci_dss.access_control.requirement_8.authentication_factors_protected with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_system_application_accounts_credentials_not_in_vault_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"credentials": {"in_vault": false}}}})
	not data.pci_dss.access_control.requirement_8.system_application_accounts with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_system_application_accounts_credentials_not_rotated_fails if {
	fx := object.union(_green, {"pci": {"system_accounts": {"credentials": {"rotation": {"automated": false}}}}})
	not data.pci_dss.access_control.requirement_8.system_application_accounts with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_remote_access_vpn_without_mfa_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"vpn": {"mfa_enforced": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_remote_access with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}

test_r8_mfa_for_remote_access_rdp_without_mfa_fails if {
	fx := object.union(_green, {"pci": {"mfa": {"remote_desktop": {"mfa_enforced": false}}}})
	not data.pci_dss.access_control.requirement_8.mfa_for_remote_access with input as fx
	not data.pci_dss.access_control.requirement_8.pci_requirement_8_compliant with input as fx
}
