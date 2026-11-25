package corporate.missing_row_fields_test

import rego.v1

# A user without roles, a role without a name, a manager without a status and an environment without a config
# used to drop out of their checks (`count(user.roles)`, `role.name`, `manager.status`, `input.environments[env]`
# are undefined when the field is missing).

ac := data.corporate.access.control

test_active_user_without_roles_field_has_no_roles if {
	not ac.all_users_have_roles with input as {"users": [{"status": "active"}]}
	ac.all_users_have_roles with input as {"users": [{"status": "active", "roles": [{"name": "r"}]}]}
}

test_manager_without_status_makes_an_orphan if {
	data.corporate.access.control.account_is_orphaned({"manager_id": "m"}) with input as {"users": {"m": {"name": "boss"}}}
	not data.corporate.access.control.account_is_orphaned({"manager_id": "m"}) with input as {"users": {"m": {"status": "active"}}}
}

test_role_without_name_is_inappropriate if {
	data.corporate.access.control.excessive_permissions({"job_function": "engineer", "roles": [{"permissions": []}]})
}

test_environment_without_a_config_has_a_monitoring_violation if {
	v := data.corporate.environment.controls.monitoring_violations with input as {"environments": {"development": {}}}
	count(v) > 0
	v2 := data.corporate.environment.controls.monitoring_violations with input as {}
	count(v2) > 0
}
