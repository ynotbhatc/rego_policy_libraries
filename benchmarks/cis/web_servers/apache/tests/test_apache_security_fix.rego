package cis.server.apache_test

import rego.v1

# Validation fix pass 2026-10-17.

test_tls12_tls13_only_is_secure if {
	data.cis.server.apache.insecure_ssl_protocols_disabled with input as {"apache_config": {"ssl_protocol": "TLSv1.2 TLSv1.3"}}
}

test_plus_minus_syntax if {
	data.cis.server.apache.insecure_ssl_protocols_disabled with input as {"apache_config": {"ssl_protocol": "-SSLv3 +TLSv1.2 +TLSv1.3"}}
}

test_legacy_protocols_flagged if {
	every p in ["TLSv1 TLSv1.2 TLSv1.3", "TLSv1.1 TLSv1.2 TLSv1.3", "all", "SSLv3 TLSv1.2 TLSv1.3", "TLSv1.2"] {
		not data.cis.server.apache.insecure_ssl_protocols_disabled with input as {"apache_config": {"ssl_protocol": p}}
	}
}

test_group_writable_detected_on_group_digit if {
	not data.cis.server.apache.apache_files_group_not_writable with input as {"apache_file_permissions": [{"owner": "root", "mode": "0664"}]}
	not data.cis.server.apache.apache_files_group_not_writable with input as {"apache_file_permissions": [{"owner": "root", "mode": "0720"}]}
}

test_group_not_writable_when_only_other_write_or_exec if {
	data.cis.server.apache.apache_files_group_not_writable with input as {"apache_file_permissions": [{"owner": "root", "mode": "0645"}]}
}

test_others_writable_ignores_execute_only if {
	data.cis.server.apache.apache_files_others_not_writable with input as {"apache_file_permissions": [{"owner": "root", "mode": "0751"}]}
	not data.cis.server.apache.apache_files_others_not_writable with input as {"apache_file_permissions": [{"owner": "root", "mode": "0752"}]}
}

test_empty_file_list_is_not_evidence if {
	not data.cis.server.apache.apache_files_owned_by_root with input as {"apache_file_permissions": []}
	not data.cis.server.apache.apache_files_group_not_writable with input as {"apache_file_permissions": []}
	not data.cis.server.apache.apache_files_others_not_writable with input as {"apache_file_permissions": []}
}

test_module_list_as_array if {
	not data.cis.server.apache.mod_dav_disabled with input as {"apache_modules": ["mod_dav", "mod_status"]}
	not data.cis.server.apache.mod_status_disabled with input as {"apache_modules": ["mod_dav", "mod_status"]}
	data.cis.server.apache.mod_info_disabled with input as {"apache_modules": ["mod_dav", "mod_status"]}
	data.cis.server.apache.mod_ssl_enabled with input as {"apache_modules": ["mod_ssl"]}
}

test_module_list_as_string if {
	not data.cis.server.apache.mod_status_disabled with input as {"apache_modules": "core_module\nstatus_module\nmod_status (shared)"}
	data.cis.server.apache.mod_info_disabled with input as {"apache_modules": "mod_ssl mod_status"}
}

test_absent_module_list_not_disabled_evidence if {
	not data.cis.server.apache.mod_dav_disabled with input as {}
}

test_log_mode_forms if {
	inp := {"apache_config": {"user": "apache", "error_log": "/l"}, "file_permissions": {"/l": {"owner": "apache", "mode": "640"}}}
	data.cis.server.apache.error_log_secured with input as inp
	inp2 := {"apache_config": {"user": "apache", "error_log": "/l"}, "file_permissions": {"/l": {"owner": "apache", "mode": "0644"}}}
	not data.cis.server.apache.error_log_secured with input as inp2
}

test_report_populated_on_empty_input if {
	r := data.cis.server.apache.apache_server_compliance with input as {}
	r.overall_compliant == false
	count(r) == 40
}
