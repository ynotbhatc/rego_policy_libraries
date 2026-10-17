package cis_nginx_1_20_test

import rego.v1

# Validation fix 2026-10-17: undefined condition rules dropped whole sections of violations;
# octal modes compared as decimal; combined log format / 1m body size flagged; empty protocols passed.

pkg := data.cis_nginx_1_20

test_undefined_conditions_still_report_violations if {
	v := pkg.violations with input as {"nginx": {"config": {"server_tokens": "on"}}}
	count(v) > 0
	"2.1.1 Ensure server_tokens directive is set to off" in v
	"1.1.1 Ensure NGINX is installed with minimal required modules" in v
}

test_not_compliant_with_server_tokens_on if {
	not pkg.compliant with input as {"nginx": {"config": {"server_tokens": "on"}}}
}

test_binary_mode_752_fails if {
	not pkg.nginx_binary_permissions with input as {"nginx": {"binary": {"permissions": 752, "owner": "root"}}}
}

test_binary_mode_755_ok if {
	pkg.nginx_binary_permissions with input as {"nginx": {"binary": {"permissions": "0755", "owner": "root"}}}
}

test_config_mode_664_fails if {
	not pkg.nginx_config_permissions with input as {"nginx": {"config": {"permissions": 664}}}
}

test_config_mode_640_ok if {
	pkg.nginx_config_permissions with input as {"nginx": {"config": {"permissions": 640}}}
}

test_log_mode_660_fails if {
	not pkg.log_file_permissions with input as {"nginx": {"logging": {"log_permissions": 660}}}
}

test_combined_format_ok if {
	pkg.access_log_format_configured with input as {"nginx": {"logging": {"access_log_format": "combined"}}}
}

test_one_m_body_size_ok if {
	pkg.client_max_body_size_configured with input as {"nginx": {"config": {"client_max_body_size": "1m"}}}
}

test_empty_protocols_fail_both if {
	not pkg.strong_ssl_protocols with input as {"nginx": {"ssl": {"protocols": []}}}
	not pkg.weak_protocols_disabled with input as {"nginx": {"ssl": {"protocols": []}}}
}

test_absent_protocols_fail_weak_check if {
	not pkg.weak_protocols_disabled with input as {"nginx": {"ssl": {}}}
}

test_good_protocols_ok if {
	pkg.strong_ssl_protocols with input as {"nginx": {"ssl": {"protocols": ["TLSv1.2", "TLSv1.3"]}}}
	pkg.weak_protocols_disabled with input as {"nginx": {"ssl": {"protocols": ["TLSv1.2", "TLSv1.3"]}}}
}

test_absent_methods_and_modules_fail if {
	not pkg.dangerous_methods_disabled with input as {"nginx": {"config": {}}}
	not pkg.trace_method_disabled with input as {"nginx": {"config": {}}}
	not pkg.dangerous_modules_disabled with input as {"nginx": {"modules": {}}}
}
