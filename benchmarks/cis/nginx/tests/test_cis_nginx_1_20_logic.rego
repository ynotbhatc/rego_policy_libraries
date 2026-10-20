package cis_nginx_1_20_test

import rego.v1

# Validation fix 2026-10-17 regression tests, re-pointed at the CIS NGINX Benchmark v3.1.0 rebuild (2026-10-20).
# The test names are kept; each body now exercises the v3.1.0 recommendation that covers the same concern.

pkg := data.cis_nginx_1_20

g := data.cis_nginx_1_20_test.green

_id_in(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

# Sparse facts must still report every section (missing evidence is a violation, never a pass).
test_undefined_conditions_still_report_violations if {
	v := pkg.violations with input as {"nginx": {"config": {"server_tokens": "on"}}}
	count(v) > 0
	"2.5.1: evidence missing — nginx.directives not collected" in v
	"1.1.1: evidence missing — nginx.version not collected" in v
}

test_not_compliant_with_server_tokens_on if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/directives/server_tokens", "value": ["on"]}])
	not pkg.compliant with input as inp
}

# 2.3.2 directory modes are octal, not decimal: 752 grants group and other bits beyond 750
test_binary_mode_752_fails if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/files/dir_modes", "value": {"/etc/nginx": 752}}])
	v := pkg.violations with input as inp
	_id_in(v, "2.3.2")
}

test_binary_mode_755_ok if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/files/dir_modes", "value": {"/etc/nginx": "0750"}}])
	v := pkg.violations with input as inp
	not _id_in(v, "2.3.2")
}

test_config_mode_664_fails if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/files/file_modes", "value": {"/etc/nginx/nginx.conf": 664}}])
	v := pkg.violations with input as inp
	_id_in(v, "2.3.2")
}

test_config_mode_640_ok if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/files/file_modes", "value": {"/etc/nginx/nginx.conf": 640}}])
	v := pkg.violations with input as inp
	not _id_in(v, "2.3.2")
}

# 2.3.3 PID file: 660 is group-writable, beyond 644
test_log_mode_660_fails if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/pid_file/mode", "value": 660}])
	v := pkg.violations with input as inp
	_id_in(v, "2.3.3")
}

# 3.1: nginx's built-in "combined" format is detailed enough
test_combined_format_ok if {
	inp := json.patch(g, [
		{"op": "remove", "path": "/nginx/directives/log_format"},
		{"op": "replace", "path": "/nginx/directives/access_log", "value": ["/var/log/nginx/access.log combined"]},
	])
	v := pkg.violations with input as inp
	not _id_in(v, "3.1")
}

# 5.2.2 any explicit client_max_body_size, including 1m, satisfies the recommendation
test_one_m_body_size_ok if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/directives/client_max_body_size", "value": ["1m"]}])
	v := pkg.violations with input as inp
	not _id_in(v, "5.2.2")
}

test_empty_protocols_fail_both if {
	inp := json.patch(g, [{"op": "replace", "path": "/nginx/directives/ssl_protocols", "value": []}])
	v := pkg.violations with input as inp
	_id_in(v, "4.1.4")
	_id_in(v, "4.1.5")
}

test_absent_protocols_fail_weak_check if {
	inp := json.patch(g, [{"op": "remove", "path": "/nginx/directives/ssl_protocols"}])
	v := pkg.violations with input as inp
	_id_in(v, "4.1.5")
}

test_good_protocols_ok if {
	v := pkg.violations with input as g
	not _id_in(v, "4.1.4")
	not _id_in(v, "4.1.5")
}

test_absent_methods_and_modules_fail if {
	inp := json.patch(g, [
		{"op": "remove", "path": "/nginx/directives/limit_except"},
		{"op": "remove", "path": "/nginx/attest/dynamic_modules_reviewed"},
	])
	v := pkg.violations with input as inp
	_id_in(v, "5.1.2")
	_id_in(v, "2.1.1")
}
