package cis_nginx_1_20_test

import rego.v1

import data.cis_nginx_1_20 as b

# Generated per-recommendation tests for CIS NGINX Benchmark v3.1.0: every recommendation has a pass test (green input) and a
# fail test; configuration checks also have an evidence-missing test; attestations fail when false or absent.

green := {
	"nginx": {
		"profiles": [
			"webserver",
			"proxy",
			"loadbalancer"
		],
		"version": "1.28.0",
		"package": {
			"update_available": false
		},
		"user": {
			"name": "nginx",
			"uid": 988,
			"groups": [
				"nginx"
			],
			"sudo_allowed": false,
			"password_locked": true,
			"shell": "/sbin/nologin"
		},
		"files": {
			"not_root_owned": [],
			"dir_modes": {
				"/etc/nginx": "750",
				"/etc/nginx/conf.d": "750"
			},
			"file_modes": {
				"/etc/nginx/nginx.conf": "640",
				"/etc/nginx/conf.d/app.conf": "600"
			}
		},
		"pid_file": {
			"owner": "root",
			"group": "root",
			"mode": "644"
		},
		"listen_ports": [
			80,
			443
		],
		"default_server": {
			"present": true,
			"return_code": 444,
			"ssl_reject_handshake": true
		},
		"probe": {
			"error_page_mentions_nginx": false
		},
		"hidden_files_denied": true,
		"access_log_off_outside_location": false,
		"servers": [
			{
				"name": "app",
				"ssl": true
			},
			{
				"name": "redirect",
				"ssl": false,
				"redirects_to_https": true
			}
		],
		"certificates": [
			{
				"path": "/etc/nginx/ssl/site.crt",
				"chain_trusted": true
			}
		],
		"private_keys": {
			"/etc/nginx/ssl/site.key": "400"
		},
		"directives": {
			"keepalive_timeout": [
				"10"
			],
			"send_timeout": [
				"10s"
			],
			"server_tokens": [
				"off"
			],
			"proxy_hide_header": [
				"X-Powered-By",
				"Server"
			],
			"log_format": [
				"main_json escape=json '{\"time\":\"$time_iso8601\",\"remote_addr\":\"$remote_addr\",\"remote_user\":\"$remote_user\",\"request\":\"$request\",\"status\":\"$status\",\"user_agent\":\"$http_user_agent\"}'"
			],
			"access_log": [
				"/var/log/nginx/access.json main_json"
			],
			"error_log": [
				"/var/log/nginx/error.log info"
			],
			"ssl_protocols": [
				"TLSv1.3"
			],
			"proxy_ssl_protocols": [
				"TLSv1.3"
			],
			"ssl_stapling": [
				"on"
			],
			"ssl_stapling_verify": [
				"on"
			],
			"ssl_trusted_certificate": [
				"/etc/nginx/ssl/chain.pem"
			],
			"resolver": [
				"10.0.0.53"
			],
			"add_header": [
				"Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always",
				"X-Content-Type-Options \"nosniff\" always",
				"Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always",
				"Referrer-Policy \"strict-origin-when-cross-origin\" always",
				"Alt-Svc 'h3=\":443\"; ma=86400'"
			],
			"proxy_ssl_certificate": [
				"/etc/nginx/ssl/client.crt"
			],
			"proxy_ssl_certificate_key": [
				"/etc/nginx/ssl/client.key"
			],
			"proxy_ssl_verify": [
				"on"
			],
			"proxy_ssl_trusted_certificate": [
				"/etc/nginx/ssl/upstream-ca.crt"
			],
			"proxy_ssl_name": [
				"backend.internal"
			],
			"http2": [
				"on"
			],
			"listen": [
				"80",
				"443 ssl",
				"443 quic reuseport"
			],
			"limit_except": [
				"GET HEAD POST"
			],
			"proxy_set_header": [
				"X-Forwarded-For $proxy_add_x_forwarded_for",
				"X-Real-IP $remote_addr"
			],
			"client_header_timeout": [
				"10"
			],
			"client_body_timeout": [
				"10"
			],
			"client_max_body_size": [
				"1m"
			]
		},
		"attest": {
			"package_repositories_reviewed": true,
			"dynamic_modules_reviewed": true,
			"ip_allow_deny_reviewed": true,
			"connection_limits_reviewed": true,
			"rate_limits_reviewed": true
		}
	}
}

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

test_green_input_is_compliant if {
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 44
	count([id | some id, r in b.recommendations; r.level == 2]) == 7
}

test_report_shape_on_empty_input if {
	r := b.compliance_report with input as {}
	r.total_controls == 44
	r.compliant == false
	r.failed_controls == 44
	r.passed_controls == 0
	f := b.findings with input as {}
	count(f) == 1
	count(f[0].violations) > 0
}

test_webserver_profile_skips_proxy_only if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/profiles", "value": ["webserver"]}, {"op": "remove", "path": "/nginx/directives/proxy_ssl_certificate"}])
	vs := b.violations with input as inp
	not _has_id(vs, "4.1.9")
	r := b.compliance_report with input as inp
	r.applicable_controls == 40
}

test_proxy_profile_skips_webserver_only if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/profiles", "value": ["proxy"]}, {"op": "remove", "path": "/nginx/directives/http2"}])
	vs := b.violations with input as inp
	not _has_id(vs, "4.1.12")
}

test_unknown_profile_falls_back_to_all if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/profiles", "value": ["web"]}, {"op": "remove", "path": "/nginx/directives/http2"}])
	vs := b.violations with input as inp
	_has_id(vs, "4.1.12")
	not b.compliant with input as inp
	c := b.compliant with input as {"nginx": {"profiles": ["web"]}}
	c == false
}

test_absent_profiles_means_all if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/profiles"}, {"op": "remove", "path": "/nginx/directives/http2"}])
	vs := b.violations with input as inp
	_has_id(vs, "4.1.12")
}

test_5_2_3_documented_deviation_passes if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/large_client_header_buffers", "value": ["2 1k"]}])
	vs := b.violations with input as inp
	_has_id(vs, "5.2.3")
	inp2 := json.patch(inp, [{"op": "add", "path": "/nginx/attest/large_client_header_buffers_documented", "value": true}])
	vs2 := b.violations with input as inp2
	not _has_id(vs2, "5.2.3")
}

test_1_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.1")
}

test_1_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/version", "value": "1.24.0"}])
	vs := b.violations with input as inp
	"1.1.1: Ensure NGINX is installed" in vs
}

test_1_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/version"}])
	vs := b.violations with input as inp
	"1.1.1: evidence missing — nginx.version not collected" in vs
	not "1.1.1: Ensure NGINX is installed" in vs
}

test_1_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.1")
}

test_1_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/attest/package_repositories_reviewed", "value": false}])
	vs := b.violations with input as inp
	"1.2.1: Ensure package manager repositories are properly configured (manual review not attested)" in vs
}

test_1_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/attest/package_repositories_reviewed"}])
	vs := b.violations with input as inp
	"1.2.1: Ensure package manager repositories are properly configured (manual review not attested)" in vs
}

test_1_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.2")
}

test_1_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/package/update_available", "value": true}])
	vs := b.violations with input as inp
	"1.2.2: Ensure the latest software package is installed" in vs
}

test_1_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/package/update_available"}])
	vs := b.violations with input as inp
	"1.2.2: evidence missing — nginx.package.update_available not collected" in vs
	not "1.2.2: Ensure the latest software package is installed" in vs
}

test_2_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1.1")
}

test_2_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/attest/dynamic_modules_reviewed", "value": false}])
	vs := b.violations with input as inp
	"2.1.1: Ensure only required dynamic modules are loaded (manual review not attested)" in vs
}

test_2_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/attest/dynamic_modules_reviewed"}])
	vs := b.violations with input as inp
	"2.1.1: Ensure only required dynamic modules are loaded (manual review not attested)" in vs
}

test_2_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.1")
}

test_2_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/user/uid", "value": 0}])
	vs := b.violations with input as inp
	"2.2.1: Ensure that NGINX is run using a non-privileged, dedicated service account" in vs
}

test_2_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/user/sudo_allowed"}])
	vs := b.violations with input as inp
	"2.2.1: evidence missing — nginx.user.{name,uid,groups,sudo_allowed} not collected" in vs
	not "2.2.1: Ensure that NGINX is run using a non-privileged, dedicated service account" in vs
}

test_2_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.2")
}

test_2_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/user/password_locked", "value": false}])
	vs := b.violations with input as inp
	"2.2.2: Ensure the NGINX service account is locked" in vs
}

test_2_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/user/password_locked"}])
	vs := b.violations with input as inp
	"2.2.2: evidence missing — nginx.user.password_locked not collected" in vs
	not "2.2.2: Ensure the NGINX service account is locked" in vs
}

test_2_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2.3")
}

test_2_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/user/shell", "value": "/bin/bash"}])
	vs := b.violations with input as inp
	"2.2.3: Ensure the NGINX service account has an invalid shell" in vs
}

test_2_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/user/shell"}])
	vs := b.violations with input as inp
	"2.2.3: evidence missing — nginx.user.shell not collected" in vs
	not "2.2.3: Ensure the NGINX service account has an invalid shell" in vs
}

test_2_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.1")
}

test_2_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/files/not_root_owned", "value": ["/etc/nginx/conf.d/app.conf"]}])
	vs := b.violations with input as inp
	"2.3.1: Ensure NGINX directories and files are owned by root" in vs
}

test_2_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/files/not_root_owned"}])
	vs := b.violations with input as inp
	"2.3.1: evidence missing — nginx.files.not_root_owned not collected" in vs
	not "2.3.1: Ensure NGINX directories and files are owned by root" in vs
}

test_2_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.2")
}

test_2_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/files/file_modes/~1etc~1nginx~1nginx.conf", "value": "644"}])
	vs := b.violations with input as inp
	"2.3.2: Ensure access to NGINX directories and files is restricted" in vs
}

test_2_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/files/file_modes"}])
	vs := b.violations with input as inp
	"2.3.2: evidence missing — nginx.files.{dir_modes,file_modes} not collected" in vs
	not "2.3.2: Ensure access to NGINX directories and files is restricted" in vs
}

test_2_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3.3")
}

test_2_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/pid_file/mode", "value": "664"}])
	vs := b.violations with input as inp
	"2.3.3: Ensure the NGINX process ID (PID) file is secured" in vs
}

test_2_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/pid_file"}])
	vs := b.violations with input as inp
	"2.3.3: evidence missing — nginx.pid_file.{owner,group,mode} not collected" in vs
	not "2.3.3: Ensure the NGINX process ID (PID) file is secured" in vs
}

test_2_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.1")
}

test_2_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/listen_ports", "value": [80, 443, 8080]}])
	vs := b.violations with input as inp
	"2.4.1: Ensure NGINX only listens for network connections on authorized ports" in vs
}

test_2_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/listen_ports"}])
	vs := b.violations with input as inp
	"2.4.1: evidence missing — nginx.listen_ports not collected" in vs
	not "2.4.1: Ensure NGINX only listens for network connections on authorized ports" in vs
}

test_2_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.2")
}

test_2_4_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/default_server/ssl_reject_handshake", "value": false}])
	vs := b.violations with input as inp
	"2.4.2: Ensure requests for unknown host names are rejected" in vs
}

test_2_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/default_server"}])
	vs := b.violations with input as inp
	"2.4.2: evidence missing — nginx.default_server not collected" in vs
	not "2.4.2: Ensure requests for unknown host names are rejected" in vs
}

test_2_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.3")
}

test_2_4_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/keepalive_timeout", "value": ["75"]}])
	vs := b.violations with input as inp
	"2.4.3: Ensure keepalive_timeout is 10 seconds or less, but not 0" in vs
}

test_2_4_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"2.4.3: evidence missing — nginx.directives not collected" in vs
	not "2.4.3: Ensure keepalive_timeout is 10 seconds or less, but not 0" in vs
}

test_2_4_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4.4")
}

test_2_4_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/send_timeout", "value": ["0"]}])
	vs := b.violations with input as inp
	"2.4.4: Ensure send_timeout is set to 10 seconds or less, but not 0" in vs
}

test_2_4_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"2.4.4: evidence missing — nginx.directives not collected" in vs
	not "2.4.4: Ensure send_timeout is set to 10 seconds or less, but not 0" in vs
}

test_2_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.1")
}

test_2_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/server_tokens", "value": ["on"]}])
	vs := b.violations with input as inp
	"2.5.1: Ensure server_tokens directive is set to `off`" in vs
}

test_2_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"2.5.1: evidence missing — nginx.directives not collected" in vs
	not "2.5.1: Ensure server_tokens directive is set to `off`" in vs
}

test_2_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.2")
}

test_2_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/probe/error_page_mentions_nginx", "value": true}])
	vs := b.violations with input as inp
	"2.5.2: Ensure default error and index.html pages do not reference NGINX" in vs
}

test_2_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/probe/error_page_mentions_nginx"}])
	vs := b.violations with input as inp
	"2.5.2: evidence missing — nginx.probe.error_page_mentions_nginx not collected" in vs
	not "2.5.2: Ensure default error and index.html pages do not reference NGINX" in vs
}

test_2_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.3")
}

test_2_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/hidden_files_denied", "value": false}])
	vs := b.violations with input as inp
	"2.5.3: Ensure hidden file serving is disabled" in vs
}

test_2_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/hidden_files_denied"}])
	vs := b.violations with input as inp
	"2.5.3: evidence missing — nginx.hidden_files_denied not collected" in vs
	not "2.5.3: Ensure hidden file serving is disabled" in vs
}

test_2_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5.4")
}

test_2_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/proxy_hide_header", "value": ["X-Powered-By"]}])
	vs := b.violations with input as inp
	"2.5.4: Ensure the NGINX reverse proxy does not enable information disclosure" in vs
}

test_2_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"2.5.4: evidence missing — nginx.directives not collected" in vs
	not "2.5.4: Ensure the NGINX reverse proxy does not enable information disclosure" in vs
}

test_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1")
}

test_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/log_format", "value": ["main '$remote_addr $status'"]}])
	vs := b.violations with input as inp
	"3.1: Ensure detailed logging is enabled" in vs
}

test_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"3.1: evidence missing — nginx.directives not collected" in vs
	not "3.1: Ensure detailed logging is enabled" in vs
}

test_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2")
}

test_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/access_log_off_outside_location", "value": true}])
	vs := b.violations with input as inp
	"3.2: Ensure access logging is enabled" in vs
}

test_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/access_log_off_outside_location"}])
	vs := b.violations with input as inp
	"3.2: evidence missing — nginx.directives / nginx.access_log_off_outside_location not collected" in vs
	not "3.2: Ensure access logging is enabled" in vs
}

test_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3")
}

test_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/error_log", "value": ["/var/log/nginx/error.log crit"]}])
	vs := b.violations with input as inp
	"3.3: Ensure error logging is enabled and set to the info logging level" in vs
}

test_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"3.3: evidence missing — nginx.directives not collected" in vs
	not "3.3: Ensure error logging is enabled and set to the info logging level" in vs
}

test_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.4")
}

test_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/proxy_set_header", "value": ["X-Forwarded-For $proxy_add_x_forwarded_for"]}])
	vs := b.violations with input as inp
	"3.4: Ensure proxies pass source IP information" in vs
}

test_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"3.4: evidence missing — nginx.directives not collected" in vs
	not "3.4: Ensure proxies pass source IP information" in vs
}

test_4_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.1")
}

test_4_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/servers/-", "value": {"name": "plain", "ssl": false, "redirects_to_https": false}}])
	vs := b.violations with input as inp
	"4.1.1: Ensure HTTP is redirected to HTTPS" in vs
}

test_4_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/servers"}])
	vs := b.violations with input as inp
	"4.1.1: evidence missing — nginx.servers not collected" in vs
	not "4.1.1: Ensure HTTP is redirected to HTTPS" in vs
}

test_4_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.2")
}

test_4_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/certificates/0/chain_trusted", "value": false}])
	vs := b.violations with input as inp
	"4.1.2: Ensure a trusted certificate and trust chain is installed" in vs
}

test_4_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/certificates"}])
	vs := b.violations with input as inp
	"4.1.2: evidence missing — nginx.certificates not collected" in vs
	not "4.1.2: Ensure a trusted certificate and trust chain is installed" in vs
}

test_4_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.3")
}

test_4_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/private_keys/~1etc~1nginx~1ssl~1site.key", "value": "640"}])
	vs := b.violations with input as inp
	"4.1.3: Ensure private key permissions are restricted" in vs
}

test_4_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/private_keys"}])
	vs := b.violations with input as inp
	"4.1.3: evidence missing — nginx.private_keys not collected" in vs
	not "4.1.3: Ensure private key permissions are restricted" in vs
}

test_4_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.4")
}

test_4_1_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/ssl_protocols", "value": ["TLSv1.2 TLSv1.3"]}])
	vs := b.violations with input as inp
	"4.1.4: Ensure only modern TLS protocols are used" in vs
}

test_4_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.4: evidence missing — nginx.directives not collected" in vs
	not "4.1.4: Ensure only modern TLS protocols are used" in vs
}

test_4_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.5")
}

test_4_1_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/ssl_protocols", "value": ["TLSv1.2 TLSv1.3"]}])
	vs := b.violations with input as inp
	"4.1.5: Disable weak ciphers" in vs
}

test_4_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.5: evidence missing — nginx.directives not collected" in vs
	not "4.1.5: Disable weak ciphers" in vs
}

test_4_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.6")
}

test_4_1_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/ssl_protocols", "value": ["TLSv1.2 TLSv1.3"]}])
	vs := b.violations with input as inp
	"4.1.6: Ensure awareness of TLS 1.3 new Diffie-Hellman parameters" in vs
}

test_4_1_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.6: evidence missing — nginx.directives not collected" in vs
	not "4.1.6: Ensure awareness of TLS 1.3 new Diffie-Hellman parameters" in vs
}

test_4_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.7")
}

test_4_1_7_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives/resolver"}])
	vs := b.violations with input as inp
	"4.1.7: Ensure Online Certificate Status Protocol (OCSP) stapling is enabled" in vs
}

test_4_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.7: evidence missing — nginx.directives not collected" in vs
	not "4.1.7: Ensure Online Certificate Status Protocol (OCSP) stapling is enabled" in vs
}

test_4_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.8")
}

test_4_1_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/add_header", "value": ["Strict-Transport-Security \"max-age=300\" always"]}])
	vs := b.violations with input as inp
	"4.1.8: Ensure HTTP Strict Transport Security (HSTS) is enabled" in vs
}

test_4_1_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.8: evidence missing — nginx.directives not collected" in vs
	not "4.1.8: Ensure HTTP Strict Transport Security (HSTS) is enabled" in vs
}

test_4_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.9")
}

test_4_1_9_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives/proxy_ssl_certificate"}])
	vs := b.violations with input as inp
	"4.1.9: Ensure upstream server traffic is authenticated with a client certificate" in vs
}

test_4_1_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.9: evidence missing — nginx.directives not collected" in vs
	not "4.1.9: Ensure upstream server traffic is authenticated with a client certificate" in vs
}

test_4_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.10")
}

test_4_1_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/proxy_ssl_verify", "value": ["off"]}])
	vs := b.violations with input as inp
	"4.1.10: Ensure the upstream traffic server certificate is trusted" in vs
}

test_4_1_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.10: evidence missing — nginx.directives not collected" in vs
	not "4.1.10: Ensure the upstream traffic server certificate is trusted" in vs
}

test_4_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.11")
}

test_4_1_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/ssl_session_tickets", "value": ["off"]}])
	vs := b.violations with input as inp
	"4.1.11: Ensure Secure Session Resumption is Enabled" in vs
}

test_4_1_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.11: evidence missing — nginx.directives not collected" in vs
	not "4.1.11: Ensure Secure Session Resumption is Enabled" in vs
}

test_4_1_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.12")
}

test_4_1_12_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives/http2"}])
	vs := b.violations with input as inp
	"4.1.12: Ensure HTTP/3.0 is used" in vs
}

test_4_1_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"4.1.12: evidence missing — nginx.directives not collected" in vs
	not "4.1.12: Ensure HTTP/3.0 is used" in vs
}

test_5_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.1")
}

test_5_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/attest/ip_allow_deny_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.1: Ensure allow and deny filters limit access to specific IP addresses (manual review not attested)" in vs
}

test_5_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/attest/ip_allow_deny_reviewed"}])
	vs := b.violations with input as inp
	"5.1.1: Ensure allow and deny filters limit access to specific IP addresses (manual review not attested)" in vs
}

test_5_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.2")
}

test_5_1_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives/limit_except"}])
	vs := b.violations with input as inp
	"5.1.2: Ensure only approved HTTP methods are allowed" in vs
}

test_5_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.1.2: evidence missing — nginx.directives not collected" in vs
	not "5.1.2: Ensure only approved HTTP methods are allowed" in vs
}

test_5_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.1")
}

test_5_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/client_body_timeout", "value": ["60"]}])
	vs := b.violations with input as inp
	"5.2.1: Ensure timeout values for reading the client header and body are set correctly" in vs
}

test_5_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.2.1: evidence missing — nginx.directives not collected" in vs
	not "5.2.1: Ensure timeout values for reading the client header and body are set correctly" in vs
}

test_5_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.2")
}

test_5_2_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives/client_max_body_size"}])
	vs := b.violations with input as inp
	"5.2.2: Ensure the maximum request body size is set correctly" in vs
}

test_5_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.2.2: evidence missing — nginx.directives not collected" in vs
	not "5.2.2: Ensure the maximum request body size is set correctly" in vs
}

test_5_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.3")
}

test_5_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/large_client_header_buffers", "value": ["2 1k"]}])
	vs := b.violations with input as inp
	"5.2.3: Ensure the maximum buffer size for URIs is defined" in vs
}

test_5_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.2.3: evidence missing — nginx.directives not collected" in vs
	not "5.2.3: Ensure the maximum buffer size for URIs is defined" in vs
}

test_5_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.4")
}

test_5_2_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/attest/connection_limits_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.2.4: Ensure the number of connections per IP address is limited (manual review not attested)" in vs
}

test_5_2_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/attest/connection_limits_reviewed"}])
	vs := b.violations with input as inp
	"5.2.4: Ensure the number of connections per IP address is limited (manual review not attested)" in vs
}

test_5_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.5")
}

test_5_2_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/nginx/attest/rate_limits_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.2.5: Ensure rate limits by IP address are set (manual review not attested)" in vs
}

test_5_2_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/attest/rate_limits_reviewed"}])
	vs := b.violations with input as inp
	"5.2.5: Ensure rate limits by IP address are set (manual review not attested)" in vs
}

test_5_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3.1")
}

test_5_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/add_header", "value": ["X-Content-Type-Options \"nosniff\""]}])
	vs := b.violations with input as inp
	"5.3.1: Ensure X-Content-Type-Options header is configured and enabled" in vs
}

test_5_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.3.1: evidence missing — nginx.directives not collected" in vs
	not "5.3.1: Ensure X-Content-Type-Options header is configured and enabled" in vs
}

test_5_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3.2")
}

test_5_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/add_header", "value": ["Content-Security-Policy \"default-src 'self' 'unsafe-inline'; frame-ancestors 'self'\" always"]}])
	vs := b.violations with input as inp
	"5.3.2: Ensure that Content Security Policy (CSP) is enabled and configured properly" in vs
}

test_5_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.3.2: evidence missing — nginx.directives not collected" in vs
	not "5.3.2: Ensure that Content Security Policy (CSP) is enabled and configured properly" in vs
}

test_5_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3.3")
}

test_5_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/nginx/directives/add_header", "value": ["Referrer-Policy \"no-referrer-when-downgrade\" always"]}])
	vs := b.violations with input as inp
	"5.3.3: Ensure the Referrer Policy is enabled and configured properly" in vs
}

test_5_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/nginx/directives"}])
	vs := b.violations with input as inp
	"5.3.3: evidence missing — nginx.directives not collected" in vs
	not "5.3.3: Ensure the Referrer Policy is enabled and configured properly" in vs
}
