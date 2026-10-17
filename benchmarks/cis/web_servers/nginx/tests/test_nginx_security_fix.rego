package cis.server.nginx_test

import rego.v1

# Validation fix pass 2026-10-17.

test_port_80_without_redirect_field_flagged if {
	not data.cis.server.nginx.http_redirected_to_https with input as {"nginx_config": {"servers": [{"listen_port": 80}]}}
}

test_port_80_with_redirect_passes if {
	data.cis.server.nginx.http_redirected_to_https with input as {"nginx_config": {"servers": [{"listen_port": 80, "ssl_redirect": true}]}}
}

test_port_80_redirect_false_flagged if {
	not data.cis.server.nginx.http_redirected_to_https with input as {"nginx_config": {"servers": [{"listen_port": 80, "ssl_redirect": false}]}}
}

test_no_servers_is_not_evidence if {
	not data.cis.server.nginx.http_redirected_to_https with input as {}
	not data.cis.server.nginx.modern_tls_protocols with input as {"nginx_config": {"servers": []}}
}

test_missing_ssl_enabled_does_not_skip_tls_checks if {
	inp := {"nginx_config": {"servers": [{"listen_port": 443, "ssl_protocols": ["TLSv1", "TLSv1.2", "TLSv1.3"]}]}}
	not data.cis.server.nginx.modern_tls_protocols with input as inp
	not data.cis.server.nginx.trusted_certificate_installed with input as inp
}

test_explicit_plaintext_server_skips_tls_checks if {
	inp := {"nginx_config": {"servers": [{"listen_port": 8080, "ssl_enabled": false}]}}
	data.cis.server.nginx.modern_tls_protocols with input as inp
	data.cis.server.nginx.trusted_certificate_installed with input as inp
}

test_tls_protocols_string_and_list if {
	s1 := {"nginx_config": {"servers": [{"ssl_enabled": true, "ssl_protocols": "TLSv1.2 TLSv1.3"}]}}
	s2 := {"nginx_config": {"servers": [{"ssl_enabled": true, "ssl_protocols": ["TLSv1.2", "TLSv1.3"]}]}}
	s3 := {"nginx_config": {"servers": [{"ssl_enabled": true, "ssl_protocols": "TLSv1.1 TLSv1.2 TLSv1.3"}]}}
	data.cis.server.nginx.modern_tls_protocols with input as s1
	data.cis.server.nginx.modern_tls_protocols with input as s2
	not data.cis.server.nginx.modern_tls_protocols with input as s3
}

test_allowed_methods_order_independent if {
	data.cis.server.nginx.http_methods_restricted with input as {"nginx_config": {"allowed_methods": ["POST", "GET", "HEAD"]}}
	data.cis.server.nginx.http_methods_restricted with input as {"nginx_config": {"allowed_methods": ["GET"]}}
	not data.cis.server.nginx.http_methods_restricted with input as {"nginx_config": {"allowed_methods": ["GET", "DELETE"]}}
	not data.cis.server.nginx.http_methods_restricted with input as {"nginx_config": {"allowed_methods": []}}
}

test_modules_array_and_string if {
	not data.cis.server.nginx.webdav_module_not_installed with input as {"nginx_modules": ["http_dav_module"]}
	data.cis.server.nginx.webdav_module_not_installed with input as {"nginx_modules": ["http_ssl_module"]}
	not data.cis.server.nginx.webdav_module_not_installed with input as {"nginx_modules": "--with-http_dav_module"}
	not data.cis.server.nginx.webdav_module_not_installed with input as {}
}

test_key_mode_forms if {
	inp := {"nginx_config": {"servers": [{"ssl_enabled": true, "ssl_certificate_key": "/k"}]}, "file_permissions": {"/k": {"mode": "400", "owner": "root"}}}
	data.cis.server.nginx.private_key_permissions_restricted with input as inp
	inp2 := {"nginx_config": {"servers": [{"ssl_enabled": true, "ssl_certificate_key": "/k"}]}, "file_permissions": {"/k": {"mode": "0440", "owner": "root"}}}
	not data.cis.server.nginx.private_key_permissions_restricted with input as inp2
}

test_report_populated_on_empty_input if {
	r := data.cis.server.nginx.nginx_server_compliance with input as {}
	r.overall_compliant == false
	count(r) == 23
}
