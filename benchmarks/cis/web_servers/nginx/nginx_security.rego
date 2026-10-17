# METADATA
# title: "CIS NGINX Benchmark"
# custom:
#   class: security
#   framework: cis_web_servers
#   source: cis
#   domains: [web-server]
#   coverage:
#     checks: 21
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.server.nginx

import rego.v1

# CIS NGINX Benchmark
# Web Server Security Configuration

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# nginx_modules may be a list of module names or a string (`nginx -V` output); `contains` on a list never matches.
modules_collected if is_array(input.nginx_modules)

modules_collected if is_string(input.nginx_modules)

has_module(name) if name in input.nginx_modules

has_module(name) if {
	is_string(input.nginx_modules)
	contains(input.nginx_modules, name)
}

# `every server in servers` is vacuously true for an empty list, so require evidence.
servers_collected if count(input.nginx_config.servers) > 0

# A server is plaintext only when ssl_enabled is explicitly false; an absent flag is not
# treated as plaintext (that would skip the TLS checks), so the TLS checks apply.
tls_applies(server) if object.get(server, "ssl_enabled", true) != false

# ssl_protocols may be a list or a space-separated string
ssl_protocol_set(server) := {lower(p) | some p in server.ssl_protocols} if is_array(server.ssl_protocols)

ssl_protocol_set(server) := {lower(p) | some p in split(server.ssl_protocols, " "); p != ""} if is_string(server.ssl_protocols)

redirects_to_https(server) if server.ssl_redirect == true

# CIS 1.1 - Ensure NGINX is installed from a package manager or compiled from source
default nginx_properly_installed := false

nginx_properly_installed if {
    method := input.nginx_info.installation_method
    some valid_method in ["package_manager", "source"]
    method == valid_method
    input.nginx_info.version != ""
}

# CIS 1.2 - Ensure NGINX is running as a non-privileged user
default nginx_non_privileged_user := false

nginx_non_privileged_user if {
    input.nginx_config.user != "root"
    input.nginx_config.user != ""
}

# CIS 1.3 - Ensure the NGINX service account is locked
default nginx_service_account_locked := false

nginx_service_account_locked if {
    input.system_users[input.nginx_config.user].shell in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
    input.system_users[input.nginx_config.user].locked == true
}

# CIS 2.1 - Ensure only required modules are installed
default only_required_modules := false

only_required_modules if {
    modules_collected
    # Check that dangerous modules are not loaded
    not has_module("http_autoindex_module")
    not has_module("http_ssi_module") 
    not has_module("http_userid_module")
}

# CIS 2.2 - Ensure HTTP WebDAV module is not installed
default webdav_module_not_installed := false

webdav_module_not_installed if {
    modules_collected
    not has_module("http_dav_module")
}

# CIS 2.3 - Ensure modules with gzip functionality are disabled
default gzip_modules_disabled := false

gzip_modules_disabled if {
    modules_collected
    not has_module("http_gzip_module")
    not has_module("http_gzip_static_module")
}

# CIS 2.4 - Ensure the autoindex module is disabled
default autoindex_module_disabled := false

autoindex_module_disabled if {
    modules_collected
    not has_module("http_autoindex_module")
}

# CIS 3.1 - Ensure detailed logging is enabled
default detailed_logging_enabled := false

detailed_logging_enabled if {
    input.nginx_config.access_log.enabled == true
    input.nginx_config.error_log.enabled == true
    input.nginx_config.error_log.level in ["info", "notice", "warn", "error"]
}

# CIS 3.2 - Ensure access logging is enabled
default access_logging_enabled := false

access_logging_enabled if {
    input.nginx_config.access_log.enabled == true
    input.nginx_config.access_log.path != "off"
}

# CIS 3.3 - Ensure error logging is enabled and set appropriately
default error_logging_configured := false

error_logging_configured if {
    input.nginx_config.error_log.enabled == true
    input.nginx_config.error_log.level in ["warn", "error", "crit"]
}

# CIS 3.4 - Ensure log files are rotated
default log_rotation_configured := false

log_rotation_configured if {
    input.nginx_config.log_rotation.enabled == true
    input.nginx_config.log_rotation.max_size_mb <= 100
    input.nginx_config.log_rotation.max_files <= 52
}

# CIS 4.1 - Ensure HTTP is redirected to HTTPS
default http_redirected_to_https := false

http_redirected_to_https if {
    servers_collected
    count([server | some server in input.nginx_config.servers; server.listen_port == 80; not redirects_to_https(server)]) == 0
}

# CIS 4.2 - Ensure a trusted certificate and trust chain is installed
default trusted_certificate_installed := false

trusted_certificate_installed if {
    servers_collected
    every server in input.nginx_config.servers {
        server_certificates_valid(server)
    }
}

server_certificates_valid(server) if {
    not tls_applies(server)
}

server_certificates_valid(server) if {
    tls_applies(server)
    server.ssl_certificate != ""
    server.ssl_certificate_key != ""
    server.ssl_trusted_certificate != ""
}

# CIS 4.3 - Ensure private key permissions are restricted
default private_key_permissions_restricted := false

private_key_permissions_restricted if {
    servers_collected
    every server in input.nginx_config.servers {
        server_key_permissions_valid(server)
    }
}

server_key_permissions_valid(server) if {
    not tls_applies(server)
}

server_key_permissions_valid(server) if {
    tls_applies(server)
    mode_within(input.file_permissions[server.ssl_certificate_key].mode, "0400")
    input.file_permissions[server.ssl_certificate_key].owner == "root"
}

# CIS 4.4 - Ensure only modern TLS protocols are used
default modern_tls_protocols := false

modern_tls_protocols if {
    servers_collected
    every server in input.nginx_config.servers {
        server_tls_protocols_valid(server)
    }
}

server_tls_protocols_valid(server) if {
    not tls_applies(server)
}

server_tls_protocols_valid(server) if {
    tls_applies(server)
    protocols := ssl_protocol_set(server)
    "tlsv1.2" in protocols
    "tlsv1.3" in protocols
    count(protocols & {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}) == 0
}

# CIS 4.5 - Ensure secure cipher suites are configured
default secure_cipher_suites := false

secure_cipher_suites if {
    servers_collected
    every server in input.nginx_config.servers {
        server_ciphers_valid(server)
    }
}

server_ciphers_valid(server) if {
    not tls_applies(server)
}

server_ciphers_valid(server) if {
    tls_applies(server)
    server.ssl_prefer_server_ciphers == true
    contains(server.ssl_ciphers, "ECDHE")
    not contains(server.ssl_ciphers, "NULL")
    not contains(server.ssl_ciphers, "aNULL")
    not contains(server.ssl_ciphers, "MD5")
    not contains(server.ssl_ciphers, "DSS")
}

# CIS 5.1 - Ensure server_tokens directive is set to off
default server_tokens_disabled := false

server_tokens_disabled if {
    input.nginx_config.server_tokens == "off"
}

# CIS 5.2 - Ensure default error and index page do not reference NGINX
default custom_error_pages := false

custom_error_pages if {
    input.nginx_config.custom_error_pages == true
    not contains(input.nginx_config.default_error_page, "nginx")
}

# CIS 5.3 - Ensure hidden file serving is disabled
default hidden_files_disabled := false

hidden_files_disabled if {
    input.nginx_config.hidden_files_blocked == true
}

# CIS 5.4 - Ensure the NGINX reverse proxy does not enable information disclosure
default proxy_headers_secure := false

proxy_headers_secure if {
    input.nginx_config.proxy_hide_headers.server == true
    input.nginx_config.proxy_hide_headers.x_powered_by == true
    input.nginx_config.proxy_hide_headers.x_aspnet_version == true
}

# CIS 6.1 - Ensure HTTP request methods are restricted
default http_methods_restricted := false

http_methods_restricted if {
    count(input.nginx_config.allowed_methods) > 0
    every m in input.nginx_config.allowed_methods {
        upper(m) in {"GET", "HEAD", "POST"}
    }
}

# CIS 6.2 - Ensure timeout values for client connections are set appropriately
default client_timeouts_configured := false

client_timeouts_configured if {
    input.nginx_config.client_body_timeout <= 60
    input.nginx_config.client_header_timeout <= 60
    input.nginx_config.keepalive_timeout <= 75
    input.nginx_config.send_timeout <= 60
}

# CIS 6.3 - Ensure the maximum request body size is set correctly
default max_body_size_configured := false

max_body_size_configured if {
    input.nginx_config.client_max_body_size_mb <= 1
}

# CIS 6.4 - Ensure buffer overflow attacks are prevented
default buffer_overflow_prevention := false

buffer_overflow_prevention if {
    input.nginx_config.client_body_buffer_size_kb <= 16
    input.nginx_config.client_header_buffer_size_kb <= 1
    input.nginx_config.large_client_header_buffers.number <= 4
    input.nginx_config.large_client_header_buffers.size_kb <= 8
}

# Aggregate NGINX server compliance
default nginx_server_compliant := false

nginx_server_compliant if {
    nginx_properly_installed
    nginx_non_privileged_user
    nginx_service_account_locked
    only_required_modules
    webdav_module_not_installed
    detailed_logging_enabled
    access_logging_enabled
    error_logging_configured
    log_rotation_configured
    http_redirected_to_https
    trusted_certificate_installed
    private_key_permissions_restricted
    modern_tls_protocols
    secure_cipher_suites
    server_tokens_disabled
    custom_error_pages
    hidden_files_disabled
    proxy_headers_secure
    http_methods_restricted
    client_timeouts_configured
    max_body_size_configured
    buffer_overflow_prevention
}

# Detailed NGINX server compliance report
nginx_server_compliance := {
    "nginx_properly_installed": nginx_properly_installed,
    "nginx_non_privileged_user": nginx_non_privileged_user,
    "nginx_service_account_locked": nginx_service_account_locked,
    "only_required_modules": only_required_modules,
    "webdav_module_not_installed": webdav_module_not_installed,
    "detailed_logging_enabled": detailed_logging_enabled,
    "access_logging_enabled": access_logging_enabled,
    "error_logging_configured": error_logging_configured,
    "log_rotation_configured": log_rotation_configured,
    "http_redirected_to_https": http_redirected_to_https,
    "trusted_certificate_installed": trusted_certificate_installed,
    "private_key_permissions_restricted": private_key_permissions_restricted,
    "modern_tls_protocols": modern_tls_protocols,
    "secure_cipher_suites": secure_cipher_suites,
    "server_tokens_disabled": server_tokens_disabled,
    "custom_error_pages": custom_error_pages,
    "hidden_files_disabled": hidden_files_disabled,
    "proxy_headers_secure": proxy_headers_secure,
    "http_methods_restricted": http_methods_restricted,
    "client_timeouts_configured": client_timeouts_configured,
    "max_body_size_configured": max_body_size_configured,
    "buffer_overflow_prevention": buffer_overflow_prevention,
    "overall_compliant": nginx_server_compliant
}