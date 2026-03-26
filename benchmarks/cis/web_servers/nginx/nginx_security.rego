package cis.server.nginx

import rego.v1

# CIS NGINX Benchmark
# Web Server Security Configuration

# CIS 1.1 - Ensure NGINX is installed from a package manager or compiled from source
nginx_properly_installed if {
    method := input.nginx_info.installation_method
    some valid_method in ["package_manager", "source"]
    method == valid_method
    input.nginx_info.version != ""
}

# CIS 1.2 - Ensure NGINX is running as a non-privileged user
nginx_non_privileged_user if {
    input.nginx_config.user != "root"
    input.nginx_config.user != ""
}

# CIS 1.3 - Ensure the NGINX service account is locked
nginx_service_account_locked if {
    input.system_users[input.nginx_config.user].shell in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
    input.system_users[input.nginx_config.user].locked == true
}

# CIS 2.1 - Ensure only required modules are installed
only_required_modules if {
    # Check that dangerous modules are not loaded
    not contains(input.nginx_modules, "http_autoindex_module")
    not contains(input.nginx_modules, "http_ssi_module") 
    not contains(input.nginx_modules, "http_userid_module")
}

# CIS 2.2 - Ensure HTTP WebDAV module is not installed
webdav_module_not_installed if {
    not contains(input.nginx_modules, "http_dav_module")
}

# CIS 2.3 - Ensure modules with gzip functionality are disabled
gzip_modules_disabled if {
    not contains(input.nginx_modules, "http_gzip_module")
    not contains(input.nginx_modules, "http_gzip_static_module")
}

# CIS 2.4 - Ensure the autoindex module is disabled
autoindex_module_disabled if {
    not contains(input.nginx_modules, "http_autoindex_module")
}

# CIS 3.1 - Ensure detailed logging is enabled
detailed_logging_enabled if {
    input.nginx_config.access_log.enabled == true
    input.nginx_config.error_log.enabled == true
    input.nginx_config.error_log.level in ["info", "notice", "warn", "error"]
}

# CIS 3.2 - Ensure access logging is enabled
access_logging_enabled if {
    input.nginx_config.access_log.enabled == true
    input.nginx_config.access_log.path != "off"
}

# CIS 3.3 - Ensure error logging is enabled and set appropriately
error_logging_configured if {
    input.nginx_config.error_log.enabled == true
    input.nginx_config.error_log.level in ["warn", "error", "crit"]
}

# CIS 3.4 - Ensure log files are rotated
log_rotation_configured if {
    input.nginx_config.log_rotation.enabled == true
    input.nginx_config.log_rotation.max_size_mb <= 100
    input.nginx_config.log_rotation.max_files <= 52
}

# CIS 4.1 - Ensure HTTP is redirected to HTTPS
http_redirected_to_https if {
    count([server | server := input.nginx_config.servers[_]; server.listen_port == 80; server.ssl_redirect == false]) == 0
}

# CIS 4.2 - Ensure a trusted certificate and trust chain is installed
trusted_certificate_installed if {
    every server in input.nginx_config.servers {
        server_certificates_valid(server)
    }
}

server_certificates_valid(server) if {
    not server.ssl_enabled
}

server_certificates_valid(server) if {
    server.ssl_enabled
    server.ssl_certificate != ""
    server.ssl_certificate_key != ""
    server.ssl_trusted_certificate != ""
}

# CIS 4.3 - Ensure private key permissions are restricted
private_key_permissions_restricted if {
    every server in input.nginx_config.servers {
        server_key_permissions_valid(server)
    }
}

server_key_permissions_valid(server) if {
    not server.ssl_enabled
}

server_key_permissions_valid(server) if {
    server.ssl_enabled
    input.file_permissions[server.ssl_certificate_key].mode == "0400"
    input.file_permissions[server.ssl_certificate_key].owner == "root"
}

# CIS 4.4 - Ensure only modern TLS protocols are used
modern_tls_protocols if {
    every server in input.nginx_config.servers {
        server_tls_protocols_valid(server)
    }
}

server_tls_protocols_valid(server) if {
    not server.ssl_enabled
}

server_tls_protocols_valid(server) if {
    server.ssl_enabled
    "TLSv1.2" in server.ssl_protocols
    "TLSv1.3" in server.ssl_protocols
    not "TLSv1" in server.ssl_protocols
    not "TLSv1.1" in server.ssl_protocols
    not "SSLv2" in server.ssl_protocols
    not "SSLv3" in server.ssl_protocols
}

# CIS 4.5 - Ensure secure cipher suites are configured
secure_cipher_suites if {
    every server in input.nginx_config.servers {
        server_ciphers_valid(server)
    }
}

server_ciphers_valid(server) if {
    not server.ssl_enabled
}

server_ciphers_valid(server) if {
    server.ssl_enabled
    server.ssl_prefer_server_ciphers == true
    contains(server.ssl_ciphers, "ECDHE")
    not contains(server.ssl_ciphers, "NULL")
    not contains(server.ssl_ciphers, "aNULL")
    not contains(server.ssl_ciphers, "MD5")
    not contains(server.ssl_ciphers, "DSS")
}

# CIS 5.1 - Ensure server_tokens directive is set to off
server_tokens_disabled if {
    input.nginx_config.server_tokens == "off"
}

# CIS 5.2 - Ensure default error and index page do not reference NGINX
custom_error_pages if {
    input.nginx_config.custom_error_pages == true
    not contains(input.nginx_config.default_error_page, "nginx")
}

# CIS 5.3 - Ensure hidden file serving is disabled
hidden_files_disabled if {
    input.nginx_config.hidden_files_blocked == true
}

# CIS 5.4 - Ensure the NGINX reverse proxy does not enable information disclosure
proxy_headers_secure if {
    input.nginx_config.proxy_hide_headers.server == true
    input.nginx_config.proxy_hide_headers.x_powered_by == true
    input.nginx_config.proxy_hide_headers.x_aspnet_version == true
}

# CIS 6.1 - Ensure HTTP request methods are restricted
http_methods_restricted if {
    input.nginx_config.allowed_methods == ["GET", "HEAD", "POST"]
}

# CIS 6.2 - Ensure timeout values for client connections are set appropriately
client_timeouts_configured if {
    input.nginx_config.client_body_timeout <= 60
    input.nginx_config.client_header_timeout <= 60
    input.nginx_config.keepalive_timeout <= 75
    input.nginx_config.send_timeout <= 60
}

# CIS 6.3 - Ensure the maximum request body size is set correctly
max_body_size_configured if {
    input.nginx_config.client_max_body_size_mb <= 1
}

# CIS 6.4 - Ensure buffer overflow attacks are prevented
buffer_overflow_prevention if {
    input.nginx_config.client_body_buffer_size_kb <= 16
    input.nginx_config.client_header_buffer_size_kb <= 1
    input.nginx_config.large_client_header_buffers.number <= 4
    input.nginx_config.large_client_header_buffers.size_kb <= 8
}

# Aggregate NGINX server compliance
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