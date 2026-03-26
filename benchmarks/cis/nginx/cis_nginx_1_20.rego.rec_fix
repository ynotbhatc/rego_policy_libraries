package cis_nginx_1_20

import rego.v1

default compliant := false

violations := array.concat(
    installation_violations,
    array.concat(
        configuration_violations,
        array.concat(
            logging_violations,
            array.concat(
                ssl_tls_violations,
                array.concat(
                    modules_violations,
                    array.concat(
                        access_control_violations,
                        performance_violations
                    )
                )
            )
        )
    )
)

compliant if {
    count(violations) == 0
}

installation_violations := [msg |
    msgs := [
        {"msg": "1.1.1 Ensure NGINX is installed with minimal required modules", "condition": nginx_minimal_modules},
        {"msg": "1.1.2 Ensure NGINX is compiled with security flags", "condition": nginx_security_flags},
        {"msg": "1.1.3 Ensure NGINX version is up to date", "condition": nginx_current_version},
        {"msg": "1.2.1 Ensure NGINX runs as a non-privileged user", "condition": nginx_non_privileged_user},
        {"msg": "1.2.2 Ensure NGINX service account has minimal privileges", "condition": nginx_minimal_privileges},
        {"msg": "1.3.1 Ensure NGINX configuration files have appropriate ownership", "condition": nginx_config_ownership},
        {"msg": "1.3.2 Ensure NGINX configuration files have appropriate permissions", "condition": nginx_config_permissions},
        {"msg": "1.3.3 Ensure NGINX binary has appropriate ownership and permissions", "condition": nginx_binary_permissions},
        {"msg": "1.4.1 Ensure NGINX process runs in a chroot environment", "condition": nginx_chroot_enabled},
        {"msg": "1.4.2 Ensure NGINX directories have appropriate permissions", "condition": nginx_directory_permissions},
        {"msg": "1.5.1 Ensure unnecessary NGINX modules are disabled", "condition": nginx_unnecessary_modules_disabled},
        {"msg": "1.5.2 Ensure debug and test modules are removed in production", "condition": nginx_debug_modules_removed}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

configuration_violations := [msg |
    msgs := [
        {"msg": "2.1.1 Ensure server_tokens directive is set to off", "condition": server_tokens_disabled},
        {"msg": "2.1.2 Ensure server signature is not exposed in error pages", "condition": server_signature_hidden},
        {"msg": "2.1.3 Ensure NGINX version information is not disclosed", "condition": version_info_hidden},
        {"msg": "2.2.1 Ensure default NGINX configuration is removed", "condition": default_config_removed},
        {"msg": "2.2.2 Ensure default document root is changed", "condition": default_docroot_changed},
        {"msg": "2.2.3 Ensure default error pages are customized", "condition": default_error_pages_changed},
        {"msg": "2.3.1 Ensure worker_processes is set appropriately", "condition": worker_processes_configured},
        {"msg": "2.3.2 Ensure worker_connections is configured properly", "condition": worker_connections_configured},
        {"msg": "2.3.3 Ensure worker_rlimit_nofile is set appropriately", "condition": worker_rlimit_configured},
        {"msg": "2.4.1 Ensure client_max_body_size is configured", "condition": client_max_body_size_configured},
        {"msg": "2.4.2 Ensure client_body_timeout is set", "condition": client_body_timeout_configured},
        {"msg": "2.4.3 Ensure client_header_timeout is set", "condition": client_header_timeout_configured},
        {"msg": "2.4.4 Ensure keepalive_timeout is configured", "condition": keepalive_timeout_configured},
        {"msg": "2.4.5 Ensure send_timeout is configured", "condition": send_timeout_configured},
        {"msg": "2.5.1 Ensure server_name is explicitly defined", "condition": server_name_configured},
        {"msg": "2.5.2 Ensure listen directive is properly configured", "condition": listen_directive_configured},
        {"msg": "2.5.3 Ensure default server is properly configured", "condition": default_server_configured},
        {"msg": "2.6.1 Ensure HTTP methods are restricted", "condition": http_methods_restricted},
        {"msg": "2.6.2 Ensure dangerous HTTP methods are disabled", "condition": dangerous_methods_disabled},
        {"msg": "2.6.3 Ensure HTTP trace method is disabled", "condition": trace_method_disabled}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

logging_violations := [msg |
    msgs := [
        {"msg": "3.1.1 Ensure access logging is enabled", "condition": access_logging_enabled},
        {"msg": "3.1.2 Ensure error logging is enabled", "condition": error_logging_enabled},
        {"msg": "3.1.3 Ensure log files have appropriate permissions", "condition": log_file_permissions},
        {"msg": "3.1.4 Ensure log files are rotated regularly", "condition": log_rotation_configured},
        {"msg": "3.2.1 Ensure access logs capture sufficient information", "condition": access_log_format_configured},
        {"msg": "3.2.2 Ensure error logs capture appropriate detail level", "condition": error_log_level_configured},
        {"msg": "3.2.3 Ensure sensitive information is not logged", "condition": sensitive_info_filtered},
        {"msg": "3.3.1 Ensure log files are stored securely", "condition": log_storage_secure},
        {"msg": "3.3.2 Ensure log files are backed up regularly", "condition": log_backup_configured},
        {"msg": "3.3.3 Ensure log files are monitored for security events", "condition": log_monitoring_enabled},
        {"msg": "3.4.1 Ensure syslog integration is configured when required", "condition": syslog_integration},
        {"msg": "3.4.2 Ensure remote logging is secured", "condition": remote_logging_secure}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

ssl_tls_violations := [msg |
    msgs := [
        {"msg": "4.1.1 Ensure SSL/TLS is enabled for all sensitive communications", "condition": ssl_enabled},
        {"msg": "4.1.2 Ensure strong SSL/TLS protocols are used", "condition": strong_ssl_protocols},
        {"msg": "4.1.3 Ensure weak SSL/TLS protocols are disabled", "condition": weak_protocols_disabled},
        {"msg": "4.2.1 Ensure strong cipher suites are configured", "condition": strong_ciphers_configured},
        {"msg": "4.2.2 Ensure weak cipher suites are disabled", "condition": weak_ciphers_disabled},
        {"msg": "4.2.3 Ensure cipher order is server-preferred", "condition": server_cipher_order},
        {"msg": "4.3.1 Ensure SSL certificates are valid and trusted", "condition": valid_ssl_certificates},
        {"msg": "4.3.2 Ensure SSL certificates are not expired", "condition": certificates_not_expired},
        {"msg": "4.3.3 Ensure SSL certificate chain is complete", "condition": certificate_chain_complete},
        {"msg": "4.3.4 Ensure private keys are protected", "condition": private_keys_protected},
        {"msg": "4.4.1 Ensure HSTS is enabled", "condition": hsts_enabled},
        {"msg": "4.4.2 Ensure SSL session caching is configured securely", "condition": ssl_session_cache_secure},
        {"msg": "4.4.3 Ensure SSL session timeout is appropriate", "condition": ssl_session_timeout_configured},
        {"msg": "4.5.1 Ensure OCSP stapling is enabled", "condition": ocsp_stapling_enabled},
        {"msg": "4.5.2 Ensure certificate transparency is configured", "condition": certificate_transparency},
        {"msg": "4.6.1 Ensure HTTP is redirected to HTTPS", "condition": http_to_https_redirect},
        {"msg": "4.6.2 Ensure secure cookies are used", "condition": secure_cookies_configured}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

modules_violations := [msg |
    msgs := [
        {"msg": "5.1.1 Ensure only required modules are loaded", "condition": required_modules_only},
        {"msg": "5.1.2 Ensure dangerous modules are not loaded", "condition": dangerous_modules_disabled},
        {"msg": "5.2.1 Ensure realip module is configured securely", "condition": realip_module_secure},
        {"msg": "5.2.2 Ensure geoip module restrictions are in place", "condition": geoip_restrictions},
        {"msg": "5.3.1 Ensure auth modules are configured properly", "condition": auth_modules_configured},
        {"msg": "5.3.2 Ensure rate limiting modules are enabled", "condition": rate_limiting_enabled},
        {"msg": "5.3.3 Ensure security headers module is configured", "condition": security_headers_configured},
        {"msg": "5.4.1 Ensure ModSecurity or similar WAF is enabled", "condition": waf_enabled},
        {"msg": "5.4.2 Ensure anti-DDoS modules are configured", "condition": anti_ddos_configured},
        {"msg": "5.5.1 Ensure compression modules are configured securely", "condition": compression_secure},
        {"msg": "5.5.2 Ensure caching modules are configured appropriately", "condition": caching_configured}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

access_control_violations := [msg |
    msgs := [
        {"msg": "6.1.1 Ensure access controls are implemented", "condition": access_controls_implemented},
        {"msg": "6.1.2 Ensure IP-based access restrictions are configured", "condition": ip_restrictions_configured},
        {"msg": "6.1.3 Ensure geographic access restrictions are in place", "condition": geo_restrictions_configured},
        {"msg": "6.2.1 Ensure authentication is required for administrative access", "condition": admin_auth_required},
        {"msg": "6.2.2 Ensure strong authentication mechanisms are used", "condition": strong_auth_mechanisms},
        {"msg": "6.2.3 Ensure authentication bypass vulnerabilities are addressed", "condition": auth_bypass_protected},
        {"msg": "6.3.1 Ensure directory browsing is disabled", "condition": directory_browsing_disabled},
        {"msg": "6.3.2 Ensure file access permissions are restrictive", "condition": file_access_restrictive},
        {"msg": "6.3.3 Ensure symbolic links are handled securely", "condition": symlinks_secure},
        {"msg": "6.4.1 Ensure request size limits are configured", "condition": request_size_limits},
        {"msg": "6.4.2 Ensure request rate limits are configured", "condition": request_rate_limits},
        {"msg": "6.4.3 Ensure connection limits are configured", "condition": connection_limits_configured},
        {"msg": "6.5.1 Ensure security headers are implemented", "condition": security_headers_implemented},
        {"msg": "6.5.2 Ensure CSP headers are configured", "condition": csp_headers_configured},
        {"msg": "6.5.3 Ensure XSS protection headers are set", "condition": xss_protection_enabled}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

performance_violations := [msg |
    msgs := [
        {"msg": "7.1.1 Ensure buffer sizes are configured appropriately", "condition": buffer_sizes_configured},
        {"msg": "7.1.2 Ensure timeout values are set securely", "condition": timeout_values_secure},
        {"msg": "7.1.3 Ensure resource limits prevent DoS attacks", "condition": resource_limits_configured},
        {"msg": "7.2.1 Ensure connection pooling is configured", "condition": connection_pooling_configured},
        {"msg": "7.2.2 Ensure upstream server configurations are secure", "condition": upstream_servers_secure},
        {"msg": "7.2.3 Ensure load balancing is configured securely", "condition": load_balancing_secure},
        {"msg": "7.3.1 Ensure caching is configured securely", "condition": caching_secure},
        {"msg": "7.3.2 Ensure proxy caching headers are appropriate", "condition": proxy_cache_headers},
        {"msg": "7.4.1 Ensure monitoring and health checks are enabled", "condition": monitoring_enabled},
        {"msg": "7.4.2 Ensure performance metrics are collected securely", "condition": metrics_secure}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

nginx_minimal_modules if {
    input.nginx.modules_minimal == true
}

nginx_security_flags if {
    input.nginx.security_flags_enabled == true
}

nginx_current_version if {
    input.nginx.version_current == true
}

nginx_non_privileged_user if {
    input.nginx.user != "root"
    input.nginx.user != ""
}

nginx_minimal_privileges if {
    input.nginx.privileges_minimal == true
}

nginx_config_ownership if {
    input.nginx.config.owner == "root"
    input.nginx.config.group == "root"
}

nginx_config_permissions if {
    input.nginx.config.permissions <= 644
}

nginx_binary_permissions if {
    input.nginx.binary.permissions <= 755
    input.nginx.binary.owner == "root"
}

nginx_chroot_enabled if {
    input.nginx.chroot.enabled == true
}

nginx_directory_permissions if {
    input.nginx.directories.permissions_secure == true
}

nginx_unnecessary_modules_disabled if {
    count(input.nginx.modules.unnecessary) == 0
}

nginx_debug_modules_removed if {
    count(input.nginx.modules.debug) == 0
}

server_tokens_disabled if {
    input.nginx.config.server_tokens == "off"
}

server_signature_hidden if {
    input.nginx.config.server_signature_hidden == true
}

version_info_hidden if {
    input.nginx.config.version_disclosure == false
}

default_config_removed if {
    input.nginx.config.default_removed == true
}

default_docroot_changed if {
    input.nginx.config.default_docroot_changed == true
}

default_error_pages_changed if {
    input.nginx.config.custom_error_pages == true
}

worker_processes_configured if {
    input.nginx.config.worker_processes > 0
    input.nginx.config.worker_processes <= input.system.cpu_cores * 2
}

worker_connections_configured if {
    input.nginx.config.worker_connections > 0
    input.nginx.config.worker_connections <= 4096
}

worker_rlimit_configured if {
    input.nginx.config.worker_rlimit_nofile > 0
}

client_max_body_size_configured if {
    input.nginx.config.client_max_body_size != ""
    input.nginx.config.client_max_body_size != "1m"
}

client_body_timeout_configured if {
    input.nginx.config.client_body_timeout > 0
    input.nginx.config.client_body_timeout <= 60
}

client_header_timeout_configured if {
    input.nginx.config.client_header_timeout > 0
    input.nginx.config.client_header_timeout <= 60
}

keepalive_timeout_configured if {
    input.nginx.config.keepalive_timeout > 0
    input.nginx.config.keepalive_timeout <= 30
}

send_timeout_configured if {
    input.nginx.config.send_timeout > 0
    input.nginx.config.send_timeout <= 60
}

server_name_configured if {
    count(input.nginx.config.server_blocks) > 0
    count([block | block := input.nginx.config.server_blocks[_]; block.server_name == "_"]) == 0
}

listen_directive_configured if {
    count([block | block := input.nginx.config.server_blocks[_]; block.listen_configured != true]) == 0
    count(input.nginx.config.server_blocks) > 0
}

default_server_configured if {
    input.nginx.config.default_server_secure == true
}

http_methods_restricted if {
    input.nginx.config.allowed_methods != null
    count(input.nginx.config.allowed_methods) <= 5
}

dangerous_methods_disabled if {
    count([method | method := input.nginx.config.allowed_methods[_]; method in ["TRACE", "CONNECT", "DELETE", "PATCH"]]) == 0
}

trace_method_disabled if {
    not "TRACE" in input.nginx.config.allowed_methods
}

access_logging_enabled if {
    input.nginx.logging.access_log_enabled == true
}

error_logging_enabled if {
    input.nginx.logging.error_log_enabled == true
}

log_file_permissions if {
    input.nginx.logging.log_permissions <= 640
}

log_rotation_configured if {
    input.nginx.logging.rotation_configured == true
}

access_log_format_configured if {
    input.nginx.logging.access_log_format != ""
    input.nginx.logging.access_log_format != "combined"
}

error_log_level_configured if {
    input.nginx.logging.error_log_level in ["error", "crit", "alert", "emerg"]
}

sensitive_info_filtered if {
    input.nginx.logging.sensitive_data_filtered == true
}

log_storage_secure if {
    input.nginx.logging.storage_secure == true
}

log_backup_configured if {
    input.nginx.logging.backup_configured == true
}

log_monitoring_enabled if {
    input.nginx.logging.monitoring_enabled == true
}

syslog_integration if {
    input.nginx.logging.syslog_enabled == true
}

remote_logging_secure if {
    input.nginx.logging.remote_logging_secure == true
}

ssl_enabled if {
    input.nginx.ssl.enabled == true
}

strong_ssl_protocols if {
    allowed_protocols := {"TLSv1.2", "TLSv1.3"}
    count([protocol | protocol := input.nginx.ssl.protocols[_]; protocol in allowed_protocols]) == count(input.nginx.ssl.protocols)
}

weak_protocols_disabled if {
    weak_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    count([protocol | protocol := input.nginx.ssl.protocols[_]; protocol in weak_protocols]) == 0
}

strong_ciphers_configured if {
    input.nginx.ssl.strong_ciphers == true
}

weak_ciphers_disabled if {
    input.nginx.ssl.weak_ciphers_disabled == true
}

server_cipher_order if {
    input.nginx.ssl.prefer_server_ciphers == true
}

valid_ssl_certificates if {
    input.nginx.ssl.certificates_valid == true
}

certificates_not_expired if {
    input.nginx.ssl.certificates_expired == false
}

certificate_chain_complete if {
    input.nginx.ssl.certificate_chain_complete == true
}

private_keys_protected if {
    input.nginx.ssl.private_keys_protected == true
}

hsts_enabled if {
    input.nginx.ssl.hsts_enabled == true
}

ssl_session_cache_secure if {
    input.nginx.ssl.session_cache_secure == true
}

ssl_session_timeout_configured if {
    input.nginx.ssl.session_timeout > 0
    input.nginx.ssl.session_timeout <= 600
}

ocsp_stapling_enabled if {
    input.nginx.ssl.ocsp_stapling == true
}

certificate_transparency if {
    input.nginx.ssl.certificate_transparency == true
}

http_to_https_redirect if {
    input.nginx.ssl.http_redirect_enabled == true
}

secure_cookies_configured if {
    input.nginx.ssl.secure_cookies == true
}

required_modules_only if {
    input.nginx.modules.only_required_loaded == true
}

dangerous_modules_disabled if {
    dangerous_modules := {"debug", "status", "info", "autoindex"}
    count([module | module := input.nginx.modules.loaded[_]; module in dangerous_modules]) == 0
}

realip_module_secure if {
    input.nginx.modules.realip.configured_securely == true
}

geoip_restrictions if {
    input.nginx.modules.geoip.restrictions_enabled == true
}

auth_modules_configured if {
    input.nginx.modules.auth.properly_configured == true
}

rate_limiting_enabled if {
    input.nginx.modules.rate_limiting.enabled == true
}

security_headers_configured if {
    input.nginx.modules.security_headers.configured == true
}

waf_enabled if {
    input.nginx.modules.waf.enabled == true
}

anti_ddos_configured if {
    input.nginx.modules.anti_ddos.configured == true
}

compression_secure if {
    input.nginx.modules.compression.secure_config == true
}

caching_configured if {
    input.nginx.modules.caching.properly_configured == true
}

access_controls_implemented if {
    input.nginx.access_control.implemented == true
}

ip_restrictions_configured if {
    input.nginx.access_control.ip_restrictions == true
}

geo_restrictions_configured if {
    input.nginx.access_control.geo_restrictions == true
}

admin_auth_required if {
    input.nginx.access_control.admin_auth_required == true
}

strong_auth_mechanisms if {
    input.nginx.access_control.strong_auth == true
}

auth_bypass_protected if {
    input.nginx.access_control.auth_bypass_protected == true
}

directory_browsing_disabled if {
    input.nginx.access_control.autoindex == "off"
}

file_access_restrictive if {
    input.nginx.access_control.file_access_restrictive == true
}

symlinks_secure if {
    input.nginx.access_control.symlinks_secure == true
}

request_size_limits if {
    input.nginx.access_control.request_size_limits == true
}

request_rate_limits if {
    input.nginx.access_control.rate_limits == true
}

connection_limits_configured if {
    input.nginx.access_control.connection_limits == true
}

security_headers_implemented if {
    input.nginx.headers.security_headers == true
}

csp_headers_configured if {
    input.nginx.headers.csp_configured == true
}

xss_protection_enabled if {
    input.nginx.headers.xss_protection == true
}

buffer_sizes_configured if {
    input.nginx.performance.buffer_sizes_secure == true
}

timeout_values_secure if {
    input.nginx.performance.timeout_values_secure == true
}

resource_limits_configured if {
    input.nginx.performance.resource_limits == true
}

connection_pooling_configured if {
    input.nginx.performance.connection_pooling == true
}

upstream_servers_secure if {
    input.nginx.performance.upstream_secure == true
}

load_balancing_secure if {
    input.nginx.performance.load_balancing_secure == true
}

caching_secure if {
    input.nginx.performance.caching_secure == true
}

proxy_cache_headers if {
    input.nginx.performance.proxy_cache_headers == true
}

monitoring_enabled if {
    input.nginx.performance.monitoring_enabled == true
}

metrics_secure if {
    input.nginx.performance.metrics_secure == true
}

findings := [
    {
        "title": "NGINX Installation and Configuration Security",
        "description": "Comprehensive security assessment of NGINX web server installation, configuration, and operational security controls",
        "severity": "HIGH",
        "details": sprintf("Found %d configuration violations across NGINX security domains", [count(violations)]),
        "violations": violations,
        "remediation": "Review and implement the recommended NGINX security configurations including proper installation, secure configuration directives, comprehensive logging, SSL/TLS hardening, module security, access controls, and performance security settings"
    }
]