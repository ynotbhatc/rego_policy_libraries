# METADATA
# title: "Cis Nginx 1 20"
# custom:
#   class: security
#   framework: cis_nginx
#   source: cis
#   domains: [web-server]
#   coverage:
#     checks: 97
#     cited: 97
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
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
    # fail-closed: no facts, no compliance
    input.nginx
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

default nginx_minimal_modules := false

nginx_minimal_modules if {
    input.nginx.modules_minimal == true
}

default nginx_security_flags := false

nginx_security_flags if {
    input.nginx.security_flags_enabled == true
}

default nginx_current_version := false

nginx_current_version if {
    input.nginx.version_current == true
}

default nginx_non_privileged_user := false

nginx_non_privileged_user if {
    input.nginx.user != "root"
    input.nginx.user != ""
}

default nginx_minimal_privileges := false

nginx_minimal_privileges if {
    input.nginx.privileges_minimal == true
}

default nginx_config_ownership := false

nginx_config_ownership if {
    input.nginx.config.owner == "root"
    input.nginx.config.group == "root"
}

# config_mode: octal permission string ("644", "0644", "0o644") parsed to an integer; undefined if not octal.
# NOTE: no helper functions in this package: a function in the package makes `data.cis_nginx_1_20`
# ill-typed as an argument to object.get (see tests/test_cis_nginx_1_20_fail_closed.rego), so the
# octal parse is repeated per path as a plain rule.
config_mode := n if {
    t := trim_prefix(lower(trim_space(sprintf("%v", [input.nginx.config.permissions]))), "0o")
    regex.match(`^[0-7]{1,4}$`, t)
    p := concat("", [substring("0000", 0, 4 - count(t)), t])
    ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
    n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

default nginx_config_permissions := false

nginx_config_permissions if {
    bits.and(config_mode, bits.and(bits.negate(420), 4095)) == 0 # 0644
}

# binary_mode: octal permission string parsed to an integer; undefined if not octal.
binary_mode := n if {
    t := trim_prefix(lower(trim_space(sprintf("%v", [input.nginx.binary.permissions]))), "0o")
    regex.match(`^[0-7]{1,4}$`, t)
    p := concat("", [substring("0000", 0, 4 - count(t)), t])
    ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
    n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

default nginx_binary_permissions := false

nginx_binary_permissions if {
    bits.and(binary_mode, bits.and(bits.negate(493), 4095)) == 0 # 0755
    input.nginx.binary.owner == "root"
}

default nginx_chroot_enabled := false

nginx_chroot_enabled if {
    input.nginx.chroot.enabled == true
}

default nginx_directory_permissions := false

nginx_directory_permissions if {
    input.nginx.directories.permissions_secure == true
}

default nginx_unnecessary_modules_disabled := false

nginx_unnecessary_modules_disabled if {
    count(input.nginx.modules.unnecessary) == 0
}

default nginx_debug_modules_removed := false

nginx_debug_modules_removed if {
    count(input.nginx.modules.debug) == 0
}

default server_tokens_disabled := false

server_tokens_disabled if {
    input.nginx.config.server_tokens == "off"
}

default server_signature_hidden := false

server_signature_hidden if {
    input.nginx.config.server_signature_hidden == true
}

default version_info_hidden := false

version_info_hidden if {
    input.nginx.config.version_disclosure == false
}

default default_config_removed := false

default_config_removed if {
    input.nginx.config.default_removed == true
}

default default_docroot_changed := false

default_docroot_changed if {
    input.nginx.config.default_docroot_changed == true
}

default default_error_pages_changed := false

default_error_pages_changed if {
    input.nginx.config.custom_error_pages == true
}

default worker_processes_configured := false

worker_processes_configured if {
    input.nginx.config.worker_processes > 0
    input.nginx.config.worker_processes <= input.system.cpu_cores * 2
}

default worker_connections_configured := false

worker_connections_configured if {
    input.nginx.config.worker_connections > 0
    input.nginx.config.worker_connections <= 4096
}

default worker_rlimit_configured := false

worker_rlimit_configured if {
    input.nginx.config.worker_rlimit_nofile > 0
}

default client_max_body_size_configured := false

client_max_body_size_configured if {
    input.nginx.config.client_max_body_size != ""
}

default client_body_timeout_configured := false

client_body_timeout_configured if {
    input.nginx.config.client_body_timeout > 0
    input.nginx.config.client_body_timeout <= 60
}

default client_header_timeout_configured := false

client_header_timeout_configured if {
    input.nginx.config.client_header_timeout > 0
    input.nginx.config.client_header_timeout <= 60
}

default keepalive_timeout_configured := false

keepalive_timeout_configured if {
    input.nginx.config.keepalive_timeout > 0
    input.nginx.config.keepalive_timeout <= 30
}

default send_timeout_configured := false

send_timeout_configured if {
    input.nginx.config.send_timeout > 0
    input.nginx.config.send_timeout <= 60
}

default server_name_configured := false

server_name_configured if {
    count(input.nginx.config.server_blocks) > 0
    count([block | block := input.nginx.config.server_blocks[_]; block.server_name == "_"]) == 0
}

default listen_directive_configured := false

listen_directive_configured if {
    count([block | block := input.nginx.config.server_blocks[_]; block.listen_configured != true]) == 0
    count(input.nginx.config.server_blocks) > 0
}

default default_server_configured := false

default_server_configured if {
    input.nginx.config.default_server_secure == true
}

default http_methods_restricted := false

http_methods_restricted if {
    input.nginx.config.allowed_methods != null
    count(input.nginx.config.allowed_methods) <= 5
}

default dangerous_methods_disabled := false

dangerous_methods_disabled if {
    is_array(input.nginx.config.allowed_methods)
    count([method | method := input.nginx.config.allowed_methods[_]; method in ["TRACE", "CONNECT", "DELETE", "PATCH"]]) == 0
}

default trace_method_disabled := false

trace_method_disabled if {
    is_array(input.nginx.config.allowed_methods)
    not "TRACE" in input.nginx.config.allowed_methods
}

default access_logging_enabled := false

access_logging_enabled if {
    input.nginx.logging.access_log_enabled == true
}

default error_logging_enabled := false

error_logging_enabled if {
    input.nginx.logging.error_log_enabled == true
}

# log_mode: octal permission string parsed to an integer; undefined if not octal.
log_mode := n if {
    t := trim_prefix(lower(trim_space(sprintf("%v", [input.nginx.logging.log_permissions]))), "0o")
    regex.match(`^[0-7]{1,4}$`, t)
    p := concat("", [substring("0000", 0, 4 - count(t)), t])
    ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
    n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

default log_file_permissions := false

log_file_permissions if {
    bits.and(log_mode, bits.and(bits.negate(416), 4095)) == 0 # 0640
}

default log_rotation_configured := false

log_rotation_configured if {
    input.nginx.logging.rotation_configured == true
}

default access_log_format_configured := false

access_log_format_configured if {
    input.nginx.logging.access_log_format != ""
}

default error_log_level_configured := false

error_log_level_configured if {
    input.nginx.logging.error_log_level in ["error", "crit", "alert", "emerg"]
}

default sensitive_info_filtered := false

sensitive_info_filtered if {
    input.nginx.logging.sensitive_data_filtered == true
}

default log_storage_secure := false

log_storage_secure if {
    input.nginx.logging.storage_secure == true
}

default log_backup_configured := false

log_backup_configured if {
    input.nginx.logging.backup_configured == true
}

default log_monitoring_enabled := false

log_monitoring_enabled if {
    input.nginx.logging.monitoring_enabled == true
}

default syslog_integration := false

syslog_integration if {
    input.nginx.logging.syslog_enabled == true
}

default remote_logging_secure := false

remote_logging_secure if {
    input.nginx.logging.remote_logging_secure == true
}

default ssl_enabled := false

ssl_enabled if {
    input.nginx.ssl.enabled == true
}

default strong_ssl_protocols := false

strong_ssl_protocols if {
    allowed_protocols := {"TLSv1.2", "TLSv1.3"}
    is_array(input.nginx.ssl.protocols)
    count(input.nginx.ssl.protocols) > 0
    count([protocol | protocol := input.nginx.ssl.protocols[_]; protocol in allowed_protocols]) == count(input.nginx.ssl.protocols)
}

default weak_protocols_disabled := false

weak_protocols_disabled if {
    weak_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    is_array(input.nginx.ssl.protocols)
    count(input.nginx.ssl.protocols) > 0
    count([protocol | protocol := input.nginx.ssl.protocols[_]; protocol in weak_protocols]) == 0
}

default strong_ciphers_configured := false

strong_ciphers_configured if {
    input.nginx.ssl.strong_ciphers == true
}

default weak_ciphers_disabled := false

weak_ciphers_disabled if {
    input.nginx.ssl.weak_ciphers_disabled == true
}

default server_cipher_order := false

server_cipher_order if {
    input.nginx.ssl.prefer_server_ciphers == true
}

default valid_ssl_certificates := false

valid_ssl_certificates if {
    input.nginx.ssl.certificates_valid == true
}

default certificates_not_expired := false

certificates_not_expired if {
    input.nginx.ssl.certificates_expired == false
}

default certificate_chain_complete := false

certificate_chain_complete if {
    input.nginx.ssl.certificate_chain_complete == true
}

default private_keys_protected := false

private_keys_protected if {
    input.nginx.ssl.private_keys_protected == true
}

default hsts_enabled := false

hsts_enabled if {
    input.nginx.ssl.hsts_enabled == true
}

default ssl_session_cache_secure := false

ssl_session_cache_secure if {
    input.nginx.ssl.session_cache_secure == true
}

default ssl_session_timeout_configured := false

ssl_session_timeout_configured if {
    input.nginx.ssl.session_timeout > 0
    input.nginx.ssl.session_timeout <= 600
}

default ocsp_stapling_enabled := false

ocsp_stapling_enabled if {
    input.nginx.ssl.ocsp_stapling == true
}

default certificate_transparency := false

certificate_transparency if {
    input.nginx.ssl.certificate_transparency == true
}

default http_to_https_redirect := false

http_to_https_redirect if {
    input.nginx.ssl.http_redirect_enabled == true
}

default secure_cookies_configured := false

secure_cookies_configured if {
    input.nginx.ssl.secure_cookies == true
}

default required_modules_only := false

required_modules_only if {
    input.nginx.modules.only_required_loaded == true
}

default dangerous_modules_disabled := false

dangerous_modules_disabled if {
    dangerous_modules := {"debug", "status", "info", "autoindex"}
    is_array(input.nginx.modules.loaded)
    count([module | module := input.nginx.modules.loaded[_]; module in dangerous_modules]) == 0
}

default realip_module_secure := false

realip_module_secure if {
    input.nginx.modules.realip.configured_securely == true
}

default geoip_restrictions := false

geoip_restrictions if {
    input.nginx.modules.geoip.restrictions_enabled == true
}

default auth_modules_configured := false

auth_modules_configured if {
    input.nginx.modules.auth.properly_configured == true
}

default rate_limiting_enabled := false

rate_limiting_enabled if {
    input.nginx.modules.rate_limiting.enabled == true
}

default security_headers_configured := false

security_headers_configured if {
    input.nginx.modules.security_headers.configured == true
}

default waf_enabled := false

waf_enabled if {
    input.nginx.modules.waf.enabled == true
}

default anti_ddos_configured := false

anti_ddos_configured if {
    input.nginx.modules.anti_ddos.configured == true
}

default compression_secure := false

compression_secure if {
    input.nginx.modules.compression.secure_config == true
}

default caching_configured := false

caching_configured if {
    input.nginx.modules.caching.properly_configured == true
}

default access_controls_implemented := false

access_controls_implemented if {
    input.nginx.access_control.implemented == true
}

default ip_restrictions_configured := false

ip_restrictions_configured if {
    input.nginx.access_control.ip_restrictions == true
}

default geo_restrictions_configured := false

geo_restrictions_configured if {
    input.nginx.access_control.geo_restrictions == true
}

default admin_auth_required := false

admin_auth_required if {
    input.nginx.access_control.admin_auth_required == true
}

default strong_auth_mechanisms := false

strong_auth_mechanisms if {
    input.nginx.access_control.strong_auth == true
}

default auth_bypass_protected := false

auth_bypass_protected if {
    input.nginx.access_control.auth_bypass_protected == true
}

default directory_browsing_disabled := false

directory_browsing_disabled if {
    input.nginx.access_control.autoindex == "off"
}

default file_access_restrictive := false

file_access_restrictive if {
    input.nginx.access_control.file_access_restrictive == true
}

default symlinks_secure := false

symlinks_secure if {
    input.nginx.access_control.symlinks_secure == true
}

default request_size_limits := false

request_size_limits if {
    input.nginx.access_control.request_size_limits == true
}

default request_rate_limits := false

request_rate_limits if {
    input.nginx.access_control.rate_limits == true
}

default connection_limits_configured := false

connection_limits_configured if {
    input.nginx.access_control.connection_limits == true
}

default security_headers_implemented := false

security_headers_implemented if {
    input.nginx.headers.security_headers == true
}

default csp_headers_configured := false

csp_headers_configured if {
    input.nginx.headers.csp_configured == true
}

default xss_protection_enabled := false

xss_protection_enabled if {
    input.nginx.headers.xss_protection == true
}

default buffer_sizes_configured := false

buffer_sizes_configured if {
    input.nginx.performance.buffer_sizes_secure == true
}

default timeout_values_secure := false

timeout_values_secure if {
    input.nginx.performance.timeout_values_secure == true
}

default resource_limits_configured := false

resource_limits_configured if {
    input.nginx.performance.resource_limits == true
}

default connection_pooling_configured := false

connection_pooling_configured if {
    input.nginx.performance.connection_pooling == true
}

default upstream_servers_secure := false

upstream_servers_secure if {
    input.nginx.performance.upstream_secure == true
}

default load_balancing_secure := false

load_balancing_secure if {
    input.nginx.performance.load_balancing_secure == true
}

default caching_secure := false

caching_secure if {
    input.nginx.performance.caching_secure == true
}

default proxy_cache_headers := false

proxy_cache_headers if {
    input.nginx.performance.proxy_cache_headers == true
}

default monitoring_enabled := false

monitoring_enabled if {
    input.nginx.performance.monitoring_enabled == true
}

default metrics_secure := false

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