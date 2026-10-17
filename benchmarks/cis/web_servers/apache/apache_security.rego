# METADATA
# title: "CIS Apache HTTP Server Benchmark"
# custom:
#   class: security
#   framework: cis_web_servers
#   source: cis
#   domains: [web-server]
#   coverage:
#     checks: 37
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.server.apache

import rego.v1

# CIS Apache HTTP Server Benchmark
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

# apache_modules may be a list of module names or a string (e.g. `apachectl -M` output).
# Evidence is required: an absent module list must not make "module disabled" checks pass.
modules_collected if is_array(input.apache_modules)

modules_collected if is_string(input.apache_modules)

has_module(name) if name in input.apache_modules

has_module(name) if {
	is_string(input.apache_modules)
	regex.match(sprintf(`(^|[^a-z0-9_])%s([^a-z0-9_]|$)`, [name]), input.apache_modules)
}

# non-empty list of file entries is required; `every` over an empty list is vacuously true
files_collected if count(input.apache_file_permissions) > 0

# SSLProtocol tokens: "+TLSv1.2 -SSLv3 TLSv1.3" -> enabled tokens, lower-cased ("-" tokens are removals)
ssl_enabled_tokens := {t |
	some tok in split(trim_space(input.apache_config.ssl_protocol), " ")
	tok != ""
	not startswith(tok, "-")
	t := lower(trim_prefix(tok, "+"))
}

# CIS 1.1 - Ensure the pre-installed Apache is removed
default preinstalled_apache_removed := false

preinstalled_apache_removed if {
    input.apache_info.installation_method == "manual"
    input.apache_info.preinstalled_removed == true
}

# CIS 1.2 - Ensure the Apache web server runs as a non-privileged user
default apache_non_privileged_user := false

apache_non_privileged_user if {
    input.apache_config.user != "root"
    input.apache_config.user != ""
    input.apache_config.group != "root"
    input.apache_config.group != ""
}

# CIS 1.3 - Ensure the Apache user account has an invalid shell
default apache_user_invalid_shell := false

apache_user_invalid_shell if {
    shell := input.system_users[input.apache_config.user].shell
    some valid_shell in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
    shell == valid_shell
}

# CIS 1.4 - Ensure the Apache user account is locked
default apache_user_locked := false

apache_user_locked if {
    input.system_users[input.apache_config.user].locked == true
}

# CIS 2.1 - Ensure the minimal modules are installed
default minimal_modules_installed := false

minimal_modules_installed if {
    required_modules := [
        "mod_authz_core",
        "mod_authz_host", 
        "mod_auth_basic",
        "mod_access_compat",
        "mod_authn_core",
        "mod_authn_file",
        "mod_authz_user",
        "mod_alias",
        "mod_dir",
        "mod_mime",
        "mod_rewrite",
        "mod_log_config"
    ]
    modules_collected
    count([module | some module in required_modules; not has_module(module)]) == 0
}

# CIS 2.2 - Ensure mod_dav is disabled
default mod_dav_disabled := false

mod_dav_disabled if {
    modules_collected
    not has_module("mod_dav")
    not has_module("mod_dav_fs")
    not has_module("mod_dav_lock")
}

# CIS 2.3 - Ensure mod_status is disabled
default mod_status_disabled := false

mod_status_disabled if {
    modules_collected
    not has_module("mod_status")
}

# CIS 2.4 - Ensure mod_info is disabled
default mod_info_disabled := false

mod_info_disabled if {
    modules_collected
    not has_module("mod_info")
}

# CIS 2.5 - Ensure mod_autoindex is disabled
default mod_autoindex_disabled := false

mod_autoindex_disabled if {
    modules_collected
    not has_module("mod_autoindex")
}

# CIS 2.6 - Ensure mod_proxy is disabled
default mod_proxy_disabled := false

mod_proxy_disabled if {
    modules_collected
    not has_module("mod_proxy")
    not has_module("mod_proxy_http")
    not has_module("mod_proxy_ftp")
}

# CIS 2.7 - Ensure mod_userdir is disabled
default mod_userdir_disabled := false

mod_userdir_disabled if {
    modules_collected
    not has_module("mod_userdir")
}

# CIS 3.1 - Ensure the Apache directories and files are owned by root
default apache_files_owned_by_root := false

apache_files_owned_by_root if {
    files_collected
    every file in input.apache_file_permissions {
        file.owner == "root"
    }
}

# CIS 3.2 - Ensure the Apache directories and files are not write accessible by group
default apache_files_group_not_writable := false

apache_files_group_not_writable if {
    files_collected
    every file in input.apache_file_permissions {
        bits.and(octal(file.mode), 16) == 0 # group write bit (020)
    }
}

# CIS 3.3 - Ensure the Apache directories and files are not write accessible by others
default apache_files_others_not_writable := false

apache_files_others_not_writable if {
    files_collected
    every file in input.apache_file_permissions {
        bits.and(octal(file.mode), 2) == 0 # other write bit (002)
    }
}

# CIS 3.4 - Ensure core dump directory is secured
default core_dump_directory_secured := false

core_dump_directory_secured if {
    input.apache_config.core_dump_directory != ""
    mode_within(input.file_permissions[input.apache_config.core_dump_directory].mode, "0700")
    input.file_permissions[input.apache_config.core_dump_directory].owner == input.apache_config.user
}

# CIS 3.5 - Ensure the lock file is secured
default lock_file_secured := false

lock_file_secured if {
    input.apache_config.mutex_file != ""
    input.file_permissions[input.apache_config.mutex_file].owner == input.apache_config.user
    mode_within(input.file_permissions[input.apache_config.mutex_file].mode, "0644") # not writable by group/other
}

# CIS 3.6 - Ensure the pid file is secured
default pid_file_secured := false

pid_file_secured if {
    input.apache_config.pid_file != ""
    input.file_permissions[input.apache_config.pid_file].owner == input.apache_config.user
    mode_within(input.file_permissions[input.apache_config.pid_file].mode, "0644")
}

# CIS 3.7 - Ensure the scoreboard file is secured
default scoreboard_file_secured := false

scoreboard_file_secured if {
    input.apache_config.scoreboard_file != ""
    input.file_permissions[input.apache_config.scoreboard_file].owner == input.apache_config.user
    mode_within(input.file_permissions[input.apache_config.scoreboard_file].mode, "0644")
}

# CIS 4.1 - Ensure access to OS root directory is denied
default root_directory_access_denied := false

root_directory_access_denied if {
    input.apache_config.directory_rules["/"].allow_override == "None"
    input.apache_config.directory_rules["/"].require == "all denied"
}

# CIS 4.2 - Ensure appropriate access to web content is allowed
default web_content_access_controlled := false

web_content_access_controlled if {
    input.apache_config.directory_rules[input.apache_config.document_root].options == "None"
    input.apache_config.directory_rules[input.apache_config.document_root].allow_override == "None"
}

# CIS 4.3 - Ensure FollowSymLinks directive is disabled
default follow_symlinks_disabled := false

follow_symlinks_disabled if {
    not contains(input.apache_config.directory_rules[input.apache_config.document_root].options, "FollowSymLinks")
}

# CIS 4.4 - Ensure SymLinksIfOwnerMatch directive is enabled
default symlinks_if_owner_match_enabled := false

symlinks_if_owner_match_enabled if {
    contains(input.apache_config.directory_rules[input.apache_config.document_root].options, "SymLinksIfOwnerMatch")
}

# CIS 4.5 - Ensure the Indexes directive is disabled
default indexes_disabled := false

indexes_disabled if {
    not contains(input.apache_config.directory_rules[input.apache_config.document_root].options, "Indexes")
}

# CIS 4.6 - Ensure the WebDAV modules are disabled
default webdav_modules_disabled := false

webdav_modules_disabled if {
    mod_dav_disabled # Already covered in 2.2
}

# CIS 5.1 - Ensure options for the OS root directory are restricted
default os_root_options_restricted := false

os_root_options_restricted if {
    input.apache_config.directory_rules["/"].options == "None"
}

# CIS 5.2 - Ensure options for the web root directory are restricted
default web_root_options_restricted := false

web_root_options_restricted if {
    input.apache_config.directory_rules[input.apache_config.document_root].options == "None"
}

# CIS 5.3 - Ensure options for other directories are minimized
default other_directories_options_minimized := false

other_directories_options_minimized if {
    every path, dir in input.apache_config.directory_rules {
        apache_directory_check_passes(path, dir, input.apache_config.document_root)
    }
}

apache_directory_check_passes(path, _, _) if {
    path == "/"
}

apache_directory_check_passes(path, _, doc_root) if {
    path == doc_root
}

apache_directory_check_passes(_, dir, _) if {
    not contains(dir.options, "Includes")
    not contains(dir.options, "ExecCGI")
}

# CIS 6.1 - Ensure the Error Log file is properly secured
default error_log_secured := false

error_log_secured if {
    input.apache_config.error_log != ""
    input.file_permissions[input.apache_config.error_log].owner == input.apache_config.user
    mode_within(input.file_permissions[input.apache_config.error_log].mode, "0640")
}

# CIS 6.2 - Ensure the Access Log file is properly secured
default access_log_secured := false

access_log_secured if {
    input.apache_config.access_log != ""
    input.file_permissions[input.apache_config.access_log].owner == input.apache_config.user
    mode_within(input.file_permissions[input.apache_config.access_log].mode, "0640")
}

# CIS 6.3 - Ensure the LogLevel directive is enabled
default log_level_enabled := false

log_level_enabled if {
    input.apache_config.log_level in ["warn", "notice", "info"]
}

# CIS 6.4 - Ensure log files are rotated
default log_rotation_configured := false

log_rotation_configured if {
    input.apache_config.log_rotation.enabled == true
    input.apache_config.log_rotation.max_size_mb <= 100
    input.apache_config.log_rotation.retention_days <= 30
}

# CIS 7.1 - Ensure mod_ssl is enabled
default mod_ssl_enabled := false

mod_ssl_enabled if {
    modules_collected
    has_module("mod_ssl")
}

# CIS 7.2 - Ensure a valid trusted certificate is installed
default valid_certificate_installed := false

valid_certificate_installed if {
    input.apache_config.ssl_certificate != ""
    input.apache_config.ssl_certificate_key != ""
    input.apache_config.ssl_ca_certificate != ""
}

# CIS 7.3 - Ensure the private key is protected
default private_key_protected := false

private_key_protected if {
    mode_within(input.file_permissions[input.apache_config.ssl_certificate_key].mode, "0400")
    input.file_permissions[input.apache_config.ssl_certificate_key].owner == input.apache_config.user
}

# CIS 7.4 - Ensure insecure SSL protocols are disabled
default insecure_ssl_protocols_disabled := false

insecure_ssl_protocols_disabled if {
    is_string(input.apache_config.ssl_protocol)
    insecure := {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1", "all"}
    count(ssl_enabled_tokens & insecure) == 0
    "tlsv1.2" in ssl_enabled_tokens
    "tlsv1.3" in ssl_enabled_tokens
}

# CIS 7.5 - Ensure weak SSL cipher suites are disabled
default weak_ciphers_disabled := false

weak_ciphers_disabled if {
    not contains(input.apache_config.ssl_cipher_suite, "NULL")
    not contains(input.apache_config.ssl_cipher_suite, "aNULL")
    not contains(input.apache_config.ssl_cipher_suite, "eNULL")
    not contains(input.apache_config.ssl_cipher_suite, "EXPORT")
    not contains(input.apache_config.ssl_cipher_suite, "DES")
    not contains(input.apache_config.ssl_cipher_suite, "RC4")
    not contains(input.apache_config.ssl_cipher_suite, "MD5")
    contains(input.apache_config.ssl_cipher_suite, "ECDHE")
}

# CIS 8.1 - Ensure ServerTokens directive is set to Prod
default server_tokens_minimal := false

server_tokens_minimal if {
    input.apache_config.server_tokens == "Prod"
}

# CIS 8.2 - Ensure ServerSignature directive is disabled
default server_signature_disabled := false

server_signature_disabled if {
    input.apache_config.server_signature == "Off"
}

# CIS 8.3 - Ensure all default Apache content is removed
default default_content_removed := false

default_content_removed if {
    input.apache_config.default_content_removed == true
}

# CIS 8.4 - Ensure ETag header is disabled
default etag_disabled := false

etag_disabled if {
    input.apache_config.file_etag == "None"
}

# Aggregate Apache server compliance
default apache_server_compliant := false

apache_server_compliant if {
    preinstalled_apache_removed
    apache_non_privileged_user
    apache_user_invalid_shell
    apache_user_locked
    minimal_modules_installed
    mod_dav_disabled
    mod_status_disabled
    mod_info_disabled
    mod_autoindex_disabled
    mod_proxy_disabled
    mod_userdir_disabled
    apache_files_owned_by_root
    apache_files_group_not_writable
    apache_files_others_not_writable
    core_dump_directory_secured
    lock_file_secured
    pid_file_secured
    scoreboard_file_secured
    root_directory_access_denied
    web_content_access_controlled
    follow_symlinks_disabled
    symlinks_if_owner_match_enabled
    indexes_disabled
    os_root_options_restricted
    web_root_options_restricted
    other_directories_options_minimized
    error_log_secured
    access_log_secured
    log_level_enabled
    log_rotation_configured
    mod_ssl_enabled
    valid_certificate_installed
    private_key_protected
    insecure_ssl_protocols_disabled
    weak_ciphers_disabled
    server_tokens_minimal
    server_signature_disabled
    default_content_removed
    etag_disabled
}

# Detailed Apache server compliance report
apache_server_compliance := {
    "preinstalled_apache_removed": preinstalled_apache_removed,
    "apache_non_privileged_user": apache_non_privileged_user,
    "apache_user_invalid_shell": apache_user_invalid_shell,
    "apache_user_locked": apache_user_locked,
    "minimal_modules_installed": minimal_modules_installed,
    "mod_dav_disabled": mod_dav_disabled,
    "mod_status_disabled": mod_status_disabled,
    "mod_info_disabled": mod_info_disabled,
    "mod_autoindex_disabled": mod_autoindex_disabled,
    "mod_proxy_disabled": mod_proxy_disabled,
    "mod_userdir_disabled": mod_userdir_disabled,
    "apache_files_owned_by_root": apache_files_owned_by_root,
    "apache_files_group_not_writable": apache_files_group_not_writable,
    "apache_files_others_not_writable": apache_files_others_not_writable,
    "core_dump_directory_secured": core_dump_directory_secured,
    "lock_file_secured": lock_file_secured,
    "pid_file_secured": pid_file_secured,
    "scoreboard_file_secured": scoreboard_file_secured,
    "root_directory_access_denied": root_directory_access_denied,
    "web_content_access_controlled": web_content_access_controlled,
    "follow_symlinks_disabled": follow_symlinks_disabled,
    "symlinks_if_owner_match_enabled": symlinks_if_owner_match_enabled,
    "indexes_disabled": indexes_disabled,
    "os_root_options_restricted": os_root_options_restricted,
    "web_root_options_restricted": web_root_options_restricted,
    "other_directories_options_minimized": other_directories_options_minimized,
    "error_log_secured": error_log_secured,
    "access_log_secured": access_log_secured,
    "log_level_enabled": log_level_enabled,
    "log_rotation_configured": log_rotation_configured,
    "mod_ssl_enabled": mod_ssl_enabled,
    "valid_certificate_installed": valid_certificate_installed,
    "private_key_protected": private_key_protected,
    "insecure_ssl_protocols_disabled": insecure_ssl_protocols_disabled,
    "weak_ciphers_disabled": weak_ciphers_disabled,
    "server_tokens_minimal": server_tokens_minimal,
    "server_signature_disabled": server_signature_disabled,
    "default_content_removed": default_content_removed,
    "etag_disabled": etag_disabled,
    "overall_compliant": apache_server_compliant
}