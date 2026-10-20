# METADATA
# title: "CIS NGINX Benchmark v3.1.0"
# custom:
#   class: security
#   framework: cis_nginx
#   source: cis
#   domains: [web-server]
#   coverage:
#     checks: 44
#     cited: 44
#     expected: 44
#     found: 44
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_nginx_1_20

# CIS NGINX Benchmark v3.1.0
# The package name (cis_nginx_1_20) is kept so existing callers keep working; it no longer refers to NGINX 1.20.
# 44 recommendations, every one in the benchmark; ids, titles, levels, profiles and assessment status read from the
# CIS workbook. Every recommendation in v3.1.0 is assessed "Manual" by CIS.
# - 39 of them are decided from collected configuration facts, because the audit is a directive or
#   value comparison (the cis.oracle_26ai precedent): 1.1.1, 1.2.2, 2.2.1, 2.2.2, 2.2.3, 2.3.1, 2.3.2, 2.3.3, 2.4.1, 2.4.2, 2.4.3, 2.4.4, 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.1, 3.2, 3.3, 3.4, 4.1.1, 4.1.2, 4.1.3, 4.1.4, 4.1.5, 4.1.6, 4.1.7, 4.1.8, 4.1.9, 4.1.10, 4.1.11, 4.1.12, 5.1.2, 5.2.1, 5.2.2, 5.2.3, 5.3.1, 5.3.2, 5.3.3.
#   They fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# - 5 need a human judgement and use an attestation boolean under input.nginx.attest
#   (not attested => violation): 1.2.1, 2.1.1, 5.1.1, 5.2.4, 5.2.5.
# - 5.2.3 passes on the default (absent or "4 8k"); any other value needs
#   input.nginx.attest.large_client_header_buffers_documented == true.
#
# Profiles: CIS defines Webserver, Proxy and Loadbalancer profiles (Level 1 and Level 2). input.nginx.profiles
# (any of "webserver", "proxy", "loadbalancer") selects the roles this server plays; a recommendation is evaluated
# when one of its profiles is selected. When input.nginx.profiles is absent, empty or names no known profile, every profile applies
# (strictest). All levels are evaluated; `recommendations` lists each id's level and profiles.
#
# Input contract (input.nginx):
#   version                         : installed version, "1.28.0" (from nginx -v)
#   package.update_available        : bool, package manager reports a newer nginx package
#   user.{name,uid,groups[],sudo_allowed,password_locked,shell} : the account in the `user` directive
#   files.not_root_owned[]          : paths under the config dir not owned by root:root
#   files.dir_modes / file_modes    : {path: octal mode} for directories / files under the config dir
#   pid_file.{owner,group,mode}     : the PID file
#   listen_ports[]                  : ports in `listen` directives; authorized_ports[] (optional, default 80, 443)
#   default_server.{present,return_code,ssl_reject_handshake} : the catch-all default_server block
#   directives{name: [values]}      : every occurrence of each directive in `nginx -T` (arguments as one string)
#   probe.error_page_mentions_nginx : bool, an error page body names nginx
#   hidden_files_denied             : bool, a `location ~ /\.` block denies hidden files
#   access_log_off_outside_location : bool, `access_log off` appears in the http or a server block
#   servers[].{ssl,redirects_to_https} : one entry per server block
#   certificates[].chain_trusted    : bool per ssl_certificate, chain verifies to a trusted root
#   private_keys{path: octal mode}  : every ssl_certificate_key file
#   request_method_filter           : bool (optional), an `if ($request_method ...)` filter is used instead of limit_except
#   attest.*                        : attestation booleans for the judgement recommendations

import rego.v1

default compliant := false

compliant if {
	# fail-closed: no facts, no compliance
	input.nginx
	count(violations) == 0
}

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
					array.concat(access_control_violations, performance_violations),
				),
			),
		),
	),
)


# 1 Initial Setup
installation_violations := sort([m | some m in _v_installation])

# 2.2-2.5 Basic Configuration (account, permissions, network, information disclosure)
configuration_violations := sort([m | some m in _v_configuration])

# 3 Logging
logging_violations := sort([m | some m in _v_logging])

# 4 Encryption
ssl_tls_violations := sort([m | some m in _v_ssl_tls])

# 2.1 Minimize NGINX Modules
modules_violations := sort([m | some m in _v_modules])

# 5.1/5.3 Access control and browser security
access_control_violations := sort([m | some m in _v_access_control])

# 5.2 Request limits
performance_violations := sort([m | some m in _v_performance])

# ── helpers ──────────────────────────────────────────────────────────────────
default _selected_profiles := {"webserver", "proxy", "loadbalancer"}

_known_profiles := {"webserver", "proxy", "loadbalancer"}

# only known profile names select; an unknown or empty selection falls back to every profile (fail closed)
_selected_profiles := sel if {
	is_array(input.nginx.profiles)
	sel := {lower(p) | some p in input.nginx.profiles; is_string(p)} & _known_profiles
	count(sel) > 0
}

_applies(id) if {
	some p in recommendations[id].applies_to
	p in _selected_profiles
}

default _config_collected := false

_config_collected if {
	is_object(input.nginx.directives)
	count(input.nginx.directives) > 0
}

# every occurrence of a directive, as trimmed strings (a lone string counts as one occurrence)
_dv(name) := [trim_space(sprintf("%v", [x])) | some x in r] if {
	r := object.get(input.nginx.directives, name, [])
	is_array(r)
}

_dv(name) := [trim_space(r)] if {
	r := object.get(input.nginx.directives, name, [])
	is_string(r)
}

_tokens(s) := [t | some t in regex.split(`\s+`, trim_space(s)); t != ""]

_first(s) := _tokens(s)[0]

# nginx time value to seconds ("10", "10s", "1m", "500ms"); undefined otherwise
_secs(v) := to_number(trim_suffix(lower(v), "s")) if regex.match(`^[0-9]+s?$`, lower(v))

_secs(v) := to_number(trim_suffix(lower(v), "m")) * 60 if regex.match(`^[0-9]+m$`, lower(v))

_secs(v) := to_number(trim_suffix(lower(v), "ms")) / 1000 if regex.match(`^[0-9]+ms$`, lower(v))

# present, and every occurrence is above 0 and at most max seconds (absent = nginx default, which is longer)
_all_secs_within(name, max) if {
	vs := _dv(name)
	count(vs) > 0
	every v in vs {
		_secs(_first(v)) > 0
		_secs(_first(v)) <= max
	}
}

# set explicitly to a low value somewhere (http/server level); location overrides for uploads are allowed
_some_secs_within(name, max) if {
	some v in _dv(name)
	_secs(_first(v)) > 0
	_secs(_first(v)) <= max
}

_all_on(name) if {
	vs := _dv(name)
	count(vs) > 0
	every v in vs { lower(v) == "on" }
}

_tls13_only(name) if {
	vs := _dv(name)
	count(vs) > 0
	every v in vs {
		count(_tokens(v)) > 0
		every t in _tokens(v) { t == "TLSv1.3" }
	}
}

# a proxy that sets proxy_ssl_protocols must also use TLS 1.3 only
default _proxy_protocols_ok := false

_proxy_protocols_ok if count(_dv("proxy_ssl_protocols")) == 0

_proxy_protocols_ok if _tls13_only("proxy_ssl_protocols")

_nologin_shells := {"/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin", "/bin/false", "/usr/bin/false"}

default _authorized_ports := {80, 443}

_authorized_ports := {to_number(p) | some p in input.nginx.authorized_ports} if is_array(input.nginx.authorized_ports)

# 3.1: a log format carrying who/what/when; nginx's built-in "combined" format qualifies
_detailed_format(f) if {
	every v in ["$remote_addr", "$remote_user", "$request", "$status", "$http_user_agent"] { contains(f, v) }
	regex.match(`\$time_(iso8601|local)`, f)
}

_builtin_detailed_formats := {"combined"}

_access_log_uses(fmt) if {
	some a in _dv("access_log")
	toks := _tokens(a)
	count(toks) >= 2
	toks[1] == fmt
}

_error_log_ok(e) if {
	toks := _tokens(e)
	count(toks) > 0
	toks[0] != "/dev/null"
	not _error_log_level_too_high(toks)
}

_error_log_level_too_high(toks) if {
	count(toks) > 1
	lower(toks[1]) in {"crit", "alert", "emerg"}
}

_https_or_redirect(s) if s.ssl == true

_https_or_redirect(s) if s.redirects_to_https == true

_header_name(h) := lower(_first(h))

_header_always(h) if {
	toks := _tokens(h)
	lower(toks[count(toks) - 1]) == "always"
}

_hsts_ok(h) if {
	_header_name(h) == "strict-transport-security"
	l := lower(h)
	m := regex.find_all_string_submatch_n(`max-age=([0-9]+)`, l, 1)
	to_number(m[0][1]) >= 31536000
	contains(l, "includesubdomains")
	_header_always(h)
}

_csp_ok(h) if {
	_header_name(h) == "content-security-policy"
	l := lower(h)
	contains(l, "default-src")
	contains(l, "frame-ancestors")
	not contains(l, "unsafe-inline")
	not contains(l, "unsafe-eval")
	_header_always(h)
}

_good_referrer_policies := {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0


# 1.1.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_1_1 := false

r_1_1_1 if {
	semver.compare(input.nginx.version, "1.28.0") >= 0
}

default e_1_1_1 := false

e_1_1_1 if {
	is_string(input.nginx.version)
	semver.is_valid(input.nginx.version)
}

_v_installation contains "1.1.1: evidence missing — nginx.version not collected" if {
	_applies("1.1.1")
	not e_1_1_1
}

_v_installation contains "1.1.1: Ensure NGINX is installed" if {
	_applies("1.1.1")
	e_1_1_1
	not r_1_1_1
}

# 1.2.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer)
default r_1_2_1 := false

r_1_2_1 if {
	input.nginx.attest.package_repositories_reviewed == true
}

_v_installation contains "1.2.1: Ensure package manager repositories are properly configured (manual review not attested)" if {
	_applies("1.2.1")
	not r_1_2_1
}

# 1.2.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_2_2 := false

r_1_2_2 if {
	input.nginx.package.update_available == false
}

default e_1_2_2 := false

e_1_2_2 if {
	is_boolean(input.nginx.package.update_available)
}

_v_installation contains "1.2.2: evidence missing — nginx.package.update_available not collected" if {
	_applies("1.2.2")
	not e_1_2_2
}

_v_installation contains "1.2.2: Ensure the latest software package is installed" if {
	_applies("1.2.2")
	e_1_2_2
	not r_1_2_2
}

# 2.1.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer)
default r_2_1_1 := false

r_2_1_1 if {
	input.nginx.attest.dynamic_modules_reviewed == true
}

_v_modules contains "2.1.1: Ensure only required dynamic modules are loaded (manual review not attested)" if {
	_applies("2.1.1")
	not r_2_1_1
}

# 2.2.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_1 := false

r_2_2_1 if {
	not input.nginx.user.name in {"", "root"}
	input.nginx.user.uid != 0
	count({lower(g) | some g in input.nginx.user.groups} & {"root", "wheel", "sudo"}) == 0
	input.nginx.user.sudo_allowed == false
}

default e_2_2_1 := false

e_2_2_1 if {
	is_string(input.nginx.user.name)
	is_number(input.nginx.user.uid)
	is_array(input.nginx.user.groups)
	is_boolean(input.nginx.user.sudo_allowed)
}

_v_configuration contains "2.2.1: evidence missing — nginx.user.{name,uid,groups,sudo_allowed} not collected" if {
	_applies("2.2.1")
	not e_2_2_1
}

_v_configuration contains "2.2.1: Ensure that NGINX is run using a non-privileged, dedicated service account" if {
	_applies("2.2.1")
	e_2_2_1
	not r_2_2_1
}

# 2.2.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_2 := false

r_2_2_2 if {
	input.nginx.user.password_locked == true
}

default e_2_2_2 := false

e_2_2_2 if {
	is_boolean(input.nginx.user.password_locked)
}

_v_configuration contains "2.2.2: evidence missing — nginx.user.password_locked not collected" if {
	_applies("2.2.2")
	not e_2_2_2
}

_v_configuration contains "2.2.2: Ensure the NGINX service account is locked" if {
	_applies("2.2.2")
	e_2_2_2
	not r_2_2_2
}

# 2.2.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_3 := false

r_2_2_3 if {
	input.nginx.user.shell in _nologin_shells
}

default e_2_2_3 := false

e_2_2_3 if {
	is_string(input.nginx.user.shell)
}

_v_configuration contains "2.2.3: evidence missing — nginx.user.shell not collected" if {
	_applies("2.2.3")
	not e_2_2_3
}

_v_configuration contains "2.2.3: Ensure the NGINX service account has an invalid shell" if {
	_applies("2.2.3")
	e_2_2_3
	not r_2_2_3
}

# 2.3.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3_1 := false

r_2_3_1 if {
	count(input.nginx.files.not_root_owned) == 0
}

default e_2_3_1 := false

e_2_3_1 if {
	is_array(input.nginx.files.not_root_owned)
}

_v_configuration contains "2.3.1: evidence missing — nginx.files.not_root_owned not collected" if {
	_applies("2.3.1")
	not e_2_3_1
}

_v_configuration contains "2.3.1: Ensure NGINX directories and files are owned by root" if {
	_applies("2.3.1")
	e_2_3_1
	not r_2_3_1
}

# 2.3.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3_2 := false

r_2_3_2 if {
	every _, m in input.nginx.files.dir_modes { mode_within(m, "750") }
	every _, m in input.nginx.files.file_modes { mode_within(m, "640") }
}

default e_2_3_2 := false

e_2_3_2 if {
	is_object(input.nginx.files.dir_modes)
	count(input.nginx.files.dir_modes) > 0
	is_object(input.nginx.files.file_modes)
	count(input.nginx.files.file_modes) > 0
}

_v_configuration contains "2.3.2: evidence missing — nginx.files.{dir_modes,file_modes} not collected" if {
	_applies("2.3.2")
	not e_2_3_2
}

_v_configuration contains "2.3.2: Ensure access to NGINX directories and files is restricted" if {
	_applies("2.3.2")
	e_2_3_2
	not r_2_3_2
}

# 2.3.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3_3 := false

r_2_3_3 if {
	input.nginx.pid_file.owner == "root"
	input.nginx.pid_file.group == "root"
	mode_within(input.nginx.pid_file.mode, "644")
}

default e_2_3_3 := false

e_2_3_3 if {
	is_object(input.nginx.pid_file)
	is_string(input.nginx.pid_file.owner)
	is_string(input.nginx.pid_file.group)
	_ = input.nginx.pid_file.mode
}

_v_configuration contains "2.3.3: evidence missing — nginx.pid_file.{owner,group,mode} not collected" if {
	_applies("2.3.3")
	not e_2_3_3
}

_v_configuration contains "2.3.3: Ensure the NGINX process ID (PID) file is secured" if {
	_applies("2.3.3")
	e_2_3_3
	not r_2_3_3
}

# 2.4.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_1 := false

r_2_4_1 if {
	every p in input.nginx.listen_ports { to_number(p) in _authorized_ports }
}

default e_2_4_1 := false

e_2_4_1 if {
	is_array(input.nginx.listen_ports)
	count(input.nginx.listen_ports) > 0
}

_v_configuration contains "2.4.1: evidence missing — nginx.listen_ports not collected" if {
	_applies("2.4.1")
	not e_2_4_1
}

_v_configuration contains "2.4.1: Ensure NGINX only listens for network connections on authorized ports" if {
	_applies("2.4.1")
	e_2_4_1
	not r_2_4_1
}

# 2.4.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_2 := false

r_2_4_2 if {
	input.nginx.default_server.present == true
	rc := to_number(input.nginx.default_server.return_code)
	rc >= 400
	rc <= 499
	input.nginx.default_server.ssl_reject_handshake == true
}

default e_2_4_2 := false

e_2_4_2 if {
	is_object(input.nginx.default_server)
	is_boolean(input.nginx.default_server.present)
}

_v_configuration contains "2.4.2: evidence missing — nginx.default_server not collected" if {
	_applies("2.4.2")
	not e_2_4_2
}

_v_configuration contains "2.4.2: Ensure requests for unknown host names are rejected" if {
	_applies("2.4.2")
	e_2_4_2
	not r_2_4_2
}

# 2.4.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_3 := false

r_2_4_3 if {
	_all_secs_within("keepalive_timeout", 10)
}

default e_2_4_3 := false

e_2_4_3 if {
	_config_collected
}

_v_configuration contains "2.4.3: evidence missing — nginx.directives not collected" if {
	_applies("2.4.3")
	not e_2_4_3
}

_v_configuration contains "2.4.3: Ensure keepalive_timeout is 10 seconds or less, but not 0" if {
	_applies("2.4.3")
	e_2_4_3
	not r_2_4_3
}

# 2.4.4 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_4 := false

r_2_4_4 if {
	_all_secs_within("send_timeout", 10)
}

default e_2_4_4 := false

e_2_4_4 if {
	_config_collected
}

_v_configuration contains "2.4.4: evidence missing — nginx.directives not collected" if {
	_applies("2.4.4")
	not e_2_4_4
}

_v_configuration contains "2.4.4: Ensure send_timeout is set to 10 seconds or less, but not 0" if {
	_applies("2.4.4")
	e_2_4_4
	not r_2_4_4
}

# 2.5.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_5_1 := false

r_2_5_1 if {
	vs := _dv("server_tokens")
	count(vs) > 0
	every v in vs { lower(v) == "off" }
}

default e_2_5_1 := false

e_2_5_1 if {
	_config_collected
}

_v_configuration contains "2.5.1: evidence missing — nginx.directives not collected" if {
	_applies("2.5.1")
	not e_2_5_1
}

_v_configuration contains "2.5.1: Ensure server_tokens directive is set to `off`" if {
	_applies("2.5.1")
	e_2_5_1
	not r_2_5_1
}

# 2.5.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_5_2 := false

r_2_5_2 if {
	input.nginx.probe.error_page_mentions_nginx == false
}

default e_2_5_2 := false

e_2_5_2 if {
	is_boolean(input.nginx.probe.error_page_mentions_nginx)
}

_v_configuration contains "2.5.2: evidence missing — nginx.probe.error_page_mentions_nginx not collected" if {
	_applies("2.5.2")
	not e_2_5_2
}

_v_configuration contains "2.5.2: Ensure default error and index.html pages do not reference NGINX" if {
	_applies("2.5.2")
	e_2_5_2
	not r_2_5_2
}

# 2.5.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_5_3 := false

r_2_5_3 if {
	input.nginx.hidden_files_denied == true
}

default e_2_5_3 := false

e_2_5_3 if {
	is_boolean(input.nginx.hidden_files_denied)
}

_v_configuration contains "2.5.3: evidence missing — nginx.hidden_files_denied not collected" if {
	_applies("2.5.3")
	not e_2_5_3
}

_v_configuration contains "2.5.3: Ensure hidden file serving is disabled" if {
	_applies("2.5.3")
	e_2_5_3
	not r_2_5_3
}

# 2.5.4 (Manual, Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_5_4 := false

r_2_5_4 if {
	hidden := {lower(_first(v)) | some n in ["proxy_hide_header", "fastcgi_hide_header"]; some v in _dv(n)}
	"x-powered-by" in hidden
	"server" in hidden
}

default e_2_5_4 := false

e_2_5_4 if {
	_config_collected
}

_v_configuration contains "2.5.4: evidence missing — nginx.directives not collected" if {
	_applies("2.5.4")
	not e_2_5_4
}

_v_configuration contains "2.5.4: Ensure the NGINX reverse proxy does not enable information disclosure" if {
	_applies("2.5.4")
	e_2_5_4
	not r_2_5_4
}

# 3.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_1 := false

r_3_1 if {
	some f in _dv("log_format")
	_detailed_format(f)
	_access_log_uses(_first(f))
}

r_3_1 if {
	some n in _builtin_detailed_formats
	_access_log_uses(n)
}

default e_3_1 := false

e_3_1 if {
	_config_collected
}

_v_logging contains "3.1: evidence missing — nginx.directives not collected" if {
	_applies("3.1")
	not e_3_1
}

_v_logging contains "3.1: Ensure detailed logging is enabled" if {
	_applies("3.1")
	e_3_1
	not r_3_1
}

# 3.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2 := false

r_3_2 if {
	some a in _dv("access_log")
	p := _first(a)
	lower(p) != "off"
	p != "/dev/null"
	input.nginx.access_log_off_outside_location == false
}

default e_3_2 := false

e_3_2 if {
	_config_collected
	is_boolean(input.nginx.access_log_off_outside_location)
}

_v_logging contains "3.2: evidence missing — nginx.directives / nginx.access_log_off_outside_location not collected" if {
	_applies("3.2")
	not e_3_2
}

_v_logging contains "3.2: Ensure access logging is enabled" if {
	_applies("3.2")
	e_3_2
	not r_3_2
}

# 3.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_3 := false

r_3_3 if {
	es := _dv("error_log")
	count(es) > 0
	every e in es { _error_log_ok(e) }
}

default e_3_3 := false

e_3_3 if {
	_config_collected
}

_v_logging contains "3.3: evidence missing — nginx.directives not collected" if {
	_applies("3.3")
	not e_3_3
}

_v_logging contains "3.3: Ensure error logging is enabled and set to the info logging level" if {
	_applies("3.3")
	e_3_3
	not r_3_3
}

# 3.4 (Manual, Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_4 := false

r_3_4 if {
	set_hdrs := {lower(_first(v)) | some v in _dv("proxy_set_header")}
	"x-forwarded-for" in set_hdrs
	"x-real-ip" in set_hdrs
}

default e_3_4 := false

e_3_4 if {
	_config_collected
}

_v_logging contains "3.4: evidence missing — nginx.directives not collected" if {
	_applies("3.4")
	not e_3_4
}

_v_logging contains "3.4: Ensure proxies pass source IP information" if {
	_applies("3.4")
	e_3_4
	not r_3_4
}

# 4.1.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_1 := false

r_4_1_1 if {
	every s in input.nginx.servers { _https_or_redirect(s) }
}

default e_4_1_1 := false

e_4_1_1 if {
	is_array(input.nginx.servers)
	count(input.nginx.servers) > 0
}

_v_ssl_tls contains "4.1.1: evidence missing — nginx.servers not collected" if {
	_applies("4.1.1")
	not e_4_1_1
}

_v_ssl_tls contains "4.1.1: Ensure HTTP is redirected to HTTPS" if {
	_applies("4.1.1")
	e_4_1_1
	not r_4_1_1
}

# 4.1.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_2 := false

r_4_1_2 if {
	every c in input.nginx.certificates { c.chain_trusted == true }
}

default e_4_1_2 := false

e_4_1_2 if {
	is_array(input.nginx.certificates)
	count(input.nginx.certificates) > 0
}

_v_ssl_tls contains "4.1.2: evidence missing — nginx.certificates not collected" if {
	_applies("4.1.2")
	not e_4_1_2
}

_v_ssl_tls contains "4.1.2: Ensure a trusted certificate and trust chain is installed" if {
	_applies("4.1.2")
	e_4_1_2
	not r_4_1_2
}

# 4.1.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_3 := false

r_4_1_3 if {
	every _, m in input.nginx.private_keys { mode_within(m, "400") }
}

default e_4_1_3 := false

e_4_1_3 if {
	is_object(input.nginx.private_keys)
	count(input.nginx.private_keys) > 0
}

_v_ssl_tls contains "4.1.3: evidence missing — nginx.private_keys not collected" if {
	_applies("4.1.3")
	not e_4_1_3
}

_v_ssl_tls contains "4.1.3: Ensure private key permissions are restricted" if {
	_applies("4.1.3")
	e_4_1_3
	not r_4_1_3
}

# 4.1.4 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_4 := false

r_4_1_4 if {
	_tls13_only("ssl_protocols")
	_proxy_protocols_ok
}

default e_4_1_4 := false

e_4_1_4 if {
	_config_collected
}

_v_ssl_tls contains "4.1.4: evidence missing — nginx.directives not collected" if {
	_applies("4.1.4")
	not e_4_1_4
}

_v_ssl_tls contains "4.1.4: Ensure only modern TLS protocols are used" if {
	_applies("4.1.4")
	e_4_1_4
	not r_4_1_4
}

# 4.1.5 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_5 := false

r_4_1_5 if {
	_tls13_only("ssl_protocols")
}

default e_4_1_5 := false

e_4_1_5 if {
	_config_collected
}

_v_ssl_tls contains "4.1.5: evidence missing — nginx.directives not collected" if {
	_applies("4.1.5")
	not e_4_1_5
}

_v_ssl_tls contains "4.1.5: Disable weak ciphers" if {
	_applies("4.1.5")
	e_4_1_5
	not r_4_1_5
}

# 4.1.6 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_6 := false

r_4_1_6 if {
	_tls13_only("ssl_protocols")
}

r_4_1_6 if {
	count(_dv("ssl_dhparam")) > 0
}

default e_4_1_6 := false

e_4_1_6 if {
	_config_collected
}

_v_ssl_tls contains "4.1.6: evidence missing — nginx.directives not collected" if {
	_applies("4.1.6")
	not e_4_1_6
}

_v_ssl_tls contains "4.1.6: Ensure awareness of TLS 1.3 new Diffie-Hellman parameters" if {
	_applies("4.1.6")
	e_4_1_6
	not r_4_1_6
}

# 4.1.7 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_7 := false

r_4_1_7 if {
	_all_on("ssl_stapling")
	_all_on("ssl_stapling_verify")
	count(_dv("ssl_trusted_certificate")) > 0
	count(_dv("resolver")) > 0
}

default e_4_1_7 := false

e_4_1_7 if {
	_config_collected
}

_v_ssl_tls contains "4.1.7: evidence missing — nginx.directives not collected" if {
	_applies("4.1.7")
	not e_4_1_7
}

_v_ssl_tls contains "4.1.7: Ensure Online Certificate Status Protocol (OCSP) stapling is enabled" if {
	_applies("4.1.7")
	e_4_1_7
	not r_4_1_7
}

# 4.1.8 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_8 := false

r_4_1_8 if {
	some h in _dv("add_header")
	_hsts_ok(h)
}

default e_4_1_8 := false

e_4_1_8 if {
	_config_collected
}

_v_ssl_tls contains "4.1.8: evidence missing — nginx.directives not collected" if {
	_applies("4.1.8")
	not e_4_1_8
}

_v_ssl_tls contains "4.1.8: Ensure HTTP Strict Transport Security (HSTS) is enabled" if {
	_applies("4.1.8")
	e_4_1_8
	not r_4_1_8
}

# 4.1.9 (Manual, Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_9 := false

r_4_1_9 if {
	count(_dv("proxy_ssl_certificate")) > 0
	count(_dv("proxy_ssl_certificate_key")) > 0
}

default e_4_1_9 := false

e_4_1_9 if {
	_config_collected
}

_v_ssl_tls contains "4.1.9: evidence missing — nginx.directives not collected" if {
	_applies("4.1.9")
	not e_4_1_9
}

_v_ssl_tls contains "4.1.9: Ensure upstream server traffic is authenticated with a client certificate" if {
	_applies("4.1.9")
	e_4_1_9
	not r_4_1_9
}

# 4.1.10 (Manual, Level 2 - Proxy; Level 2 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_10 := false

r_4_1_10 if {
	_all_on("proxy_ssl_verify")
	count(_dv("proxy_ssl_trusted_certificate")) > 0
	count(_dv("proxy_ssl_name")) > 0
}

default e_4_1_10 := false

e_4_1_10 if {
	_config_collected
}

_v_ssl_tls contains "4.1.10: evidence missing — nginx.directives not collected" if {
	_applies("4.1.10")
	not e_4_1_10
}

_v_ssl_tls contains "4.1.10: Ensure the upstream traffic server certificate is trusted" if {
	_applies("4.1.10")
	e_4_1_10
	not r_4_1_10
}

# 4.1.11 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_11 := false

r_4_1_11 if {
	every v in _dv("ssl_session_tickets") { lower(v) != "off" }
}

default e_4_1_11 := false

e_4_1_11 if {
	_config_collected
}

_v_ssl_tls contains "4.1.11: evidence missing — nginx.directives not collected" if {
	_applies("4.1.11")
	not e_4_1_11
}

_v_ssl_tls contains "4.1.11: Ensure Secure Session Resumption is Enabled" if {
	_applies("4.1.11")
	e_4_1_11
	not r_4_1_11
}

# 4.1.12 (Manual, Level 2 - Webserver) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_12 := false

r_4_1_12 if {
	_all_on("http2")
	some l in _dv("listen")
	"quic" in _tokens(l)
	some h in _dv("add_header")
	_header_name(h) == "alt-svc"
}

default e_4_1_12 := false

e_4_1_12 if {
	_config_collected
}

_v_ssl_tls contains "4.1.12: evidence missing — nginx.directives not collected" if {
	_applies("4.1.12")
	not e_4_1_12
}

_v_ssl_tls contains "4.1.12: Ensure HTTP/3.0 is used" if {
	_applies("4.1.12")
	e_4_1_12
	not r_4_1_12
}

# 5.1.1 (Manual, Level 2 - Webserver; Level 2 - Proxy; Level 2 - Loadbalancer)
default r_5_1_1 := false

r_5_1_1 if {
	input.nginx.attest.ip_allow_deny_reviewed == true
}

_v_access_control contains "5.1.1: Ensure allow and deny filters limit access to specific IP addresses (manual review not attested)" if {
	_applies("5.1.1")
	not r_5_1_1
}

# 5.1.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_1_2 := false

r_5_1_2 if {
	count(_dv("limit_except")) > 0
}

r_5_1_2 if {
	input.nginx.request_method_filter == true
}

default e_5_1_2 := false

e_5_1_2 if {
	_config_collected
}

_v_access_control contains "5.1.2: evidence missing — nginx.directives not collected" if {
	_applies("5.1.2")
	not e_5_1_2
}

_v_access_control contains "5.1.2: Ensure only approved HTTP methods are allowed" if {
	_applies("5.1.2")
	e_5_1_2
	not r_5_1_2
}

# 5.2.1 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_2_1 := false

r_5_2_1 if {
	_some_secs_within("client_header_timeout", 20)
	_some_secs_within("client_body_timeout", 20)
}

default e_5_2_1 := false

e_5_2_1 if {
	_config_collected
}

_v_performance contains "5.2.1: evidence missing — nginx.directives not collected" if {
	_applies("5.2.1")
	not e_5_2_1
}

_v_performance contains "5.2.1: Ensure timeout values for reading the client header and body are set correctly" if {
	_applies("5.2.1")
	e_5_2_1
	not r_5_2_1
}

# 5.2.2 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_2_2 := false

r_5_2_2 if {
	count(_dv("client_max_body_size")) > 0
}

default e_5_2_2 := false

e_5_2_2 if {
	_config_collected
}

_v_performance contains "5.2.2: evidence missing — nginx.directives not collected" if {
	_applies("5.2.2")
	not e_5_2_2
}

_v_performance contains "5.2.2: Ensure the maximum request body size is set correctly" if {
	_applies("5.2.2")
	e_5_2_2
	not r_5_2_2
}

# 5.2.3 (Manual, Level 1 - Webserver; Level 1 - Proxy; Level 1 - Loadbalancer) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_2_3 := false

r_5_2_3 if {
	every v in _dv("large_client_header_buffers") { _tokens(v) == ["4", "8k"] }
}

r_5_2_3 if {
	input.nginx.attest.large_client_header_buffers_documented == true
}

default e_5_2_3 := false

e_5_2_3 if {
	_config_collected
}

_v_performance contains "5.2.3: evidence missing — nginx.directives not collected" if {
	_applies("5.2.3")
	not e_5_2_3
}

_v_performance contains "5.2.3: Ensure the maximum buffer size for URIs is defined" if {
	_applies("5.2.3")
	e_5_2_3
	not r_5_2_3
}

# 5.2.4 (Manual, Level 2 - Webserver; Level 2 - Proxy; Level 2 - Loadbalancer)
default r_5_2_4 := false

r_5_2_4 if {
	input.nginx.attest.connection_limits_reviewed == true
}

_v_performance contains "5.2.4: Ensure the number of connections per IP address is limited (manual review not attested)" if {
	_applies("5.2.4")
	not r_5_2_4
}

# 5.2.5 (Manual, Level 2 - Webserver; Level 2 - Proxy; Level 2 - Loadbalancer)
default r_5_2_5 := false

r_5_2_5 if {
	input.nginx.attest.rate_limits_reviewed == true
}

_v_performance contains "5.2.5: Ensure rate limits by IP address are set (manual review not attested)" if {
	_applies("5.2.5")
	not r_5_2_5
}

# 5.3.1 (Manual, Level 1 - Webserver) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_3_1 := false

r_5_3_1 if {
	some h in _dv("add_header")
	_header_name(h) == "x-content-type-options"
	contains(lower(h), "nosniff")
	_header_always(h)
}

default e_5_3_1 := false

e_5_3_1 if {
	_config_collected
}

_v_access_control contains "5.3.1: evidence missing — nginx.directives not collected" if {
	_applies("5.3.1")
	not e_5_3_1
}

_v_access_control contains "5.3.1: Ensure X-Content-Type-Options header is configured and enabled" if {
	_applies("5.3.1")
	e_5_3_1
	not r_5_3_1
}

# 5.3.2 (Manual, Level 2 - Webserver) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_3_2 := false

r_5_3_2 if {
	some h in _dv("add_header")
	_csp_ok(h)
}

default e_5_3_2 := false

e_5_3_2 if {
	_config_collected
}

_v_access_control contains "5.3.2: evidence missing — nginx.directives not collected" if {
	_applies("5.3.2")
	not e_5_3_2
}

_v_access_control contains "5.3.2: Ensure that Content Security Policy (CSP) is enabled and configured properly" if {
	_applies("5.3.2")
	e_5_3_2
	not r_5_3_2
}

# 5.3.3 (Manual, Level 2 - Webserver) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_3_3 := false

r_5_3_3 if {
	some h in _dv("add_header")
	_header_name(h) == "referrer-policy"
	trim(_tokens(h)[1], "\"'") in _good_referrer_policies
	_header_always(h)
}

default e_5_3_3 := false

e_5_3_3 if {
	_config_collected
}

_v_access_control contains "5.3.3: evidence missing — nginx.directives not collected" if {
	_applies("5.3.3")
	not e_5_3_3
}

_v_access_control contains "5.3.3: Ensure the Referrer Policy is enabled and configured properly" if {
	_applies("5.3.3")
	e_5_3_3
	not r_5_3_3
}

# Every recommendation in the benchmark: title, level, assessment status, CIS profiles, roles it applies to.
recommendations := {
	"1.1.1": {
		"title": "Ensure NGINX is installed",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "installation"
	},
	"1.2.1": {
		"title": "Ensure package manager repositories are properly configured",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "attestation",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "installation"
	},
	"1.2.2": {
		"title": "Ensure the latest software package is installed",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "installation"
	},
	"2.1.1": {
		"title": "Ensure only required dynamic modules are loaded",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "attestation",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "modules"
	},
	"2.2.1": {
		"title": "Ensure that NGINX is run using a non-privileged, dedicated service account",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.2.2": {
		"title": "Ensure the NGINX service account is locked",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.2.3": {
		"title": "Ensure the NGINX service account has an invalid shell",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.3.1": {
		"title": "Ensure NGINX directories and files are owned by root",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.3.2": {
		"title": "Ensure access to NGINX directories and files is restricted",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.3.3": {
		"title": "Ensure the NGINX process ID (PID) file is secured",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.4.1": {
		"title": "Ensure NGINX only listens for network connections on authorized ports",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.4.2": {
		"title": "Ensure requests for unknown host names are rejected",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.4.3": {
		"title": "Ensure keepalive_timeout is 10 seconds or less, but not 0",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.4.4": {
		"title": "Ensure send_timeout is set to 10 seconds or less, but not 0",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.5.1": {
		"title": "Ensure server_tokens directive is set to `off`",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.5.2": {
		"title": "Ensure default error and index.html pages do not reference NGINX",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.5.3": {
		"title": "Ensure hidden file serving is disabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "configuration"
	},
	"2.5.4": {
		"title": "Ensure the NGINX reverse proxy does not enable information disclosure",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy"
		],
		"section": "configuration"
	},
	"3.1": {
		"title": "Ensure detailed logging is enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "logging"
	},
	"3.2": {
		"title": "Ensure access logging is enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "logging"
	},
	"3.3": {
		"title": "Ensure error logging is enabled and set to the info logging level",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "logging"
	},
	"3.4": {
		"title": "Ensure proxies pass source IP information",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy"
		],
		"section": "logging"
	},
	"4.1.1": {
		"title": "Ensure HTTP is redirected to HTTPS",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.2": {
		"title": "Ensure a trusted certificate and trust chain is installed",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.3": {
		"title": "Ensure private key permissions are restricted",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.4": {
		"title": "Ensure only modern TLS protocols are used",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.5": {
		"title": "Disable weak ciphers",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.6": {
		"title": "Ensure awareness of TLS 1.3 new Diffie-Hellman parameters",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.7": {
		"title": "Ensure Online Certificate Status Protocol (OCSP) stapling is enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.8": {
		"title": "Ensure HTTP Strict Transport Security (HSTS) is enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.9": {
		"title": "Ensure upstream server traffic is authenticated with a client certificate",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy"
		],
		"section": "ssl_tls"
	},
	"4.1.10": {
		"title": "Ensure the upstream traffic server certificate is trusted",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Proxy",
			"Level 2 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy"
		],
		"section": "ssl_tls"
	},
	"4.1.11": {
		"title": "Ensure Secure Session Resumption is Enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "ssl_tls"
	},
	"4.1.12": {
		"title": "Ensure HTTP/3.0 is used",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver"
		],
		"check": "configuration",
		"applies_to": [
			"webserver"
		],
		"section": "ssl_tls"
	},
	"5.1.1": {
		"title": "Ensure allow and deny filters limit access to specific IP addresses",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver",
			"Level 2 - Proxy",
			"Level 2 - Loadbalancer"
		],
		"check": "attestation",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "access_control"
	},
	"5.1.2": {
		"title": "Ensure only approved HTTP methods are allowed",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "access_control"
	},
	"5.2.1": {
		"title": "Ensure timeout values for reading the client header and body are set correctly",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "performance"
	},
	"5.2.2": {
		"title": "Ensure the maximum request body size is set correctly",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "performance"
	},
	"5.2.3": {
		"title": "Ensure the maximum buffer size for URIs is defined",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver",
			"Level 1 - Proxy",
			"Level 1 - Loadbalancer"
		],
		"check": "configuration",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "performance"
	},
	"5.2.4": {
		"title": "Ensure the number of connections per IP address is limited",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver",
			"Level 2 - Proxy",
			"Level 2 - Loadbalancer"
		],
		"check": "attestation",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "performance"
	},
	"5.2.5": {
		"title": "Ensure rate limits by IP address are set",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver",
			"Level 2 - Proxy",
			"Level 2 - Loadbalancer"
		],
		"check": "attestation",
		"applies_to": [
			"loadbalancer",
			"proxy",
			"webserver"
		],
		"section": "performance"
	},
	"5.3.1": {
		"title": "Ensure X-Content-Type-Options header is configured and enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1 - Webserver"
		],
		"check": "configuration",
		"applies_to": [
			"webserver"
		],
		"section": "access_control"
	},
	"5.3.2": {
		"title": "Ensure that Content Security Policy (CSP) is enabled and configured properly",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver"
		],
		"check": "configuration",
		"applies_to": [
			"webserver"
		],
		"section": "access_control"
	},
	"5.3.3": {
		"title": "Ensure the Referrer Policy is enabled and configured properly",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2 - Webserver"
		],
		"check": "configuration",
		"applies_to": [
			"webserver"
		],
		"section": "access_control"
	}
}


default _applicable_ids := set()

_applicable_ids := {id | some id, _ in recommendations; _applies(id)}

_failed_ids := {id | some v in violations; id := split(v, ":")[0]}

findings := [{
	"title": "NGINX Installation and Configuration Security",
	"description": "CIS NGINX Benchmark v3.1.0 assessment of installation, service account, file permissions, network and information-disclosure settings, logging, TLS, and request filtering",
	"severity": "HIGH",
	"details": sprintf("Found %d violations across %d recommendations", [count(violations), count(_failed_ids)]),
	"violations": violations,
	"remediation": "Apply the CIS NGINX Benchmark v3.1.0 recommendation named in each violation; collect the missing facts where a violation reports evidence missing",
}]

compliance_report := {
	"benchmark": "CIS NGINX Benchmark v3.1.0",
	"total_controls": count(recommendations),
	"standard_total": 44,
	"standard_total_source": "CIS NGINX Benchmark v3.1.0, recommendations counted from the CIS workbook",
	"applicable_controls": count(_applicable_ids),
	"profiles": sort([p | some p in _selected_profiles]),
	"failed_controls": count(_failed_ids),
	"passed_controls": count(_applicable_ids) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
