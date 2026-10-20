import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import load_workbook_json, emit_control, emit_tests, table, u  # noqa: E402

WB = load_workbook_json(sys.argv[1])  # JSON from dump_workbook.py
OUT = sys.argv[2]  # benchmarks/cis/nginx dir
BENCH = "CIS NGINX Benchmark v3.1.0"
N = "input.nginx"
CFG = ["_config_collected"]
CFG_LABEL = "nginx.directives"
CFG_MISS = [{"op": "remove", "path": "/nginx/directives"}]


def rep(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def d(name, value):
    return rep(f"/nginx/directives/{name}", value)


def cfg(cid, ok, fail, ok2=None):
    oks = [ok] + ([ok2] if ok2 else [])
    return {"id": cid, "kind": "fact", "ev": CFG, "label": CFG_LABEL, "ok": oks, "fail": fail, "miss": CFG_MISS}


def fact(cid, ev, label, ok, fail, miss, ok2=None):
    oks = [ok] + ([ok2] if ok2 else [])
    return {"id": cid, "kind": "fact", "ev": ev, "label": label, "ok": oks, "fail": fail, "miss": miss}


def att(cid, key):
    return {"id": cid, "kind": "attest", "attest": key, "attest_root": N}


C = [
    fact("1.1.1", [f"is_string({N}.version)", f"semver.is_valid({N}.version)"], "nginx.version",
         [f'semver.compare({N}.version, "1.28.0") >= 0'], rep("/nginx/version", "1.24.0"), rm("/nginx/version")),
    att("1.2.1", "package_repositories_reviewed"),
    fact("1.2.2", [f"is_boolean({N}.package.update_available)"], "nginx.package.update_available",
         [f"{N}.package.update_available == false"], rep("/nginx/package/update_available", True),
         rm("/nginx/package/update_available")),
    att("2.1.1", "dynamic_modules_reviewed"),
    fact("2.2.1", [f"is_string({N}.user.name)", f"is_number({N}.user.uid)", f"is_array({N}.user.groups)",
                   f"is_boolean({N}.user.sudo_allowed)"], "nginx.user.{name,uid,groups,sudo_allowed}",
         [f'not {N}.user.name in {{"", "root"}}', f"{N}.user.uid != 0",
          f'count({{lower(g) | some g in {N}.user.groups}} & {{"root", "wheel", "sudo"}}) == 0',
          f"{N}.user.sudo_allowed == false"],
         rep("/nginx/user/uid", 0), rm("/nginx/user/sudo_allowed")),
    fact("2.2.2", [f"is_boolean({N}.user.password_locked)"], "nginx.user.password_locked",
         [f"{N}.user.password_locked == true"], rep("/nginx/user/password_locked", False),
         rm("/nginx/user/password_locked")),
    fact("2.2.3", [f"is_string({N}.user.shell)"], "nginx.user.shell",
         [f"{N}.user.shell in _nologin_shells"], rep("/nginx/user/shell", "/bin/bash"), rm("/nginx/user/shell")),
    fact("2.3.1", [f"is_array({N}.files.not_root_owned)"], "nginx.files.not_root_owned",
         [f"count({N}.files.not_root_owned) == 0"], rep("/nginx/files/not_root_owned", ["/etc/nginx/conf.d/app.conf"]),
         rm("/nginx/files/not_root_owned")),
    fact("2.3.2", [f"is_object({N}.files.dir_modes)", f"count({N}.files.dir_modes) > 0",
                   f"is_object({N}.files.file_modes)", f"count({N}.files.file_modes) > 0"],
         "nginx.files.{dir_modes,file_modes}",
         [f'every _, m in {N}.files.dir_modes {{ mode_within(m, "750") }}',
          f'every _, m in {N}.files.file_modes {{ mode_within(m, "640") }}'],
         rep("/nginx/files/file_modes/~1etc~1nginx~1nginx.conf", "644"), rm("/nginx/files/file_modes")),
    fact("2.3.3", [f"is_object({N}.pid_file)", f"is_string({N}.pid_file.owner)", f"is_string({N}.pid_file.group)",
                   f"_ = {N}.pid_file.mode"], "nginx.pid_file.{owner,group,mode}",
         [f'{N}.pid_file.owner == "root"', f'{N}.pid_file.group == "root"', f'mode_within({N}.pid_file.mode, "644")'],
         rep("/nginx/pid_file/mode", "664"), rm("/nginx/pid_file")),
    fact("2.4.1", [f"is_array({N}.listen_ports)", f"count({N}.listen_ports) > 0"], "nginx.listen_ports",
         [f"every p in {N}.listen_ports {{ to_number(p) in _authorized_ports }}"],
         rep("/nginx/listen_ports", [80, 443, 8080]), rm("/nginx/listen_ports")),
    fact("2.4.2", [f"is_object({N}.default_server)", f"is_boolean({N}.default_server.present)"],
         "nginx.default_server",
         [f"{N}.default_server.present == true", f"rc := to_number({N}.default_server.return_code)", "rc >= 400",
          "rc <= 499", f"{N}.default_server.ssl_reject_handshake == true"],
         rep("/nginx/default_server/ssl_reject_handshake", False), rm("/nginx/default_server")),
    cfg("2.4.3", ['_all_secs_within("keepalive_timeout", 10)'], d("keepalive_timeout", ["75"])),
    cfg("2.4.4", ['_all_secs_within("send_timeout", 10)'], d("send_timeout", ["0"])),
    cfg("2.5.1", ['vs := _dv("server_tokens")', "count(vs) > 0", 'every v in vs { lower(v) == "off" }'],
        d("server_tokens", ["on"])),
    fact("2.5.2", [f"is_boolean({N}.probe.error_page_mentions_nginx)"], "nginx.probe.error_page_mentions_nginx",
         [f"{N}.probe.error_page_mentions_nginx == false"], rep("/nginx/probe/error_page_mentions_nginx", True),
         rm("/nginx/probe/error_page_mentions_nginx")),
    fact("2.5.3", [f"is_boolean({N}.hidden_files_denied)"], "nginx.hidden_files_denied",
         [f"{N}.hidden_files_denied == true"], rep("/nginx/hidden_files_denied", False), rm("/nginx/hidden_files_denied")),
    cfg("2.5.4", ['hidden := {lower(_first(v)) | some n in ["proxy_hide_header", "fastcgi_hide_header"]; some v in _dv(n)}',
                  '"x-powered-by" in hidden', '"server" in hidden'],
        d("proxy_hide_header", ["X-Powered-By"])),
    cfg("3.1", ["some f in _dv(\"log_format\")", "_detailed_format(f)", "_access_log_uses(_first(f))"],
        d("log_format", ["main '$remote_addr $status'"]),
        ok2=['some n in _builtin_detailed_formats', "_access_log_uses(n)"]),
    fact("3.2", CFG + [f"is_boolean({N}.access_log_off_outside_location)"],
         "nginx.directives / nginx.access_log_off_outside_location",
         ['some a in _dv("access_log")', "p := _first(a)", 'lower(p) != "off"', 'p != "/dev/null"',
          f"{N}.access_log_off_outside_location == false"],
         rep("/nginx/access_log_off_outside_location", True), rm("/nginx/access_log_off_outside_location")),
    cfg("3.3", ['es := _dv("error_log")', "count(es) > 0", "every e in es { _error_log_ok(e) }"],
        d("error_log", ["/var/log/nginx/error.log crit"])),
    cfg("3.4", ['set_hdrs := {lower(_first(v)) | some v in _dv("proxy_set_header")}', '"x-forwarded-for" in set_hdrs',
                '"x-real-ip" in set_hdrs'], d("proxy_set_header", ["X-Forwarded-For $proxy_add_x_forwarded_for"])),
    fact("4.1.1", [f"is_array({N}.servers)", f"count({N}.servers) > 0"], "nginx.servers",
         [f"every s in {N}.servers {{ _https_or_redirect(s) }}"],
         [{"op": "add", "path": "/nginx/servers/-", "value": {"name": "plain", "ssl": False, "redirects_to_https": False}}],
         rm("/nginx/servers")),
    fact("4.1.2", [f"is_array({N}.certificates)", f"count({N}.certificates) > 0"], "nginx.certificates",
         [f"every c in {N}.certificates {{ c.chain_trusted == true }}"],
         rep("/nginx/certificates/0/chain_trusted", False), rm("/nginx/certificates")),
    fact("4.1.3", [f"is_object({N}.private_keys)", f"count({N}.private_keys) > 0"], "nginx.private_keys",
         [f'every _, m in {N}.private_keys {{ mode_within(m, "400") }}'],
         rep("/nginx/private_keys/~1etc~1nginx~1ssl~1site.key", "640"), rm("/nginx/private_keys")),
    cfg("4.1.4", ['_tls13_only("ssl_protocols")', '_proxy_protocols_ok'], d("ssl_protocols", ["TLSv1.2 TLSv1.3"])),
    cfg("4.1.5", ['_tls13_only("ssl_protocols")'], d("ssl_protocols", ["TLSv1.2 TLSv1.3"])),
    cfg("4.1.6", ['_tls13_only("ssl_protocols")'], d("ssl_protocols", ["TLSv1.2 TLSv1.3"]),
        ok2=['count(_dv("ssl_dhparam")) > 0']),
    cfg("4.1.7", ['_all_on("ssl_stapling")', '_all_on("ssl_stapling_verify")', 'count(_dv("ssl_trusted_certificate")) > 0',
                  'count(_dv("resolver")) > 0'], rm("/nginx/directives/resolver")),
    cfg("4.1.8", ['some h in _dv("add_header")', "_hsts_ok(h)"],
        d("add_header", ['Strict-Transport-Security "max-age=300" always'])),
    cfg("4.1.9", ['count(_dv("proxy_ssl_certificate")) > 0', 'count(_dv("proxy_ssl_certificate_key")) > 0'],
        rm("/nginx/directives/proxy_ssl_certificate")),
    cfg("4.1.10", ['_all_on("proxy_ssl_verify")', 'count(_dv("proxy_ssl_trusted_certificate")) > 0',
                   'count(_dv("proxy_ssl_name")) > 0'], d("proxy_ssl_verify", ["off"])),
    cfg("4.1.11", ['every v in _dv("ssl_session_tickets") { lower(v) != "off" }'], d("ssl_session_tickets", ["off"])),
    cfg("4.1.12", ['_all_on("http2")', 'some l in _dv("listen")', '"quic" in _tokens(l)',
                   'some h in _dv("add_header")', '_header_name(h) == "alt-svc"'], rm("/nginx/directives/http2")),
    att("5.1.1", "ip_allow_deny_reviewed"),
    cfg("5.1.2", ['count(_dv("limit_except")) > 0'], rm("/nginx/directives/limit_except"),
        ok2=[f"{N}.request_method_filter == true"]),
    cfg("5.2.1", ['_some_secs_within("client_header_timeout", 20)', '_some_secs_within("client_body_timeout", 20)'],
        d("client_body_timeout", ["60"])),
    cfg("5.2.2", ['count(_dv("client_max_body_size")) > 0'], rm("/nginx/directives/client_max_body_size")),
    cfg("5.2.3", ['every v in _dv("large_client_header_buffers") { _tokens(v) == ["4", "8k"] }'],
        d("large_client_header_buffers", ["2 1k"]),
        ok2=[f"{N}.attest.large_client_header_buffers_documented == true"]),
    att("5.2.4", "connection_limits_reviewed"),
    att("5.2.5", "rate_limits_reviewed"),
    cfg("5.3.1", ['some h in _dv("add_header")', '_header_name(h) == "x-content-type-options"',
                  'contains(lower(h), "nosniff")', "_header_always(h)"],
        d("add_header", ['X-Content-Type-Options "nosniff"'])),
    cfg("5.3.2", ['some h in _dv("add_header")', "_csp_ok(h)"],
        d("add_header", ["Content-Security-Policy \"default-src 'self' 'unsafe-inline'; frame-ancestors 'self'\" always"])),
    cfg("5.3.3", ['some h in _dv("add_header")', '_header_name(h) == "referrer-policy"',
                  'trim(_tokens(h)[1], "\\"\'") in _good_referrer_policies', "_header_always(h)"],
        d("add_header", ['Referrer-Policy "no-referrer-when-downgrade" always'])),
]

SECTION_OF = {
    "1": "installation", "2.1": "modules", "2.2": "configuration", "2.3": "configuration",
    "2.4": "configuration", "2.5": "configuration", "3": "logging", "4": "ssl_tls",
    "5.1": "access_control", "5.3": "access_control", "5.2": "performance",
}


def section(cid):
    p = cid.split(".")
    return SECTION_OF.get(".".join(p[:2])) or SECTION_OF[p[0]]


SECTIONS = ["installation", "configuration", "logging", "ssl_tls", "modules", "access_control", "performance"]
SECTION_TITLES = {
    "installation": "1 Initial Setup", "modules": "2.1 Minimize NGINX Modules",
    "configuration": "2.2-2.5 Basic Configuration (account, permissions, network, information disclosure)",
    "logging": "3 Logging", "ssl_tls": "4 Encryption", "access_control": "5.1/5.3 Access control and browser security",
    "performance": "5.2 Request limits",
}

ids = [c["id"] for c in C]
assert len(ids) == len(set(ids)) == len(WB) == 44, (len(ids), len(WB))
assert set(ids) == set(WB)

GREEN = {"nginx": {
    "profiles": ["webserver", "proxy", "loadbalancer"],
    "version": "1.28.0",
    "package": {"update_available": False},
    "user": {"name": "nginx", "uid": 988, "groups": ["nginx"], "sudo_allowed": False, "password_locked": True,
             "shell": "/sbin/nologin"},
    "files": {"not_root_owned": [], "dir_modes": {"/etc/nginx": "750", "/etc/nginx/conf.d": "750"},
              "file_modes": {"/etc/nginx/nginx.conf": "640", "/etc/nginx/conf.d/app.conf": "600"}},
    "pid_file": {"owner": "root", "group": "root", "mode": "644"},
    "listen_ports": [80, 443],
    "default_server": {"present": True, "return_code": 444, "ssl_reject_handshake": True},
    "probe": {"error_page_mentions_nginx": False},
    "hidden_files_denied": True,
    "access_log_off_outside_location": False,
    "servers": [{"name": "app", "ssl": True}, {"name": "redirect", "ssl": False, "redirects_to_https": True}],
    "certificates": [{"path": "/etc/nginx/ssl/site.crt", "chain_trusted": True}],
    "private_keys": {"/etc/nginx/ssl/site.key": "400"},
    "directives": {
        "keepalive_timeout": ["10"], "send_timeout": ["10s"], "server_tokens": ["off"],
        "proxy_hide_header": ["X-Powered-By", "Server"],
        "log_format": ["main_json escape=json '{\"time\":\"$time_iso8601\",\"remote_addr\":\"$remote_addr\",\"remote_user\":\"$remote_user\",\"request\":\"$request\",\"status\":\"$status\",\"user_agent\":\"$http_user_agent\"}'"],
        "access_log": ["/var/log/nginx/access.json main_json"],
        "error_log": ["/var/log/nginx/error.log info"],
        "ssl_protocols": ["TLSv1.3"], "proxy_ssl_protocols": ["TLSv1.3"],
        "ssl_stapling": ["on"], "ssl_stapling_verify": ["on"],
        "ssl_trusted_certificate": ["/etc/nginx/ssl/chain.pem"], "resolver": ["10.0.0.53"],
        "add_header": ['Strict-Transport-Security "max-age=63072000; includeSubDomains" always',
                       'X-Content-Type-Options "nosniff" always',
                       "Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always",
                       'Referrer-Policy "strict-origin-when-cross-origin" always',
                       "Alt-Svc 'h3=\":443\"; ma=86400'"],
        "proxy_ssl_certificate": ["/etc/nginx/ssl/client.crt"], "proxy_ssl_certificate_key": ["/etc/nginx/ssl/client.key"],
        "proxy_ssl_verify": ["on"], "proxy_ssl_trusted_certificate": ["/etc/nginx/ssl/upstream-ca.crt"],
        "proxy_ssl_name": ["backend.internal"],
        "http2": ["on"], "listen": ["80", "443 ssl", "443 quic reuseport"],
        "limit_except": ["GET HEAD POST"],
        "proxy_set_header": ["X-Forwarded-For $proxy_add_x_forwarded_for", "X-Real-IP $remote_addr"],
        "client_header_timeout": ["10"], "client_body_timeout": ["10"], "client_max_body_size": ["1m"],
    },
    "attest": {"package_repositories_reviewed": True, "dynamic_modules_reviewed": True,
               "ip_allow_deny_reviewed": True, "connection_limits_reviewed": True, "rate_limits_reviewed": True},
}}

fact_manual = [c["id"] for c in C if c["kind"] == "fact"]
attest_ids = [c["id"] for c in C if c["kind"] == "attest"]

HEADER = f'''# METADATA
# title: "{BENCH}"
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

# {BENCH}
# The package name (cis_nginx_1_20) is kept so existing callers keep working; it no longer refers to NGINX 1.20.
# 44 recommendations, every one in the benchmark; ids, titles, levels, profiles and assessment status read from the
# CIS workbook. Every recommendation in v3.1.0 is assessed "Manual" by CIS.
# - {len(fact_manual)} of them are decided from collected configuration facts, because the audit is a directive or
#   value comparison (the cis.oracle_26ai precedent): {", ".join(fact_manual)}.
#   They fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# - {len(attest_ids)} need a human judgement and use an attestation boolean under input.nginx.attest
#   (not attested => violation): {", ".join(attest_ids)}.
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
#   user.{{name,uid,groups[],sudo_allowed,password_locked,shell}} : the account in the `user` directive
#   files.not_root_owned[]          : paths under the config dir not owned by root:root
#   files.dir_modes / file_modes    : {{path: octal mode}} for directories / files under the config dir
#   pid_file.{{owner,group,mode}}     : the PID file
#   listen_ports[]                  : ports in `listen` directives; authorized_ports[] (optional, default 80, 443)
#   default_server.{{present,return_code,ssl_reject_handshake}} : the catch-all default_server block
#   directives{{name: [values]}}      : every occurrence of each directive in `nginx -T` (arguments as one string)
#   probe.error_page_mentions_nginx : bool, an error page body names nginx
#   hidden_files_denied             : bool, a `location ~ /\\.` block denies hidden files
#   access_log_off_outside_location : bool, `access_log off` appears in the http or a server block
#   servers[].{{ssl,redirects_to_https}} : one entry per server block
#   certificates[].chain_trusted    : bool per ssl_certificate, chain verifies to a trusted root
#   private_keys{{path: octal mode}}  : every ssl_certificate_key file
#   request_method_filter           : bool (optional), an `if ($request_method ...)` filter is used instead of limit_except
#   attest.*                        : attestation booleans for the judgement recommendations

import rego.v1

default compliant := false

compliant if {{
	# fail-closed: no facts, no compliance
	input.nginx
	count(violations) == 0
}}

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

'''

HELPERS = r'''# ── helpers ──────────────────────────────────────────────────────────────────
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

'''

parts = [HEADER]
for s in SECTIONS:
    parts.append(f"# {SECTION_TITLES[s]}\n{s}_violations := sort([m | some m in _v_{s}])\n")
parts.append(HELPERS)
for c in C:
    parts.append(emit_control(c, WB, f"_v_{section(c['id'])}", applies=True))


def extra(c, w):
    return {"applies_to": sorted({p.split(" - ")[1].lower() for p in w["profiles"]}), "section": section(c["id"])}


parts.append("# Every recommendation in the benchmark: title, level, assessment status, CIS profiles, roles it applies to.\n"
             "recommendations := " + table(C, WB, extra) + "\n")
parts.append('''
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
''')
open(f"{OUT}/cis_nginx_1_20.rego", "w").write("\n".join(parts))

tests = f'''package cis_nginx_1_20_test

import rego.v1

import data.cis_nginx_1_20 as b

# Generated per-recommendation tests for {BENCH}: every recommendation has a pass test (green input) and a
# fail test; configuration checks also have an evidence-missing test; attestations fail when false or absent.

green := {json.dumps(GREEN, indent=chr(9), ensure_ascii=False)}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}

test_green_input_is_compliant if {{
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
}}

test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == 44
	count([id | some id, r in b.recommendations; r.level == 2]) == {sum(1 for w in WB.values() if w["level"] == 2)}
}}

test_report_shape_on_empty_input if {{
	r := b.compliance_report with input as {{}}
	r.total_controls == 44
	r.compliant == false
	r.failed_controls == 44
	r.passed_controls == 0
	f := b.findings with input as {{}}
	count(f) == 1
	count(f[0].violations) > 0
}}

test_webserver_profile_skips_proxy_only if {{
	inp := json.patch(green, [{{"op": "replace", "path": "/nginx/profiles", "value": ["webserver"]}}, {{"op": "remove", "path": "/nginx/directives/proxy_ssl_certificate"}}])
	vs := b.violations with input as inp
	not _has_id(vs, "4.1.9")
	r := b.compliance_report with input as inp
	r.applicable_controls == {sum(1 for w in WB.values() if any("Webserver" in p for p in w["profiles"]))}
}}

test_proxy_profile_skips_webserver_only if {{
	inp := json.patch(green, [{{"op": "replace", "path": "/nginx/profiles", "value": ["proxy"]}}, {{"op": "remove", "path": "/nginx/directives/http2"}}])
	vs := b.violations with input as inp
	not _has_id(vs, "4.1.12")
}}

test_unknown_profile_falls_back_to_all if {{
	inp := json.patch(green, [{{"op": "replace", "path": "/nginx/profiles", "value": ["web"]}}, {{"op": "remove", "path": "/nginx/directives/http2"}}])
	vs := b.violations with input as inp
	_has_id(vs, "4.1.12")
	not b.compliant with input as inp
	c := b.compliant with input as {{"nginx": {{"profiles": ["web"]}}}}
	c == false
}}

test_absent_profiles_means_all if {{
	inp := json.patch(green, [{{"op": "remove", "path": "/nginx/profiles"}}, {{"op": "remove", "path": "/nginx/directives/http2"}}])
	vs := b.violations with input as inp
	_has_id(vs, "4.1.12")
}}

test_5_2_3_documented_deviation_passes if {{
	inp := json.patch(green, [{{"op": "add", "path": "/nginx/directives/large_client_header_buffers", "value": ["2 1k"]}}])
	vs := b.violations with input as inp
	_has_id(vs, "5.2.3")
	inp2 := json.patch(inp, [{{"op": "add", "path": "/nginx/attest/large_client_header_buffers_documented", "value": true}}])
	vs2 := b.violations with input as inp2
	not _has_id(vs2, "5.2.3")
}}

{emit_tests("cis_nginx_1_20", C, WB, GREEN, "/nginx/attest")}'''
open(f"{OUT}/tests/test_cis_nginx_1_20_controls.rego", "w").write(tests)

print("ok", len(C))
