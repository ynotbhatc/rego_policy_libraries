package cis.apache_2_4_test

import rego.v1

import data.cis.apache_2_4 as p

# Validation fix 2026-10-17 regression tests, re-pointed at the CIS Apache HTTP Server 2.4 Benchmark v2.4.0
# rebuild (2026-11-11). Test names are kept where the concern survives; each body exercises the v2.4.0 helper
# or recommendation that covers it.

g := data.cis.apache_2_4_test.green

_id_in(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

# Sparse facts must still report every section (missing evidence is a violation, never a pass).
test_undefined_conditions_still_report_violations if {
	vs := p.violations with input as {"apache": {"directives": {"ServerTokens": ["OS"]}}}
	count(vs) > 0
	"8.1: required value of ServerTokens is 'Prod' or 'ProductOnly'" in vs
	"2.2: evidence missing — apache.modules not collected" in vs
	"3.1: evidence missing — apache.config.{user,group} / apache.account.{uid,uid_min} / apache.processes.worker_users not collected" in vs
}

# 3.9 / 3.8 / 3.10: runtime directories are octal, not decimal; group or other write fails
test_other_write_bit_detected_without_digit_2 if {
	not p._runtime_dir_ok({"within_docroot": false, "owner": "root", "group": "root", "mode": "0757"})
	not p._runtime_dir_ok({"within_docroot": false, "owner": "root", "group": "root", "mode": "0777"})
	not p._runtime_dir_ok({"within_docroot": false, "owner": "root", "group": "root", "mode": "0775"})
}

test_no_other_write_ok if {
	p._runtime_dir_ok({"within_docroot": false, "owner": "root", "group": "root", "mode": "0750"})
	p._runtime_dir_ok({"within_docroot": false, "owner": "root", "group": "root", "mode": "755"})
	not p._runtime_dir_ok({"within_docroot": true, "owner": "root", "group": "root", "mode": "755"})
}

test_runtime_dir_honours_startup_user if {
	dir := {"within_docroot": false, "owner": "httpd", "group": "httpd", "mode": "755"}
	not p._runtime_dir_ok(dir)
	p._runtime_dir_ok(dir) with input as {"apache": {"startup_user": "httpd"}}
}

# 7.4: SSLProtocol modifiers are applied in order
test_tls12_and_13_not_flagged_as_tlsv1 if {
	p._protocols_ok("-all +TLSv1.2 +TLSv1.3")
	p._protocols_ok("TLSv1.2 TLSv1.3")
	p._protocols_ok("+TLSv1.2")
	p._protocols_ok("TLSv1.3")
}

test_real_insecure_protocols_flagged if {
	not p._protocols_ok("-all +TLSv1 +TLSv1.2")
	not p._protocols_ok("+TLSv1.1 +TLSv1.2")
	not p._protocols_ok("all")
	not p._protocols_ok("+SSLv3")
	not p._protocols_ok("-all")
}

test_all_with_removals_ok if {
	p._protocols_ok("all -SSLv3 -TLSv1 -TLSv1.1")
	not p._protocols_ok("all -SSLv3")
}

# 5.1-5.3: Options as a string or a list, with +/- prefixes, All and None
test_string_options_are_evaluated if {
	p._opts({"options": "Indexes"}) == {"indexes"}
	p._opts({"options": "FollowSymLinks +Indexes"}) == {"followsymlinks", "indexes"}
	"includes" in p._opts({"options": "Includes"})
	"execcgi" in p._opts({"options": "ExecCGI"})
}

test_array_options_still_evaluated if {
	p._opts({"options": ["Indexes"]}) == {"indexes"}
	p._opts({"options": ["FollowSymLinks"]}) == {"followsymlinks"}
}

test_options_all_enables_everything if {
	"indexes" in p._opts({"options": "All"})
	"includes" in p._opts({"options": "All"})
}

test_removed_option_not_counted if {
	count(p._opts({"options": "-Indexes"})) == 0
	count(p._opts({"options": "None"})) == 0
}

test_options_restricted_requires_every_directory if {
	inp := json.patch(g, [{"op": "add", "path": "/apache/directories/-", "value": {"path": "/srv/app", "options": "Includes"}}])
	vs := p.violations with input as inp
	_id_in(vs, "5.3")
	not _id_in(vs, "5.1")
	not _id_in(vs, "5.2")
}

test_root_directory_options_must_be_none if {
	inp := json.patch(g, [{"op": "replace", "path": "/apache/directories/0/options", "value": "FollowSymLinks"}])
	vs := p.violations with input as inp
	_id_in(vs, "5.1")
	inp2 := json.patch(g, [{"op": "remove", "path": "/apache/directories/0/options"}])
	vs2 := p.violations with input as inp2
	_id_in(vs2, "5.1")
}

# 3.1: any non-root service account below UID_MIN is accepted (RHEL apache, Debian www-data)
test_debian_service_account_accepted if {
	inp := json.patch(g, [
		{"op": "replace", "path": "/apache/config", "value": {"user": "www-data", "group": "www-data"}},
		{"op": "replace", "path": "/apache/account/uid", "value": 33},
		{"op": "replace", "path": "/apache/processes/worker_users", "value": ["www-data"]},
	])
	vs := p.violations with input as inp
	not _id_in(vs, "3.1")
	inp2 := json.patch(inp, [{"op": "replace", "path": "/apache/account/uid", "value": 1001}])
	vs2 := p.violations with input as inp2
	_id_in(vs2, "3.1")
	inp3 := json.patch(inp, [{"op": "replace", "path": "/apache/processes/worker_users", "value": ["www-data", "root"]}])
	vs3 := p.violations with input as inp3
	_id_in(vs3, "3.1")
}

# 2.x: module names normalise across `httpd -M` output styles
test_module_names_normalise if {
	p._mod("ssl") with input as {"apache": {"modules": ["ssl_module (shared)"]}}
	p._mod("ssl") with input as {"apache": {"modules": ["mod_ssl"]}}
	p._mod("log_config") with input as {"apache": {"modules": ["log_config_module (static)"]}}
	not p._mod("status") with input as {"apache": {"modules": ["ssl_module"]}}
}

# 4.1: both access-control syntaxes are recognised; mixing them is not
test_root_access_denied_both_syntaxes if {
	p._denies_all({"require": ["all denied"]})
	p._denies_all({"order": "deny, allow", "deny": ["from all"]})
	not p._denies_all({"require": ["all denied"], "allow": ["from 10.0.0.0/8"]})
	not p._denies_all({"order": "allow,deny", "deny": ["from all"]})
	not p._denies_all({"require": ["all granted"]})
}

# 5.16 / 7.11: Header directive parsing (condition, action, name, quoted value)
test_header_parsing if {
	p._hdr_name("always set X-Frame-Options \"SAMEORIGIN\"") == "x-frame-options"
	p._hdr_value("always set X-Frame-Options \"SAMEORIGIN\"") == "sameorigin"
	p._hdr_action("set Referrer-Policy no-referrer") == "set"
	not p._hdr_always("set X-Frame-Options DENY")
	p._framing_header_ok("always append Content-Security-Policy \"frame-ancestors 'none'\"")
	not p._framing_header_ok("set X-Frame-Options SAMEORIGIN")
	p._hsts_in(["always set Strict-Transport-Security \"max-age=480\""])
	not p._hsts_in(["always set Strict-Transport-Security \"max-age=479\""])
	not p._hsts_in(["set Strict-Transport-Security \"max-age=600\""])
}

# 6.1: LogLevel severity (core at info or more verbose, others at notice or more verbose)
test_loglevel_severity if {
	p._loglevel_ok("notice core:info")
	p._loglevel_ok("info")
	p._loglevel_ok("debug")
	not p._loglevel_ok("notice")
	not p._loglevel_ok("warn core:info")
	not p._loglevel_ok("notice core:warn")
	not p._loglevel_ok("notice info")
}

# 6.3: the access-log format may be explicit or a LogFormat nickname
test_access_log_format_resolution if {
	inp := {"apache": {"directives": {"LogFormat": ["\"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-agent}i\\\"\" combined"]}}}
	p._access_format_complete("logs/access_log combined") with input as inp
	not p._access_format_complete("logs/access_log common") with input as inp
	p._access_format_complete("logs/access_log \"%{X-Forwarded-For}i %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-agent}i\\\"\"") with input as inp
	not p._access_format_complete("logs/access_log \"%h %l %u %t\"") with input as inp
}

# 9.5 / 9.6: RequestReadTimeout ranges take their upper bound
test_request_read_timeout_parsing if {
	inp := {"apache": {"directives": {"RequestReadTimeout": ["header=20-40,MinRate=500 body=20,MinRate=500"]}}}
	p._rrt_max("header") == {40} with input as inp
	p._rrt_max("body") == {20} with input as inp
	inp2 := {"apache": {"directives": {"RequestReadTimeout": ["header=60"]}}}
	p._rrt_max("header") == {60} with input as inp2
	count(p._rrt_max("body")) == 0 with input as inp2
}

# 7.5 / 7.8 / 7.12: cipher-suite strings
test_cipher_suite_strings if {
	p._weak_excluded("ALL:!EXP:!NULL:!LOW:!SSLv2:!RC4:!aNULL")
	not p._weak_excluded("ALL:!EXP:!NULL")
	p._medium_excluded("ALL:!3DES:!IDEA")
	not p._medium_excluded("ALL:!3DES")
	p._forward_secrecy_only("EECDH:EDH:!NULL:!SSLv2:!RC4:!3DES:!IDEA:!aNULL:!SHA1")
	p._forward_secrecy_only("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
	not p._forward_secrecy_only("ALL:!aNULL")
}

# 5.15: Listen must name an address
test_listen_address_required if {
	p._listen_has_address("10.0.0.5:443")
	p._listen_has_address("[2001:db8::1]:443")
	not p._listen_has_address("443")
	not p._listen_has_address("0.0.0.0:443")
	not p._listen_has_address("*:80")
}

# 5.4: a custom index page is not default content, a default one is
test_custom_index_html_not_flagged_as_default if {
	vs := p.violations with input as g
	not _id_in(vs, "5.4")
	inp := json.patch(g, [{"op": "replace", "path": "/apache/default_content/default_index_present", "value": true}])
	vs2 := p.violations with input as inp
	_id_in(vs2, "5.4")
}
