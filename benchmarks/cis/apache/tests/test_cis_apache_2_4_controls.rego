package cis.apache_2_4_test

import rego.v1

import data.cis.apache_2_4 as b

# Generated per-recommendation tests for CIS Apache HTTP Server 2.4 Benchmark v2.4.0: every recommendation has a pass test (green input) and a
# fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.

green := {"apache": {
	"modules": [
		"core_module",
		"so_module",
		"http_module",
		"mpm_event_module",
		"log_config_module",
		"ssl_module",
		"rewrite_module",
		"headers_module",
		"reqtimeout_module",
		"security2_module",
		"allowmethods_module",
		"authz_core_module",
		"unixd_module",
		"mime_module",
		"dir_module",
	],
	"config": {
		"user": "apache",
		"group": "apache",
	},
	"account": {
		"name": "apache",
		"uid": 48,
		"uid_min": 1000,
		"shell": "/sbin/nologin",
		"locked": true,
	},
	"processes": {"worker_users": [
		"apache",
		"apache",
	]},
	"files": {
		"not_root_owned": [],
		"wrong_group": [],
		"other_writable": [],
		"group_writable": [],
	},
	"docroot": {"group_writable": []},
	"core_dump": {"configured": false},
	"lock_file": {"file_mutex": false},
	"pid_file": {"dir": {
		"within_docroot": false,
		"owner": "root",
		"group": "root",
		"mode": "755",
	}},
	"scoreboard": {"configured": false},
	"writable_dirs": [{
		"path": "/var/phptmp/sessions",
		"single_purpose": true,
		"within_docroot": false,
		"owner": "root",
		"other_writable": false,
	}],
	"directories": [
		{
			"path": "/",
			"is_root": true,
			"options": "None",
			"allow_override": ["None"],
			"allow_override_list": [],
			"require": ["all denied"],
			"allow": [],
			"deny": [],
		},
		{
			"path": "/var/www/html",
			"is_docroot": true,
			"options": ["None"],
			"allow_override": ["None"],
			"require": ["all granted"],
			"limit_except": {
				"methods": [
					"GET",
					"POST",
					"OPTIONS",
				],
				"require": ["all denied"],
			},
		},
		{
			"path": "/var/www/cgi-bin",
			"options": ["None"],
			"allow_override": ["None"],
			"require": ["all granted"],
			"allow_methods": [
				"GET",
				"POST",
				"OPTIONS",
			],
		},
	],
	"default_content": {
		"default_index_present": false,
		"manual_configured": false,
		"server_status_handler": false,
		"server_info_handler": false,
		"other_status_handlers": [],
		"icons_accessible": false,
	},
	"cgi": {
		"printenv_present": false,
		"test_cgi_present": false,
	},
	"files_match": [
		{
			"pattern": "^\\.ht",
			"require": ["all denied"],
		},
		{
			"pattern": "/\\.git",
			"require": ["all denied"],
		},
		{
			"pattern": "/\\.svn",
			"deny": ["from all"],
		},
	],
	"directory_match": [{
		"pattern": "/\\.git",
		"require": ["all denied"],
	}],
	"directives": {
		"TraceEnable": ["Off"],
		"RewriteEngine": ["On"],
		"RewriteOptions": ["Inherit"],
		"RewriteCond": [
			"%{THE_REQUEST} !(HTTP/1\\.1|HTTP/2\\.0)$",
			"%{HTTP_HOST} !^www\\.example\\.com [NC]",
			"%{REQUEST_URI} !^/error [NC]",
		],
		"RewriteRule": [
			".* - [F]",
			"^.(.*) - [L,F]",
		],
		"Listen": [
			"10.0.0.5:80",
			"10.0.0.5:443",
		],
		"Header": [
			"always set X-Frame-Options \"SAMEORIGIN\"",
			"always set Content-Security-Policy \"frame-ancestors 'self'\"",
			"set Referrer-Policy \"strict-origin-when-cross-origin\"",
			"set Permissions-Policy \"geolocation=()\"",
			"always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"",
		],
		"LogLevel": ["notice core:info"],
		"ErrorLog": ["syslog:local1"],
		"LogFormat": [
			"\"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-agent}i\\\"\" combined",
			"\"%h %l %u %t \\\"%r\\\" %>s %b\" common",
		],
		"CustomLog": ["logs/access_log combined"],
		"SSLProtocol": ["-all +TLSv1.2 +TLSv1.3"],
		"SSLHonorCipherOrder": ["On"],
		"SSLCipherSuite": ["ALL:!EXP:!NULL:!LOW:!SSLv2:!RC4:!aNULL:!3DES:!IDEA"],
		"SSLInsecureRenegotiation": ["off"],
		"SSLCompression": ["off"],
		"SSLStaplingCache": ["shmcb:logs/ssl_stapling(32768)"],
		"SSLUseStapling": ["on"],
		"ServerTokens": ["Prod"],
		"ServerSignature": ["Off"],
		"Timeout": ["10"],
		"KeepAlive": ["On"],
		"MaxKeepAliveRequests": ["100"],
		"KeepAliveTimeout": ["15"],
		"RequestReadTimeout": ["header=20-40,MinRate=500 body=20,MinRate=500"],
		"LimitRequestLine": ["512"],
		"LimitRequestFields": ["100"],
		"LimitRequestFieldSize": ["1024"],
		"LimitRequestBody": ["102400"],
	},
	"vhosts": [{
		"name": "www.example.com",
		"ssl": true,
		"directives": {
			"RewriteEngine": ["On"],
			"RewriteOptions": ["Inherit"],
			"SSLUseStapling": ["on"],
			"Header": ["always set Strict-Transport-Security \"max-age=63072000\""],
		},
	}],
	"log_rotation": {
		"covers_configured_logs": true,
		"retention_weeks": 13,
		"vhost_logs_included": true,
	},
	"patches": {"overdue_security_updates": 0},
	"tls": {
		"certificates": [{
			"path": "/etc/pki/tls/certs/www.crt",
			"trusted": true,
			"signature_weak": false,
		}],
		"cert_files_with_private_key": [],
		"key_files": [{
			"path": "/etc/pki/tls/private/www.key",
			"owner": "root",
			"group": "root",
			"mode": "400",
		}],
		"scan": {"non_forward_secrecy_ciphers": []},
	},
	"http_probe": {"content_served": []},
	"selinux": {
		"enabled": true,
		"current_mode": "enforcing",
		"config_mode": "enforcing",
		"httpd_process_types": ["httpd_t"],
		"httpd_t_permissive": false,
		"enabled_httpd_booleans": ["httpd_builtin_scripting"],
		"approved_httpd_booleans": ["httpd_builtin_scripting"],
	},
	"apparmor": {
		"enabled": true,
		"profile": {
			"present": true,
			"wildcard_root_rules": [],
		},
		"apache_processes": [{
			"pid": 1899,
			"confinement": "enforce",
		}],
	},
	"attest": {
		"planning_checklist_implemented": true,
		"single_purpose_server_reviewed": true,
		"installed_from_approved_binaries": true,
		"auth_modules_reviewed": true,
		"web_content_access_reviewed": true,
		"file_extension_allowlist_reviewed": true,
	},
}}

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
	count(b.recommendations) == 86
	count([id | some id, r in b.recommendations; r.level == 1]) == 57
	count([id | some id, r in b.recommendations; r.level == 2]) == 29
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 43
}

test_report_shape_on_empty_input if {
	r := b.compliance_report with input as {}
	r.total_controls == 86
	r.applicable_controls == 86
	r.compliant == false
	r.failed_controls == 86
	r.passed_controls == 0
	r.level_1.total == 57
	r.level_2.total == 29
	f := b.findings with input as {}
	count(f) == 1
	count(f[0].violations) > 0
}

test_selinux_host_skips_apparmor if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/platform", "value": {"mac": "selinux"}}, {"op": "remove", "path": "/apache/apparmor"}])
	vs := b.violations with input as inp
	count(vs) == 0
	r := b.compliance_report with input as inp
	r.applicable_controls == 83
	r.mac_frameworks == ["selinux"]
}

test_apparmor_host_skips_selinux if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/platform", "value": {"mac": "AppArmor"}}, {"op": "remove", "path": "/apache/selinux"}])
	vs := b.violations with input as inp
	count(vs) == 0
	not _has_id(vs, "11.1")
}

test_unknown_mac_applies_both if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/platform", "value": {"mac": "grsecurity"}}, {"op": "remove", "path": "/apache/selinux"}])
	vs := b.violations with input as inp
	_has_id(vs, "11.1")
	not _has_id(vs, "12.1")
	not b.compliant with input as inp
	r := b.compliance_report with input as inp
	r.applicable_controls == 86
}

test_2_6_proxy_in_use_attested_passes if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "proxy_http_module"}])
	vs := b.violations with input as inp
	_has_id(vs, "2.6")
	inp2 := json.patch(inp, [{"op": "add", "path": "/apache/attest/proxy_modules_required", "value": true}])
	vs2 := b.violations with input as inp2
	not _has_id(vs2, "2.6")
}

test_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1")
}

test_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/planning_checklist_implemented", "value": false}])
	vs := b.violations with input as inp
	"1.1: the Pre-Installation Planning Checklist must have Been Implemented (manual review not attested)" in vs
}

test_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/planning_checklist_implemented"}])
	vs := b.violations with input as inp
	"1.1: the Pre-Installation Planning Checklist must have Been Implemented (manual review not attested)" in vs
}

test_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2")
}

test_1_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/single_purpose_server_reviewed", "value": false}])
	vs := b.violations with input as inp
	"1.2: the Server must be Not a Multi-Use System (manual review not attested)" in vs
}

test_1_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/single_purpose_server_reviewed"}])
	vs := b.violations with input as inp
	"1.2: the Server must be Not a Multi-Use System (manual review not attested)" in vs
}

test_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3")
}

test_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/installed_from_approved_binaries", "value": false}])
	vs := b.violations with input as inp
	"1.3: Apache must be Installed From the Appropriate Binaries (manual review not attested)" in vs
}

test_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/installed_from_approved_binaries"}])
	vs := b.violations with input as inp
	"1.3: Apache must be Installed From the Appropriate Binaries (manual review not attested)" in vs
}

test_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1")
}

test_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/auth_modules_reviewed", "value": false}])
	vs := b.violations with input as inp
	"2.1: Only Necessary Authentication and Authorization Modules must be turned on (manual review not attested)" in vs
}

test_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/auth_modules_reviewed"}])
	vs := b.violations with input as inp
	"2.1: Only Necessary Authentication and Authorization Modules must be turned on (manual review not attested)" in vs
}

test_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2")
}

test_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules", "value": ["core_module", "ssl_module"]}])
	vs := b.violations with input as inp
	"2.2: the Log Config Module must be turned on" in vs
}

test_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.2: evidence missing — apache.modules not collected" in vs
	not "2.2: the Log Config Module must be turned on" in vs
}

test_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3")
}

test_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "dav_module"}])
	vs := b.violations with input as inp
	"2.3: the WebDAV Modules must be turned off" in vs
}

test_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.3: evidence missing — apache.modules not collected" in vs
	not "2.3: the WebDAV Modules must be turned off" in vs
}

test_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4")
}

test_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "status_module"}])
	vs := b.violations with input as inp
	"2.4: the Status Module must be turned off" in vs
}

test_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.4: evidence missing — apache.modules not collected" in vs
	not "2.4: the Status Module must be turned off" in vs
}

test_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5")
}

test_2_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "autoindex_module"}])
	vs := b.violations with input as inp
	"2.5: the Autoindex Module must be turned off" in vs
}

test_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.5: evidence missing — apache.modules not collected" in vs
	not "2.5: the Autoindex Module must be turned off" in vs
}

test_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.6")
}

test_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "proxy_module"}])
	vs := b.violations with input as inp
	"2.6: the Proxy Modules must be turned off if not in use" in vs
}

test_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.6: evidence missing — apache.modules not collected" in vs
	not "2.6: the Proxy Modules must be turned off if not in use" in vs
}

test_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.7")
}

test_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "userdir_module"}])
	vs := b.violations with input as inp
	"2.7: the User Directories Module must be turned off" in vs
}

test_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.7: evidence missing — apache.modules not collected" in vs
	not "2.7: the User Directories Module must be turned off" in vs
}

test_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.8")
}

test_2_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "info_module"}])
	vs := b.violations with input as inp
	"2.8: the Info Module must be turned off" in vs
}

test_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.8: evidence missing — apache.modules not collected" in vs
	not "2.8: the Info Module must be turned off" in vs
}

test_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.9")
}

test_2_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules/-", "value": "auth_basic_module"}])
	vs := b.violations with input as inp
	"2.9: the Basic and Digest Authentication Modules must be turned off" in vs
}

test_2_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"2.9: evidence missing — apache.modules not collected" in vs
	not "2.9: the Basic and Digest Authentication Modules must be turned off" in vs
}

test_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1")
}

test_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/config/user", "value": "root"}])
	vs := b.violations with input as inp
	"3.1: checked condition — the Apache Web Server Runs As a Non-Root User" in vs
}

test_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/config"}])
	vs := b.violations with input as inp
	"3.1: evidence missing — apache.config.{user,group} / apache.account.{uid,uid_min} / apache.processes.worker_users not collected" in vs
	not "3.1: checked condition — the Apache Web Server Runs As a Non-Root User" in vs
}

test_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2")
}

test_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/account/shell", "value": "/bin/bash"}])
	vs := b.violations with input as inp
	"3.2: the Apache User Account must use a non-login shell" in vs
}

test_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/account/shell"}])
	vs := b.violations with input as inp
	"3.2: evidence missing — apache.account.shell not collected" in vs
	not "3.2: the Apache User Account must use a non-login shell" in vs
}

test_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.3")
}

test_3_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/account/locked", "value": false}])
	vs := b.violations with input as inp
	"3.3: the Apache User Account must be locked" in vs
}

test_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/account/locked"}])
	vs := b.violations with input as inp
	"3.3: evidence missing — apache.account.locked not collected" in vs
	not "3.3: the Apache User Account must be locked" in vs
}

test_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.4")
}

test_3_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files/not_root_owned", "value": ["/etc/httpd/conf.d/app.conf"]}])
	vs := b.violations with input as inp
	"3.4: Apache Directories and Files must be Owned By Root" in vs
}

test_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files/not_root_owned"}])
	vs := b.violations with input as inp
	"3.4: evidence missing — apache.files.not_root_owned not collected" in vs
	not "3.4: Apache Directories and Files must be Owned By Root" in vs
}

test_3_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.5")
}

test_3_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files/wrong_group", "value": ["/etc/httpd/modules"]}])
	vs := b.violations with input as inp
	"3.5: the Group must be Set Correctly on Apache Directories and Files" in vs
}

test_3_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files/wrong_group"}])
	vs := b.violations with input as inp
	"3.5: evidence missing — apache.files.wrong_group not collected" in vs
	not "3.5: the Group must be Set Correctly on Apache Directories and Files" in vs
}

test_3_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.6")
}

test_3_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files/other_writable", "value": ["/etc/httpd/logs"]}])
	vs := b.violations with input as inp
	"3.6: Other Write Access on Apache Directories and Files must be Restricted" in vs
}

test_3_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files/other_writable"}])
	vs := b.violations with input as inp
	"3.6: evidence missing — apache.files.other_writable not collected" in vs
	not "3.6: Other Write Access on Apache Directories and Files must be Restricted" in vs
}

test_3_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.7")
}

test_3_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/core_dump", "value": {"configured": true, "within_docroot": false, "owner": "root", "group": "apache", "mode": "757"}}])
	vs := b.violations with input as inp
	"3.7: the Core Dump Directory must be Secured" in vs
}

test_3_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/core_dump"}])
	vs := b.violations with input as inp
	"3.7: evidence missing — apache.core_dump not collected" in vs
	not "3.7: the Core Dump Directory must be Secured" in vs
}

test_3_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.8")
}

test_3_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/lock_file", "value": {"file_mutex": true, "dir": {"within_docroot": false, "owner": "root", "group": "root", "mode": "775", "local_fs": true}}}])
	vs := b.violations with input as inp
	"3.8: the Lock File must be Secured" in vs
}

test_3_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/lock_file"}])
	vs := b.violations with input as inp
	"3.8: evidence missing — apache.lock_file not collected" in vs
	not "3.8: the Lock File must be Secured" in vs
}

test_3_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.9")
}

test_3_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/pid_file/dir/within_docroot", "value": true}])
	vs := b.violations with input as inp
	"3.9: the Pid File must be Secured" in vs
}

test_3_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/pid_file"}])
	vs := b.violations with input as inp
	"3.9: evidence missing — apache.pid_file.dir not collected" in vs
	not "3.9: the Pid File must be Secured" in vs
}

test_3_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.10")
}

test_3_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/scoreboard", "value": {"configured": true, "dir": {"within_docroot": true}}}])
	vs := b.violations with input as inp
	"3.10: the ScoreBoard File must be Secured" in vs
}

test_3_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/scoreboard"}])
	vs := b.violations with input as inp
	"3.10: evidence missing — apache.scoreboard not collected" in vs
	not "3.10: the ScoreBoard File must be Secured" in vs
}

test_3_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.11")
}

test_3_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files/group_writable", "value": ["/etc/httpd/conf"]}])
	vs := b.violations with input as inp
	"3.11: Group Write Access for the Apache Directories and Files must be Properly Restricted" in vs
}

test_3_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files/group_writable"}])
	vs := b.violations with input as inp
	"3.11: evidence missing — apache.files.group_writable not collected" in vs
	not "3.11: Group Write Access for the Apache Directories and Files must be Properly Restricted" in vs
}

test_3_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.12")
}

test_3_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/docroot/group_writable", "value": ["/var/www/html/upload"]}])
	vs := b.violations with input as inp
	"3.12: Group Write Access for the Document Root Directories and Files must be Properly Restricted" in vs
}

test_3_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/docroot"}])
	vs := b.violations with input as inp
	"3.12: evidence missing — apache.docroot.group_writable not collected" in vs
	not "3.12: Group Write Access for the Document Root Directories and Files must be Properly Restricted" in vs
}

test_3_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.13")
}

test_3_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/writable_dirs/0/other_writable", "value": true}])
	vs := b.violations with input as inp
	"3.13: Access to Special Purpose Application Writable Directories must be Properly Restricted" in vs
}

test_3_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/writable_dirs"}])
	vs := b.violations with input as inp
	"3.13: evidence missing — apache.writable_dirs not collected" in vs
	not "3.13: Access to Special Purpose Application Writable Directories must be Properly Restricted" in vs
}

test_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1")
}

test_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/0/require", "value": ["all granted"]}])
	vs := b.violations with input as inp
	"4.1: Access to OS Root Directory must be Denied By Default" in vs
}

test_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"4.1: evidence missing — apache.directories not collected" in vs
	not "4.1: Access to OS Root Directory must be Denied By Default" in vs
}

test_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2")
}

test_4_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/web_content_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.2: Appropriate Access to Web Content must be Allowed (manual review not attested)" in vs
}

test_4_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/web_content_access_reviewed"}])
	vs := b.violations with input as inp
	"4.2: Appropriate Access to Web Content must be Allowed (manual review not attested)" in vs
}

test_4_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3")
}

test_4_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/0/allow_override", "value": ["All"]}])
	vs := b.violations with input as inp
	"4.3: OverRide must be turned off for the OS Root Directory" in vs
}

test_4_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"4.3: evidence missing — apache.directories not collected" in vs
	not "4.3: OverRide must be turned off for the OS Root Directory" in vs
}

test_4_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.4")
}

test_4_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/1/allow_override", "value": ["AuthConfig"]}])
	vs := b.violations with input as inp
	"4.4: OverRide must be turned off for All Directories" in vs
}

test_4_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"4.4: evidence missing — apache.directories not collected" in vs
	not "4.4: OverRide must be turned off for All Directories" in vs
}

test_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1")
}

test_5_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/0/options", "value": "FollowSymLinks"}])
	vs := b.violations with input as inp
	"5.1: Options for the OS Root Directory must be Restricted" in vs
}

test_5_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"5.1: evidence missing — apache.directories not collected" in vs
	not "5.1: Options for the OS Root Directory must be Restricted" in vs
}

test_5_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2")
}

test_5_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/1/options", "value": ["Indexes", "FollowSymLinks"]}])
	vs := b.violations with input as inp
	"5.2: Options for the Web Root Directory must be Restricted" in vs
}

test_5_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"5.2: evidence missing — apache.directories not collected" in vs
	not "5.2: Options for the Web Root Directory must be Restricted" in vs
}

test_5_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3")
}

test_5_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/2/options", "value": "+Includes"}])
	vs := b.violations with input as inp
	"5.3: Options for Other Directories must be Minimized" in vs
}

test_5_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"5.3: evidence missing — apache.directories not collected" in vs
	not "5.3: Options for Other Directories must be Minimized" in vs
}

test_5_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.4")
}

test_5_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/default_content/server_status_handler", "value": true}])
	vs := b.violations with input as inp
	"5.4: Default HTML Content must be Removed" in vs
}

test_5_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/default_content"}])
	vs := b.violations with input as inp
	"5.4: evidence missing — apache.default_content not collected" in vs
	not "5.4: Default HTML Content must be Removed" in vs
}

test_5_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.5")
}

test_5_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/cgi/printenv_present", "value": true}])
	vs := b.violations with input as inp
	"5.5: the Default CGI Content printenv Script must be Removed" in vs
}

test_5_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/cgi/printenv_present"}])
	vs := b.violations with input as inp
	"5.5: evidence missing — apache.cgi.printenv_present not collected" in vs
	not "5.5: the Default CGI Content printenv Script must be Removed" in vs
}

test_5_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6")
}

test_5_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/cgi/test_cgi_present", "value": true}])
	vs := b.violations with input as inp
	"5.6: the Default CGI Content test-cgi Script must be Removed" in vs
}

test_5_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/cgi/test_cgi_present"}])
	vs := b.violations with input as inp
	"5.6: evidence missing — apache.cgi.test_cgi_present not collected" in vs
	not "5.6: the Default CGI Content test-cgi Script must be Removed" in vs
}

test_5_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.7")
}

test_5_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directories/1/limit_except/methods", "value": ["GET", "POST", "PUT", "DELETE"]}])
	vs := b.violations with input as inp
	"5.7: HTTP Request Methods must be Restricted" in vs
}

test_5_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directories"}])
	vs := b.violations with input as inp
	"5.7: evidence missing — apache.directories not collected" in vs
	not "5.7: HTTP Request Methods must be Restricted" in vs
}

test_5_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.8")
}

test_5_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/TraceEnable", "value": ["on"]}])
	vs := b.violations with input as inp
	"5.8: the HTTP TRACE Method must be turned off" in vs
}

test_5_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.8: evidence missing — apache.directives not collected" in vs
	not "5.8: the HTTP TRACE Method must be turned off" in vs
}

test_5_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.9")
}

test_5_9_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives/RewriteCond"}])
	vs := b.violations with input as inp
	"5.9: Old HTTP Protocol Versions must be Disallowed" in vs
}

test_5_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.9: evidence missing — apache.directives / apache.modules not collected" in vs
	not "5.9: Old HTTP Protocol Versions must be Disallowed" in vs
}

test_5_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.10")
}

test_5_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files_match", "value": []}])
	vs := b.violations with input as inp
	"5.10: Access to .ht* Files must be Restricted" in vs
}

test_5_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files_match"}])
	vs := b.violations with input as inp
	"5.10: evidence missing — apache.files_match not collected" in vs
	not "5.10: Access to .ht* Files must be Restricted" in vs
}

test_5_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.11")
}

test_5_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directory_match", "value": []}])
	vs := b.violations with input as inp
	"5.11: Access to .git Files must be Restricted" in vs
}

test_5_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directory_match"}])
	vs := b.violations with input as inp
	"5.11: evidence missing — apache.files_match / apache.directory_match not collected" in vs
	not "5.11: Access to .git Files must be Restricted" in vs
}

test_5_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.12")
}

test_5_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/files_match", "value": [{"pattern": "^\\.ht", "require": ["all denied"]}]}])
	vs := b.violations with input as inp
	"5.12: Access to .svn Files must be Restricted" in vs
}

test_5_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/files_match"}])
	vs := b.violations with input as inp
	"5.12: evidence missing — apache.files_match not collected" in vs
	not "5.12: Access to .svn Files must be Restricted" in vs
}

test_5_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.13")
}

test_5_13_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/attest/file_extension_allowlist_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.13: Access to Inappropriate File Extensions must be Restricted (manual review not attested)" in vs
}

test_5_13_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/attest/file_extension_allowlist_reviewed"}])
	vs := b.violations with input as inp
	"5.13: Access to Inappropriate File Extensions must be Restricted (manual review not attested)" in vs
}

test_5_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.14")
}

test_5_14_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/apache/directives/RewriteCond", "value": ["%{THE_REQUEST} !(HTTP/1\\.1|HTTP/2\\.0)$"]}])
	vs := b.violations with input as inp
	"5.14: IP Address Based Requests must be Disallowed" in vs
}

test_5_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.14: evidence missing — apache.directives / apache.modules not collected" in vs
	not "5.14: IP Address Based Requests must be Disallowed" in vs
}

test_5_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.15")
}

test_5_15_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Listen", "value": ["80", "10.0.0.5:443"]}])
	vs := b.violations with input as inp
	"5.15: the IP Addresses for Listening for Requests must be Specified" in vs
}

test_5_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.15: evidence missing — apache.directives not collected" in vs
	not "5.15: the IP Addresses for Listening for Requests must be Specified" in vs
}

test_5_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.16")
}

test_5_16_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Header", "value": ["always set X-Frame-Options \"ALLOWALL\""]}])
	vs := b.violations with input as inp
	"5.16: Browser Framing must be Restricted" in vs
}

test_5_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.16: evidence missing — apache.directives not collected" in vs
	not "5.16: Browser Framing must be Restricted" in vs
}

test_5_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.17")
}

test_5_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Header", "value": ["set Referrer-Policy \"unsafe-url\""]}])
	vs := b.violations with input as inp
	"5.17: HTTP Header Referrer-Policy must match the approved value" in vs
}

test_5_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.17: evidence missing — apache.directives not collected" in vs
	not "5.17: HTTP Header Referrer-Policy must match the approved value" in vs
}

test_5_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.18")
}

test_5_18_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Header", "value": ["set X-Content-Type-Options \"nosniff\""]}])
	vs := b.violations with input as inp
	"5.18: HTTP Header Permissions-Policy must match the approved value" in vs
}

test_5_18_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"5.18: evidence missing — apache.directives not collected" in vs
	not "5.18: HTTP Header Permissions-Policy must match the approved value" in vs
}

test_6_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.1")
}

test_6_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/LogLevel", "value": ["warn"]}])
	vs := b.violations with input as inp
	"6.1: the Error Log Filename and Severity Level must match the approved configuration" in vs
}

test_6_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"6.1: evidence missing — apache.directives not collected" in vs
	not "6.1: the Error Log Filename and Severity Level must match the approved configuration" in vs
}

test_6_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.2")
}

test_6_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/ErrorLog", "value": ["logs/error_log"]}])
	vs := b.violations with input as inp
	"6.2: a Syslog Facility must be explicitly configured for Error Logging" in vs
}

test_6_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"6.2: evidence missing — apache.directives not collected" in vs
	not "6.2: a Syslog Facility must be explicitly configured for Error Logging" in vs
}

test_6_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.3")
}

test_6_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/CustomLog", "value": ["logs/access_log common"]}])
	vs := b.violations with input as inp
	"6.3: the Server Access Log must match the approved configuration" in vs
}

test_6_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"6.3: evidence missing — apache.directives not collected" in vs
	not "6.3: the Server Access Log must match the approved configuration" in vs
}

test_6_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.4")
}

test_6_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/log_rotation/retention_weeks", "value": 4}])
	vs := b.violations with input as inp
	"6.4: Log Storage and Rotation must match the approved configuration" in vs
}

test_6_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/log_rotation"}])
	vs := b.violations with input as inp
	"6.4: evidence missing — apache.log_rotation not collected" in vs
	not "6.4: Log Storage and Rotation must match the approved configuration" in vs
}

test_6_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.5")
}

test_6_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/patches/overdue_security_updates", "value": 2}])
	vs := b.violations with input as inp
	"6.5: Applicable Patches must be Applied" in vs
}

test_6_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/patches"}])
	vs := b.violations with input as inp
	"6.5: evidence missing — apache.patches.overdue_security_updates not collected" in vs
	not "6.5: Applicable Patches must be Applied" in vs
}

test_6_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "6.6")
}

test_6_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules", "value": ["core_module", "ssl_module", "log_config_module"]}])
	vs := b.violations with input as inp
	"6.6: ModSecurity must be Installed and Enabled" in vs
}

test_6_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"6.6: evidence missing — apache.modules not collected" in vs
	not "6.6: ModSecurity must be Installed and Enabled" in vs
}

test_7_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.1")
}

test_7_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/modules", "value": ["core_module", "log_config_module"]}])
	vs := b.violations with input as inp
	"7.1: mod_ssl and/or mod_nss must be present" in vs
}

test_7_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/modules"}])
	vs := b.violations with input as inp
	"7.1: evidence missing — apache.modules not collected" in vs
	not "7.1: mod_ssl and/or mod_nss must be present" in vs
}

test_7_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.2")
}

test_7_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/tls/certificates/0/signature_weak", "value": true}])
	vs := b.violations with input as inp
	"7.2: a Valid Trusted Certificate must be present" in vs
}

test_7_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/tls/certificates"}])
	vs := b.violations with input as inp
	"7.2: evidence missing — apache.tls.certificates not collected" in vs
	not "7.2: a Valid Trusted Certificate must be present" in vs
}

test_7_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.3")
}

test_7_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/tls/key_files/0/mode", "value": "640"}])
	vs := b.violations with input as inp
	"7.3: the Server's Private Key must be Protected" in vs
}

test_7_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/tls/key_files"}])
	vs := b.violations with input as inp
	"7.3: evidence missing — apache.tls.{cert_files_with_private_key,key_files} not collected" in vs
	not "7.3: the Server's Private Key must be Protected" in vs
}

test_7_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.4")
}

test_7_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/SSLProtocol", "value": ["all -SSLv3"]}])
	vs := b.violations with input as inp
	"7.4: the TLSv1.0 and TLSv1.1 Protocols must be turned off" in vs
}

test_7_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.4: evidence missing — apache.directives not collected" in vs
	not "7.4: the TLSv1.0 and TLSv1.1 Protocols must be turned off" in vs
}

test_7_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.5")
}

test_7_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/SSLCipherSuite", "value": ["ALL:!EXP:!NULL"]}])
	vs := b.violations with input as inp
	"7.5: Weak SSL/TLS Ciphers must be turned off" in vs
}

test_7_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.5: evidence missing — apache.directives not collected" in vs
	not "7.5: Weak SSL/TLS Ciphers must be turned off" in vs
}

test_7_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.6")
}

test_7_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/SSLInsecureRenegotiation", "value": ["on"]}])
	vs := b.violations with input as inp
	"7.6: Insecure SSL Renegotiation must stay off" in vs
}

test_7_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.6: evidence missing — apache.directives not collected" in vs
	not "7.6: Insecure SSL Renegotiation must stay off" in vs
}

test_7_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.7")
}

test_7_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/SSLCompression", "value": ["on"]}])
	vs := b.violations with input as inp
	"7.7: SSL Compression must stay off" in vs
}

test_7_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.7: evidence missing — apache.directives not collected" in vs
	not "7.7: SSL Compression must stay off" in vs
}

test_7_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.8")
}

test_7_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/SSLCipherSuite", "value": ["ALL:!EXP:!NULL:!LOW:!RC4:!aNULL"]}])
	vs := b.violations with input as inp
	"7.8: Medium Strength SSL/TLS Ciphers must be turned off" in vs
}

test_7_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.8: evidence missing — apache.directives not collected" in vs
	not "7.8: Medium Strength SSL/TLS Ciphers must be turned off" in vs
}

test_7_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.9")
}

test_7_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/http_probe/content_served", "value": ["http://10.0.0.5/"]}])
	vs := b.violations with input as inp
	"7.9: All Web Content must be Accessed via HTTPS" in vs
}

test_7_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/http_probe"}])
	vs := b.violations with input as inp
	"7.9: evidence missing — apache.http_probe.content_served not collected" in vs
	not "7.9: All Web Content must be Accessed via HTTPS" in vs
}

test_7_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.10")
}

test_7_10_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives/SSLStaplingCache"}])
	vs := b.violations with input as inp
	"7.10: OCSP Stapling must be turned on" in vs
}

test_7_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.10: evidence missing — apache.directives not collected" in vs
	not "7.10: OCSP Stapling must be turned on" in vs
}

test_7_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.11")
}

test_7_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Header", "value": ["always set Strict-Transport-Security \"max-age=300\""]}, {"op": "add", "path": "/apache/vhosts/0/directives/Header", "value": ["set Strict-Transport-Security \"max-age=300\""]}])
	vs := b.violations with input as inp
	"7.11: HTTP Strict Transport Security must be turned on" in vs
}

test_7_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.11: evidence missing — apache.directives not collected" in vs
	not "7.11: HTTP Strict Transport Security must be turned on" in vs
}

test_7_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "7.12")
}

test_7_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/tls/scan/non_forward_secrecy_ciphers", "value": ["AES256-GCM-SHA384"]}])
	vs := b.violations with input as inp
	"7.12: Only Cipher Suites That Provide Forward Secrecy must be turned on" in vs
}

test_7_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"7.12: evidence missing — apache.directives not collected" in vs
	not "7.12: Only Cipher Suites That Provide Forward Secrecy must be turned on" in vs
}

test_8_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.1")
}

test_8_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/ServerTokens", "value": ["OS"]}])
	vs := b.violations with input as inp
	"8.1: required value of ServerTokens is 'Prod' or 'ProductOnly'" in vs
}

test_8_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"8.1: evidence missing — apache.directives not collected" in vs
	not "8.1: required value of ServerTokens is 'Prod' or 'ProductOnly'" in vs
}

test_8_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.2")
}

test_8_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/ServerSignature", "value": ["On"]}])
	vs := b.violations with input as inp
	"8.2: ServerSignature must stay off" in vs
}

test_8_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"8.2: evidence missing — apache.directives not collected" in vs
	not "8.2: ServerSignature must stay off" in vs
}

test_8_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.3")
}

test_8_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/default_content/icons_accessible", "value": true}])
	vs := b.violations with input as inp
	"8.3: All Default Apache Content must be Removed" in vs
}

test_8_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/default_content/icons_accessible"}])
	vs := b.violations with input as inp
	"8.3: evidence missing — apache.default_content.icons_accessible not collected" in vs
	not "8.3: All Default Apache Content must be Removed" in vs
}

test_8_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "8.4")
}

test_8_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/FileETag", "value": ["INode MTime Size"]}])
	vs := b.violations with input as inp
	"8.4: checked condition — ETag Response Header Fields Do Not Include Inodes" in vs
}

test_8_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"8.4: evidence missing — apache.directives not collected" in vs
	not "8.4: checked condition — ETag Response Header Fields Do Not Include Inodes" in vs
}

test_9_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.1")
}

test_9_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/Timeout", "value": ["60"]}])
	vs := b.violations with input as inp
	"9.1: required value of the TimeOut is 10 or Less" in vs
}

test_9_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.1: evidence missing — apache.directives not collected" in vs
	not "9.1: required value of the TimeOut is 10 or Less" in vs
}

test_9_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.2")
}

test_9_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/KeepAlive", "value": ["Off"]}])
	vs := b.violations with input as inp
	"9.2: KeepAlive must be turned on" in vs
}

test_9_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.2: evidence missing — apache.directives not collected" in vs
	not "9.2: KeepAlive must be turned on" in vs
}

test_9_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.3")
}

test_9_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/MaxKeepAliveRequests", "value": ["50"]}])
	vs := b.violations with input as inp
	"9.3: required value of MaxKeepAliveRequests is a Value of 100 or Greater" in vs
}

test_9_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.3: evidence missing — apache.directives not collected" in vs
	not "9.3: required value of MaxKeepAliveRequests is a Value of 100 or Greater" in vs
}

test_9_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.4")
}

test_9_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/KeepAliveTimeout", "value": ["30"]}])
	vs := b.violations with input as inp
	"9.4: required value of KeepAliveTimeout is a Value of 15 or Less" in vs
}

test_9_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.4: evidence missing — apache.directives not collected" in vs
	not "9.4: required value of KeepAliveTimeout is a Value of 15 or Less" in vs
}

test_9_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.5")
}

test_9_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/RequestReadTimeout", "value": ["header=20-60,MinRate=500 body=20"]}])
	vs := b.violations with input as inp
	"9.5: required value of the Timeout Limits for Request Headers is 40 or Less" in vs
}

test_9_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.5: evidence missing — apache.directives / apache.modules not collected" in vs
	not "9.5: required value of the Timeout Limits for Request Headers is 40 or Less" in vs
}

test_9_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "9.6")
}

test_9_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/RequestReadTimeout", "value": ["header=20-40,MinRate=500 body=60"]}])
	vs := b.violations with input as inp
	"9.6: required value of Timeout Limits for the Request Body is 20 or Less" in vs
}

test_9_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"9.6: evidence missing — apache.directives / apache.modules not collected" in vs
	not "9.6: required value of Timeout Limits for the Request Body is 20 or Less" in vs
}

test_10_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "10.1")
}

test_10_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/LimitRequestLine", "value": ["0"]}])
	vs := b.violations with input as inp
	"10.1: required value of the LimitRequestLine directive is 8190 or less but not 0" in vs
}

test_10_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"10.1: evidence missing — apache.directives not collected" in vs
	not "10.1: required value of the LimitRequestLine directive is 8190 or less but not 0" in vs
}

test_10_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "10.2")
}

test_10_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/LimitRequestFields", "value": ["200"]}])
	vs := b.violations with input as inp
	"10.2: required value of the LimitRequestFields Directive is 100 or Less but not 0" in vs
}

test_10_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"10.2: evidence missing — apache.directives not collected" in vs
	not "10.2: required value of the LimitRequestFields Directive is 100 or Less but not 0" in vs
}

test_10_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "10.3")
}

test_10_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/LimitRequestFieldSize", "value": ["16380"]}])
	vs := b.violations with input as inp
	"10.3: required value of the LimitRequestFieldsize Directive is 8190 or Less" in vs
}

test_10_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"10.3: evidence missing — apache.directives not collected" in vs
	not "10.3: required value of the LimitRequestFieldsize Directive is 8190 or Less" in vs
}

test_10_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "10.4")
}

test_10_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/directives/LimitRequestBody", "value": ["0"]}])
	vs := b.violations with input as inp
	"10.4: required value of the LimitRequestBody Directive is 102400 or Less but not 0" in vs
}

test_10_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/directives"}])
	vs := b.violations with input as inp
	"10.4: evidence missing — apache.directives not collected" in vs
	not "10.4: required value of the LimitRequestBody Directive is 102400 or Less but not 0" in vs
}

test_11_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "11.1")
}

test_11_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/selinux/current_mode", "value": "permissive"}])
	vs := b.violations with input as inp
	"11.1: SELinux must be turned on in Enforcing Mode" in vs
}

test_11_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/selinux"}])
	vs := b.violations with input as inp
	"11.1: evidence missing — apache.selinux not collected" in vs
	not "11.1: SELinux must be turned on in Enforcing Mode" in vs
}

test_11_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "11.2")
}

test_11_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/selinux/httpd_process_types/-", "value": "unconfined_t"}])
	vs := b.violations with input as inp
	"11.2: checked condition — Apache Processes Run in the httpd_t Confined Context" in vs
}

test_11_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/selinux/httpd_process_types"}])
	vs := b.violations with input as inp
	"11.2: evidence missing — apache.selinux.httpd_process_types not collected" in vs
	not "11.2: checked condition — Apache Processes Run in the httpd_t Confined Context" in vs
}

test_11_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "11.3")
}

test_11_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/selinux/httpd_t_permissive", "value": true}])
	vs := b.violations with input as inp
	"11.3: the httpd_t Type must be Not in Permissive Mode" in vs
}

test_11_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/selinux/httpd_t_permissive"}])
	vs := b.violations with input as inp
	"11.3: evidence missing — apache.selinux.httpd_t_permissive not collected" in vs
	not "11.3: the httpd_t Type must be Not in Permissive Mode" in vs
}

test_11_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "11.4")
}

test_11_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/selinux/enabled_httpd_booleans/-", "value": "httpd_unified"}])
	vs := b.violations with input as inp
	"11.4: Only the Necessary SELinux Booleans must be turned on" in vs
}

test_11_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/selinux/approved_httpd_booleans"}])
	vs := b.violations with input as inp
	"11.4: evidence missing — apache.selinux.{enabled_httpd_booleans,approved_httpd_booleans} not collected" in vs
	not "11.4: Only the Necessary SELinux Booleans must be turned on" in vs
}

test_12_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "12.1")
}

test_12_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/apparmor/enabled", "value": false}])
	vs := b.violations with input as inp
	"12.1: the AppArmor Framework must be turned on" in vs
}

test_12_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/apparmor/enabled"}])
	vs := b.violations with input as inp
	"12.1: evidence missing — apache.apparmor.enabled not collected" in vs
	not "12.1: the AppArmor Framework must be turned on" in vs
}

test_12_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "12.2")
}

test_12_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/apparmor/profile/wildcard_root_rules", "value": ["/** r"]}])
	vs := b.violations with input as inp
	"12.2: the Apache AppArmor Profile must be explicitly configured Properly" in vs
}

test_12_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/apparmor/profile"}])
	vs := b.violations with input as inp
	"12.2: evidence missing — apache.apparmor.profile not collected" in vs
	not "12.2: the Apache AppArmor Profile must be explicitly configured Properly" in vs
}

test_12_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "12.3")
}

test_12_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/apache/apparmor/apache_processes/0/confinement", "value": "complain"}])
	vs := b.violations with input as inp
	"12.3: Apache AppArmor Profile must be in Enforce Mode" in vs
}

test_12_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/apache/apparmor/apache_processes"}])
	vs := b.violations with input as inp
	"12.3: evidence missing — apache.apparmor.apache_processes not collected" in vs
	not "12.3: Apache AppArmor Profile must be in Enforce Mode" in vs
}
