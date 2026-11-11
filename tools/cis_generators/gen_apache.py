"""CIS Apache HTTP Server 2.4 Benchmark v2.4.0 -> benchmarks/cis/apache/cis_apache_2_4.rego (+ tests).

    python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> apache.json
    python3 tools/cis_generators/gen_apache.py apache.json benchmarks/cis/apache
    opa fmt -w benchmarks/cis/apache && python3 scripts/coverage_stamp.py

Same pattern as gen_nginx.py (cis_genlib.py emitter): ids, levels and Automated/Manual status come from the
workbook; the logic table below is hand-authored from each recommendation's audit procedure. Aborts when the
workbook does not hold exactly the 86 ids the table covers. Wording is original (neutralize.py).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import load_workbook_json, emit_control, emit_tests, table  # noqa: E402

WB = load_workbook_json(sys.argv[1])
OUT = sys.argv[2]
BENCH = "CIS Apache HTTP Server 2.4 Benchmark v2.4.0"
A = "input.apache"
CFG = ["_config_collected"]
CFG_LABEL = "apache.directives"
CFG_MISS = [{"op": "remove", "path": "/apache/directives"}]
MODS = ["_modules_collected"]
MODS_LABEL = "apache.modules"
MODS_MISS = [{"op": "remove", "path": "/apache/modules"}]
DIRS = ["_dirs_collected"]
DIRS_LABEL = "apache.directories"
DIRS_MISS = [{"op": "remove", "path": "/apache/directories"}]


def rep(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def d(name, value):
    return rep(f"/apache/directives/{name}", value)


def fact(cid, ev, label, ok, fail, miss, ok2=None):
    oks = [ok] + ([ok2] if ok2 else [])
    return {"id": cid, "kind": "fact", "ev": ev, "label": label, "ok": oks, "fail": fail, "miss": miss}


def cfg(cid, ok, fail, ok2=None, miss=None):
    return fact(cid, CFG, CFG_LABEL, ok, fail, miss or CFG_MISS, ok2)


def cfgmod(cid, ok, fail):
    return fact(cid, CFG + MODS, "apache.directives / apache.modules", ok, fail, CFG_MISS)


def mod(cid, ok, fail, ok2=None):
    return fact(cid, MODS, MODS_LABEL, ok, fail, MODS_MISS, ok2)


def dirs(cid, ok, fail):
    return fact(cid, DIRS, DIRS_LABEL, ok, fail, DIRS_MISS)


def att(cid, key):
    return {"id": cid, "kind": "attest", "attest": key, "attest_root": A}


def no_mod(cid, pred, loaded_name, ok2=None):
    return mod(cid, [pred], rep("/apache/modules/-", loaded_name), ok2)


C = [
    att("1.1", "planning_checklist_implemented"),
    att("1.2", "single_purpose_server_reviewed"),
    att("1.3", "installed_from_approved_binaries"),
    att("2.1", "auth_modules_reviewed"),
    mod("2.2", ['_mod("log_config")'], rep("/apache/modules", ["core_module", "ssl_module"])),
    no_mod("2.3", 'count([m | some m in _mods; contains(m, "dav")]) == 0', "dav_module"),
    no_mod("2.4", 'not _mod("status")', "status_module"),
    no_mod("2.5", 'not _mod("autoindex")', "autoindex_module"),
    no_mod("2.6", 'count([m | some m in _mods; startswith(m, "proxy")]) == 0', "proxy_module",
           ok2=[f"{A}.attest.proxy_modules_required == true"]),
    no_mod("2.7", 'not _mod("userdir")', "userdir_module"),
    no_mod("2.8", 'not _mod("info")', "info_module"),
    no_mod("2.9", 'not _mod("auth_basic")\n\tnot _mod("auth_digest")', "auth_basic_module"),
    fact("3.1", [f"is_string({A}.config.user)", f"is_string({A}.config.group)", f"is_number({A}.account.uid)",
                 f"is_number({A}.account.uid_min)", f"is_array({A}.processes.worker_users)"],
         "apache.config.{user,group} / apache.account.{uid,uid_min} / apache.processes.worker_users",
         [f'not lower({A}.config.user) in {{"", "root"}}', f'not lower({A}.config.group) in {{"", "root"}}',
          f"{A}.account.uid != 0", f"{A}.account.uid < {A}.account.uid_min",
          f"every u in {A}.processes.worker_users {{ u == {A}.config.user }}"],
         rep("/apache/config/user", "root"), rm("/apache/config")),
    fact("3.2", [f"is_string({A}.account.shell)"], "apache.account.shell",
         [f"{A}.account.shell in _nologin_shells"], rep("/apache/account/shell", "/bin/bash"), rm("/apache/account/shell")),
    fact("3.3", [f"is_boolean({A}.account.locked)"], "apache.account.locked",
         [f"{A}.account.locked == true"], rep("/apache/account/locked", False), rm("/apache/account/locked")),
    fact("3.4", [f"is_array({A}.files.not_root_owned)"], "apache.files.not_root_owned",
         [f"count({A}.files.not_root_owned) == 0"], rep("/apache/files/not_root_owned", ["/etc/httpd/conf.d/app.conf"]),
         rm("/apache/files/not_root_owned")),
    fact("3.5", [f"is_array({A}.files.wrong_group)"], "apache.files.wrong_group",
         [f"count({A}.files.wrong_group) == 0"], rep("/apache/files/wrong_group", ["/etc/httpd/modules"]),
         rm("/apache/files/wrong_group")),
    fact("3.6", [f"is_array({A}.files.other_writable)"], "apache.files.other_writable",
         [f"count({A}.files.other_writable) == 0"], rep("/apache/files/other_writable", ["/etc/httpd/logs"]),
         rm("/apache/files/other_writable")),
    fact("3.7", [f"is_object({A}.core_dump)", f"is_boolean({A}.core_dump.configured)"], "apache.core_dump",
         [f"{A}.core_dump.configured == false"], rep("/apache/core_dump", {"configured": True, "within_docroot": False, "owner": "root", "group": "apache", "mode": "757"}), rm("/apache/core_dump"),
         ok2=[f"{A}.core_dump.configured == true", f"{A}.core_dump.within_docroot == false",
              f'{A}.core_dump.owner == "root"', f"{A}.core_dump.group == {A}.config.group",
              f"bits.and(octal({A}.core_dump.mode), 7) == 0"]),
    fact("3.8", [f"is_object({A}.lock_file)", f"is_boolean({A}.lock_file.file_mutex)"], "apache.lock_file",
         [f"{A}.lock_file.file_mutex == false"], rep("/apache/lock_file", {"file_mutex": True, "dir": {"within_docroot": False, "owner": "root", "group": "root", "mode": "775", "local_fs": True}}), rm("/apache/lock_file"),
         ok2=[f"{A}.lock_file.file_mutex == true", f"_runtime_dir_ok({A}.lock_file.dir)", f"{A}.lock_file.dir.local_fs == true"]),
    fact("3.9", [f"is_object({A}.pid_file.dir)"], "apache.pid_file.dir",
         [f"_runtime_dir_ok({A}.pid_file.dir)"], rep("/apache/pid_file/dir/within_docroot", True), rm("/apache/pid_file")),
    fact("3.10", [f"is_object({A}.scoreboard)", f"is_boolean({A}.scoreboard.configured)"], "apache.scoreboard",
         [f"{A}.scoreboard.configured == false"], rep("/apache/scoreboard", {"configured": True, "dir": {"within_docroot": True}}),
         rm("/apache/scoreboard"),
         ok2=[f"{A}.scoreboard.configured == true", f"_runtime_dir_ok({A}.scoreboard.dir)", f"{A}.scoreboard.dir.local_fs == true"]),
    fact("3.11", [f"is_array({A}.files.group_writable)"], "apache.files.group_writable",
         [f"count({A}.files.group_writable) == 0"], rep("/apache/files/group_writable", ["/etc/httpd/conf"]),
         rm("/apache/files/group_writable")),
    fact("3.12", [f"is_array({A}.docroot.group_writable)"], "apache.docroot.group_writable",
         [f"count({A}.docroot.group_writable) == 0"], rep("/apache/docroot/group_writable", ["/var/www/html/upload"]),
         rm("/apache/docroot")),
    fact("3.13", [f"is_array({A}.writable_dirs)"], "apache.writable_dirs",
         [f"every w in {A}.writable_dirs {{ _writable_dir_ok(w) }}"],
         rep("/apache/writable_dirs/0/other_writable", True), rm("/apache/writable_dirs")),
    dirs("4.1", ["count(_root_dirs) > 0", "every r in _root_dirs { _denies_all(r) }"], rep("/apache/directories/0/require", ["all granted"])),
    att("4.2", "web_content_access_reviewed"),
    dirs("4.3", ["count(_root_dirs) > 0", "every r in _root_dirs { _override_none(r) }"], rep("/apache/directories/0/allow_override", ["All"])),
    dirs("4.4", [f"every x in {A}.directories {{ _override_none_or_absent(x) }}"], rep("/apache/directories/1/allow_override", ["AuthConfig"])),
    dirs("5.1", ["count(_root_dirs) > 0", "every r in _root_dirs { _options_defined(r); count(_opts(r)) == 0 }"],
         rep("/apache/directories/0/options", "FollowSymLinks")),
    dirs("5.2", ["count(_docroot_dirs) > 0", 'every x in _docroot_dirs { _options_defined(x); count(_opts(x) - {"multiviews"}) == 0 }'],
         rep("/apache/directories/1/options", ["Indexes", "FollowSymLinks"])),
    dirs("5.3", [f'every x in {A}.directories {{ count(_opts(x) & {{"includes", "includesnoexec"}}) == 0 }}'],
         rep("/apache/directories/2/options", "+Includes")),
    fact("5.4", [f"is_object({A}.default_content)", f"is_boolean({A}.default_content.default_index_present)",
                 f"is_array({A}.default_content.other_status_handlers)"], "apache.default_content",
         [f"{A}.default_content.default_index_present == false", f"{A}.default_content.manual_configured == false",
          f"{A}.default_content.server_status_handler == false", f"{A}.default_content.server_info_handler == false",
          f"count({A}.default_content.other_status_handlers) == 0"],
         rep("/apache/default_content/server_status_handler", True), rm("/apache/default_content")),
    fact("5.5", [f"is_boolean({A}.cgi.printenv_present)"], "apache.cgi.printenv_present",
         [f"{A}.cgi.printenv_present == false"], rep("/apache/cgi/printenv_present", True), rm("/apache/cgi/printenv_present")),
    fact("5.6", [f"is_boolean({A}.cgi.test_cgi_present)"], "apache.cgi.test_cgi_present",
         [f"{A}.cgi.test_cgi_present == false"], rep("/apache/cgi/test_cgi_present", True), rm("/apache/cgi/test_cgi_present")),
    dirs("5.7", ["count(_non_root_dirs) > 0", "every x in _non_root_dirs { _methods_restricted(x) }"],
         rep("/apache/directories/1/limit_except/methods", ["GET", "POST", "PUT", "DELETE"])),
    cfg("5.8", ['_dv_lower("TraceEnable") == ["off"]'], d("TraceEnable", ["on"])),
    cfgmod("5.9", ['_mod("rewrite")', '_rewrite_on', 'some c in _dv("RewriteCond")', 'contains(c, "%{THE_REQUEST}")',
                       'contains(c, "HTTP/1")', 'some r in _dv("RewriteRule")', "_rule_forbids(r)",
                       "every v in _vhosts { _vhost_inherits_rewrite(v) }"],
        rm("/apache/directives/RewriteCond")),
    fact("5.10", [f"is_array({A}.files_match)"], "apache.files_match", ['_fm_denies(".ht")'],
         rep("/apache/files_match", []), rm("/apache/files_match")),
    fact("5.11", [f"is_array({A}.files_match)", f"is_array({A}.directory_match)"], "apache.files_match / apache.directory_match",
         ['_fm_denies(".git")', '_dm_denies(".git")'], rep("/apache/directory_match", []), rm("/apache/directory_match")),
    fact("5.12", [f"is_array({A}.files_match)"], "apache.files_match", ['_fm_denies(".svn")'],
         rep("/apache/files_match", [{"pattern": "^\\.ht", "require": ["all denied"]}]), rm("/apache/files_match")),
    att("5.13", "file_extension_allowlist_reviewed"),
    cfgmod("5.14", ['_mod("rewrite")', '_rewrite_on', 'some c in _dv("RewriteCond")', 'contains(c, "%{HTTP_HOST}")',
                        'contains(c, "!")', 'some r in _dv("RewriteRule")', "_rule_forbids(r)"],
        [{"op": "replace", "path": "/apache/directives/RewriteCond", "value": ["%{THE_REQUEST} !(HTTP/1\\.1|HTTP/2\\.0)$"]}]),
    cfg("5.15", ['ls := _dv("Listen")', "count(ls) > 0", "every l in ls { _listen_has_address(l) }"], d("Listen", ["80", "10.0.0.5:443"])),
    cfg("5.16", ["some h in _headers", "_framing_header_ok(h)"], d("Header", ['always set X-Frame-Options "ALLOWALL"'])),
    cfg("5.17", ["some h in _headers", '_hdr_name(h) == "referrer-policy"', "_hdr_value(h) in _good_referrer_policies"],
        d("Header", ['set Referrer-Policy "unsafe-url"'])),
    cfg("5.18", ["some h in _headers", '_hdr_name(h) == "permissions-policy"', '_hdr_value(h) != ""'],
        d("Header", ['set X-Content-Type-Options "nosniff"'])),
    cfg("6.1", ['lv := _dv("LogLevel")', "count(lv) == 1", "_loglevel_ok(lv[0])", 'el := _dv("ErrorLog")', "count(el) > 0",
                'every e in el { trim_space(e) != "" }'], d("LogLevel", ["warn"])),
    cfg("6.2", ['el := _dv("ErrorLog")', "count(el) > 0", 'every e in el { startswith(lower(e), "syslog") }'],
        d("ErrorLog", ["logs/error_log"])),
    cfg("6.3", ['cl := _dv("CustomLog")', "count(cl) > 0", "every c in cl { _access_format_complete(c) }"],
        d("CustomLog", ["logs/access_log common"])),
    fact("6.4", [f"is_object({A}.log_rotation)", f"is_number({A}.log_rotation.retention_weeks)"], "apache.log_rotation",
         [f"{A}.log_rotation.covers_configured_logs == true", f"{A}.log_rotation.retention_weeks >= 13",
          f"{A}.log_rotation.vhost_logs_included == true"],
         rep("/apache/log_rotation/retention_weeks", 4), rm("/apache/log_rotation")),
    fact("6.5", [f"is_number({A}.patches.overdue_security_updates)"], "apache.patches.overdue_security_updates",
         [f"{A}.patches.overdue_security_updates == 0"], rep("/apache/patches/overdue_security_updates", 2), rm("/apache/patches")),
    mod("6.6", ['_mod("security2")'], rep("/apache/modules", ["core_module", "ssl_module", "log_config_module"])),
    mod("7.1", ['_mod("ssl")'], rep("/apache/modules", ["core_module", "log_config_module"]), ok2=['_mod("nss")']),
    fact("7.2", [f"is_array({A}.tls.certificates)", f"count({A}.tls.certificates) > 0"], "apache.tls.certificates",
         [f"every c in {A}.tls.certificates {{ c.trusted == true; c.signature_weak == false }}"],
         rep("/apache/tls/certificates/0/signature_weak", True), rm("/apache/tls/certificates")),
    fact("7.3", [f"is_array({A}.tls.cert_files_with_private_key)", f"is_array({A}.tls.key_files)", f"count({A}.tls.key_files) > 0"],
         "apache.tls.{cert_files_with_private_key,key_files}",
         [f"count({A}.tls.cert_files_with_private_key) == 0",
          f'every k in {A}.tls.key_files {{ k.owner == "root"; k.group == "root"; mode_within(k.mode, "400") }}'],
         rep("/apache/tls/key_files/0/mode", "640"), rm("/apache/tls/key_files")),
    cfg("7.4", ['ps := _dv("SSLProtocol")', "count(ps) > 0", "every p in ps { _protocols_ok(p) }"], d("SSLProtocol", ["all -SSLv3"])),
    cfg("7.5", ['cs := _dv("SSLCipherSuite")', "count(cs) > 0", "every c in cs { _weak_excluded(c) }", '_dv_lower("SSLHonorCipherOrder") == ["on"]'],
        d("SSLCipherSuite", ["ALL:!EXP:!NULL"]), ok2=[f"is_array({A}.tls.scan.weak_ciphers)", f"count({A}.tls.scan.weak_ciphers) == 0"]),
    cfg("7.6", ['every v in _dv_lower("SSLInsecureRenegotiation") { v == "off" }'], d("SSLInsecureRenegotiation", ["on"])),
    cfg("7.7", ['every v in _dv_lower("SSLCompression") { v == "off" }'], d("SSLCompression", ["on"])),
    cfg("7.8", ['cs := _dv("SSLCipherSuite")', "count(cs) > 0", "every c in cs { _medium_excluded(c) }"],
        d("SSLCipherSuite", ["ALL:!EXP:!NULL:!LOW:!RC4:!aNULL"]),
        ok2=[f"is_array({A}.tls.scan.medium_ciphers)", f"count({A}.tls.scan.medium_ciphers) == 0"]),
    fact("7.9", [f"is_array({A}.http_probe.content_served)"], "apache.http_probe.content_served",
         [f"count({A}.http_probe.content_served) == 0"], rep("/apache/http_probe/content_served", ["http://10.0.0.5/"]),
         rm("/apache/http_probe")),
    cfg("7.10", ['count(_dv("SSLStaplingCache")) > 0', '_everywhere_ssl("SSLUseStapling", "on")'], rm("/apache/directives/SSLStaplingCache")),
    cfg("7.11", ["_hsts_everywhere"], d("Header", ['always set Strict-Transport-Security "max-age=300"'])
        + rep("/apache/vhosts/0/directives/Header", ['set Strict-Transport-Security "max-age=300"'])),
    cfg("7.12", [f"is_array({A}.tls.scan.non_forward_secrecy_ciphers)", f"count({A}.tls.scan.non_forward_secrecy_ciphers) == 0"],
        rep("/apache/tls/scan/non_forward_secrecy_ciphers", ["AES256-GCM-SHA384"]),
        ok2=['cs := _dv("SSLCipherSuite")', "count(cs) > 0", "every c in cs { _forward_secrecy_only(c) }"]),
    cfg("8.1", ['st := _dv_lower("ServerTokens")', "count(st) > 0", 'every s in st { s in {"prod", "productonly"} }'], d("ServerTokens", ["OS"])),
    cfg("8.2", ['every v in _dv_lower("ServerSignature") { v == "off" }'], d("ServerSignature", ["On"])),
    fact("8.3", [f"is_boolean({A}.default_content.icons_accessible)"], "apache.default_content.icons_accessible",
         [f"{A}.default_content.icons_accessible == false"], rep("/apache/default_content/icons_accessible", True),
         rm("/apache/default_content/icons_accessible")),
    cfg("8.4", ['every v in _dv("FileETag") { _etag_ok(v) }'], d("FileETag", ["INode MTime Size"])),
    cfg("9.1", ['_all_num_within("Timeout", 1, 10)'], d("Timeout", ["60"])),
    cfg("9.2", ['every v in _dv_lower("KeepAlive") { v == "on" }'], d("KeepAlive", ["Off"])),
    cfg("9.3", ['every v in _dv("MaxKeepAliveRequests") { _num(v) >= 100 }'], d("MaxKeepAliveRequests", ["50"])),
    cfg("9.4", ['every v in _dv("KeepAliveTimeout") { _num(v) >= 1; _num(v) <= 15 }'], d("KeepAliveTimeout", ["30"])),
    cfgmod("9.5", ['_mod("reqtimeout")', 'every m in _rrt_max("header") { m <= 40 }'], d("RequestReadTimeout", ["header=20-60,MinRate=500 body=20"])),
    cfgmod("9.6", ['_mod("reqtimeout")', 'every m in _rrt_max("body") { m <= 20 }'], d("RequestReadTimeout", ["header=20-40,MinRate=500 body=60"])),
    cfg("10.1", ['_all_num_within("LimitRequestLine", 1, 8190)'], d("LimitRequestLine", ["0"])),
    cfg("10.2", ['_all_num_within("LimitRequestFields", 1, 100)'], d("LimitRequestFields", ["200"])),
    cfg("10.3", ['_all_num_within("LimitRequestFieldSize", 1, 8190)'], d("LimitRequestFieldSize", ["16380"])),
    cfg("10.4", ['_all_num_within("LimitRequestBody", 1, 102400)'], d("LimitRequestBody", ["0"])),
    fact("11.1", [f"is_object({A}.selinux)", f"is_boolean({A}.selinux.enabled)"], "apache.selinux",
         [f"{A}.selinux.enabled == true", f'lower({A}.selinux.current_mode) == "enforcing"', f'lower({A}.selinux.config_mode) == "enforcing"'],
         rep("/apache/selinux/current_mode", "permissive"), rm("/apache/selinux")),
    fact("11.2", [f"is_array({A}.selinux.httpd_process_types)", f"count({A}.selinux.httpd_process_types) > 0"],
         "apache.selinux.httpd_process_types", [f'every t in {A}.selinux.httpd_process_types {{ t == "httpd_t" }}'],
         rep("/apache/selinux/httpd_process_types/-", "unconfined_t"), rm("/apache/selinux/httpd_process_types")),
    fact("11.3", [f"is_boolean({A}.selinux.httpd_t_permissive)"], "apache.selinux.httpd_t_permissive",
         [f"{A}.selinux.httpd_t_permissive == false"], rep("/apache/selinux/httpd_t_permissive", True),
         rm("/apache/selinux/httpd_t_permissive")),
    fact("11.4", [f"is_array({A}.selinux.enabled_httpd_booleans)", f"is_array({A}.selinux.approved_httpd_booleans)"],
         "apache.selinux.{enabled_httpd_booleans,approved_httpd_booleans}",
         [f"every b in {A}.selinux.enabled_httpd_booleans {{ b in _approved_booleans }}"],
         rep("/apache/selinux/enabled_httpd_booleans/-", "httpd_unified"), rm("/apache/selinux/approved_httpd_booleans")),
    fact("12.1", [f"is_boolean({A}.apparmor.enabled)"], "apache.apparmor.enabled",
         [f"{A}.apparmor.enabled == true"], rep("/apache/apparmor/enabled", False), rm("/apache/apparmor/enabled")),
    fact("12.2", [f"is_object({A}.apparmor.profile)", f"is_array({A}.apparmor.profile.wildcard_root_rules)"], "apache.apparmor.profile",
         [f"{A}.apparmor.profile.present == true", f"count({A}.apparmor.profile.wildcard_root_rules) == 0"],
         rep("/apache/apparmor/profile/wildcard_root_rules", ["/** r"]), rm("/apache/apparmor/profile")),
    fact("12.3", [f"is_array({A}.apparmor.apache_processes)", f"count({A}.apparmor.apache_processes) > 0"],
         "apache.apparmor.apache_processes", [f'every p in {A}.apparmor.apache_processes {{ p.confinement == "enforce" }}'],
         rep("/apache/apparmor/apache_processes/0/confinement", "complain"), rm("/apache/apparmor/apache_processes")),
]

SECTIONS = ["planning", "modules", "permissions", "access_control", "features", "logging", "tls", "information_leakage",
            "dos_mitigation", "request_limits", "selinux", "apparmor"]
SECTION_TITLES = {
    "planning": "1 Planning the installation", "modules": "2 Loaded modules",
    "permissions": "3 Service account, ownership and permissions", "access_control": "4 Directory access control",
    "features": "5 Options, methods, default content and headers", "logging": "6 Logging, rotation and patching",
    "tls": "7 TLS", "information_leakage": "8 Information leakage", "dos_mitigation": "9 Timeouts and keep-alive",
    "request_limits": "10 Request limits", "selinux": "11 SELinux (Level 2, applies when the host runs SELinux)",
    "apparmor": "12 AppArmor (Level 2, applies when the host runs AppArmor)",
}
SECTION_OF = dict(zip([str(i) for i in range(1, 13)], SECTIONS))


def section(cid):
    return SECTION_OF[cid.split(".")[0]]


ids = [c["id"] for c in C]
assert len(ids) == len(set(ids)) == len(WB) == 86, (len(ids), len(WB))
assert set(ids) == set(WB), (set(ids) ^ set(WB))

GREEN = {"apache": {
    "modules": ["core_module", "so_module", "http_module", "mpm_event_module", "log_config_module", "ssl_module",
                "rewrite_module", "headers_module", "reqtimeout_module", "security2_module", "allowmethods_module",
                "authz_core_module", "unixd_module", "mime_module", "dir_module"],
    "config": {"user": "apache", "group": "apache"},
    "account": {"name": "apache", "uid": 48, "uid_min": 1000, "shell": "/sbin/nologin", "locked": True},
    "processes": {"worker_users": ["apache", "apache"]},
    "files": {"not_root_owned": [], "wrong_group": [], "other_writable": [], "group_writable": []},
    "docroot": {"group_writable": []},
    "core_dump": {"configured": False},
    "lock_file": {"file_mutex": False},
    "pid_file": {"dir": {"within_docroot": False, "owner": "root", "group": "root", "mode": "755"}},
    "scoreboard": {"configured": False},
    "writable_dirs": [{"path": "/var/phptmp/sessions", "single_purpose": True, "within_docroot": False, "owner": "root",
                       "other_writable": False}],
    "directories": [
        {"path": "/", "is_root": True, "options": "None", "allow_override": ["None"], "allow_override_list": [],
         "require": ["all denied"], "allow": [], "deny": []},
        {"path": "/var/www/html", "is_docroot": True, "options": ["None"], "allow_override": ["None"],
         "require": ["all granted"], "limit_except": {"methods": ["GET", "POST", "OPTIONS"], "require": ["all denied"]}},
        {"path": "/var/www/cgi-bin", "options": ["None"], "allow_override": ["None"], "require": ["all granted"],
         "allow_methods": ["GET", "POST", "OPTIONS"]},
    ],
    "default_content": {"default_index_present": False, "manual_configured": False, "server_status_handler": False,
                        "server_info_handler": False, "other_status_handlers": [], "icons_accessible": False},
    "cgi": {"printenv_present": False, "test_cgi_present": False},
    "files_match": [{"pattern": "^\\.ht", "require": ["all denied"]}, {"pattern": "/\\.git", "require": ["all denied"]},
                    {"pattern": "/\\.svn", "deny": ["from all"]}],
    "directory_match": [{"pattern": "/\\.git", "require": ["all denied"]}],
    "directives": {
        "TraceEnable": ["Off"], "RewriteEngine": ["On"], "RewriteOptions": ["Inherit"],
        "RewriteCond": ["%{THE_REQUEST} !(HTTP/1\\.1|HTTP/2\\.0)$", "%{HTTP_HOST} !^www\\.example\\.com [NC]",
                        "%{REQUEST_URI} !^/error [NC]"],
        "RewriteRule": [".* - [F]", "^.(.*) - [L,F]"],
        "Listen": ["10.0.0.5:80", "10.0.0.5:443"],
        "Header": ['always set X-Frame-Options "SAMEORIGIN"', "always set Content-Security-Policy \"frame-ancestors 'self'\"",
                   'set Referrer-Policy "strict-origin-when-cross-origin"', 'set Permissions-Policy "geolocation=()"',
                   'always set Strict-Transport-Security "max-age=63072000; includeSubDomains"'],
        "LogLevel": ["notice core:info"], "ErrorLog": ["syslog:local1"],
        "LogFormat": ['"%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-agent}i\\"" combined',
                      '"%h %l %u %t \\"%r\\" %>s %b" common'],
        "CustomLog": ["logs/access_log combined"],
        "SSLProtocol": ["-all +TLSv1.2 +TLSv1.3"], "SSLHonorCipherOrder": ["On"],
        "SSLCipherSuite": ["ALL:!EXP:!NULL:!LOW:!SSLv2:!RC4:!aNULL:!3DES:!IDEA"],
        "SSLInsecureRenegotiation": ["off"], "SSLCompression": ["off"],
        "SSLStaplingCache": ["shmcb:logs/ssl_stapling(32768)"], "SSLUseStapling": ["on"],
        "ServerTokens": ["Prod"], "ServerSignature": ["Off"],
        "Timeout": ["10"], "KeepAlive": ["On"], "MaxKeepAliveRequests": ["100"], "KeepAliveTimeout": ["15"],
        "RequestReadTimeout": ["header=20-40,MinRate=500 body=20,MinRate=500"],
        "LimitRequestLine": ["512"], "LimitRequestFields": ["100"], "LimitRequestFieldSize": ["1024"],
        "LimitRequestBody": ["102400"],
    },
    "vhosts": [{"name": "www.example.com", "ssl": True, "directives": {
        "RewriteEngine": ["On"], "RewriteOptions": ["Inherit"], "SSLUseStapling": ["on"],
        "Header": ['always set Strict-Transport-Security "max-age=63072000"']}}],
    "log_rotation": {"covers_configured_logs": True, "retention_weeks": 13, "vhost_logs_included": True},
    "patches": {"overdue_security_updates": 0},
    "tls": {"certificates": [{"path": "/etc/pki/tls/certs/www.crt", "trusted": True, "signature_weak": False}],
            "cert_files_with_private_key": [],
            "key_files": [{"path": "/etc/pki/tls/private/www.key", "owner": "root", "group": "root", "mode": "400"}],
            "scan": {"non_forward_secrecy_ciphers": []}},
    "http_probe": {"content_served": []},
    "selinux": {"enabled": True, "current_mode": "enforcing", "config_mode": "enforcing", "httpd_process_types": ["httpd_t"],
                "httpd_t_permissive": False, "enabled_httpd_booleans": ["httpd_builtin_scripting"],
                "approved_httpd_booleans": ["httpd_builtin_scripting"]},
    "apparmor": {"enabled": True, "profile": {"present": True, "wildcard_root_rules": []},
                 "apache_processes": [{"pid": 1899, "confinement": "enforce"}]},
    "attest": {"planning_checklist_implemented": True, "single_purpose_server_reviewed": True,
               "installed_from_approved_binaries": True, "auth_modules_reviewed": True,
               "web_content_access_reviewed": True, "file_extension_allowlist_reviewed": True},
}}

fact_manual = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]
attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
l2 = sorted([i for i in ids if WB[i]["level"] == 2], key=lambda x: [int(p) for p in x.split(".")])

HEADER = f'''# METADATA
# title: "{BENCH}"
# custom:
#   class: security
#   framework: cis_apache
#   source: cis
#   domains: [web-server]
#   coverage:
#     checks: 0
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis.apache_2_4

# {BENCH} (October 2026; supersedes v2.3.0).
# The package name (cis.apache_2_4) and the entrypoints (compliant, violations, compliance_report, findings) are kept
# so existing callers keep working. Generated by tools/cis_generators/gen_apache.py from the CIS workbook: do not
# edit by hand, regenerate.
#
# 86 recommendations, every one in the benchmark; ids, levels and assessment status read from the workbook
# ({len(ids) - len(l2)} Level 1, {len(l2)} Level 2). Every recommendation is evaluated; `recommendations` lists each id's level.
# - {len(attest_ids)} need a human judgement and use an attestation boolean under input.apache.attest
#   (not attested => violation): {", ".join(attest_ids)}.
# - {len(fact_manual)} are Manual in the workbook but decided from collected facts, because the audit is a directive,
#   permission or probe comparison (the cis.oracle_26ai / cis_nginx precedent): {", ".join(fact_manual)}.
# - Automated recommendations are decided from facts. Every fact-based check fails closed: facts not collected =>
#   "<id>: evidence missing — <field> not collected".
# - 2.6 passes with proxy modules loaded only when input.apache.attest.proxy_modules_required == true.
# - 7.5, 7.8 and 7.12 accept either the SSLCipherSuite directive or a cipher scan (input.apache.tls.scan.*).
#
# Sections 11 (SELinux) and 12 (AppArmor) are Level 2 and platform-specific. input.apache.platform.mac
# ("selinux" or "apparmor") selects the one that applies; absent or unknown => both apply (strictest).
#
# Input contract (input.apache):
#   modules[]                       : names from `httpd -M` ("ssl_module (shared)", "mod_ssl" and "ssl" all match)
#   config.{{user,group}}             : User / Group directive values
#   account.{{uid,uid_min,shell,locked}} : the service account (uid_min from /etc/login.defs; locked from passwd -S)
#   processes.worker_users[]        : users of the running httpd worker processes (not the root parent)
#   files.{{not_root_owned,wrong_group,other_writable,group_writable}}[] : paths under ServerRoot (3.4-3.6, 3.11)
#   docroot.group_writable[]        : paths under DocumentRoot writable by the Apache group (3.12)
#   core_dump.{{configured,within_docroot,owner,group,mode}} : CoreDumpDirectory (3.7)
#   lock_file.{{file_mutex,dir}} / pid_file.dir / scoreboard.{{configured,dir}} : dir = {{within_docroot,owner,group,mode,local_fs}}
#   startup_user                    : optional, the account httpd starts as (default "root")
#   writable_dirs[].{{single_purpose,within_docroot,owner,owner_is_admin,other_writable}} : application writable dirs (3.13)
#   directories[]                   : one entry per <Directory>: {{path,is_root,is_docroot,options,allow_override[],
#                                     allow_override_list[],require[],order,allow[],deny[],limit_except{{methods[],require[],order,deny[]}},
#                                     allow_methods[]}}; options is the token list or the directive string
#   files_match[] / directory_match[] : {{pattern,require[],deny[]}} per <FilesMatch> / <DirectoryMatch>
#   directives{{name: [values]}}      : every occurrence of each server-context directive (arguments as one string)
#   vhosts[].{{name,ssl,directives}}   : one entry per <VirtualHost> (used for RewriteOptions Inherit, stapling, HSTS)
#   default_content.{{default_index_present,manual_configured,server_status_handler,server_info_handler,other_status_handlers[],icons_accessible}}
#   cgi.{{printenv_present,test_cgi_present}}
#   log_rotation.{{covers_configured_logs,retention_weeks,vhost_logs_included}}
#   patches.overdue_security_updates : security releases older than 30 days not installed
#   tls.certificates[].{{trusted,signature_weak}}, tls.cert_files_with_private_key[], tls.key_files[].{{owner,group,mode}}
#   tls.scan.{{weak_ciphers,medium_ciphers,non_forward_secrecy_ciphers}}[] : from an sslscan-style probe (optional)
#   http_probe.content_served[]     : http:// URLs that returned page content instead of a redirect or error
#   selinux.{{enabled,current_mode,config_mode,httpd_process_types[],httpd_t_permissive,enabled_httpd_booleans[],approved_httpd_booleans[]}}
#   apparmor.{{enabled,profile{{present,wildcard_root_rules[]}},apache_processes[].confinement}}
#   attest.*                        : attestation booleans for the judgement recommendations

import rego.v1

default compliant := false

compliant if {{
	# fail-closed: no facts, no compliance
	input.apache
	count(violations) == 0
}}

violations := sort([m | some m in _all_violations])

'''

HELPERS = r'''# ── applicability ────────────────────────────────────────────────────────────
_known_mac := {"selinux", "apparmor"}

default _mac := {"selinux", "apparmor"}

_mac := {m} if {
	m := lower(input.apache.platform.mac)
	m in _known_mac
}

_applies(id) if {
	not startswith(id, "11.")
	not startswith(id, "12.")
}

_applies(id) if {
	startswith(id, "11.")
	"selinux" in _mac
}

_applies(id) if {
	startswith(id, "12.")
	"apparmor" in _mac
}

# ── evidence presence ────────────────────────────────────────────────────────
default _config_collected := false

_config_collected if {
	is_object(input.apache.directives)
	count(input.apache.directives) > 0
}

default _modules_collected := false

_modules_collected if {
	is_array(input.apache.modules)
	count(input.apache.modules) > 0
}

default _dirs_collected := false

_dirs_collected if {
	is_array(input.apache.directories)
	count(input.apache.directories) > 0
}

# ── directives ───────────────────────────────────────────────────────────────
# every occurrence of a directive (name compared case-insensitively), as trimmed strings
_dv(name) := [trim_space(sprintf("%v", [x])) |
	some k, vs in input.apache.directives
	lower(k) == lower(name)
	some x in _as_list(vs)
]

_dv_lower(name) := [lower(v) | some v in _dv(name)]

_as_list(v) := v if is_array(v)

_as_list(v) := [v] if is_string(v)

_tokens(s) := [t | some t in regex.split(`\s+`, trim_space(s)); t != ""]

_first(s) := _tokens(s)[0]

_num(v) := to_number(_first(v)) if regex.match(`^[0-9]+$`, _first(v))

# present, and every occurrence is an integer within [lo, hi]
_all_num_within(name, lo, hi) if {
	vs := _dv(name)
	count(vs) > 0
	every v in vs {
		_num(v) >= lo
		_num(v) <= hi
	}
}

# ── modules ──────────────────────────────────────────────────────────────────
# "ssl_module (shared)", "mod_ssl", "ssl_module" and "ssl" all normalise to "ssl"
_modname(m) := trim_suffix(trim_prefix(lower(_first(sprintf("%v", [m]))), "mod_"), "_module")

_mods := {_modname(m) | some m in input.apache.modules}

_mod(name) if name in _mods

# ── service account and files ────────────────────────────────────────────────
_nologin_shells := {"/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin", "/bin/false", "/usr/bin/false", "/dev/null"}

default _startup_user := "root"

_startup_user := u if {
	u := input.apache.startup_user
	is_string(u)
}

# a runtime directory (lock, pid, scoreboard): outside DocumentRoot, owned by the startup user, writable only by it
_runtime_dir_ok(dir) if {
	dir.within_docroot == false
	dir.owner == _startup_user
	dir.group == _startup_user
	mode_within(dir.mode, "755")
}

_writable_dir_ok(w) if {
	w.single_purpose == true
	w.within_docroot == false
	_admin_owner(w)
	w.other_writable == false
}

_admin_owner(w) if w.owner == "root"

_admin_owner(w) if w.owner_is_admin == true

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

# ── <Directory> blocks ───────────────────────────────────────────────────────
_is_root(x) if x.is_root == true

_is_root(x) if x.path == "/"

_root_dirs := [x | some x in input.apache.directories; _is_root(x)]

_non_root_dirs := [x | some x in input.apache.directories; not _is_root(x)]

_docroot_dirs := [x | some x in input.apache.directories; x.is_docroot == true]

_list(x, key) := [sprintf("%v", [v]) | some v in _as_list(object.get(x, key, []))]

_lower_list(x, key) := [lower(trim_space(v)) | some v in _list(x, key)]

# Options directive: array of tokens or a whitespace separated string, with optional +/- prefixes.
# The set of lower-cased options switched on ("all" expands; "none" adds nothing).
_options_defined(x) if is_array(x.options)

_options_defined(x) if is_string(x.options)

_option_tokens(x) := [sprintf("%v", [t]) | some t in x.options] if is_array(x.options)

_option_tokens(x) := _tokens(x.options) if is_string(x.options)

_opts(x) := {o |
	some t in _option_tokens(x)
	t != ""
	not startswith(t, "-")
	base := lower(trim_prefix(t, "+"))
	some o in _expand_option(base)
}

_expand_option(o) := {"indexes", "includes", "execcgi", "followsymlinks", "symlinksifownermatch", "multiviews"} if o == "all"

_expand_option(o) := set() if o == "none"

_expand_option(o) := {o} if not o in {"all", "none"}

# access denied to everyone: Require all denied (no Allow/Deny), or Order deny,allow + Deny from all (no Allow/Require)
_denies_all(x) if {
	_lower_list(x, "require") == ["all denied"]
	count(_list(x, "allow")) == 0
	count(_list(x, "deny")) == 0
}

_denies_all(x) if {
	regex.replace(lower(sprintf("%v", [object.get(x, "order", "")])), `\s`, "") == "deny,allow"
	some dd in _lower_list(x, "deny")
	dd in {"from all", "all"}
	count(_list(x, "allow")) == 0
	count(_list(x, "require")) == 0
}

# a block denies access (either syntax); used for FilesMatch, DirectoryMatch and LimitExcept bodies
_blocks(x) if {
	some r in _lower_list(x, "require")
	r == "all denied"
}

_blocks(x) if {
	some dd in _lower_list(x, "deny")
	dd in {"from all", "all"}
}

_override_none(x) if {
	_lower_list(x, "allow_override") == ["none"]
	count(_list(x, "allow_override_list")) == 0
}

_override_none_or_absent(x) if {
	every a in _lower_list(x, "allow_override") { a == "none" }
	count(_list(x, "allow_override_list")) == 0
}

_safe_methods := {"GET", "POST", "OPTIONS"}

_methods_restricted(x) if {
	le := x.limit_except
	is_object(le)
	every m in _list(le, "methods") { upper(m) in _safe_methods }
	_blocks(le)
}

_methods_restricted(x) if {
	_mod("allowmethods")
	is_array(x.allow_methods)
	every m in x.allow_methods { upper(m) in _safe_methods }
}

_fm_denies(sub) if {
	some fm in input.apache.files_match
	contains(fm.pattern, sub)
	_blocks(fm)
}

_dm_denies(sub) if {
	some dm in input.apache.directory_match
	contains(dm.pattern, sub)
	_blocks(dm)
}

# ── rewrite rules and Listen ─────────────────────────────────────────────────
_rewrite_on if {
	some v in _dv_lower("RewriteEngine")
	v == "on"
}

# a RewriteRule whose flags include F (forbidden)
_rule_forbids(r) if regex.match(`\[[^\]]*\bF\b[^\]]*\]`, r)

_vhosts := input.apache.vhosts if is_array(input.apache.vhosts)

# built with a builtin, not a literal `[]`: OPA >= 1.22 types a literal empty array as having no members
_vhosts := array.concat([], []) if not is_array(input.apache.vhosts)

_ssl_vhosts := [v | some v in _vhosts; v.ssl == true]

_vd(v, name) := [trim_space(sprintf("%v", [x])) |
	some k, vs in object.get(v, "directives", {})
	lower(k) == lower(name)
	some x in _as_list(vs)
]

_vd_lower(v, name) := [lower(x) | some x in _vd(v, name)]

_vhost_inherits_rewrite(v) if {
	"on" in _vd_lower(v, "RewriteEngine")
	"inherit" in _vd_lower(v, "RewriteOptions")
}

# a Listen that names an address (not a bare port, not all-zeros, not a wildcard)
_listen_has_address(l) if {
	t := _first(l)
	not regex.match(`^[0-9]+$`, t)
	not startswith(t, "0.0.0.0")
	not startswith(t, "[::]")
	not startswith(t, "*")
}

# ── Header directives ────────────────────────────────────────────────────────
_headers := _dv("Header")

_hdr_off(h) := 1 if lower(_tokens(h)[0]) in {"always", "onsuccess"}

_hdr_off(h) := 0 if not lower(_tokens(h)[0]) in {"always", "onsuccess"}

_hdr_always(h) if lower(_tokens(h)[0]) == "always"

_hdr_action(h) := lower(_tokens(h)[_hdr_off(h)])

_hdr_name(h) := trim(lower(_tokens(h)[_hdr_off(h) + 1]), "\"'")

_hdr_value(h) := trim(lower(concat(" ", array.slice(_tokens(h), _hdr_off(h) + 2, count(_tokens(h))))), "\"'")

_framing_header_ok(h) if {
	_hdr_name(h) == "content-security-policy"
	_hdr_always(h)
	_hdr_action(h) in {"set", "append"}
	regex.match(`frame-ancestors\s+'?(none|self)'?`, _hdr_value(h))
}

_framing_header_ok(h) if {
	_hdr_name(h) == "x-frame-options"
	_hdr_always(h)
	_hdr_action(h) in {"set", "append"}
	_hdr_value(h) in {"sameorigin", "deny"}
}

_good_referrer_policies := {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}

# HSTS with max-age >= 480 s, at the server level or in every TLS virtual host
_hsts_in(hs) if {
	some h in hs
	_hdr_name(h) == "strict-transport-security"
	_hdr_always(h)
	m := regex.find_all_string_submatch_n(`max-age=([0-9]+)`, _hdr_value(h), 1)
	to_number(m[0][1]) >= 480
}

_hsts_everywhere if _hsts_in(_headers)

_hsts_everywhere if {
	count(_ssl_vhosts) > 0
	every v in _ssl_vhosts { _hsts_in(_vd(v, "Header")) }
}

# a directive value set at the server level or in every TLS virtual host
_everywhere_ssl(name, want) if want in _dv_lower(name)

_everywhere_ssl(name, want) if {
	count(_ssl_vhosts) > 0
	every v in _ssl_vhosts { want in _vd_lower(v, name) }
}

# ── logging ──────────────────────────────────────────────────────────────────
_verbose_levels := {"notice", "info", "debug", "trace1", "trace2", "trace3", "trace4", "trace5", "trace6", "trace7", "trace8"}

_core_levels := _verbose_levels - {"notice"}

# LogLevel: one global level of notice or more verbose; the core module at info or more verbose
_loglevel_ok(v) if {
	toks := [lower(t) | some t in _tokens(v)]
	gl := [t | some t in toks; not contains(t, ":")]
	count(gl) == 1
	gl[0] in _verbose_levels
	_core_level(toks, gl[0]) in _core_levels
}

_core_level(toks, _) := lvl if {
	some t in toks
	startswith(t, "core:")
	lvl := trim_prefix(t, "core:")
}

_core_level(toks, g) := g if not _has_core_level(toks)

_has_core_level(toks) if {
	some t in toks
	startswith(t, "core:")
}

# the format string a CustomLog uses: explicit (quoted) or a LogFormat nickname
_access_format_complete(c) if {
	toks := _tokens(c)
	count(toks) >= 2
	startswith(toks[1], "\"")
	_fmt_complete(substring(c, indexof(c, "\""), -1))
}

_access_format_complete(c) if {
	toks := _tokens(c)
	count(toks) >= 2
	not startswith(toks[1], "\"")
	some lf in _dv("LogFormat")
	lt := _tokens(lf)
	lt[count(lt) - 1] == toks[1]
	_fmt_complete(lf)
}

_fmt_complete(f) if {
	l := lower(f)
	every tok in ["%l", "%u", "%t", "%r", "%>s", "%b", "%{referer}i", "%{user-agent}i"] { contains(l, tok) }
	_has_client_token(l)
}

_has_client_token(l) if contains(l, "%h")

_has_client_token(l) if contains(l, "%{x-forwarded-for}i")

# ── TLS ──────────────────────────────────────────────────────────────────────
_all_protos := {"sslv3", "tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"}

_proto_expand(t) := _all_protos if t == "all"

_proto_expand(t) := {t} if t != "all"

# protocols an SSLProtocol value enables, applying +/- in order ("-all +TLSv1.2" and "all -SSLv3 -TLSv1 -TLSv1.1")
_ssl_enabled(v) := {p |
	toks := [lower(t) | some t in _tokens(v)]
	some i, t in toks
	not startswith(t, "-")
	some p in _proto_expand(trim_prefix(t, "+"))
	not _removed_after(toks, p, i)
}

_removed_after(toks, p, i) if {
	some j, t in toks
	j > i
	startswith(t, "-")
	p in _proto_expand(trim_prefix(t, "-"))
}

_protocols_ok(v) if {
	en := _ssl_enabled(v)
	count(en) > 0
	count(en - {"tlsv1.2", "tlsv1.3"}) == 0
}

_cipher_parts(c) := {trim_space(p) | some p in split(lower(c), ":")}

_weak_excluded(c) if {
	ps := _cipher_parts(c)
	every x in ["!null", "!low", "!rc4", "!anull"] { x in ps }
	count(ps & {"!exp", "!export"}) > 0
}

_medium_excluded(c) if {
	ps := _cipher_parts(c)
	"!3des" in ps
	"!idea" in ps
}

_forward_secrecy_only(c) if {
	ps := _cipher_parts(c)
	count(ps) > 0
	every p in ps { _fs_component(p) }
}

_fs_component(p) if startswith(p, "!")

_fs_component(p) if startswith(p, "-")

_fs_component(p) if startswith(p, "@")

_fs_component(p) if p in {"eecdh", "edh", "ecdhe", "dhe", "keecdh", "kedh"}

_fs_component(p) if regex.match(`^(ecdhe|dhe|eecdh|edh)[-+]`, p)

# ── misc directives ──────────────────────────────────────────────────────────
_etag_ok(v) if every t in _tokens(lower(v)) { not t in {"all", "inode", "+inode"} }

# the maximum of each header= / body= RequestReadTimeout setting ("20-40" -> 40, "40" -> 40)
_rrt_max(kind) := {m |
	some v in _dv("RequestReadTimeout")
	some t in _tokens(v)
	lt := lower(t)
	pre := concat("", [kind, "="])
	startswith(lt, pre)
	spec := split(trim_prefix(lt, pre), ",")[0]
	parts := split(spec, "-")
	m := to_number(parts[count(parts) - 1])
}

_approved_booleans := {b | some b in input.apache.selinux.approved_httpd_booleans}

'''

parts = [HEADER]
for s in SECTIONS:
    parts.append(f"# {SECTION_TITLES[s]}\n{s}_violations := sort([m | some m in _v_{s}])\n\n_all_violations contains m if some m in _v_{s}\n")
parts.append(HELPERS)
for c in C:
    parts.append(emit_control(c, WB, f"_v_{section(c['id'])}", applies=True))


def extra(c, w):
    return {"section": int(c["id"].split(".")[0])}


parts.append("# Every recommendation in the benchmark: title, level, assessment status, CIS profile, section.\n"
             "recommendations := " + table(C, WB, extra) + "\n")
parts.append(f'''
_applicable_ids := {{id | some id, _ in recommendations; _applies(id)}}

_failed_ids := {{id | some v in violations; id := split(v, ":")[0]}}

_level_ids(l) := {{id | some id, r in recommendations; r.level == l; _applies(id)}}

findings := [{{
	"title": "Apache HTTP Server 2.4 hardening",
	"description": "{BENCH} assessment of loaded modules, service account and permissions, directory access, options and methods, logging, TLS, information leakage, request limits and mandatory access control",
	"severity": "HIGH",
	"details": sprintf("Found %d violations across %d recommendations", [count(violations), count(_failed_ids)]),
	"violations": violations,
	"remediation": "Apply the {BENCH} recommendation named in each violation; collect the missing facts where a violation reports evidence missing",
}}]

compliance_report := {{
	"benchmark": "{BENCH}",
	"total_controls": count(recommendations),
	"standard_total": 86,
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",
	"applicable_controls": count(_applicable_ids),
	"mac_frameworks": sort([m | some m in _mac]),
	"failed_controls": count(_failed_ids),
	"passed_controls": count(_applicable_ids) - count(_failed_ids),
	"level_1": {{"total": count(_level_ids(1)), "failed": count(_level_ids(1) & _failed_ids)}},
	"level_2": {{"total": count(_level_ids(2)), "failed": count(_level_ids(2) & _failed_ids)}},
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}}
''')
open(f"{OUT}/cis_apache_2_4.rego", "w").write("\n".join(parts))

L1 = len(ids) - len(l2)
tests = f'''package cis.apache_2_4_test

import rego.v1

import data.cis.apache_2_4 as b

# Generated per-recommendation tests for {BENCH}: every recommendation has a pass test (green input) and a
# fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.

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
	count(b.recommendations) == 86
	count([id | some id, r in b.recommendations; r.level == 1]) == {L1}
	count([id | some id, r in b.recommendations; r.level == 2]) == {len(l2)}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {sum(1 for w in WB.values() if w["assessment"] == "Automated")}
}}

test_report_shape_on_empty_input if {{
	r := b.compliance_report with input as {{}}
	r.total_controls == 86
	r.applicable_controls == 86
	r.compliant == false
	r.failed_controls == 86
	r.passed_controls == 0
	r.level_1.total == {L1}
	r.level_2.total == {len(l2)}
	f := b.findings with input as {{}}
	count(f) == 1
	count(f[0].violations) > 0
}}

test_selinux_host_skips_apparmor if {{
	inp := json.patch(green, [{{"op": "add", "path": "/apache/platform", "value": {{"mac": "selinux"}}}}, {{"op": "remove", "path": "/apache/apparmor"}}])
	vs := b.violations with input as inp
	count(vs) == 0
	r := b.compliance_report with input as inp
	r.applicable_controls == 83
	r.mac_frameworks == ["selinux"]
}}

test_apparmor_host_skips_selinux if {{
	inp := json.patch(green, [{{"op": "add", "path": "/apache/platform", "value": {{"mac": "AppArmor"}}}}, {{"op": "remove", "path": "/apache/selinux"}}])
	vs := b.violations with input as inp
	count(vs) == 0
	not _has_id(vs, "11.1")
}}

test_unknown_mac_applies_both if {{
	inp := json.patch(green, [{{"op": "add", "path": "/apache/platform", "value": {{"mac": "grsecurity"}}}}, {{"op": "remove", "path": "/apache/selinux"}}])
	vs := b.violations with input as inp
	_has_id(vs, "11.1")
	not _has_id(vs, "12.1")
	not b.compliant with input as inp
	r := b.compliance_report with input as inp
	r.applicable_controls == 86
}}

test_2_6_proxy_in_use_attested_passes if {{
	inp := json.patch(green, [{{"op": "add", "path": "/apache/modules/-", "value": "proxy_http_module"}}])
	vs := b.violations with input as inp
	_has_id(vs, "2.6")
	inp2 := json.patch(inp, [{{"op": "add", "path": "/apache/attest/proxy_modules_required", "value": true}}])
	vs2 := b.violations with input as inp2
	not _has_id(vs2, "2.6")
}}

{emit_tests("cis.apache_2_4", C, WB, GREEN, "/apache/attest")}'''
open(f"{OUT}/tests/test_cis_apache_2_4_controls.rego", "w").write(tests)

print("ok", len(C), "L1", L1, "L2", len(l2), "attest", len(attest_ids), "fact-manual", len(fact_manual))
