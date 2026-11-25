"""Per-version configuration for gen_postgresql.py (CIS PostgreSQL 16, 17 and 18).

The PostgreSQL 17 logic table (postgresql_17_spec.SPEC) is the base. A version shares an entry when the
benchmark's audit procedure for that recommendation is the same, and diverges explicitly below when it is not.
`spec_for(version)` returns the table for one version; gen_postgresql.py checks it against the workbook
(ids, Automated/Manual status), so a renumbered or added recommendation aborts the run.
"""
import copy

from postgresql_17_spec import SPEC as SPEC_17, A, M, on  # noqa: F401


# ── divergent logic ───────────────────────────────────────────────────────────

# 4.8 in 16 and 18: set_user must be available, and the role-tree query (login roles that are superusers or
# inherit a superuser role) must return nothing but authorized accounts. 17 checks the login superusers only.
# New fact: input.postgresql.login_roles_with_superuser_path[] (role names, or rows with rolname).
SET_USER_ROLETREE = A(
    [("available_extensions", "arr"), ("login_roles_with_superuser_path", "arr")],
    ['"set_user" in pg.available_extensions', "is_array(pg.login_roles_with_superuser_path)",
     'every r in pg.login_roles_with_superuser_path { _role_name(r) in _policy_list("authorized_superusers") }'],
    [("available_extensions", ["set_user", "pgaudit"]), ("login_roles_with_superuser_path", ["postgres"])],
    [[("available_extensions", ["pgaudit"])],
     [("login_roles_with_superuser_path", ["postgres", "mallory"])],
     [("login_roles_with_superuser_path", [{"rolname": "app_admin", "rolparents": ["dba"]}])]])

# 6.8 in 16 and 18: only the ssl setting is audited (17 also audits pg_hba host/hostnossl rules and live sessions).
TLS_ONLY = A([("ssl.enabled", "val")], ["_on(pg.ssl.enabled)"], [("ssl.enabled", True)], [[("ssl.enabled", False)]])

# 6.10 in 16: ssl_ciphers may only name the three approved TLS 1.3 suites, and no live session may use another
# cipher (17: four ECDHE GCM suites, and only TLS 1.2 sessions are examined).
# New fact: input.postgresql.ssl.unapproved_cipher_sessions[] (pg_stat_ssl rows whose cipher is not approved).
CIPHERS_16 = A(
    [("ssl.ssl_ciphers", "val"), ("ssl.unapproved_cipher_sessions", "arr")],
    ["cs := _cipher_list(pg.ssl.ssl_ciphers)", "count(cs) > 0", "every c in cs { c in _approved_ciphers }",
     "count(pg.ssl.unapproved_cipher_sessions) == 0"],
    [("ssl.ssl_ciphers", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"), ("ssl.unapproved_cipher_sessions", [])],
    [[("ssl.ssl_ciphers", "HIGH:MEDIUM:+3DES:!aNULL")], [("ssl.ssl_ciphers", "")],
     [("ssl.unapproved_cipher_sessions", [{"pid": 9, "cipher": "AES128-SHA"}])]])

# 6.10 in 18: as 16, and ssl_tls13_ciphers (new in PostgreSQL 18's benchmark) is held to the same list; an
# empty ssl_tls13_ciphers is allowed (PostgreSQL then uses the OpenSSL default list).
# New fact: input.postgresql.ssl.ssl_tls13_ciphers.
CIPHERS_18 = A(
    [("ssl.ssl_ciphers", "val"), ("ssl.ssl_tls13_ciphers", "val"), ("ssl.unapproved_cipher_sessions", "arr")],
    ["cs := _cipher_list(pg.ssl.ssl_ciphers)", "count(cs) > 0", "every c in cs { c in _approved_ciphers }",
     # a string, then its members: _cipher_list of a non-string is [] (the error stays inside its comprehension),
     # and `every` over [] is true
     "is_string(pg.ssl.ssl_tls13_ciphers)",
     "every c in _cipher_list(pg.ssl.ssl_tls13_ciphers) { c in _approved_ciphers }",
     "count(pg.ssl.unapproved_cipher_sessions) == 0"],
    [("ssl.ssl_ciphers", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"),
     ("ssl.ssl_tls13_ciphers", "TLS_AES_256_GCM_SHA384"), ("ssl.unapproved_cipher_sessions", [])],
    [[("ssl.ssl_ciphers", "HIGH:MEDIUM:+3DES:!aNULL")], [("ssl.ssl_ciphers", "")],
     [("ssl.ssl_tls13_ciphers", "TLS_CHACHA20_POLY1305_SHA256")], [("ssl.ssl_tls13_ciphers", 7)],
     [("ssl.ssl_tls13_ciphers", True)], [("ssl.ssl_tls13_ciphers", ["TLS_AES_256_GCM_SHA384"])],
     [("ssl.unapproved_cipher_sessions", [{"pid": 9, "cipher": "AES128-SHA"}])]])

# 3.1.20 in 18: log_connections is a list in PostgreSQL 18; the benchmark requires `all`.
LOG_CONNECTIONS_18 = A([("logging.log_connections", "val")], ["_log_connections_all(pg.logging.log_connections)"],
                       [("logging.log_connections", "all")],
                       [[("logging.log_connections", "on")], [("logging.log_connections", "off")],
                        [("logging.log_connections", "receipt,authentication")]])

# 6.2 in 18: as 17 with log_connections held to `all`.
BACKEND_18 = A(
    [("backend_settings", "obj")],
    ["b := pg.backend_settings", "_off(b.ignore_system_indexes)", "_off(b.jit_debugging_support)",
     "_off(b.jit_profiling_support)", "_log_connections_all(b.log_connections)", "_on(b.log_disconnections)",
     'regex.match(`^\\s*0+\\s*(ms|s|min)?\\s*$`, sprintf("%v", [b.post_auth_delay]))'],
    [("backend_settings", {"ignore_system_indexes": "off", "jit_debugging_support": "off",
                           "jit_profiling_support": "off", "log_connections": "all",
                           "log_disconnections": "on", "post_auth_delay": "0"})],
    [[("backend_settings.post_auth_delay", "5")], [("backend_settings.ignore_system_indexes", "on")],
     [("backend_settings.log_connections", "on")], [("backend_settings.log_connections", "off")]])

ROLE_NAME_HELPER = r'''
# A role in a collected list: a bare name or a row with rolname.
_role_name(r) := r if is_string(r)

_role_name(r) := r.rolname if is_object(r)
'''

LOG_CONNECTIONS_HELPER = r'''
# PostgreSQL 18 log_connections: `all`, or a list naming every aspect that `all` stands for.
_log_connections_all(v) if lower(trim_space(sprintf("%v", [v]))) == "all"

_log_connections_all(v) if {
	have := {lower(trim_space(x)) | some x in split(sprintf("%v", [v]), ","); trim_space(x) != ""}
	count({"receipt", "authentication", "authorization", "setup_durations"} - have) == 0
}
'''

# ── per-version configuration ────────────────────────────────────────────────
VERSIONS = {
    17: {
        "ver": 17,
        "bench": "CIS PostgreSQL 17 Benchmark v1.1.0",
        "gen_name": "gen_postgresql_17.py",
        "ciphers": "tls12_ecdhe",
        "drop": [],
        "override": {},
    },
    16: {
        "ver": 16,
        "bench": "CIS PostgreSQL 16 Benchmark v1.1.0",
        "gen_name": "gen_postgresql_16.py",
        "ciphers": "tls13",
        "own_dir": True,
        "drop": ["4.10"],
        "override": {"4.8": SET_USER_ROLETREE, "6.8": TLS_ONLY, "6.10": CIPHERS_16},
        "extra_helpers": ROLE_NAME_HELPER,
        "contract_extra": (
            "\n#   Beyond the PostgreSQL 17 contract: input.postgresql.login_roles_with_superuser_path[] (4.8),"
            "\n#   input.postgresql.ssl.unapproved_cipher_sessions[] (6.10)."),
        "differences": [
            "no 4.10 (login accounts have passwords): the 16 benchmark has 71 recommendations, not 72.",
            "4.8 audits the role-tree result (login roles that are superusers or inherit one), fact "
            "`login_roles_with_superuser_path`, instead of the login superusers list; every row must be in "
            "`policy.authorized_superusers`.",
            "6.8 audits only `ssl` being on; the pg_hba host/hostnossl rules and live non-TLS sessions are not part "
            "of the 16 audit.",
            "6.10 allows only the three TLS 1.3 suite names in `ssl_ciphers` and no live session on another cipher "
            "(fact `ssl.unapproved_cipher_sessions`); 17 allows four ECDHE GCM suites and looks at TLS 1.2 sessions.",
            "6.10 is in the Level 1 - PostgreSQL on Linux profile in 16 and in Level 1 - PostgreSQL in 17.",
            "install paths in 1.3, 1.4 and 2.2 name PostgreSQL 16; the facts are the same.",
        ],
    },
    18: {
        "ver": 18,
        "bench": "CIS PostgreSQL 18 Benchmark v1.0.0",
        "gen_name": "gen_postgresql_18.py",
        "ciphers": "tls13",
        "own_dir": True,
        "drop": [],
        "override": {"3.1.20": LOG_CONNECTIONS_18, "4.8": SET_USER_ROLETREE, "6.2": BACKEND_18, "6.8": TLS_ONLY,
                     "6.10": CIPHERS_18},
        "extra_helpers": ROLE_NAME_HELPER + LOG_CONNECTIONS_HELPER,
        "contract_extra": (
            "\n#   Beyond the PostgreSQL 17 contract: input.postgresql.login_roles_with_superuser_path[] (4.8),"
            "\n#   input.postgresql.ssl.unapproved_cipher_sessions[] and ssl.ssl_tls13_ciphers (6.10)."),
        "differences": [
            "3.1.20 and 6.2 require `log_connections` to be `all` (or every aspect listed), not `on`.",
            "4.8 audits the role-tree result (login roles that are superusers or inherit one), fact "
            "`login_roles_with_superuser_path`, instead of the login superusers list; every row must be in "
            "`policy.authorized_superusers`.",
            "6.8 audits only `ssl` being on; the pg_hba host/hostnossl rules and live non-TLS sessions are not part "
            "of the 18 audit.",
            "6.10 allows only the three TLS 1.3 suite names in `ssl_ciphers` and `ssl_tls13_ciphers` (empty is "
            "allowed for the latter) and no live session on another cipher; 17 allows four ECDHE GCM suites.",
            "install paths in 1.3, 1.4 and 2.2 name PostgreSQL 18; the facts are the same.",
        ],
    },
}


def _retarget(obj, ver):
    if isinstance(obj, str):
        return obj.replace("pgsql-17", f"pgsql-{ver}")
    if isinstance(obj, list):
        return [_retarget(x, ver) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_retarget(x, ver) for x in obj)
    if isinstance(obj, dict):
        return {k: _retarget(x, ver) for k, x in obj.items()}
    return obj


def spec_for(ver):
    cfg = VERSIONS[ver]
    spec = {k: v for k, v in copy.deepcopy(SPEC_17).items() if k not in cfg["drop"]}
    for rid, entry in cfg["override"].items():
        assert rid in spec, rid
        spec[rid] = copy.deepcopy(entry)
    return {k: _retarget(v, ver) for k, v in spec.items()}
