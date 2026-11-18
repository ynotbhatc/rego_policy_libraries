"""Reviewed logic table for gen_rhel9.py (DISA STIG for RHEL 9, V2R10).

A spec (see R below):
  sec     : section module          name  : the rule's boolean (kept from the hand-maintained module)
  ev      : evidence paths that must be collected (else Open "evidence missing")
  alts    : alternative bodies (OR), each a list of Rego lines (AND), evaluated only with all evidence present
  attest_alts : bodies that pass on an attestation alone (the check's "ask the SA ..." clause)
  na / na_expect / na_cases : the check text's Not Applicable clause, as explicit evidence
  green   : fixture patch that passes      bad : list of patches (object.union onto green) that fail
  expect  : what the check requires (the Open detail)      fix : fix text      kind : machine | machine+attestation
Rules not yet moved here are carried verbatim from the hand-maintained module (rhel9_legacy.py).
"""
from rhel9_legacy import LEGACY, LEGACY_HELPERS

SECTION_HELPERS = dict(LEGACY_HELPERS)
RULES = {sid: dict(spec, legacy=True) for sid, spec in LEGACY.items()}


def helpers(sec, text):
    SECTION_HELPERS[sec] = (SECTION_HELPERS.get(sec, "").strip() + "\n\n" + text.strip()).strip()


def R(sec, sid, name, ev, alts, green, bad, expect, fix, comment="", kind="machine", attest_alts=(), na=(),
      na_expect="", na_cases=(), pass_cases=()):
    assert sid in RULES and RULES[sid]["sec"] == sec, sid
    if attest_alts and kind == "machine":
        kind = "machine+attestation"
    RULES[sid] = dict(sec=sec, name=name, ev=[tuple(e) for e in ev], alts=alts, green=green, bad=list(bad),
                      expect=expect, fix=fix, comment=comment or RULES[sid].get("comment", ""), kind=kind,
                      attest_alts=list(attest_alts), na=list(na), na_expect=na_expect, na_cases=list(na_cases),
                      pass_cases=list(pass_cases))


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# CAT I (reviewed 2026-11-18 against the V2R10 check text)
# ═════════════════════════════════════════════════════════════════════════════════════════════════

FIPS_HASHES = ["SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-256"]

R("configuration_management", "RHEL-09-211050", "ctrl_alt_del_disabled",
  [("systemd_units", "ctrl-alt-del.target", "load_state")],
  [['_kw(["systemd_units", "ctrl-alt-del.target", "load_state"]) == "masked"']],
  {"systemd_units": {"ctrl-alt-del.target": {"load_state": "masked"}}},
  [{"systemd_units": {"ctrl-alt-del.target": {"load_state": "loaded"}}}],
  "ctrl-alt-del.target must be masked (systemctl status: Loaded: masked)",
  "Mask the target: systemctl disable --now ctrl-alt-del.target && systemctl mask ctrl-alt-del.target",
  comment="ctrl-alt-del.target load state (systemctl show -p LoadState) must be masked")

R("configuration_management", "RHEL-09-431010", "selinux_enforcing",
  [("selinux", "getenforce"), ("selinux", "config_selinux")],
  [['_kw(["selinux", "getenforce"]) == "enforcing"', '_kw(["selinux", "config_selinux"]) == "enforcing"']],
  {"selinux": {"getenforce": "Enforcing", "config_selinux": "enforcing"}},
  [{"selinux": {"getenforce": "Permissive"}}, {"selinux": {"config_selinux": "permissive"}}],
  "getenforce must return Enforcing and /etc/selinux/config must set SELINUX=enforcing",
  "Set SELINUX=enforcing in /etc/selinux/config and run setenforce 1",
  comment="SELinux enforcing at runtime (getenforce) and at boot (SELINUX= in /etc/selinux/config)")

R("configuration_management", "RHEL-09-671010", "fips_mode_enabled",
  [("fips", "fips_enabled")],
  [['_str(["fips", "fips_enabled"]) == "1"']],
  {"fips": {"fips_enabled": "1"}},
  [{"fips": {"fips_enabled": "0"}}],
  "/proc/sys/crypto/fips_enabled must contain 1",
  "Enable FIPS mode: fips-mode-setup --enable, then reboot",
  comment="content of /proc/sys/crypto/fips_enabled must be 1")

helpers("configuration_management", r'''
# FIPS 140-3 hash set the crypto-policy check requires in /etc/crypto-policies/state/CURRENT.pol
fips_policy_hashes := ''' + "{" + ", ".join(f'"{h}"' for h in FIPS_HASHES) + "}" + r'''

# a hash the crypto-policy check rejects: SHA1 (or MD5), or a digest size below 224
_weak_hash(h) if not is_string(h)

_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "SHA1")
}

_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "MD5")
}

_weak_hash(h) if {
	is_string(h)
	m := regex.find_all_string_submatch_n(`-([0-9]+)$`, h, 1)
	bits := to_number(m[0][1])
	bits < 224
}''')

R("configuration_management", "RHEL-09-215105", "crypto_policy_fips",
  [("crypto_policy",), ("crypto_policy_state", "hash"), ("crypto_policy_state", "min_rsa_size")],
  [['_str(["crypto_policy"]) == "FIPS"',
    "hashes := input.crypto_policy_state.hash",
    "is_array(hashes)",
    "every h in fips_policy_hashes {\n\th in hashes\n}",
    "count([h | some h in hashes; _weak_hash(h)]) == 0",
    '_num(["crypto_policy_state", "min_rsa_size"]) >= 2048']],
  {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": FIPS_HASHES, "min_rsa_size": 2048}},
  [{"crypto_policy": "FIPS:OSPP"}, {"crypto_policy": "DEFAULT"},
   {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHA1"]}},
   {"crypto_policy_state": {"hash": FIPS_HASHES[:-1]}},
   {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHAKE-128"]}},
   {"crypto_policy_state": {"min_rsa_size": 1024}}, {"crypto_policy_state": {"min_rsa_size": "2048 bits"}}],
  "update-crypto-policies --show must be FIPS; CURRENT.pol hash must include " + " ".join(FIPS_HASHES)
  + ", nothing with SHA1 or below 224 bits; min_rsa_size must be at least 2048",
  "Set the FIPS policy: update-crypto-policies --set FIPS, then reboot",
  comment="systemwide crypto policy FIPS; CURRENT.pol hash list and min_rsa_size",
  pass_cases=[{"crypto_policy_state": {"min_rsa_size": "3072"}}])

helpers("pki_crypto", r'''
# a crypto back-end in /etc/crypto-policies/back-ends/: nss.config is a regular file; every other one is a
# symlink to its own file under /usr/share/crypto-policies/FIPS/ (bind.config -> FIPS/bind.txt)
_backend_ok(b) if {
	b.name == "nss.config"
	b.is_symlink == false
}

_backend_ok(b) if {
	is_string(b.name)
	b.name != "nss.config"
	b.is_symlink == true
	base := trim_suffix(b.name, ".config")
	b.target == concat("", ["/usr/share/crypto-policies/FIPS/", base, ".txt"])
}''')

R("pki_crypto", "RHEL-09-672020", "crypto_policy_not_overridden",
  [("crypto_policy_check", "output"), ("crypto_backends",)],
  [['out := _str(["crypto_policy_check", "output"])',
    'contains(out, "The configured policy matches the generated policy")',
    'not contains(out, "does NOT match")',
    "backends := input.crypto_backends",
    "is_array(backends)",
    "count(backends) > 0",
    "count([b | some b in backends; not _backend_ok(b)]) == 0"]],
  {"crypto_policy_check": {"output": "The configured policy matches the generated policy"},
   "crypto_backends": [{"name": "openssh.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/openssh.txt"},
                       {"name": "opensslcnf.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/opensslcnf.txt"},
                       {"name": "nss.config", "is_symlink": False, "target": None}]},
  [{"crypto_policy_check": {"output": "The configured policy does NOT match the generated policy"}},
   {"crypto_backends": [{"name": "openssh.config", "is_symlink": True, "target": "/usr/share/crypto-policies/DEFAULT/openssh.txt"}]},
   {"crypto_backends": [{"name": "openssh.config", "is_symlink": False, "target": None}]},
   {"crypto_backends": [{"name": "nss.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/nss.txt"}]},
   {"crypto_backends": []}],
  "update-crypto-policies --check must report the configured policy matches the generated policy, and every "
  "back-end in /etc/crypto-policies/back-ends/ except nss.config must link to its file under /usr/share/crypto-policies/FIPS/",
  "Remove overrides and regenerate: update-crypto-policies --set FIPS",
  comment="update-crypto-policies --check output and the back-end symlinks (input.crypto_backends[{name, is_symlink, target}])")

R("pki_crypto", "RHEL-09-672055", "openssl_system_policy",
  [("openssl_cnf", "lines")],
  [["lines := input.openssl_cnf.lines", "is_array(lines)", "some l in lines",
    r"regex.match(`^\s*\.include\s*=?\s*/etc/crypto-policies/back-ends/opensslcnf\.config\s*$`, l)"]],
  {"openssl_cnf": {"lines": ["[ crypto_policy ]", ".include = /etc/crypto-policies/back-ends/opensslcnf.config"]}},
  [{"openssl_cnf": {"lines": ["# .include = /etc/crypto-policies/back-ends/opensslcnf.config"]}},
   {"openssl_cnf": {"lines": [".include = /etc/pki/tls/other.cnf"]}}],
  "/etc/pki/tls/openssl.cnf must include /etc/crypto-policies/back-ends/opensslcnf.config (uncommented)",
  "Add .include = /etc/crypto-policies/back-ends/opensslcnf.config to /etc/pki/tls/openssl.cnf",
  comment="the lines of /etc/pki/tls/openssl.cnf must include the crypto-policy opensslcnf.config back-end")

R("services", "RHEL-09-215060", "tftp_secure_mode",
  [("packages", "tftp-server")],
  [['input.packages["tftp-server"] == true', 's := _str(["tftp", "execstart"])', r"regex.match(`(^|\s)-s(\s|$)`, s)"]],
  {"packages": {"tftp-server": True}, "tftp": {"execstart": "/usr/sbin/in.tftpd -s /var/lib/tftpboot"}},
  [{"tftp": {"execstart": "/usr/sbin/in.tftpd /var/lib/tftpboot"}}, {"tftp": {"execstart": None}}],
  "tftp-server is installed: the ExecStart of tftp.service (input.tftp.execstart) must run in.tftpd with -s",
  "Remove tftp-server (dnf remove tftp-server) or set ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot",
  comment="if tftp-server is installed, tftp.service ExecStart must carry -s; not installed is Not Applicable",
  na=[['input.packages["tftp-server"] == false']],
  na_expect="tftp-server is not installed",
  na_cases=[{"packages": {"tftp-server": False}}])

R("services", "RHEL-09-215015", "ftp_server_disabled",
  [("packages", "vsftpd")],
  [["input.packages.vsftpd == false"]],
  {"packages": {"vsftpd": False}},
  [{"packages": {"vsftpd": True}}],
  "the vsftpd package must not be installed",
  "Remove the FTP server: dnf remove vsftpd",
  comment="the vsftpd package must not be installed (input.packages.vsftpd == false)")

GPG_ATTEST = "a process to verify the GPG signatures of software packages is approved by the organization"
R("software_integrity", "RHEL-09-214025", "all_repos_gpgcheck",
  [("yum_repos",)],
  [["repos := input.yum_repos", "is_array(repos)", "count(repos) > 0",
    'every r in repos {\n\t_truthy(object.get(r, "gpgcheck", null))\n}']],
  {"yum_repos": [{"file": "/etc/yum.repos.d/redhat.repo", "name": "rhel-9-for-x86_64-baseos-rpms", "gpgcheck": "1"}]},
  [{"yum_repos": [{"file": "/etc/yum.repos.d/redhat.repo", "name": "rhel-9-for-x86_64-baseos-rpms", "gpgcheck": "0"}]},
   {"yum_repos": [{"file": "/etc/yum.repos.d/local.repo", "name": "local"}]},
   {"yum_repos": []}],
  "every repository in /etc/yum.repos.d/*.repo must set gpgcheck to 1, true or yes, or an approved GPG "
  "verification process must be attested (input.attest.rhel_09_214025_gpg_process)",
  "Set gpgcheck=1 in every repository definition under /etc/yum.repos.d/",
  comment="gpgcheck as written in each /etc/yum.repos.d/*.repo section (input.yum_repos[{file, name, gpgcheck}])",
  attest_alts=[['_attested("rhel_09_214025_gpg_process")']],
  pass_cases=[{"yum_repos": [{"name": "a", "gpgcheck": "Yes"}, {"name": "b", "gpgcheck": "TRUE"}]},
              {"yum_repos": [{"name": "a", "gpgcheck": "0"}], "attest": {"rhel_09_214025_gpg_process": True}}])

R("software_integrity", "RHEL-09-214020", "localpkg_gpgcheck",
  [("dnf_config", "localpkg_gpgcheck")],
  [["_truthy(input.dnf_config.localpkg_gpgcheck)"]],
  {"dnf_config": {"localpkg_gpgcheck": "1"}},
  [{"dnf_config": {"localpkg_gpgcheck": "0"}}, {"dnf_config": {"localpkg_gpgcheck": "False"}}],
  "localpkg_gpgcheck in /etc/dnf/dnf.conf must be 1, true or yes, or an approved GPG verification process must "
  "be attested (input.attest.rhel_09_214020_gpg_process)",
  "Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
  comment="localpkg_gpgcheck as written in /etc/dnf/dnf.conf",
  attest_alts=[['_attested("rhel_09_214020_gpg_process")']],
  pass_cases=[{"dnf_config": {"localpkg_gpgcheck": "True"}}])

SSH_CIPHERS = "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
SSH_MACS = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
helpers("ssh_config", r'''
# DISA's lists for the opensshserver crypto-policy back-end (RHEL-09-255065 / RHEL-09-255075)
fips_ssh_ciphers := ''' + "{" + ", ".join(f'"{c}"' for c in SSH_CIPHERS.split(",")) + "}" + r'''

fips_ssh_macs := ''' + "{" + ", ".join(f'"{c}"' for c in SSH_MACS.split(",")) + "}" + r'''

# the comma-separated list at path, each entry trimmed; undefined unless a string
_csv(path) := [trim_space(x) | some x in parts] if {
	s := _str(path)
	parts := split(s, ",")
}''')

for sid, key, allowed, setname, extra in (("RHEL-09-255065", "Ciphers", SSH_CIPHERS, "fips_ssh_ciphers", "aes192-ctr"),
                                          ("RHEL-09-255075", "MACs", SSH_MACS, "fips_ssh_macs", "hmac-sha1")):
    R("ssh_config", sid, "ssh_fips_ciphers" if key == "Ciphers" else "ssh_fips_macs",
      [("opensshserver_config", key)],
      [[f'vals := _csv(["opensshserver_config", "{key}"])', "count(vals) > 0",
        f"every v in vals {{\n\tv in {setname}\n}}"]],
      {"opensshserver_config": {key: allowed}},
      [{"opensshserver_config": {key: allowed + "," + extra}}, {"opensshserver_config": {key: ""}}],
      f"{key} in /etc/crypto-policies/back-ends/opensshserver.config must list only {allowed}",
      "Apply the FIPS crypto policy (update-crypto-policies --set FIPS) so opensshserver.config carries the DISA list",
      comment=f"{key} line of /etc/crypto-policies/back-ends/opensshserver.config (not sshd_config)",
      pass_cases=[{"opensshserver_config": {key: allowed.split(",")[1]}}])

for sid, key, name, want, bad in (("RHEL-09-255040", "PermitEmptyPasswords", "ssh_no_empty_passwords", "no", "yes"),
                                  ("RHEL-09-255050", "UsePAM", "ssh_use_pam", "yes", "no")):
    R("ssh_config", sid, name, [("ssh_config", key)],
      [[f'_kw(["ssh_config", "{key}"]) == "{want}"']],
      {"ssh_config": {key: want}}, [{"ssh_config": {key: bad}}],
      f"sshd {key} must be {want}", f"Set {key} {want} in /etc/ssh/sshd_config (or a drop-in) and restart sshd",
      comment=f"effective sshd {key} (case-insensitive) must be {want}")


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# CAT II (reviewed 2026-11-18 against the V2R10 check text)
# ═════════════════════════════════════════════════════════════════════════════════════════════════

def num_rule(sec, sid, name, path, lo, hi, green, bads, expect, fix, comment, **kw):
    """a numeric setting within [lo, hi] (None = unbounded), type-guarded by _num"""
    p = '["' + '", "'.join(path) + '"]'
    lines = [f"n := _num({p})"] + ([f"n >= {lo}"] if lo is not None else []) + ([f"n <= {hi}"] if hi is not None else [])
    patch = lambda v: nest(path, v)
    R(sec, sid, name, [tuple(path)], [lines], patch(green), [patch(b) for b in bads], expect, fix, comment=comment,
      pass_cases=kw.pop("pass_cases", [patch(str(green))]), **kw)


def nest(path, v):
    for k in reversed(path):
        v = {k: v}
    return v


# ── account_auth ────────────────────────────────────────────────────────────────────────────────
R("account_auth", "RHEL-09-611165", "mfa_enabled",
  [("sssd", "pam_cert_auth")],
  [['_kw(["sssd", "pam_cert_auth"]) == "true"']],
  {"sssd": {"pam_cert_auth": "True"}},
  [{"sssd": {"pam_cert_auth": "False"}}],
  "pam_cert_auth = True must be set (uncommented) in /etc/sssd/sssd.conf or /etc/sssd/conf.d/",
  "Set pam_cert_auth = True in the [pam] section of /etc/sssd/sssd.conf (or a conf.d drop-in) and restart sssd",
  comment="pam_cert_auth as configured in /etc/sssd/sssd.conf or /etc/sssd/conf.d/ (null when missing or commented out)",
  na=[['_attested("rhel_09_611165_alternate_mfa")']],
  na_expect="the SA demonstrated an approved alternate multifactor authentication method",
  na_cases=[{"sssd": {"pam_cert_auth": None}, "attest": {"rhel_09_611165_alternate_mfa": True}}])

R("account_auth", "RHEL-09-611140", "password_sha512",
  [("login_defs", "ENCRYPT_METHOD")],
  [['_str(["login_defs", "ENCRYPT_METHOD"]) == "SHA512"']],
  {"login_defs": {"ENCRYPT_METHOD": "SHA512"}},
  [{"login_defs": {"ENCRYPT_METHOD": "MD5"}}, {"login_defs": {"ENCRYPT_METHOD": "YESCRYPT"}}],
  "ENCRYPT_METHOD in /etc/login.defs must be SHA512",
  "Set ENCRYPT_METHOD SHA512 in /etc/login.defs",
  comment="ENCRYPT_METHOD as configured in /etc/login.defs (null when missing or commented out)")

num_rule("account_auth", "RHEL-09-411075", "account_lockout_enabled", ["faillock_conf", "deny"], 1, 3, 3, [4, 0, "three"],
         "deny in /etc/security/faillock.conf must be 1 to 3 (not 0)",
         "Set deny = 3 in /etc/security/faillock.conf",
         "deny as configured in /etc/security/faillock.conf")

R("account_auth", "RHEL-09-611155", "no_empty_password_hashes",
  [("local_accounts_with_empty_passwords",)],
  [["accts := input.local_accounts_with_empty_passwords", "is_array(accts)", "count(accts) == 0"]],
  {"local_accounts_with_empty_passwords": []},
  [{"local_accounts_with_empty_passwords": ["guest"]}],
  "no /etc/shadow entry may have an empty password field",
  "Lock or set a password for each listed account: passwd -l <username>",
  comment="accounts whose /etc/shadow password field is empty (awk -F: '!$2 {print $1}' /etc/shadow)")

num_rule("account_auth", "RHEL-09-611090", "password_minlen", ["password_policy", "minlen"], 15, None, 15, [8, "8"],
         "minlen in /etc/security/pwquality.conf(.d) must be 15 or greater",
         "Set minlen = 15 in /etc/security/pwquality.conf",
         "effective minlen from /etc/security/pwquality.conf and pwquality.conf.d/*.conf")

for sid, name, key, what in (("RHEL-09-611110", "password_uppercase", "ucredit", "uppercase"),
                             ("RHEL-09-611065", "password_lowercase", "lcredit", "lowercase"),
                             ("RHEL-09-611070", "password_numeric", "dcredit", "numeric"),
                             ("RHEL-09-611100", "password_special", "ocredit", "special")):
    num_rule("account_auth", sid, name, ["password_policy", key], None, -1, -1, [1, 0, "1"],
             f"{key} in /etc/security/pwquality.conf(.d) must be negative (-1: at least one {what} character)",
             f"Set {key} = -1 in /etc/security/pwquality.conf",
             f"effective {key} from /etc/security/pwquality.conf and pwquality.conf.d/*.conf")

num_rule("account_auth", "RHEL-09-411010", "password_maxage", ["password_policy", "maxdays"], 1, 180, 180, [181, 365, -1, "99999"],
         "PASS_MAX_DAYS in /etc/login.defs must be 180 or less (and set: -1 disables the limit)",
         "Set PASS_MAX_DAYS 180 in /etc/login.defs",
         "PASS_MAX_DAYS as configured in /etc/login.defs",
         pass_cases=[{"password_policy": {"maxdays": 60}}, {"password_policy": {"maxdays": "180"}}])

num_rule("account_auth", "RHEL-09-611075", "password_minage", ["password_policy", "mindays"], 1, None, 1, [0, "0"],
         "PASS_MIN_DAYS in /etc/login.defs must be 1 or greater",
         "Set PASS_MIN_DAYS 1 in /etc/login.defs",
         "PASS_MIN_DAYS as configured in /etc/login.defs")

num_rule("account_auth", "RHEL-09-411085", "lockout_duration_ok", ["faillock_conf", "fail_interval"], 1, 900, 900, [901, 0, "900s"],
         "fail_interval in /etc/security/faillock.conf must be 900 or less (not 0)",
         "Set fail_interval = 900 in /etc/security/faillock.conf",
         "fail_interval as configured in /etc/security/faillock.conf",
         na=[['_attested("rhel_09_411085_central_lockout")']],
         na_expect="the SA demonstrated an approved centralized account management method that locks after three failures in 15 minutes",
         na_cases=[{"faillock_conf": {"fail_interval": None}, "attest": {"rhel_09_411085_central_lockout": True}}])

num_rule("account_auth", "RHEL-09-411050", "inactive_lock_ok", ["password_policy", "inactive_days"], 0, 35, 35, [-1, 36, "-1"],
         "INACTIVE in /etc/default/useradd must be 0 to 35 (not -1)",
         "Set INACTIVE=35 in /etc/default/useradd",
         "INACTIVE as configured in /etc/default/useradd")

R("account_auth", "RHEL-09-411030", "no_duplicate_uids",
  [("duplicate_uid_accounts",)],
  [["accts := input.duplicate_uid_accounts", "is_array(accts)",
    "count([a | some a in accts; not a.interactive == false]) == 0"]],
  {"duplicate_uid_accounts": []},
  [{"duplicate_uid_accounts": [{"name": "alice2", "uid": 1001, "interactive": True}]},
   {"duplicate_uid_accounts": [{"name": "alice2", "uid": 1001}]}],
  "no interactive account in /etc/passwd may share its UID with another account",
  "Give each interactive account a unique UID (usermod -u) and fix file ownership",
  comment="accounts printed by awk -F: 'list[$3]++{print $1, $3}' /etc/passwd, each {name, uid, interactive}",
  pass_cases=[{"duplicate_uid_accounts": [{"name": "toor", "uid": 0, "interactive": False}]}])

R("account_auth", "RHEL-09-411110", "no_duplicate_gids",
  [("duplicate_gids",)],
  [["gids := input.duplicate_gids", "is_array(gids)", "count(gids) == 0"]],
  {"duplicate_gids": []},
  [{"duplicate_gids": [1001]}],
  "no GID may appear twice in /etc/group",
  "Give each group a unique GID (groupmod -g)",
  comment="GIDs printed by cut -d : -f 3 /etc/group | uniq -d")


# ── audit_logging ───────────────────────────────────────────────────────────────────────────────
SECTION_HELPERS["audit_logging"] = r'''
# input.audit_rules: the loaded rules, one string per line of `auditctl -l`
_audit_lines := [l | some l in input.audit_rules; is_string(l)]

_tokens(line) := [t | some t in parts; t != ""] if parts := split(line, " ")

_syscalls(toks) := {s | some i, t in toks; t == "-S"; v := toks[i + 1]; parts := split(v, ","); some s in parts}

_exit_rule(toks) if "always,exit" in toks

_exit_rule(toks) if "exit,always" in toks

# every syscall in `needed` is audited for `arch` by an always,exit rule that also carries every token in `fields`
_syscalls_audited(arch, needed, fields) if {
	a := concat("=", ["arch", arch])
	every s in needed {
		some line in _audit_lines
		toks := _tokens(line)
		_exit_rule(toks)
		a in toks
		s in _syscalls(toks)
		every f in fields {
			f in toks
		}
	}
}

# a rule watches exactly `path`: `-w <path>` or an always,exit rule with `-F path=<path>`
_path_audited(path) if {
	some line in _audit_lines
	toks := _tokens(line)
	some i, t in toks
	t == "-w"
	toks[i + 1] == path
}

_path_audited(path) if {
	some line in _audit_lines
	toks := _tokens(line)
	_exit_rule(toks)
	concat("=", ["path", path]) in toks
}'''


def sc_line(arch, calls, extra=""):
    return f"-a always,exit -F arch={arch} -S {','.join(calls)}{extra} -F auid>=1000 -F auid!=-1 -F key=k"


def syscall_rule(sid, name, calls, fields_sets, expect, comment, bad_drop):
    alts = [[f"_syscalls_audited(\"{arch}\", {{{', '.join(chr(34) + c + chr(34) for c in calls)}}}, {{{', '.join(chr(34) + f + chr(34) for f in fs)}}})"
             for arch in ("b32", "b64") for fs in fields_sets]]
    alts[0] = ["is_array(input.audit_rules)"] + [a.replace("{}", "set()") for a in alts[0]]
    lines = []
    for arch in ("b32", "b64"):
        for fs in fields_sets:
            extra = "".join(f" -C {f}" if "!=" in f else f" -F {f}" for f in fs)
            lines.append(sc_line(arch, calls, extra))
    bad = [{"audit_rules": [l for l in AUDIT_GREEN_FINAL if l not in bad_drop(lines)]}]
    R("audit_logging", sid, name, [("audit_rules",)], alts, {"audit_rules": "__AUDIT__"}, bad, expect,
      f"Add the rules to /etc/audit/rules.d/audit.rules and load them (augenrules --load): {lines[-1]}",
      comment=comment)


AUDIT_GREEN_FINAL = (
    [sc_line(a, ["execve"], f" -C {c} -F {e}") for a in ("b32", "b64") for c, e in (("uid!=euid", "euid=0"), ("gid!=egid", "egid=0"))]
    + [sc_line(a, ["chown", "fchown", "fchownat", "lchown"]) for a in ("b32", "b64")]
    + [sc_line(a, ["chmod", "fchmod", "fchmodat"]) for a in ("b32", "b64")]
    + [sc_line(a, ["setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", "lremovexattr"]) for a in ("b32", "b64")]
    + [sc_line(a, ["truncate", "ftruncate", "creat", "open", "openat", "open_by_handle_at"], f" -F exit={e}")
       for a in ("b32", "b64") for e in ("-EPERM", "-EACCES")]
    + [sc_line(a, ["init_module", "finit_module"]) for a in ("b32", "b64")]
    + ["-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F key=identity",
       "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F key=identity",
       "-w /etc/passwd -p wa -k identity",
       "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"])

syscall_rule("RHEL-09-654010", "audit_execve_b64", ["execve"], [("uid!=euid", "euid=0"), ("gid!=egid", "egid=0")],
             "execve must be audited for b32 and b64 with -C uid!=euid -F euid=0 and -C gid!=egid -F egid=0 (all four rules)",
             "execve rules (auditctl -l) for both arches and both setuid/setgid conditions", lambda ls: [ls[3]])
syscall_rule("RHEL-09-654020", "audit_chown", ["chown", "fchown", "fchownat", "lchown"], [()],
             "chown, fchown, fchownat and lchown must be audited for both b32 and b64",
             "always,exit rules for the chown family, both arches (auditctl -l)", lambda ls: [ls[0]])
syscall_rule("RHEL-09-654015", "audit_chmod", ["chmod", "fchmod", "fchmodat"], [()],
             "chmod, fchmod and fchmodat must be audited for both b32 and b64",
             "always,exit rules for the chmod family, both arches (auditctl -l)", lambda ls: [ls[0]])
syscall_rule("RHEL-09-654025", "audit_setxattr", ["setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", "lremovexattr"], [()],
             "setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr and lremovexattr must be audited for both b32 and b64",
             "always,exit rules for the xattr family, both arches (auditctl -l)", lambda ls: [ls[1]])
syscall_rule("RHEL-09-654070", "audit_open_failure", ["truncate", "ftruncate", "creat", "open", "openat", "open_by_handle_at"],
             [("exit=-EPERM",), ("exit=-EACCES",)],
             "truncate, ftruncate, creat, open, openat and open_by_handle_at must be audited for both arches with -F exit=-EPERM and -F exit=-EACCES",
             "always,exit rules for the open/truncate family with exit=-EPERM and exit=-EACCES, both arches", lambda ls: [ls[3]])
syscall_rule("RHEL-09-654080", "audit_modules", ["init_module", "finit_module"], [()],
             "init_module and finit_module must be audited for both b32 and b64",
             "always,exit rules for init_module and finit_module, both arches (auditctl -l)", lambda ls: [ls[0]])

for sid, name, path, expect in (
        ("RHEL-09-654215", "audit_sudoers", "/etc/sudoers", "a loaded audit rule must watch /etc/sudoers itself (not only /etc/sudoers.d/)"),
        ("RHEL-09-654240", "audit_passwd_file", "/etc/passwd", "a loaded audit rule must watch /etc/passwd"),
        ("RHEL-09-654150", "audit_privileged_cmds", "/usr/bin/sudo", "a loaded audit rule must audit execution of /usr/bin/sudo")):
    keep = [l for l in AUDIT_GREEN_FINAL if path + " " not in l and "=" + path + " " not in l]
    bads = [{"audit_rules": keep}]
    if path == "/etc/sudoers":
        bads.append({"audit_rules": keep + ["-w /etc/sudoers.d/ -p wa -k identity"]})
    if path == "/usr/bin/sudo":
        bads.append({"audit_rules": keep + ["-a always,exit -F path=/usr/bin/su -F perm=x -F key=privileged"]})
    R("audit_logging", sid, name, [("audit_rules",)],
      [["is_array(input.audit_rules)", f'_path_audited("{path}")']],
      {"audit_rules": "__AUDIT__"}, bads, expect,
      f"Add an audit rule for {path} to /etc/audit/rules.d/ and load it (augenrules --load)",
      comment=f"a loaded rule (auditctl -l) on exactly {path}: -w {path} or -F path={path}",
      pass_cases=[{"audit_rules": keep + [f"-w {path} -p wa -k k"]}])

# the shared green list: every audit rule above passes on it
for _sid, _spec in RULES.items():
    if _spec.get("green") == {"audit_rules": "__AUDIT__"}:
        _spec["green"] = {"audit_rules": AUDIT_GREEN_FINAL}

R("audit_logging", "RHEL-09-653015", "auditd_active",
  [("services", "auditd")],
  [['_kw(["services", "auditd"]) == "active"']],
  {"services": {"auditd": "active"}}, [{"services": {"auditd": "inactive"}}, {"services": {"auditd": "failed"}}],
  "auditd.service must be active (running)", "Enable and start auditd: systemctl enable --now auditd",
  comment="systemctl is-active auditd")

for sid, name, key, allowed, att, what in (
        ("RHEL-09-653055", "audit_storage_ok", "max_log_file_action", ["rotate", "single"], "rhel_09_653055_storage_action",
         "the system takes appropriate action when the audit files reach maximum size"),
        ("RHEL-09-653025", "admin_space_left_action_ok", "disk_full_action", ["syslog", "single", "halt"], "rhel_09_653025_disk_full_action",
         "the system takes appropriate action when the audit storage volume is full"),
        ("RHEL-09-653040", "space_left_action_ok", "space_left_action", ["email"], "rhel_09_653040_realtime_alerts",
         "real-time alerts to the SA and ISSO are configured at 75 percent of audit storage")):
    R("audit_logging", sid, name, [("auditd_config", key)],
      [[f'_kw(["auditd_config", "{key}"]) in {{{", ".join(chr(34) + a + chr(34) for a in allowed)}}}']],
      {"auditd_config": {key: allowed[0].upper()}},
      [{"auditd_config": {key: "ignore"}}] + ([{"auditd_config": {key: "syslog"}}] if key == "space_left_action" else [])
      + ([{"auditd_config": {key: "keep_logs"}}] if key == "max_log_file_action" else []),
      f"{key} in /etc/audit/auditd.conf must be {' or '.join(a.upper() for a in allowed)}, or the SA must attest that {what} "
      f"(input.attest.{att})",
      f"Set {key} = {allowed[0].upper()} in /etc/audit/auditd.conf",
      comment=f"{key} as configured in /etc/audit/auditd.conf",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[{"auditd_config": {key: a}} for a in allowed[1:]] + [{"auditd_config": {key: "ignore"}, "attest": {att: True}}])
