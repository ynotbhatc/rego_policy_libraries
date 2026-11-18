"""Reviewed logic table for gen_rhel9.py oracle_linux_9 (DISA STIG for Oracle Linux 9, V1R7).

Built 2026-11-18 rule by rule against the OL 9 V1R7 check text (tools/stig_generators/catalogs/oracle_linux_9.json),
replacing the by-title derivation (gen_oracle_linux.py). `T.reuse(ol_id, rhel9_id)` only where the OL 9 check is
the same check as the reviewed RHEL 9 V2R10 rule: same setting, same file or command, same expected value and
comparison. Every other rule is written here from the OL 9 check text. See linux_stig_table.py.
"""
from linux_stig_table import Table

T = Table()


def ol_audit(spec):
    """OL 9 prints its expected audit rules with `-k <key>` and `auid!=unset` (RHEL 9: `-F key=`, `auid!=-1`); the
    rule logic accepts both. The fixtures are rewritten to the OL form so the tests prove the OL output passes."""
    def sub(o):
        if isinstance(o, str):
            return o.replace(" -F key=", " -k ").replace("auid!=-1", "auid!=unset")
        if isinstance(o, list):
            return [sub(x) for x in o]
        if isinstance(o, dict):
            return {k: sub(v) for k, v in o.items()}
        return o
    return {k: sub(spec[k]) for k in ("green", "bad", "pass_cases")}


def audit(ol, r9):
    s = T.src[r9]
    T.reuse(ol, r9, **ol_audit(s))


# ── same check as the reviewed RHEL 9 rule (OS name, "sudo" and quoting aside) ──────────────────────────────
for ol, r9 in [
    ("OL09-00-002413", "RHEL-09-211050"), ("OL09-00-000130", "RHEL-09-215015"), ("OL09-00-000254", "RHEL-09-255065"),
    ("OL09-00-000255", "RHEL-09-255075"), ("OL09-00-002343", "RHEL-09-255040"), ("OL09-00-002344", "RHEL-09-255050"),
    ("OL09-00-003020", "RHEL-09-411075"), ("OL09-00-001105", "RHEL-09-611090"), ("OL09-00-001015", "RHEL-09-611065"),
    ("OL09-00-001020", "RHEL-09-611070"), ("OL09-00-001120", "RHEL-09-611100"), ("OL09-00-001095", "RHEL-09-411010"),
    ("OL09-00-003065", "RHEL-09-411050"), ("OL09-00-003001", "RHEL-09-411030"), ("OL09-00-003006", "RHEL-09-411110"),
    ("OL09-00-000441", "RHEL-09-653015"), ("OL09-00-000770", "RHEL-09-653055"), ("OL09-00-000765", "RHEL-09-653025"),
    ("OL09-00-000870", "RHEL-09-653040"), ("OL09-00-000090", "RHEL-09-211020"), ("OL09-00-000047", "RHEL-09-291010"),
    ("OL09-00-000301", "RHEL-09-651015"), ("OL09-00-002512", "RHEL-09-232255"), ("OL09-00-002525", "RHEL-09-232020"),
    ("OL09-00-002524", "RHEL-09-232200"), ("OL09-00-002506", "RHEL-09-232010"), ("OL09-00-006032", "RHEL-09-253065"),
    ("OL09-00-002000", "RHEL-09-231040"), ("OL09-00-002351", "RHEL-09-255160"), ("OL09-00-002348", "RHEL-09-255145"),
    ("OL09-00-002349", "RHEL-09-255150"), ("OL09-00-002352", "RHEL-09-255165"), ("OL09-00-002350", "RHEL-09-255155"),
    ("OL09-00-000060", "RHEL-09-431010"), ("OL09-00-002424", "RHEL-09-672055"), ("OL09-00-001055", "RHEL-09-611140"),
    ("OL09-00-001005", "RHEL-09-611110"), ("OL09-00-001085", "RHEL-09-611075"), ("OL09-00-002407", "RHEL-09-213015"),
    ("OL09-00-002070", "RHEL-09-231045"), ("OL09-00-002071", "RHEL-09-231050"), ("OL09-00-002072", "RHEL-09-231055"),
    ("OL09-00-002511", "RHEL-09-232250"), ("OL09-00-002548", "RHEL-09-232075"), ("OL09-00-002555", "RHEL-09-232270"),
    ("OL09-00-002536", "RHEL-09-232055"), ("OL09-00-002542", "RHEL-09-232065"), ("OL09-00-000221", "RHEL-09-251015"),
    ("OL09-00-000046", "RHEL-09-291035"), ("OL09-00-006004", "RHEL-09-251040"), ("OL09-00-000110", "RHEL-09-215040"),
    ("OL09-00-000100", "RHEL-09-215025"), ("OL09-00-002428", "RHEL-09-213020"), ("OL09-00-000351", "RHEL-09-652020"),
    ("OL09-00-002357", "RHEL-09-255080"), ("OL09-00-000065", "RHEL-09-431015"), ("OL09-00-002423", "RHEL-09-213070"),
    ("OL09-00-002406", "RHEL-09-213010"), ("OL09-00-000004", "RHEL-09-231015"), ("OL09-00-000002", "RHEL-09-231030"),
    ("OL09-00-002515", "RHEL-09-232050"), ("OL09-00-006028", "RHEL-09-253075"), ("OL09-00-006050", "RHEL-09-253010"),
    ("OL09-00-000302", "RHEL-09-651020"), ("OL09-00-002346", "RHEL-09-255095"), ("OL09-00-002347", "RHEL-09-255100"),
    ("OL09-00-006020", "RHEL-09-253015"), ("OL09-00-006021", "RHEL-09-253020"), ("OL09-00-006031", "RHEL-09-253060"),
    ("OL09-00-006001", "RHEL-09-291040"), ("OL09-00-002107", "RHEL-09-271105"), ("OL09-00-001130", "RHEL-09-611155"),
    ("OL09-00-000006", "RHEL-09-231025"), ("OL09-00-002409", "RHEL-09-213075"), ("OL09-00-002430", "RHEL-09-251045"), ("OL09-00-006024", "RHEL-09-253035"),
    # OL 9 prints "rsyslogd package" in prose, but its command and output are the rsyslog package (rsyslog.x86_64)
    ("OL09-00-000350", "RHEL-09-652010"),
    # OL 9's finding names "yes", missing or commented out; its expected output is "PermitRootLogin no" and the fix
    # sets "no". Kept: only "no" passes (prohibit-password still permits a direct root logon, which the title forbids).
    ("OL09-00-002345", "RHEL-09-255045"),
]:
    T.reuse(ol, r9)

# audit rules: same rule text (OL prints -k / auid!=unset); /etc/passwd and /etc/sudoers are -w watches in OL 9's
# expected output, which the RHEL 9 logic accepts as one of its two forms
for ol, r9 in [("OL09-00-000715", "RHEL-09-654010"), ("OL09-00-000640", "RHEL-09-654015"), ("OL09-00-000635", "RHEL-09-654070"),
               ("OL09-00-000690", "RHEL-09-654080"), ("OL09-00-000645", "RHEL-09-654020"), ("OL09-00-000545", "RHEL-09-654025"),
               ("OL09-00-000525", "RHEL-09-654240"), ("OL09-00-000670", "RHEL-09-654150"), ("OL09-00-000500", "RHEL-09-654215")]:
    audit(ol, r9)

# ── same check, one clause different (recorded per rule) ───────────────────────────────────────────────────────
# OL 9 has no alternate-MFA Not Applicable note on these: the clause is dropped
T.reuse("OL09-00-000930", "RHEL-09-611170", na=[], na_expect="", na_cases=[])
T.reuse("OL09-00-000900", "RHEL-09-631010", na=[], na_expect="", na_cases=[])
# OL 9 has no centralized-account-management Not Applicable note
T.reuse("OL09-00-002416", "RHEL-09-411085", na=[], na_expect="", na_cases=[])
# OL 9 reads /boot/grub2/user.cfg only (no legacy EFI location)
T.reuse("OL09-00-001115", "RHEL-09-212010",
        expect="GRUB2_PASSWORD in /boot/grub2/user.cfg must begin with grub.pbkdf2.sha512")
# OL 9 adds "or if the file is missing": the banner file sshd names must exist
s = T.src["RHEL-09-255025"]
T.reuse("OL09-00-000256", "RHEL-09-255025",
        ev=s["ev"] + [("ssh_banner_file", "exists")],
        alts=[s["alts"][0] + ["input.ssh_banner_file.exists == true"]],
        green={**s["green"], "ssh_banner_file": {"exists": True}},
        bad=s["bad"] + [{"ssh_banner_file": {"exists": False}}],
        expect="sshd must have an uncommented Banner keyword naming the banner file, and that file must exist",
        comment="Banner keyword in the sshd configuration; input.ssh_banner_file.exists: the file it names exists")

# ── OL 9's own check ───────────────────────────────────────────────────────────────────────────────────────────
T.helpers("configuration_management", r'''
# uncommented modprobe lines for a module: install <mod> <cmd> and blacklist <mod>
_module_install_blacklisted(mod, cmd) if {
	m := input.modprobe[mod]
	m.install == cmd
	m.blacklisted == true
}''')

T.R("configuration_management", "OL09-00-000042", "firewire_disabled", [("modprobe", "firewire-core")],
    [['_module_install_blacklisted("firewire-core", "/bin/true")']],
    {"modprobe": {"firewire-core": {"install": "/bin/true", "blacklisted": True}}},
    [{"modprobe": {"firewire-core": {"install": "/bin/true", "blacklisted": False}}},
     {"modprobe": {"firewire-core": {"install": "/bin/false", "blacklisted": True}}}],
    "/etc/modprobe.conf or /etc/modprobe.d/* must carry uncommented 'install firewire-core /bin/true' and "
    "'blacklist firewire-core', or its use must be documented with the ISSO (input.attest.ol09_00_000042_firewire_documented)",
    "Add 'install firewire-core /bin/true' and 'blacklist firewire-core' to /etc/modprobe.d/firewire-core.conf",
    comment="OL 9 expects 'install firewire-core /bin/true' (RHEL 9: /bin/false); input.modprobe[\"firewire-core\"] = {install, blacklisted}",
    attest_alts=[['_attested("ol09_00_000042_firewire_documented")']],
    pass_cases=[{"modprobe": {"firewire-core": {"install": None, "blacklisted": False}},
                 "attest": {"ol09_00_000042_firewire_documented": True}}])

FIPS_HASHES = ["SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-256"]
T.helpers("configuration_management", r'''
# OL 9 crypto-policy hash list: SHA1/MD5, or a digest below 256 bits that is not one of the required algorithms
# (OL 9 requires SHA2-224 and also says a hash value below 256 is a finding; the required list is kept)
ol_fips_policy_hashes := ''' + "{" + ", ".join(f'"{h}"' for h in FIPS_HASHES) + "}" + r'''

_ol_weak_hash(h) if not is_string(h)

_ol_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "SHA1")
}

_ol_weak_hash(h) if {
	is_string(h)
	u := upper(h)
	contains(u, "MD5")
}

_ol_weak_hash(h) if {
	is_string(h)
	not h in ol_fips_policy_hashes
	m := regex.find_all_string_submatch_n(`-([0-9]+)$`, h, 1)
	bits := to_number(m[0][1])
	bits < 256
}

# FIPS, or FIPS followed by subpolicies (FIPS:<SUBPOLICY>:<SUBPOLICY>)
_ol_fips_policy(p) if p == "FIPS"

_ol_fips_policy(p) if regex.match(`^FIPS(:[A-Za-z0-9_-]+)+$`, p)''')

T.R("configuration_management", "OL09-00-000241", "crypto_policy_fips",
    [("crypto_policy",), ("crypto_policy_state", "hash"), ("crypto_policy_state", "min_rsa_size")],
    [['_ol_fips_policy(_str(["crypto_policy"]))',
      "hashes := input.crypto_policy_state.hash",
      "is_array(hashes)",
      "every h in ol_fips_policy_hashes {\n\th in hashes\n}",
      "count([h | some h in hashes; _ol_weak_hash(h)]) == 0",
      '_num(["crypto_policy_state", "min_rsa_size"]) >= 2048']],
    {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": FIPS_HASHES, "min_rsa_size": 2048}},
    [{"crypto_policy": "DEFAULT"}, {"crypto_policy": "DEFAULT:FIPS"}, {"crypto_policy": "FIPS:"},
     {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHA1"]}},
     {"crypto_policy_state": {"hash": FIPS_HASHES[:-1]}},
     {"crypto_policy_state": {"hash": FIPS_HASHES + ["SHA3-224"]}},
     {"crypto_policy_state": {"min_rsa_size": 1024}}, {"crypto_policy_state": {"min_rsa_size": "2048 bits"}}],
    "update-crypto-policies --show must be FIPS (or FIPS:<subpolicy>...); CURRENT.pol hash must include "
    + " ".join(FIPS_HASHES) + ", nothing with SHA1 or another hash below 256 bits; min_rsa_size must be at least 2048",
    "Set the FIPS policy: update-crypto-policies --set FIPS, then reboot",
    comment="systemwide crypto policy FIPS (subpolicies allowed, as OL 9's note says); CURRENT.pol hash list and min_rsa_size",
    pass_cases=[{"crypto_policy": "FIPS:OSPP"}, {"crypto_policy_state": {"min_rsa_size": "3072"}}])

T.R("configuration_management", "OL09-00-000070", "fips_mode_enabled", [("fips", "mode_setup_check")],
    [['out := _str(["fips", "mode_setup_check"])',
      'ls := split(out, "\\n")', 'some l in ls', 'regex.match(`^FIPS mode is enabled\\.?$`, trim_space(l))']],
    {"fips": {"mode_setup_check": "FIPS mode is enabled."}},
    [{"fips": {"mode_setup_check": "FIPS mode is disabled."}},
     {"fips": {"mode_setup_check": "Inconsistent state detected.\nFIPS mode is not enabled."}}],
    "fips-mode-setup --check must report 'FIPS mode is enabled.'",
    "Enable FIPS mode: fips-mode-setup --enable, then reboot",
    comment="output of fips-mode-setup --check (OL 9; RHEL 9 reads /proc/sys/crypto/fips_enabled)")

BACKENDS = [{"name": "nss.config", "is_symlink": False, "target": ""}] + [
    {"name": f"{b}.config", "is_symlink": True, "target": f"/usr/share/crypto-policies/FIPS/{b}.txt"}
    for b in ("bind", "gnutls", "java", "javasystem", "krb5", "libreswan", "libssh", "openssh", "opensshserver",
              "opensslcnf", "openssl", "openssl_fips")]
T.R("pki_crypto", "OL09-00-000242", "crypto_policy_not_overridden",
    [("crypto_policy_check", "pass_output"), ("crypto_backends",)],
    [['out := _str(["crypto_policy_check", "pass_output"])',
      'raw := split(out, "\\n")', 'lines := [l | some x in raw; l := trim_space(x); l != ""]',
      "count(lines) > 0", 'lines[count(lines) - 1] == "PASS"',
      "backends := input.crypto_backends", "is_array(backends)", "count(backends) > 0",
      "count([b | some b in backends; not _backend_ok(b)]) == 0"]],
    {"crypto_policy_check": {"pass_output": "The configured policy matches the generated policy\nPASS"},
     "crypto_backends": BACKENDS},
    [{"crypto_policy_check": {"pass_output": "The configured policy does NOT match the generated policy"}},
     {"crypto_policy_check": {"pass_output": "PASS\nThe configured policy does NOT match the generated policy"}},
     {"crypto_backends": BACKENDS[:-1] + [{"name": "openssl_fips.config", "is_symlink": True,
                                           "target": "/usr/share/crypto-policies/DEFAULT/openssl_fips.txt"}]},
     {"crypto_backends": [{"name": "nss.config", "is_symlink": True, "target": "/usr/share/crypto-policies/FIPS/nss.txt"}] + BACKENDS[1:]}],
    "the last line of 'update-crypto-policies --check && echo PASS' must be PASS, and every back-end in "
    "/etc/crypto-policies/back-ends/ except nss.config (not a link) must link to its file under /usr/share/crypto-policies/FIPS/",
    "Remove the overrides and run update-crypto-policies --set FIPS, then reboot",
    comment="input.crypto_policy_check.pass_output: output of `update-crypto-policies --check && echo PASS`; "
            "input.crypto_backends[{name, is_symlink, target}] from ls -l /etc/crypto-policies/back-ends/")

T.R("software_integrity", "OL09-00-000496", "localpkg_gpgcheck", [("dnf_config", "localpkg_gpgcheck")],
    [['_str(["dnf_config", "localpkg_gpgcheck"]) == "1"']],
    {"dnf_config": {"localpkg_gpgcheck": "1"}},
    [{"dnf_config": {"localpkg_gpgcheck": "0"}}, {"dnf_config": {"localpkg_gpgcheck": "True"}}],
    "localpkg_gpgcheck in /etc/dnf/dnf.conf must be 1, or an approved GPG verification process must be attested "
    "(input.attest.ol09_00_000496_gpg_process)",
    "Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf",
    comment="OL 9 accepts only \"1\" (RHEL 9 also accepts true/yes); the ask-the-SA clause is an attestation",
    attest_alts=[['_attested("ol09_00_000496_gpg_process")']],
    pass_cases=[{"dnf_config": {"localpkg_gpgcheck": "0"}, "attest": {"ol09_00_000496_gpg_process": True}},
                {"dnf_config": {"localpkg_gpgcheck": 1}}])

T.R("software_integrity", "OL09-00-000497", "dnf_gpgcheck", [("dnf_config", "gpgcheck")],
    [['_str(["dnf_config", "gpgcheck"]) == "1"']],
    {"dnf_config": {"gpgcheck": "1"}},
    [{"dnf_config": {"gpgcheck": "0"}}, {"dnf_config": {"gpgcheck": "yes"}}],
    "gpgcheck in /etc/dnf/dnf.conf must be 1, or an approved GPG verification process must be attested "
    "(input.attest.ol09_00_000497_gpg_process)",
    "Set gpgcheck=1 in /etc/dnf/dnf.conf",
    comment="gpgcheck in /etc/dnf/dnf.conf (grep gpgcheck /etc/dnf/dnf.conf); only \"1\" passes; the SA clause is an attestation",
    attest_alts=[['_attested("ol09_00_000497_gpg_process")']],
    pass_cases=[{"dnf_config": {"gpgcheck": None}, "attest": {"ol09_00_000497_gpg_process": True}}])

T.R("software_integrity", "OL09-00-000498", "all_repos_gpgcheck", [("yum_repos",)],
    [["repos := input.yum_repos", "is_array(repos)", "count(repos) > 0",
      'every r in repos {\n\t_str_val(object.get(r, "gpgcheck", null)) == "1"\n}']],
    {"yum_repos": [{"name": "ol9_baseos_latest", "gpgcheck": "1"}, {"name": "ol9_appstream", "gpgcheck": 1}]},
    [{"yum_repos": [{"name": "ol9_baseos_latest", "gpgcheck": "1"}, {"name": "ol9_appstream", "gpgcheck": "0"}]},
     {"yum_repos": [{"name": "ol9_baseos_latest", "gpgcheck": "true"}]},
     {"yum_repos": [{"name": "ol9_baseos_latest"}]}, {"yum_repos": []}],
    "every repository in /etc/yum.repos.d/*.repo must set gpgcheck = 1",
    "Set gpgcheck=1 in every repository definition under /etc/yum.repos.d/",
    comment="input.yum_repos[{name, gpgcheck}] from /etc/yum.repos.d/*.repo; OL 9: only \"1\", no SA clause")
T.helpers("software_integrity", r'''
# a setting value as a trimmed string (string as given, integer in decimal)
_str_val(v) := trim_space(v) if is_string(v)

_str_val(v) := format_int(v, 10) if {
	is_number(v)
	v == floor(v)
}

_ol_fpr(s) := upper(replace(s, " ", "")) if is_string(s)

# Oracle's OL 9 signing keys as the check's rpm -q and gpg output print them
oracle_key_fingerprints := {"3E6D826D3FBAB389C2F38E34BC4D06A08D8B756F", "982231759C7467065D0CE9B2A7DD07088B4EFBE6"}

_oracle_key_installed(label) if {
	some s in input.rpm_gpg_pubkeys
	is_string(s)
	trim_space(s) == concat("", ["Oracle Linux ", label, " <secalert_us@oracle.com> public key"])
}''')

T.R("software_integrity", "OL09-00-000499", "oracle_gpg_keys",
    [("rpm_gpg_pubkeys",), ("oracle_release_key_file", "fingerprints")],
    [['_oracle_key_installed("(release key 1)")', '_oracle_key_installed("(backup key 1)")',
      "fps := input.oracle_release_key_file.fingerprints", "is_array(fps)",
      "installed := {f | some x in fps; f := _ol_fpr(x)}",
      "every k in oracle_key_fingerprints {\n\tk in installed\n}"]],
    {"rpm_gpg_pubkeys": ["Oracle Linux (release key 1) <secalert_us@oracle.com> public key",
                         "Oracle Linux (backup key 1) <secalert_us@oracle.com> public key"],
     "oracle_release_key_file": {"fingerprints": ["3E6D 826D 3FBA B389 C2F3  8E34 BC4D 06A0 8D8B 756F",
                                                  "9822 3175 9C74 6706 5D0C  E9B2 A7DD 0708 8B4E FBE6"]}},
    [{"rpm_gpg_pubkeys": ["Oracle Linux (release key 1) <secalert_us@oracle.com> public key"]},
     {"rpm_gpg_pubkeys": ["Oracle Linux (release key 1) <secalert_us@oracle.com> public key",
                          "Not Oracle Linux (backup key 1) <secalert_us@oracle.com> public key"]},
     {"oracle_release_key_file": {"fingerprints": ["3E6D 826D 3FBA B389 C2F3  8E34 BC4D 06A0 8D8B 756F"]}},
     {"oracle_release_key_file": {"fingerprints": []}}],
    "Oracle GPG keys 'release key 1' and 'backup key 1' must be installed and /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle must "
    "carry fingerprints 3E6D826D3FBAB389C2F38E34BC4D06A08D8B756F and 982231759C7467065D0CE9B2A7DD07088B4EFBE6",
    "Install the Oracle signing keys: rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle (verify the fingerprints first)",
    comment="input.rpm_gpg_pubkeys: rpm -q --queryformat \"%{SUMMARY}\" gpg-pubkey; input.oracle_release_key_file."
            "fingerprints: gpg --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle (absent file: not collected)")

T.R("account_auth", "OL09-00-000925", "mfa_enabled", [("sssd_conf_file", "pam_cert_auth")],
    [['_kw(["sssd_conf_file", "pam_cert_auth"]) == "true"']],
    {"sssd_conf_file": {"pam_cert_auth": "True"}}, [{"sssd_conf_file": {"pam_cert_auth": "False"}}],
    "pam_cert_auth = True must be set (uncommented) in /etc/sssd/sssd.conf",
    "Set pam_cert_auth = True in the [pam] section of /etc/sssd/sssd.conf and restart sssd",
    comment="pam_cert_auth as written in /etc/sssd/sssd.conf itself (OL 9 greps that file only; RHEL 9 also reads conf.d)")

T.R("pki_crypto", "OL09-00-000910", "cert_user_mapping", [("sssd_conf_file", "certmap_rules")],
    [["rules := input.sssd_conf_file.certmap_rules", "is_array(rules)", "some r in rules",
      "is_string(r.maprule)", 'trim_space(r.maprule) != ""']],
    {"sssd_conf_file": {"certmap_rules": [{"section": "certmap/testing.test/rule_name", "matchrule": "<SAN>.*EDIPI@mil",
                                           "maprule": "(userCertificate;binary={cert!bin})", "domains": "testing.test"}]}},
    [{"sssd_conf_file": {"certmap_rules": []}},
     {"sssd_conf_file": {"certmap_rules": [{"section": "certmap/testing.test/rule_name", "maprule": " "}]}}],
    "/etc/sssd/sssd.conf must have a [certmap/...] section with a maprule, or the SA must show how certificates are "
    "mapped to accounts (input.attest.ol09_00_000910_certificate_mapping)",
    "Add a [certmap/<domain>/<rule>] section with matchrule and maprule to /etc/sssd/sssd.conf",
    comment="input.sssd_conf_file.certmap_rules: [certmap/...] sections of /etc/sssd/sssd.conf (OL 9 reads that file only)",
    attest_alts=[['_attested("ol09_00_000910_certificate_mapping")']],
    pass_cases=[{"sssd_conf_file": {"certmap_rules": []}, "attest": {"ol09_00_000910_certificate_mapping": True}}])

T.R("pki_crypto", "OL09-00-002160", "smartcard_lock_on_removal", [("dconf_db", "removal_action")],
    [["vals := input.dconf_db.removal_action", "is_array(vals)", "some v in vals", "is_string(v)",
      "trim_space(v) == \"'lock-screen'\""]],
    {"dconf_db": {"removal_action": ["'lock-screen'"]}},
    [{"dconf_db": {"removal_action": []}}, {"dconf_db": {"removal_action": ["'none'"]}},
     {"dconf_db": {"removal_action": ["'lock-screen-later'"]}}],
    "an uncommented removal-action='lock-screen' must be set in the dconf database files (/etc/dconf/db/*)",
    "Set removal-action='lock-screen' under [org/gnome/settings-daemon/peripherals/smartcard] in /etc/dconf/db/local.d/ and run dconf update",
    comment="input.dconf_db.removal_action: the values of the uncommented removal-action= lines found by "
            "grep -R removal-action /etc/dconf/db/* (OL 9 reads the dconf files; RHEL 9 reads gsettings)",
    na=[["input.gui_installed == false"]], na_expect="no graphical user interface is installed",
    na_cases=[{"dconf_db": {"removal_action": None}, "gui_installed": False}])

T.R("configuration_management", "OL09-00-000300", "aide_installed", [("packages", "aide"), ("aide", "check_output")],
    [["input.packages.aide == true",
      'not contains(_str(["aide", "check_output"]), "Couldn\'t open file /var/lib/aide/aide.db.gz for reading")']],
    {"packages": {"aide": True}, "aide": {"check_output": "AIDE found NO differences between database and filesystem. Looks okay!!"}},
    [{"packages": {"aide": False}},
     {"aide": {"check_output": "Couldn't open file /var/lib/aide/aide.db.gz for reading"}}],
    "the aide package must be installed and initialized (aide --check must not report \"Couldn't open file "
    "/var/lib/aide/aide.db.gz for reading\"), or the SA must attest another integrity tool (input.attest.ol09_00_000300_other_tool)",
    "Install and initialize AIDE: dnf install aide && aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
    comment="input.packages.aide; input.aide.check_output: output of /usr/sbin/aide --check (read when AIDE is installed)",
    attest_alts=[['_attested("ol09_00_000300_other_tool")']],
    pass_cases=[{"packages": {"aide": False}, "attest": {"ol09_00_000300_other_tool": True}}])

T.R("services", "OL09-00-002426", "tftp_secure_mode", [("packages", "tftp-server")],
    [['input.packages["tftp-server"] == true', 's := _str(["tftp", "unit_execstart"])',
      "regex.match(`(^|\\s)-s(\\s|$)`, s)"]],
    {"packages": {"tftp-server": True}, "tftp": {"unit_execstart": "ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot"}},
    [{"tftp": {"unit_execstart": "ExecStart=/usr/sbin/in.tftpd /var/lib/tftpboot"}},
     {"tftp": {"unit_execstart": "ExecStart=/usr/sbin/in.tftpd -sv"}}],
    "tftp-server is installed: the ExecStart line of `systemctl cat tftp` (input.tftp.unit_execstart) must carry the -s option",
    "Add -s <directory> to the in.tftpd ExecStart line (systemctl edit tftp)",
    comment="the tftp unit as systemd loads it (systemctl cat tftp | grep ExecStart); tftp-server not installed is Not Applicable",
    na=[['input.packages["tftp-server"] == false']], na_expect="tftp-server is not installed",
    na_cases=[{"packages": {"tftp-server": False}}],
    green_na={"packages": {"tftp-server": False}})

T.R("services", "OL09-00-000135", "tftp_server_absent", [("packages", "tftp-server")],
    [['input.packages["tftp-server"] == false']],
    {"packages": {"tftp-server": False}}, [{"packages": {"tftp-server": True}}],
    "the tftp-server package must not be installed", "Remove the TFTP server: dnf remove tftp-server",
    comment="input.packages[\"tftp-server\"] (dnf list --installed | grep tftp-server)")

T.R("services", "OL09-00-000125", "tuned_absent", [("packages", "tuned")],
    [["input.packages.tuned == false"]],
    {"packages": {"tuned": False}}, [{"packages": {"tuned": True}}],
    "the tuned package must not be installed, or its use must be documented with the ISSO "
    "(input.attest.ol09_00_000125_tuned_documented)",
    "Remove tuned: dnf remove tuned",
    comment="input.packages.tuned (dnf list --installed tuned); ISSO documentation of an operational need is an attestation",
    attest_alts=[['_attested("ol09_00_000125_tuned_documented")']],
    pass_cases=[{"packages": {"tuned": True}, "attest": {"ol09_00_000125_tuned_documented": True}}])

T.R("network", "OL09-00-000220", "firewalld_installed", [("packages", "firewalld")],
    [["input.packages.firewalld == true"]],
    {"packages": {"firewalld": True}}, [{"packages": {"firewalld": False}}],
    "the firewalld package must be installed", "Install firewalld: dnf install firewalld",
    comment="input.packages.firewalld (dnf list --installed firewalld)")

T.R("ssh_config", "OL09-00-000251", "sshd_active", [("services", "sshd")],
    [['_kw(["services", "sshd"]) == "active"']],
    {"services": {"sshd": "active"}}, [{"services": {"sshd": "inactive"}}, {"services": {"sshd": "failed"}}],
    "sshd must be active (systemctl is-active sshd)", "Enable and start sshd: systemctl enable --now sshd",
    comment="systemctl is-active sshd")

for sid, f, name in [("OL09-00-002540", "etc_gshadow", "gshadow_owner_root"), ("OL09-00-002552", "etc_shadow", "shadow_owner_root")]:
    path = "/" + f.replace("_", "/", 1)
    T.R("file_permissions", sid, name, [("file_permissions", f, "owner")],
        [[f'_str(["file_permissions", "{f}", "owner"]) == "root"']],
        {"file_permissions": {f: {"owner": "root"}}}, [{"file_permissions": {f: {"owner": "nobody"}}}],
        f"{path} must be owned by root (stat -c %U)", f"chown root {path}",
        comment=f"owner of {path} (stat -c \"%U %n\" {path})")

T.R("configuration_management", "OL09-00-002410", "ptrace_restricted", [("kernel_params", "kernel.yama.ptrace_scope")],
    [['_str(["kernel_params", "kernel.yama.ptrace_scope"]) == "1"']],
    {"kernel_params": {"kernel.yama.ptrace_scope": "1"}},
    [{"kernel_params": {"kernel.yama.ptrace_scope": "0"}}, {"kernel_params": {"kernel.yama.ptrace_scope": "2"}}],
    "kernel.yama.ptrace_scope must be 1", "Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/ and run sysctl --system",
    comment="sysctl kernel.yama.ptrace_scope (runtime value)")

for sid, key, name in [("OL09-00-006041", "net.ipv6.conf.all.accept_redirects", "ipv6_redirects_ignored"),
                       ("OL09-00-006042", "net.ipv6.conf.all.accept_source_route", "ipv6_source_route_disabled")]:
    T.R("network", sid, name, [("kernel_params", key)],
        [[f'_str(["kernel_params", "{key}"]) == "0"']],
        {"kernel_params": {key: "0"}, "ipv6_disabled": False}, [{"kernel_params": {key: "1"}}],
        f"{key} must be 0", f"Set {key} = 0 in /etc/sysctl.d/ and run sysctl --system",
        comment=f"sysctl {key}; IPv6 disabled on the system is Not Applicable (input.ipv6_disabled == true)",
        na=[["input.ipv6_disabled == true"]], na_expect="IPv6 is disabled on the system",
        na_cases=[{"kernel_params": {key: None}, "ipv6_disabled": True}])

RULES, SECTION_HELPERS = T.finish()
OWN_HELPERS = T.extra
