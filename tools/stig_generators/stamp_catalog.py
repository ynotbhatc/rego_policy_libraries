#!/usr/bin/env python3
"""Re-stamp the hand-maintained RHEL STIG modules from the current DISA XCCDF catalog.

    python3 tools/stig_generators/stamp_catalog.py [rhel_9] [rhel_8]        # writes into benchmarks/stig/
    python3 tools/stig_generators/stamp_catalog.py --check rhel_9           # report only, no writes

The RHEL 9 and RHEL 8 modules were written by hand against older catalogs, and their
`stig_id`/`vuln_id` values were found (2026-10-13) to name a different DISA rule than the
logic next to them implements. This tool keys every finding on what the LOGIC checks, not
on the id it carried: the per-platform MAP below is the reviewed table of
`<section>:<id as written in the module>` -> current DISA stig_id (None = retired, no rule
in the current catalog for what the logic checks). A finding not in MAP must match a catalog
title exactly (normalised), otherwise the run aborts and prints the closest titles for
review -- a look-alike is never stamped by similarity alone.

What is rewritten in each section module: the block header (`# <id> | <V-id> | <CAT>`), the
finding's vuln_id / stig_id / severity / rule_title, the `status_<ident>` / `finding_<ident>`
names, the CAT I/II/III grouping and the aggregation lists. Retired blocks are removed (a
helper they defined that a kept block still uses is carried over). The aggregator's version
strings and the tests' id references are updated; a test that names a retired rule is
reported for hand editing. Nothing is invented for rules the modules do not implement:
they are counted in the aggregator header as the remaining work.
"""
import difflib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "benchmarks", "stig")
CATS = os.path.join(HERE, "catalogs")
SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
LIBRARY = "October 2026 SRG-STIG library"
VERIFIED = "2026-11-10"

PLATFORMS = {
    "rhel_9": {
        "prefix": "RHEL-09", "ident": "rhel_09", "name": "RHEL 9", "complete": "stig_rhel9_complete.rego",
        # Reviewed 2026-11-10 against the V2R10 check text, keyed on the fact each block evaluates.
        # A value of None: the current RHEL 9 STIG has no rule for what the logic checks (or another
        # block already covers that rule) -- the block is removed, not re-pointed to a look-alike.
        "map": {
            "account_auth:RHEL-09-611010": "RHEL-09-611165",  # pam mfa flag -> certificate based smart card authentication
            "account_auth:RHEL-09-611015": "RHEL-09-611140",  # sha512 -> shadow file stores only encrypted representations
            "account_auth:RHEL-09-611020": "RHEL-09-411075",  # deny=3
            "account_auth:RHEL-09-611025": "RHEL-09-611155",
            "account_auth:RHEL-09-611030": "RHEL-09-611090",  # minlen 15
            "account_auth:RHEL-09-611035": "RHEL-09-611110",  # ucredit
            "account_auth:RHEL-09-611040": "RHEL-09-611065",  # lcredit
            "account_auth:RHEL-09-611045": "RHEL-09-611070",  # dcredit
            "account_auth:RHEL-09-611050": "RHEL-09-611100",  # ocredit
            "account_auth:RHEL-09-611055": "RHEL-09-411010",  # PASS_MAX_DAYS (module threshold 60 is stricter than DISA's 180)
            "account_auth:RHEL-09-611060": "RHEL-09-611075",  # PASS_MIN_DAYS
            "account_auth:RHEL-09-611065": None,              # pwhistory remember: no RHEL 9 V2R10 rule
            "account_auth:RHEL-09-611070": "RHEL-09-411085",  # fail_interval 900
            "account_auth:RHEL-09-611075": "RHEL-09-411050",  # INACTIVE 35
            "account_auth:RHEL-09-611080": None,              # PASS_WARN_AGE: no RHEL 9 rule
            "account_auth:RHEL-09-611085": "RHEL-09-411030",  # duplicate UIDs
            "account_auth:RHEL-09-611090": "RHEL-09-411110",  # duplicate GIDs
            "account_auth:RHEL-09-611095": None,              # groups in /etc/passwd defined in /etc/group: no RHEL 9 rule
            "audit_logging:RHEL-09-653010": "RHEL-09-653015",  # auditd active
            "audit_logging:RHEL-09-653015": "RHEL-09-653055",  # max_log_file_action
            "audit_logging:RHEL-09-653020": None,              # audit log directory mode: no RHEL 9 V2R10 rule
            "audit_logging:RHEL-09-653025": "RHEL-09-653025",
            "audit_logging:RHEL-09-653030": "RHEL-09-653040",  # space_left_action = email
            "audit_logging:RHEL-09-654010": "RHEL-09-654010",
            "audit_logging:RHEL-09-654015": None,              # execve b32: DISA covers both arches in 654010
            "audit_logging:RHEL-09-654020": "RHEL-09-654020",
            "audit_logging:RHEL-09-654025": "RHEL-09-654015",
            "audit_logging:RHEL-09-654030": "RHEL-09-654025",
            "audit_logging:RHEL-09-654035": "RHEL-09-654070",  # open/openat/open_by_handle_at EACCES|EPERM
            "audit_logging:RHEL-09-654040": "RHEL-09-654215",  # -w /etc/sudoers
            "audit_logging:RHEL-09-654045": "RHEL-09-654240",  # -w /etc/passwd
            "audit_logging:RHEL-09-654050": "RHEL-09-654150",  # sudo
            "audit_logging:RHEL-09-654055": None,              # mount SYSCALL: DISA audits the mount command and umount syscalls
            "audit_logging:RHEL-09-654060": "RHEL-09-654080",  # init_module/finit_module
            "audit_logging:RHEL-09-654065": None,              # -e 2 immutable: no RHEL 9 V2R10 rule
            "configuration_management:RHEL-09-211010": "RHEL-09-211050",  # ctrl-alt-del.target
            "configuration_management:RHEL-09-211015": "RHEL-09-271105",  # GNOME logout key
            "configuration_management:RHEL-09-211020": "RHEL-09-431010",  # SELinux enforcing
            "configuration_management:RHEL-09-211025": "RHEL-09-431015",  # SELinux targeted
            "configuration_management:RHEL-09-211030": "RHEL-09-212010",
            "configuration_management:RHEL-09-211040": None,              # DoD root CA: duplicate of pki_crypto RHEL-09-672010 -> 631010
            "configuration_management:RHEL-09-211050": "RHEL-09-671010",  # fips_mode
            "configuration_management:RHEL-09-211060": "RHEL-09-215105",  # crypto_policy FIPS / FIPS:OSPP
            "configuration_management:RHEL-09-212010": "RHEL-09-211020",  # /etc/issue banner
            "configuration_management:RHEL-09-212020": "RHEL-09-255025",  # sshd Banner
            "configuration_management:RHEL-09-213010": "RHEL-09-213070",  # ASLR
            "configuration_management:RHEL-09-213020": "RHEL-09-213010",  # dmesg_restrict
            "configuration_management:RHEL-09-213025": "RHEL-09-213015",  # perf_event_paranoid
            "configuration_management:RHEL-09-213030": "RHEL-09-213075",  # unprivileged_bpf_disabled
            "configuration_management:RHEL-09-213035": "RHEL-09-251045",  # bpf_jit_harden
            "configuration_management:RHEL-09-214010": "RHEL-09-291010",  # usb-storage module
            "configuration_management:RHEL-09-214015": "RHEL-09-213055",  # firewire
            "configuration_management:RHEL-09-215010": "RHEL-09-651015",  # aide cron
            "configuration_management:RHEL-09-215015": "RHEL-09-651010",  # aide package installed
            "configuration_management:RHEL-09-231010": "RHEL-09-231015",
            "configuration_management:RHEL-09-231015": "RHEL-09-231045",
            "configuration_management:RHEL-09-231020": "RHEL-09-231050",
            "configuration_management:RHEL-09-231025": "RHEL-09-231055",
            "configuration_management:RHEL-09-231180": "RHEL-09-231025",
            "configuration_management:RHEL-09-231190": "RHEL-09-231030",  # separate fs for the audit data path
            "file_permissions:RHEL-09-232010": None,              # "no world-writable files": DISA asks ownership/sticky bit instead
            "file_permissions:RHEL-09-232015": "RHEL-09-232255",
            "file_permissions:RHEL-09-232020": "RHEL-09-232250",
            "file_permissions:RHEL-09-232025": "RHEL-09-232075",
            "file_permissions:RHEL-09-232030": "RHEL-09-232270",
            "file_permissions:RHEL-09-232035": "RHEL-09-232055",
            "file_permissions:RHEL-09-232040": "RHEL-09-232065",
            "file_permissions:RHEL-09-232045": None,              # undocumented SUID/SGID: no RHEL 9 rule
            "file_permissions:RHEL-09-232050": "RHEL-09-232020",
            "file_permissions:RHEL-09-232055": "RHEL-09-232200",
            "file_permissions:RHEL-09-232060": "RHEL-09-232010",
            "file_permissions:RHEL-09-232065": "RHEL-09-232050",
            "file_permissions:RHEL-09-232070": None,              # /etc/cron.allow mode: no RHEL 9 rule
            "network:RHEL-09-251010": "RHEL-09-251015",  # firewalld active
            "network:RHEL-09-251015": "RHEL-09-253075",
            "network:RHEL-09-251020": "RHEL-09-253015",  # all.accept_redirects (253040 default.* not covered)
            "network:RHEL-09-251025": "RHEL-09-253065",  # all.send_redirects (253070 default.* not covered)
            "network:RHEL-09-251030": "RHEL-09-253020",  # all.accept_source_route (253045 default.* not covered)
            "network:RHEL-09-251035": "RHEL-09-253060",
            "network:RHEL-09-251040": "RHEL-09-253010",  # tcp_syncookies (the module title said rp_filter; the logic is syncookies)
            "network:RHEL-09-251045": "RHEL-09-253035",  # all.rp_filter
            "network:RHEL-09-251050": None,              # "IPv6 disabled or configured": no single DISA rule
            "network:RHEL-09-251055": "RHEL-09-291040",
            "network:RHEL-09-251060": "RHEL-09-291035",
            "network:RHEL-09-251065": "RHEL-09-251040",
            "pki_crypto:RHEL-09-671010": None,              # fips_mode|crypto_policy: duplicate of configuration_management 671010/215105
            "pki_crypto:RHEL-09-671015": None,              # mixed PKI flags: duplicate of 611165 (account_auth) and 631010
            "pki_crypto:RHEL-09-671020": "RHEL-09-611170",  # OCSP/CRL
            "pki_crypto:RHEL-09-672010": "RHEL-09-631010",  # DoD root CA installed (certification path to a trust anchor)
            "pki_crypto:RHEL-09-672015": None,              # crypto_policy FIPS: duplicate of configuration_management 215105
            "pki_crypto:RHEL-09-672020": "RHEL-09-672020",
            "pki_crypto:RHEL-09-672025": None,              # sssd cert auth: duplicate of 611165
            "pki_crypto:RHEL-09-672030": None,              # expired certificates: no RHEL 9 rule
            "pki_crypto:RHEL-09-672035": None,              # pam_pkcs11/pam_sss: duplicate of 611165
            "pki_crypto:RHEL-09-672040": "RHEL-09-271045",  # smart card removal lock
            "pki_crypto:RHEL-09-672045": "RHEL-09-631015",
            "pki_crypto:RHEL-09-672050": "RHEL-09-672055",  # openssl.cnf includes the crypto-policies opensslcnf
            "services:RHEL-09-291010": "RHEL-09-215040",
            "services:RHEL-09-291015": None,  # rsh-server: no RHEL 9 rule
            "services:RHEL-09-291020": None,  # ypserv: no RHEL 9 rule
            "services:RHEL-09-291025": "RHEL-09-215060",  # tftp-server
            "services:RHEL-09-291030": "RHEL-09-215015",  # vsftpd
            "services:RHEL-09-291035": "RHEL-09-231040",  # autofs
            "services:RHEL-09-291040": None,  # xinetd
            "services:RHEL-09-291045": None,  # bluetooth: duplicate of network 291035
            "services:RHEL-09-291050": None,  # avahi
            "services:RHEL-09-291055": None,  # net-snmp
            "services:RHEL-09-291060": "RHEL-09-215025",  # nfs-utils
            "services:RHEL-09-291065": None,  # cups
            "services:RHEL-09-291070": None,  # bind
            "services:RHEL-09-291075": None,  # dhcp-server
            "services:RHEL-09-291080": None,  # httpd
            "services:RHEL-09-291085": None,  # samba
            "services:RHEL-09-291090": None,  # squid
            "services:RHEL-09-291095": None,  # rsync-daemon
            "software_integrity:RHEL-09-214010": "RHEL-09-214010",  # gpgcheck=1
            "software_integrity:RHEL-09-251015": "RHEL-09-214025",  # every repo gpgcheck
            "software_integrity:RHEL-09-251020": None,              # unsigned packages installed: no RHEL 9 rule
            "software_integrity:RHEL-09-251025": "RHEL-09-651020",  # aide FIPS hashes
            "software_integrity:RHEL-09-251030": None,              # aide database exists: no RHEL 9 rule
            "software_integrity:RHEL-09-251035": None,              # aide acl|notify mix: no single DISA rule
            "software_integrity:RHEL-09-252010": "RHEL-09-213020",  # kexec_load_disabled
            "software_integrity:RHEL-09-252015": None,              # module signing/modules_disabled: no RHEL 9 rule
            "software_integrity:RHEL-09-252020": "RHEL-09-214020",  # localpkg_gpgcheck
            "software_integrity:RHEL-09-252025": None,              # crypto policy != LEGACY: weaker duplicate of 215105
            "software_integrity:RHEL-09-252030": "RHEL-09-652010",
            "software_integrity:RHEL-09-252035": "RHEL-09-652020",
            "ssh_config:RHEL-09-255010": "RHEL-09-255045",
            "ssh_config:RHEL-09-255015": None,              # Protocol 2: no RHEL 9 rule (255015 is "SSH installed and active")
            "ssh_config:RHEL-09-255020": "RHEL-09-255065",  # sshd Ciphers
            "ssh_config:RHEL-09-255025": "RHEL-09-255075",  # sshd MACs
            "ssh_config:RHEL-09-255030": "RHEL-09-255040",  # PermitEmptyPasswords
            "ssh_config:RHEL-09-255035": "RHEL-09-255080",  # HostbasedAuthentication
            "ssh_config:RHEL-09-255040": None,              # MaxAuthTries: no RHEL 9 rule
            "ssh_config:RHEL-09-255045": "RHEL-09-255100",  # ClientAliveInterval
            "ssh_config:RHEL-09-255050": "RHEL-09-255095",  # ClientAliveCountMax
            "ssh_config:RHEL-09-255055": "RHEL-09-255160",
            "ssh_config:RHEL-09-255060": None,              # Compression: no RHEL 9 rule
            "ssh_config:RHEL-09-255065": "RHEL-09-255145",  # IgnoreRhosts
            "ssh_config:RHEL-09-255070": "RHEL-09-255150",  # IgnoreUserKnownHosts
            "ssh_config:RHEL-09-255075": "RHEL-09-255050",  # UsePAM
            "ssh_config:RHEL-09-255080": "RHEL-09-255165",
            "ssh_config:RHEL-09-255085": "RHEL-09-255155",  # X11Forwarding
        },
    },
    "rhel_8": {
        "prefix": "RHEL-08", "ident": "rhel_08", "name": "RHEL 8", "complete": "stig_rhel8_complete.rego",
        # Reviewed 2026-11-10 against the V2R8 check text.
        "map": {
            "account_auth:RHEL-08-020000": "RHEL-08-020250",  # smart card logon for MFA
            "account_auth:RHEL-08-020010": "RHEL-08-020010",  # deny=3
            "account_auth:RHEL-08-020020": "RHEL-08-010110",  # ENCRYPT_METHOD SHA512
            "account_auth:RHEL-08-020030": "RHEL-08-010121",  # /etc/shadow blank passwords
            "account_auth:RHEL-08-020040": "RHEL-08-020230",
            "account_auth:RHEL-08-020050": "RHEL-08-020200",  # PASS_MAX_DAYS 60
            "account_auth:RHEL-08-020060": None,              # pwhistory remember: no RHEL 8 V2R8 rule
            "account_auth:RHEL-08-020070": "RHEL-08-020012",  # fail_interval 900
            "account_auth:RHEL-08-020080": "RHEL-08-020260",  # INACTIVE 35
            "account_auth:RHEL-08-020090": "RHEL-08-020240",
            "audit_logging:RHEL-08-030000": "RHEL-08-030181",  # auditd active
            "audit_logging:RHEL-08-030010": None,              # max_log_file_action: no RHEL 8 V2R8 rule
            "audit_logging:RHEL-08-030020": "RHEL-08-030000",  # execve (privileged functions)
            "audit_logging:RHEL-08-030030": "RHEL-08-030480",
            "audit_logging:RHEL-08-030040": "RHEL-08-030490",
            "audit_logging:RHEL-08-030050": "RHEL-08-030171",  # -w /etc/sudoers
            "audit_logging:RHEL-08-030060": "RHEL-08-030150",  # -w /etc/passwd
            "audit_logging:RHEL-08-030070": "RHEL-08-030550",  # sudo
            "audit_logging:RHEL-08-030080": "RHEL-08-030121",  # -e 2
            "audit_logging:RHEL-08-030090": "RHEL-08-030731",  # space_left_action
            "configuration_management:RHEL-08-010000": "RHEL-08-010170",  # SELinux enforcing
            "configuration_management:RHEL-08-010010": "RHEL-08-010450",
            "configuration_management:RHEL-08-010020": "RHEL-08-010020",  # fips_mode (title said disk encryption; logic is FIPS)
            "configuration_management:RHEL-08-010030": "RHEL-08-010150",  # grub password (BIOS variant; 010140 UEFI not covered)
            "configuration_management:RHEL-08-010040": "RHEL-08-040170",
            "configuration_management:RHEL-08-010050": "RHEL-08-010090",  # DoD root CA
            "configuration_management:RHEL-08-010060": None,              # crypto policy != LEGACY: no RHEL 8 rule (010020 is FIPS)
            "configuration_management:RHEL-08-010070": "RHEL-08-010040",  # /etc/issue
            "configuration_management:RHEL-08-010080": "RHEL-08-010430",
            "configuration_management:RHEL-08-010090": "RHEL-08-010375",
            "configuration_management:RHEL-08-010100": "RHEL-08-040080",
            "configuration_management:RHEL-08-010110": "RHEL-08-010359",  # aide installed
            "configuration_management:RHEL-08-010120": "RHEL-08-010360",  # aide cron notify
            "configuration_management:RHEL-08-010130": "RHEL-08-010543",
            "configuration_management:RHEL-08-010140": "RHEL-08-010541",
            "configuration_management:RHEL-08-010150": "RHEL-08-010542",
            "file_permissions:RHEL-08-010200": None,              # "no world-writable files": no RHEL 8 rule
            "file_permissions:RHEL-08-010210": "RHEL-08-010780",  # valid owner
            "file_permissions:RHEL-08-010220": None,              # /etc/passwd mode: no RHEL 8 rule
            "file_permissions:RHEL-08-010230": None,              # /etc/shadow mode: no RHEL 8 rule
            "file_permissions:RHEL-08-010240": None,              # /etc/group mode: no RHEL 8 rule
            "file_permissions:RHEL-08-010250": None,              # undocumented SUID/SGID: no RHEL 8 rule
            "file_permissions:RHEL-08-010260": "RHEL-08-010330",
            "file_permissions:RHEL-08-010270": "RHEL-08-010730",
            "network:RHEL-08-040100": "RHEL-08-040101",  # firewalld active
            "network:RHEL-08-040110": "RHEL-08-040259",
            "network:RHEL-08-040120": "RHEL-08-040279",  # all.accept_redirects (040209 default.* not covered)
            "network:RHEL-08-040130": "RHEL-08-040220",  # all.send_redirects (040270 default.* not covered)
            "network:RHEL-08-040140": "RHEL-08-040239",
            "network:RHEL-08-040150": None,              # tcp_syncookies: no RHEL 8 rule
            "network:RHEL-08-040155": "RHEL-08-040111",
            "network:RHEL-08-040157": "RHEL-08-040110",
            "network:RHEL-08-040158": "RHEL-08-040285",
            "services:RHEL-08-040000": "RHEL-08-040000",
            "services:RHEL-08-040010": None,  # rsh-server
            "services:RHEL-08-040020": None,  # ypserv
            "services:RHEL-08-040030": "RHEL-08-040190",  # tftp-server
            "services:RHEL-08-040040": "RHEL-08-040070",  # autofs
            "services:RHEL-08-040050": None,  # xinetd
            "services:RHEL-08-040060": None,  # bluetooth: duplicate of network 040111
            "services:RHEL-08-040070": None,  # net-snmp
            "services:RHEL-08-040080": None,  # nfs-utils
            "services:RHEL-08-040090": None,  # avahi
            "ssh_config:RHEL-08-040160": "RHEL-08-010550",
            "ssh_config:RHEL-08-040170": "RHEL-08-010291",  # sshd Ciphers
            "ssh_config:RHEL-08-040180": "RHEL-08-020330",  # PermitEmptyPasswords
            "ssh_config:RHEL-08-040190": None,              # MaxAuthTries
            "ssh_config:RHEL-08-040200": "RHEL-08-010201",  # ClientAliveInterval
            "ssh_config:RHEL-08-040210": "RHEL-08-010290",  # sshd MACs
            "ssh_config:RHEL-08-040220": None,              # IgnoreRhosts: no RHEL 8 V2R8 rule
            "ssh_config:RHEL-08-040230": None,              # HostbasedAuthentication: no RHEL 8 V2R8 rule
            "ssh_config:RHEL-08-040240": None,              # UsePAM: no RHEL 8 V2R8 rule
            "ssh_config:RHEL-08-040250": "RHEL-08-010060",  # sshd Banner
        },
    },
}

AGG_MARK = "# =============================================================================\n# COMPLIANCE AGGREGATION"
BANNER = re.compile(r"(?:^# =+\n)?^# CAT I{1,3}(?: - [A-Z ]+SEVERITY)?\n(?:^# =+\n)?\n?", re.M)


def norm(t):
    t = re.sub(r"\b(rhel|red hat enterprise linux)\s*[0-9]*\b", "<os>", t.lower())
    t = t.replace("dod", "dow").replace("syscalls", "system calls").replace("syscall", "system call")
    return re.sub(r"[\s.]+$", "", re.sub(r"\s+", " ", t)).strip()


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def chunks(text):
    out = []
    for para in re.split(r"\n\s*\n", text):
        code = "\n".join(l for l in para.strip().splitlines() if not l.lstrip().startswith("#"))
        m = re.match(r"(?:default )?([a-z_][a-z0-9_]*)", code)
        if m and code:
            out.append((m.group(1), para.strip()))
    return out


def stamp(key, cfg, check_only):
    cat = json.load(open(os.path.join(CATS, f"{key}.json")))
    by_id = {r["stig_id"]: r for r in cat["rules"]}
    by_title = {}
    for r in cat["rules"]:
        by_title.setdefault(norm(r["title"]), r)
    pfx, ident = cfg["prefix"], cfg["ident"]
    block_re = re.compile(r"^# (" + pfx + r"-\d+) \| (V-\d+) \| (CAT I{1,3})( - [^\n]*)?\n", re.M)
    d = os.path.join(REPO, key)
    sections = sorted(f[:-5] for f in os.listdir(d) if f.endswith(".rego") and not f.startswith("stig_"))
    used, renames, retired, problems, kept_total = {}, {}, [], [], 0
    for sec in sections:
        path = os.path.join(d, f"{sec}.rego")
        text = open(path).read()
        heads = list(block_re.finditer(text))
        agg_at = text.find(AGG_MARK)
        header, tail = text[:heads[0].start()], text[agg_at:]
        blocks = []
        for i, h in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else agg_at
            blocks.append((h.group(1), h.group(2), h.group(3), h.group(4) or "", BANNER.sub("", text[h.start():end]).rstrip() + "\n"))
        kept, sec_renames = [], {}
        for sid, vid, sev, desc, body in blocks:
            k = f"{sec}:{sid}"
            m = re.search(r'"rule_title": "((?:[^"\\\n]|\\.)*)"', body)
            lib_title = m.group(1) if m else ""
            if k in cfg["map"]:
                tgt_id = cfg["map"][k]
                if tgt_id is None:
                    retired.append((sec, sid, lib_title))
                    continue
                tgt, how = by_id.get(tgt_id), "map"
                if tgt is None:
                    problems.append(f"{k}: mapped to {tgt_id}, which is not in the {cat['version']} catalog")
                    continue
            else:
                tgt, how = by_title.get(norm(lib_title)), "title"
                if tgt is None:
                    cands = difflib.get_close_matches(norm(lib_title), list(by_title), n=3, cutoff=0.5)
                    problems.append(f"{k}: no exact title match and no MAP entry -- {lib_title!r}; closest: "
                                    + "; ".join(f"{by_title[c]['stig_id']} {by_title[c]['title'][:70]}" for c in cands))
                    continue
            if tgt["stig_id"] in used:
                problems.append(f"{k}: target {tgt['stig_id']} already taken by {used[tgt['stig_id']]}")
                continue
            used[tgt["stig_id"]] = k
            tid, tvid, tsev = tgt["stig_id"], tgt["vuln_id"], SEV[tgt["severity"]]
            # the identifier is taken from the finding's own name: a few blocks carry a header id that
            # differs from the status_/finding_ suffix (RHEL 9 software_integrity 214010 vs 251010)
            fm = re.search(r"finding_([a-z0-9_]+) := \{", body)
            old_i, new_i = fm.group(1), tid.lower().replace("-", "_")
            b = body.replace(sid, tid).replace(vid, tvid).replace(old_i, new_i)
            b = re.sub(r"^# " + re.escape(tid) + r" \| " + re.escape(tvid) + r" \| CAT I{1,3}", f"# {tid} | {tvid} | {tsev}", b, count=1, flags=re.M)
            b = re.sub(r'"severity": "CAT I{1,3}"', f'"severity": "{tsev}"', b)
            b = re.sub(r'"rule_title": "(?:[^"\\\n]|\\.)*"', f'"rule_title": "{esc(tgt["title"])}"', b)
            kept.append((tid, tsev, new_i, b))
            sec_renames[sid] = (tid, vid, tvid, old_i, new_i)
            renames[k] = (tid, how, lib_title, tgt["title"], tsev)
        # a kept block may call a helper that a retired block defined
        defined = {n for _, _, _, b in kept for n, _ in chunks(b)} | {n for n, _ in chunks(header)}
        pool = {}
        for _, _, _, _, body in blocks:
            for n, para in chunks(body):
                pool.setdefault(n, []).append(para)
        helpers, changed = [], True
        while changed:
            changed = False
            refd = set()
            for src in [b for _, _, _, b in kept] + helpers:
                refd |= set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", re.sub(r'"[^"\n]*"', "", src)))
            for n in sorted(refd - defined):
                if n in pool:
                    helpers.extend(pool[n]); defined.add(n); changed = True
        kept_total += len(kept)
        # header: version line and the id-verification note
        header = re.sub(r"^# STIG Version: .*$", f"# STIG Version: {cat['version']} | Released: {cat['release_date']}", header, flags=re.M)
        note = (f"# Rule ids, vuln ids, severities and titles stamped from the {LIBRARY} XCCDF on {VERIFIED}\n"
                f"# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.\n")
        header = re.sub(r"(?m)^# Rule ids, vuln ids, severities and titles stamped from[^\n]*\n(?:# \(tools/stig_generators/stamp_catalog\.py\)[^\n]*\n)?", "", header)
        header = re.sub(r"(?m)^(# STIG Version: [^\n]*\n)", r"\1" + note.replace("\\", "\\\\"), header, count=1)
        out = [header.rstrip("\n"), ""]
        if helpers:
            out += ["# =============================================================================",
                    "# SHARED HELPERS (defined in a block whose rule the current STIG no longer carries)",
                    "# =============================================================================", "", "\n\n".join(helpers), ""]
        by_sev = {"CAT I": [], "CAT II": [], "CAT III": []}
        for tid, tsev, new_i, b in kept:
            by_sev[tsev].append(f"finding_{new_i}")
        for sev_name, label in (("CAT I", "CAT I - HIGH SEVERITY"), ("CAT II", "CAT II - MEDIUM SEVERITY"), ("CAT III", "CAT III - LOW SEVERITY")):
            group = [b for _, s, _, b in kept if s == sev_name]
            if not group:
                continue
            out += ["# =============================================================================", f"# {label}",
                    "# =============================================================================", ""]
            out += group
        # aggregation: regenerate the three lists and the findings concat, keep the rest of the tail
        rest = tail[tail.find("violations contains"):]
        lists = []
        for k2, var in (("CAT I", "cat_i_findings"), ("CAT II", "cat_ii_findings"), ("CAT III", "cat_iii_findings")):
            names = by_sev[k2]
            if names:
                lists.append(f"{var} := [\n" + "".join(f"\t{n},\n" for n in names) + "]\n")
            else:
                lists.append(f"# No {k2} rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal\n"
                             f"# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).\n{var} := array.concat([], [])\n")
        out += [AGG_MARK, "# =============================================================================", ""]
        out += lists
        out += ["findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))", "", rest.rstrip("\n"), ""]
        new_text = "\n".join(out)
        if not check_only:
            open(path, "w").write(new_text)
        # tests of this section: rename ids / identifiers / vuln ids, report retired references
        tdir = os.path.join(d, "tests")
        for tf in sorted(os.listdir(tdir)):
            if not tf.endswith(".rego") or (f"_{sec}_" not in f"_{tf[:-5]}_" and f"test_{sec}" not in tf):
                continue
            tt = open(os.path.join(tdir, tf)).read()
            if f"stig.{key}.{sec}" not in tt and f".{sec}." not in tt:
                continue
            sub = {}
            for old, (new, ovid, nvid, oi, ni) in sec_renames.items():
                sub[old] = new
                sub[oi] = ni
                if ovid != nvid:
                    sub[ovid] = nvid
            if sub:
                tt2 = re.sub("|".join(re.escape(s) for s in sorted(sub, key=len, reverse=True)), lambda m: sub[m.group(0)], tt)
                if tt2 != tt and not check_only:
                    open(os.path.join(tdir, tf), "w").write(tt2)
                tt = tt2
            for sec2, sid, _ in retired:
                if sec2 == sec and (sid in tt or sid.lower().replace("-", "_") in tt):
                    problems.append(f"tests/{tf} references retired {sid} -- edit by hand")
    # aggregator + alias: version strings and the implemented-of-total note
    comp_path = os.path.join(d, cfg["complete"])
    comp = open(comp_path).read()
    comp = re.sub(r"^# STIG Version: .*$", f"# STIG Version: {cat['version']} | Released: {cat['release_date']}", comp, flags=re.M)
    comp = re.sub(r'"stig_title": ".*"', f'"stig_title": "{esc(cat["benchmark"])}"', comp)
    comp = re.sub(r'"version": "V\d+R\d+"', f'"version": "{cat["version"]}"', comp)
    comp = re.sub(r'"release_date": "\d{4}-\d\d-\d\d"', f'"release_date": "{cat["status_date"]}"', comp)
    comp = re.sub(r"(?m)^# Implemented: .*\n(?:# .*remaining.*\n)?", "", comp)
    note = (f"# Implemented: {kept_total} of {len(cat['rules'])} {cfg['name']} {cat['version']} rules, stamped from the {LIBRARY} XCCDF on {VERIFIED}.\n"
            f"# The remaining {len(cat['rules']) - kept_total} are tracked follow-up, not silent absence.\n")
    comp = comp.replace("\nimport rego.v1\n", "\n" + note + "\nimport rego.v1\n", 1)
    if not check_only:
        open(comp_path, "w").write(comp)
    # report
    print(f"== {key}: {cat['benchmark']} {cat['version']} ({cat['release_date']}), {len(cat['rules'])} rules; "
          f"{kept_total} implemented, {len(retired)} retired, {len(cat['rules']) - kept_total} not covered")
    for k, (tid, how, lt, nt, sev) in sorted(renames.items()):
        sec, sid = k.split(":")
        flag = "" if sid == tid else f" -> {tid}"
        print(f"  {how:5s} {sec:25s} {sid}{flag:18s} {sev:7s} {nt[:90]}")
        if norm(lt) != norm(nt):
            print(f"        was: {lt[:100]}")
    for sec, sid, lt in retired:
        print(f"  RETIRED {sec:23s} {sid}  {lt[:90]}")
    for p in problems:
        print(f"  PROBLEM {p}")
    if problems and not check_only:
        print(f"  {len(problems)} problems: review before committing")
    return not problems


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check_only = "--check" in sys.argv
    ok = True
    for key in (args or list(PLATFORMS)):
        ok &= stamp(key, PLATFORMS[key], check_only)
    sys.exit(0 if ok else 1)
