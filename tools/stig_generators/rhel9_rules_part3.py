"""Reviewed logic table for gen_rhel9.py, part 3 (DISA STIG for RHEL 9, V2R10): RHEL-09-252065 to RHEL-09-411070.

Same spec format as rhel9_rules.py (R, helpers); imported from the last line of rhel9_rules.py, so every name used
here is already defined there. Each entry was written against the full V2R10 check text of its rule.

Conventions specific to this part:
  - ssh_config.<Keyword> is the keyword's value as the check's grep finds it in the files sshd reads (uncommented),
    null when no line sets it: the checks make "missing or commented out" a finding, so a default must not pass;
  - gnome.<key> is the output of `gsettings get`, gnome_writable.<key> the output of `gsettings writable`
    ("true" / "false", or a JSON boolean);
  - input.virtual_machine / input.usb_peripherals carry the USBGuard checks' "virtual machine with no virtual or
    physical USB peripherals attached" clause as observed facts.
"""
from rhel9_rules import (R, RULES, helpers, nest, sysctl_rule, empty_list_rule, DOD_BANNER, SSH_CIPHERS, SSH_MACS)

GUI_NA = dict(na=[["input.gui_installed == false"]], na_expect="no graphical user interface is installed")
IPV6_NA = dict(na=[["input.ipv6_disabled == true"]], na_expect="IPv6 is disabled on the system")

# ── network ─────────────────────────────────────────────────────────────────────────────────────
R("network", "RHEL-09-252065", "libreswan_installed", [("packages", "libreswan")],
  [["input.packages.libreswan == true"]],
  {"packages": {"libreswan": True}}, [{"packages": {"libreswan": False}}],
  "the libreswan package must be installed (no operational need for Libreswan is Not Applicable: "
  "input.attest.rhel_09_252065_no_operational_need)",
  "Install the package: dnf install libreswan",
  comment="libreswan package installed (dnf list --installed libreswan); no operational need is Not Applicable (attested)",
  na=[['_attested("rhel_09_252065_no_operational_need")']],
  na_expect="there is no operational need for Libreswan to be installed",
  na_cases=[{"packages": {"libreswan": False}, "attest": {"rhel_09_252065_no_operational_need": True}}])

for sid, name, key, want in (
        ("RHEL-09-253025", "ipv4_log_martians_all", "net.ipv4.conf.all.log_martians", "1"),
        ("RHEL-09-253030", "ipv4_log_martians_default", "net.ipv4.conf.default.log_martians", "1"),
        ("RHEL-09-253040", "ipv4_default_accept_redirects_disabled", "net.ipv4.conf.default.accept_redirects", "0"),
        ("RHEL-09-253045", "ipv4_default_source_route_disabled", "net.ipv4.conf.default.accept_source_route", "0"),
        ("RHEL-09-253050", "ipv4_default_rp_filter_enabled", "net.ipv4.conf.default.rp_filter", "1"),
        ("RHEL-09-253055", "icmp_echo_ignore_broadcasts", "net.ipv4.icmp_echo_ignore_broadcasts", "1")):
    bad = ["1"] if want == "0" else (["0", "2"] if key.endswith("rp_filter") else ["0"])
    sysctl_rule("network", sid, name, key, want, bad, f"{key} must be {want}",
                f"Set {key} = {want} in /etc/sysctl.d/ and run sysctl --system")

_att = "rhel_09_253070_redirects_documented"
sysctl_rule("network", "RHEL-09-253070", "ipv4_default_send_redirects_disabled", "net.ipv4.conf.default.send_redirects", "0", ["1"],
            "net.ipv4.conf.default.send_redirects must be 0, or the setting must be documented with the ISSO as an "
            f"operational requirement (input.attest.{_att})",
            "Set net.ipv4.conf.default.send_redirects = 0 in /etc/sysctl.d/ and run sysctl --system",
            attest_alts=[[f'_attested("{_att}")']],
            pass_cases=[{"kernel_params": {"net.ipv4.conf.default.send_redirects": 0}},
                        {"kernel_params": {"net.ipv4.conf.default.send_redirects": "1"}, "attest": {_att: True}}])

# IPv6: the finding sentence of each check is unconditional ("not set to 0 or is missing"); the "unless the system
# is a router" wording appears only in the verify sentence, so no router attestation is encoded.
for sid, name, key in (
        ("RHEL-09-254010", "ipv6_all_accept_ra_disabled", "net.ipv6.conf.all.accept_ra"),
        ("RHEL-09-254015", "ipv6_all_accept_redirects_disabled", "net.ipv6.conf.all.accept_redirects"),
        ("RHEL-09-254020", "ipv6_all_source_route_disabled", "net.ipv6.conf.all.accept_source_route"),
        ("RHEL-09-254025", "ipv6_all_forwarding_disabled", "net.ipv6.conf.all.forwarding"),
        ("RHEL-09-254030", "ipv6_default_accept_ra_disabled", "net.ipv6.conf.default.accept_ra"),
        ("RHEL-09-254035", "ipv6_default_accept_redirects_disabled", "net.ipv6.conf.default.accept_redirects"),
        ("RHEL-09-254040", "ipv6_default_source_route_disabled", "net.ipv6.conf.default.accept_source_route")):
    sysctl_rule("network", sid, name, key, "0", ["1", "2"], f"{key} must be 0 (IPv6 disabled on the system is Not Applicable)",
                f"Set {key} = 0 in /etc/sysctl.d/ and run sysctl --system",
                na_cases=[{"kernel_params": {key: None}, "ipv6_disabled": True}], **IPV6_NA)
    RULES[sid]["comment"] = f"runtime {key} (sysctl); IPv6 disabled on the system is Not Applicable (input.ipv6_disabled == true)"


# ── ssh_config ──────────────────────────────────────────────────────────────────────────────────
empty_list_rule("ssh_config", "RHEL-09-252070", "no_shosts_equiv_files", ["shosts_equiv_files"], "/etc/ssh/shosts.equiv",
                "no shosts.equiv file may exist on the system", "Remove each listed file: rm <path>/shosts.equiv",
                "files found by find / -name shosts.equiv")
empty_list_rule("ssh_config", "RHEL-09-252075", "no_shosts_files", ["shosts_files"], "/home/disauser/.shosts",
                "no .shosts file may exist on the system", "Remove each listed file: rm <path>/.shosts",
                "files found by find / -name .shosts")

for sid, name, pkg in (("RHEL-09-255010", "openssh_server_installed", "openssh-server"),
                       ("RHEL-09-255020", "openssh_clients_installed", "openssh-clients")):
    R("ssh_config", sid, name, [("packages", pkg)], [[f'input.packages["{pkg}"] == true']],
      {"packages": {pkg: True}}, [{"packages": {pkg: False}}],
      f"the {pkg} package must be installed", f"Install the package: dnf install {pkg}",
      comment=f"{pkg} package installed (dnf list --installed {pkg})")

R("ssh_config", "RHEL-09-255015", "sshd_active", [("services", "sshd")],
  [['_kw(["services", "sshd"]) == "active"']],
  {"services": {"sshd": "active"}}, [{"services": {"sshd": "inactive"}}, {"services": {"sshd": "failed"}}],
  "sshd must be active (systemctl is-active sshd)", "Enable and start sshd: systemctl enable --now sshd",
  comment="systemctl is-active sshd")


def sshd_kw(sid, name, key, want, bad, **kw):
    """an sshd keyword the check greps from the files sshd reads: set (uncommented) to `want`"""
    R("ssh_config", sid, name, [("ssh_config", key)], [[f'_kw(["ssh_config", "{key}"]) == "{want}"']],
      {"ssh_config": {key: want}}, [{"ssh_config": {key: b}} for b in bad],
      kw.pop("expect", f"sshd {key} must be set to {want} (a missing or commented-out line is a finding)"),
      f"Set {key} {want} in /etc/ssh/sshd_config (or a file in /etc/ssh/sshd_config.d) and restart sshd",
      comment=f"sshd {key} as set (uncommented) in sshd_config / sshd_config.d, the check's grep; null when no line sets it",
      pass_cases=kw.pop("pass_cases", []) + [{"ssh_config": {key: want.upper()}}], **kw)


sshd_kw("RHEL-09-255030", "ssh_loglevel_verbose", "LogLevel", "verbose", ["INFO", "DEBUG"])
sshd_kw("RHEL-09-255035", "ssh_pubkey_authentication", "PubkeyAuthentication", "yes", ["no"],
        na=[['_attested("rhel_09_255035_alternate_mfa")']],
        na_expect="the SA demonstrated an approved alternate multifactor authentication method",
        na_cases=[{"ssh_config": {"PubkeyAuthentication": None}, "attest": {"rhel_09_255035_alternate_mfa": True}}])
sshd_kw("RHEL-09-255085", "ssh_no_user_environment", "PermitUserEnvironment", "no", ["yes", "LANG,LC_*"])
sshd_kw("RHEL-09-255175", "ssh_x11_use_localhost", "X11UseLocalhost", "yes", ["no"])
for sid, name, key, att, what in (
        ("RHEL-09-255135", "ssh_no_gssapi_auth", "GSSAPIAuthentication", "rhel_09_255135_gssapi_documented", "GSSAPI"),
        ("RHEL-09-255140", "ssh_no_kerberos_auth", "KerberosAuthentication", "rhel_09_255140_kerberos_documented", "Kerberos")):
    sshd_kw(sid, name, key, "no", ["yes"],
            expect=f"sshd {key} must be set to no (missing or commented out is a finding), unless the use of {what} "
                   f"authentication is documented with the ISSO (input.attest.{att})",
            attest_alts=[[f'_attested("{att}")']],
            pass_cases=[{"ssh_config": {key: "yes"}, "attest": {att: True}}])

R("ssh_config", "RHEL-09-255090", "ssh_rekey_limit_set", [("ssh_config", "RekeyLimit")],
  [['s := _kw(["ssh_config", "RekeyLimit"])', r"regex.match(`^[0-9]+[kmg]?\s+([0-9]+[smhdw]?)+$`, s)"]],
  {"ssh_config": {"RekeyLimit": "1G 1h"}},
  [{"ssh_config": {"RekeyLimit": "1G"}}, {"ssh_config": {"RekeyLimit": "default none"}},
   {"ssh_config": {"RekeyLimit": "1G none"}}, {"ssh_config": {"RekeyLimit": "default 1h"}}],
  "sshd RekeyLimit must define both a maximum data amount and a maximum time (e.g. RekeyLimit 1G 1h); "
  "'default' and 'none' define neither",
  "Set RekeyLimit 1G 1h in /etc/ssh/sshd_config (or a file in /etc/ssh/sshd_config.d) and restart sshd",
  comment="sshd RekeyLimit as set (uncommented) in sshd_config / sshd_config.d: <data amount> <time>; null when no line sets it",
  pass_cases=[{"ssh_config": {"RekeyLimit": "512M 30m"}}, {"ssh_config": {"RekeyLimit": "1073741824 3600"}},
              {"ssh_config": {"RekeyLimit": "1g 1h30m"}}])

for sid, key, allowed, setname, extra in (("RHEL-09-255064", "Ciphers", SSH_CIPHERS, "fips_ssh_ciphers", "aes192-ctr"),
                                          ("RHEL-09-255070", "MACs", SSH_MACS, "fips_ssh_macs", "hmac-sha1")):
    R("ssh_config", sid, "ssh_client_fips_ciphers" if key == "Ciphers" else "ssh_client_fips_macs",
      [("openssh_config", key)],
      [[f'vals := _csv(["openssh_config", "{key}"])', "count(vals) > 0",
        f"every v in vals {{\n\tv in {setname}\n}}"]],
      {"openssh_config": {key: allowed}},
      [{"openssh_config": {key: allowed + "," + extra}}, {"openssh_config": {key: ""}}],
      f"{key} in /etc/crypto-policies/back-ends/openssh.config must list only {allowed}",
      "Apply the FIPS crypto policy (dnf -y reinstall crypto-policies; update-crypto-policies --set FIPS) so openssh.config carries the DISA list",
      comment=f"{key} line of /etc/crypto-policies/back-ends/openssh.config (the SSH client back-end; null when missing or commented out)",
      pass_cases=[{"openssh_config": {key: allowed.split(",")[1]}}])


# ── file_permissions (SSH server files) ─────────────────────────────────────────────────────────
SSHD_PATHS = [{"path": "/etc/ssh/sshd_config", "owner": "root", "group": "root"},
              {"path": "/etc/ssh/sshd_config.d", "owner": "root", "group": "root"},
              {"path": "/etc/ssh/sshd_config.d/50-redhat.conf", "owner": "root", "group": "root"}]
for sid, name, field, cmd in (("RHEL-09-255105", "sshd_config_group_root", "group", "%G"),
                              ("RHEL-09-255110", "sshd_config_owner_root", "owner", "%U")):
    R("file_permissions", sid, name, [("file_permissions", "sshd_config_paths")],
      [["fs := input.file_permissions.sshd_config_paths", "is_array(fs)",
        f'every f in fs {{\n\tf.{field} == "root"\n}}']],
      {"file_permissions": {"sshd_config_paths": SSHD_PATHS}},
      [{"file_permissions": {"sshd_config_paths": SSHD_PATHS[:2] + [dict(SSHD_PATHS[2], **{field: "admin"})]}},
       {"file_permissions": {"sshd_config_paths": [{"path": "/etc/ssh/sshd_config"}]}}],
      f"/etc/ssh/sshd_config, /etc/ssh/sshd_config.d and every file in it must have {field} root",
      ("chgrp" if field == "group" else "chown") + " -R root /etc/ssh/sshd_config /etc/ssh/sshd_config.d",
      comment=f"find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c \"{cmd} %n\": "
              "input.file_permissions.sshd_config_paths [{path, owner, group}]")

helpers("file_permissions", r'''
# a line of `rpm --verify <package>` the SSH-permissions check does not print: a config file ($2 == "c") whose
# verify flags leave mode, device, link, user, group and capabilities unchanged ($1 ~ /^.\..\.\.\.\..\./)
_rpm_verify_line_ok(l) if {
	is_string(l)
	f := regex.split(`\s+`, trim_space(l))
	count(f) >= 2
	f[1] == "c"
	regex.match(`^.\..\.\.\.\..\.`, f[0])
}''')

R("file_permissions", "RHEL-09-255115", "sshd_files_permissions_unmodified", [("rpm_verify", "openssh-server")],
  [['ls := input.rpm_verify["openssh-server"]', "is_array(ls)",
    'count([l | some l in ls; not _rpm_verify_line_ok(l)]) == 0']],
  {"rpm_verify": {"openssh-server": ["S.5....T.  c /etc/ssh/sshd_config"]}},
  [{"rpm_verify": {"openssh-server": [".M.......  c /etc/ssh/sshd_config"]}},
   {"rpm_verify": {"openssh-server": ["S.5....T.  c /etc/ssh/sshd_config", "......G..  c /etc/ssh/sshd_config.d/50-redhat.conf"]}},
   {"rpm_verify": {"openssh-server": [".....U...    /usr/sbin/sshd"]}},
   {"rpm_verify": {"openssh-server": ["missing   c /etc/ssh/sshd_config"]}},
   {"rpm_verify": {"openssh-server": ["package openssh-server is not installed"]}}],
  "rpm --verify openssh-server must report nothing but configuration files (c) whose mode, user, group, device, link "
  "and capabilities are unchanged",
  "Restore the packaged ownership and permissions: rpm --setugids openssh-server && rpm --setperms openssh-server",
  comment="the output lines of rpm --verify openssh-server (input.rpm_verify[\"openssh-server\"]); the policy applies the check's awk filter",
  pass_cases=[{"rpm_verify": {"openssh-server": []}}])

for sid, name, key, mx, bad, glob in (
        ("RHEL-09-255120", "ssh_private_host_keys_mode_ok", "ssh_private_host_keys", "0600", "640", "/etc/ssh/*_key"),
        ("RHEL-09-255125", "ssh_public_host_keys_mode_ok", "ssh_public_host_keys", "0644", "664", "/etc/ssh/*.pub")):
    f = "/etc/ssh/ssh_host_ed25519_key" + (".pub" if key.endswith("public_host_keys") else "")
    R("file_permissions", sid, name, [("file_permissions", key)],
      [[f"ks := input.file_permissions.{key}", "is_array(ks)", f'every k in ks {{\n\tmode_within(k.mode, "{mx}")\n}}']],
      {"file_permissions": {key: [{"path": f, "mode": mx[1:]}]}},
      [{"file_permissions": {key: [{"path": f, "mode": bad}]}}, {"file_permissions": {key: [{"path": f}]}}],
      f"every {glob} file must have mode {mx} or less permissive", f"chmod {mx} {glob} and restart sshd",
      comment=f"stat -c \"%a %n\" {glob}: input.file_permissions.{key} [{{path, mode}}]",
      pass_cases=[{"file_permissions": {key: [{"path": f, "mode": "400"}]}}, {"file_permissions": {key: []}}])


# ── GNOME (configuration_management; the smart card lock in pki_crypto next to RHEL-09-271045) ──
GS_HELPERS = r'''
# a gsettings boolean (`gsettings get` / `gsettings writable`): "true" / "false" as printed, or a JSON boolean
_gs_bool(path) := lower(s) if s := _str(path)

_gs_bool(path) := "true" if object.get(input, path, null) == true

_gs_bool(path) := "false" if object.get(input, path, null) == false'''
helpers("configuration_management", GS_HELPERS)
helpers("pki_crypto", GS_HELPERS)
helpers("configuration_management", r'''
# a gsettings unsigned value as printed ("uint32 600"), a bare decimal string, or a number; undefined otherwise
_gs_uint(path) := n if {
	v := object.get(input, path, null)
	is_number(v)
	n := v
}

_gs_uint(path) := n if {
	v := object.get(input, path, null)
	is_string(v)
	m := regex.find_all_string_submatch_n(`^\s*(?:uint32\s+)?([0-9]+)\s*$`, v, 1)
	n := to_number(m[0][1])
}

# the gsettings string at path as GNOME shows it: outer quotes dropped, the literal \n sequences (formatting only)
# and every whitespace run turned into one space
_gs_text(path) := t if {
	s := _str(path)
	t := _squash(replace(trim(trim_space(s), "'\""), "\\n", " "))
}''')


def gs_rule(sid, name, path, want, expect, fix, schema_key, sec="configuration_management", att=None, cmd="get"):
    """a gsettings boolean: `gsettings <cmd> <schema> <key>` must print `want`; no GUI installed is Not Applicable"""
    other = "false" if want == "true" else "true"
    extra = {}
    if att:
        extra = dict(attest_alts=[[f'_attested("{att}")']], pass_cases=[nest(path, want == "true"), dict(nest(path, other), attest={att: True})])
    else:
        extra = dict(pass_cases=[nest(path, want == "true"), nest(path, want.capitalize())])
    p = '["' + '", "'.join(path) + '"]'
    R(sec, sid, name, [tuple(path)], [[f'_gs_bool({p}) == "{want}"']],
      nest(path, want), [nest(path, other), nest(path, want != "true")], expect, fix,
      comment=f"gsettings {cmd} {schema_key}; no GUI installed is Not Applicable",
      na_cases=[dict(nest(path, None), gui_installed=False)], **GUI_NA, **extra)


LOCKS = "/etc/dconf/db/local.d/locks/"
gs_rule("RHEL-09-271010", "gui_banner_enabled", ["gnome", "banner_message_enable"], "true",
        "gsettings get org.gnome.login-screen banner-message-enable must return true",
        "Set banner-message-enable=true under [org/gnome/login-screen] in /etc/dconf/db/local.d/01-banner-message and run dconf update",
        "org.gnome.login-screen banner-message-enable")
gs_rule("RHEL-09-271020", "gui_automount_disabled", ["gnome", "automount_open"], "false",
        "gsettings get org.gnome.desktop.media-handling automount-open must return false, unless documented with the ISSO "
        "as an operational requirement (input.attest.rhel_09_271020_automount_documented)",
        "Set automount-open=false under [org/gnome/desktop/media-handling] in /etc/dconf/db/local.d/00-security-settings and run dconf update",
        "org.gnome.desktop.media-handling automount-open", att="rhel_09_271020_automount_documented")
gs_rule("RHEL-09-271030", "gui_autorun_disabled", ["gnome", "autorun_never"], "true",
        "gsettings get org.gnome.desktop.media-handling autorun-never must return true, unless documented with the ISSO "
        "as an operational requirement (input.attest.rhel_09_271030_autorun_documented)",
        "Set autorun-never=true under [org/gnome/desktop/media-handling] in /etc/dconf/db/local.d/00-security-settings and run dconf update",
        "org.gnome.desktop.media-handling autorun-never", att="rhel_09_271030_autorun_documented")
gs_rule("RHEL-09-271055", "gui_screensaver_lock_enabled", ["gnome", "screensaver_lock_enabled"], "true",
        "gsettings get org.gnome.desktop.screensaver lock-enabled must return true",
        "Set lock-enabled=true under [org/gnome/desktop/screensaver] in /etc/dconf/db/local.d/00-screensaver and run dconf update",
        "org.gnome.desktop.screensaver lock-enabled")
gs_rule("RHEL-09-271095", "gui_restart_buttons_disabled", ["gnome", "disable_restart_buttons"], "true",
        "gsettings get org.gnome.login-screen disable-restart-buttons must return true",
        "Set disable-restart-buttons='true' under [org/gnome/login-screen] in /etc/dconf/db/local.d/ and run dconf update",
        "org.gnome.login-screen disable-restart-buttons")
gs_rule("RHEL-09-271115", "gui_user_list_disabled", ["gnome", "disable_user_list"], "true",
        "gsettings get org.gnome.login-screen disable-user-list must return true",
        "Set disable-user-list=true under [org/gnome/login-screen] in /etc/dconf/db/local.d/02-login-screen and run dconf update",
        "org.gnome.login-screen disable-user-list")

for sid, name, key, schema_key, lock, sec, att in (
        ("RHEL-09-271015", "gui_banner_enable_locked", "banner_message_enable", "org.gnome.login-screen banner-message-enable",
         "/org/gnome/login-screen/banner-message-enable", "configuration_management", None),
        ("RHEL-09-271035", "gui_autorun_locked", "autorun_never", "org.gnome.desktop.media-handling autorun-never",
         "/org/gnome/desktop/media-handling/autorun-never", "configuration_management", "rhel_09_271035_autorun_writable_documented"),
        ("RHEL-09-271050", "smartcard_removal_action_locked", "smartcard_removal_action",
         "org.gnome.settings-daemon.peripherals.smartcard removal-action",
         "/org/gnome/settings-daemon/peripherals/smartcard/removal-action", "pki_crypto", None),
        ("RHEL-09-271060", "gui_screensaver_lock_enabled_locked", "screensaver_lock_enabled", "org.gnome.desktop.screensaver lock-enabled",
         "/org/gnome/desktop/screensaver/lock-enabled", "configuration_management", None),
        ("RHEL-09-271070", "gui_idle_delay_locked", "session_idle_delay", "org.gnome.desktop.session idle-delay",
         "/org/gnome/desktop/session/idle-delay", "configuration_management", None),
        ("RHEL-09-271080", "gui_lock_delay_locked", "screensaver_lock_delay", "org.gnome.desktop.screensaver lock-delay",
         "/org/gnome/desktop/screensaver/lock-delay", "configuration_management", None),
        ("RHEL-09-271085", "gui_screensaver_picture_locked", "screensaver_picture_uri", "org.gnome.desktop.screensaver picture-uri",
         "/org/gnome/desktop/screensaver/picture-uri", "configuration_management", None),
        ("RHEL-09-271100", "gui_restart_buttons_locked", "disable_restart_buttons", "org.gnome.login-screen disable-restart-buttons",
         "/org/gnome/login-screen/disable-restart-buttons", "configuration_management", None),
        ("RHEL-09-271110", "ctrl_alt_del_graphical_locked", "media_keys_logout", "org.gnome.settings-daemon.plugins.media-keys logout",
         "/org/gnome/settings-daemon/plugins/media-keys/logout", "configuration_management", None)):
    gs_rule(sid, name, ["gnome_writable", key], "false",
            f"gsettings writable {schema_key} must return false (the key is locked)"
            + (f", unless documented with the ISSO as an operational requirement (input.attest.{att})" if att else ""),
            f"Add {lock} to a file in {LOCKS} and run dconf update", schema_key, sec=sec, att=att, cmd="writable")

_GUI_BANNER = "'" + DOD_BANNER.replace(". By using", ".\\nBy using").replace(" -", "\\n-") + " '"
R("configuration_management", "RHEL-09-271011", "gui_banner_text_set", [("gnome", "banner_message_text")],
  [['_gs_text(["gnome", "banner_message_text"]) == dod_banner']],
  {"gnome": {"banner_message_text": _GUI_BANNER}},
  [{"gnome": {"banner_message_text": "'Authorized users only. All activity may be monitored.'"}},
   {"gnome": {"banner_message_text": _GUI_BANNER.replace("USG-authorized use only", "authorized use only")}},
   {"gnome": {"banner_message_text": "''"}}],
  "gsettings get org.gnome.login-screen banner-message-text must return exactly the Standard Mandatory DoW Notice and "
  "Consent Banner (the \\n formatting sequences and whitespace aside)",
  "Set banner-message-text to the Standard Mandatory DoW Notice and Consent Banner under [org/gnome/login-screen] in "
  "/etc/dconf/db/local.d/01-banner-message and run dconf update",
  comment="gsettings get org.gnome.login-screen banner-message-text, compared with the banner text of the check; no GUI installed is Not Applicable",
  pass_cases=[{"gnome": {"banner_message_text": DOD_BANNER}}],
  na_cases=[{"gnome": {"banner_message_text": None}, "gui_installed": False}], **GUI_NA)

_AUTOMOUNT_LOCK = "/org/gnome/desktop/media-handling/automount-open"
R("configuration_management", "RHEL-09-271025", "gui_automount_locked", [("dconf_locks", "automount_open")],
  [["ls := input.dconf_locks.automount_open", "is_array(ls)", "some l in ls", "is_string(l)",
    r"regex.match(`(^|:)/org/gnome/desktop/media-handling/automount-open\s*$`, l)"]],
  {"dconf_locks": {"automount_open": [_AUTOMOUNT_LOCK]}},
  [{"dconf_locks": {"automount_open": []}}, {"dconf_locks": {"automount_open": ["#" + _AUTOMOUNT_LOCK]}},
   {"dconf_locks": {"automount_open": ["/org/gnome/desktop/media-handling/automount-open-other"]}}],
  f"a lock file of the system dconf database (/etc/dconf/db/<system-db>.d/locks/*) must carry {_AUTOMOUNT_LOCK}",
  f"Add {_AUTOMOUNT_LOCK} to {LOCKS}00-security-settings-lock and run dconf update",
  comment="lines returned by grep 'automount-open' /etc/dconf/db/<db>.d/locks/* for the system-db named in "
          "/etc/dconf/profile/user (input.dconf_locks.automount_open); no GUI installed is Not Applicable",
  pass_cases=[{"dconf_locks": {"automount_open": [LOCKS + "00-security-settings-lock:" + _AUTOMOUNT_LOCK]}}],
  na_cases=[{"dconf_locks": {"automount_open": None}, "gui_installed": False}], **GUI_NA)

R("configuration_management", "RHEL-09-271040", "gui_automatic_login_disabled", [("gdm_custom_conf", "AutomaticLoginEnable")],
  [['_kw(["gdm_custom_conf", "AutomaticLoginEnable"]) == "false"']],
  {"gdm_custom_conf": {"AutomaticLoginEnable": "false"}},
  [{"gdm_custom_conf": {"AutomaticLoginEnable": "true"}}, {"gdm_custom_conf": {"AutomaticLoginEnable": ""}}],
  "AutomaticLoginEnable in /etc/gdm/custom.conf must be set to false",
  "Set AutomaticLoginEnable=false in the [daemon] section of /etc/gdm/custom.conf",
  comment="AutomaticLoginEnable as set (uncommented) in /etc/gdm/custom.conf, null when not set; no GUI installed is Not Applicable",
  pass_cases=[{"gdm_custom_conf": {"AutomaticLoginEnable": "False"}}],
  na_cases=[{"gdm_custom_conf": {"AutomaticLoginEnable": None}, "gui_installed": False}], **GUI_NA)

for sid, name, key, schema_key, lo, hi, green, bads, expect, fix in (
        ("RHEL-09-271065", "gui_idle_delay_ok", "session_idle_delay", "org.gnome.desktop.session idle-delay", 1, 600, "uint32 600",
         ["uint32 0", "uint32 601", "uint32 900", "never"],
         "gsettings get org.gnome.desktop.session idle-delay must return 600 or less and not 0",
         "Set idle-delay=uint32 600 under [org/gnome/desktop/session] in /etc/dconf/db/local.d/00-screensaver and run dconf update"),
        ("RHEL-09-271075", "gui_lock_delay_ok", "screensaver_lock_delay", "org.gnome.desktop.screensaver lock-delay", 0, 5, "uint32 5",
         ["uint32 6", "uint32 300", "five"],
         "gsettings get org.gnome.desktop.screensaver lock-delay must return 5 or less",
         "Set lock-delay=uint32 5 under [org/gnome/desktop/screensaver] in /etc/dconf/db/local.d/00-screensaver and run dconf update")):
    R("configuration_management", sid, name, [("gnome", key)],
      [[f'n := _gs_uint(["gnome", "{key}"])', f"n >= {lo}", f"n <= {hi}"]],
      {"gnome": {key: green}}, [{"gnome": {key: b}} for b in bads], expect, fix,
      comment=f"gsettings get {schema_key} (\"uint32 <n>\"); no GUI installed is Not Applicable",
      pass_cases=[{"gnome": {key: "uint32 " + str(max(lo, 1))}}, {"gnome": {key: hi}}, {"gnome": {key: str(hi)}}]
      + ([{"gnome": {key: "uint32 0"}}] if lo == 0 else []),
      na_cases=[{"gnome": {key: None}, "gui_installed": False}], **GUI_NA)

R("configuration_management", "RHEL-09-271090", "dconf_databases_current", [("dconf_outdated_databases",)],
  [["xs := input.dconf_outdated_databases", "is_array(xs)", "count(xs) == 0"]],
  {"dconf_outdated_databases": []}, [{"dconf_outdated_databases": ["/etc/dconf/db/local needs update"]}],
  "no dconf database under /etc/dconf/db may be older than its keyfiles (<db>.d/*)",
  "Update the dconf databases: dconf update",
  comment="output lines of the check's dconf_needs_update function (a database whose mtime is below its newest keyfile's); "
          "no GUI installed is Not Applicable",
  na_cases=[{"dconf_outdated_databases": None, "gui_installed": False}], **GUI_NA)


# ── USBGuard ────────────────────────────────────────────────────────────────────────────────────
# "If the system is virtual machine with no virtual or physical USB peripherals attached": observed facts, read
# without the rule's own evidence (a virtual machine usually has no USBGuard to report on)
VM_NO_USB = ["input.virtual_machine == true", "ps := input.usb_peripherals", "is_array(ps)", "count(ps) == 0"]
VM_CASE = {"virtual_machine": True, "usb_peripherals": []}
VM_TEXT = "a virtual machine with no virtual or physical USB peripherals attached (input.virtual_machine, input.usb_peripherals)"

for sid, name, ev, cond, green, bad, what, fix, comment in (
        ("RHEL-09-291015", "usbguard_installed", ("packages", "usbguard"), "input.packages.usbguard == true",
         {"packages": {"usbguard": True}}, {"packages": {"usbguard": False}}, "the usbguard package must be installed",
         "Install and start USBGuard: dnf install usbguard && systemctl enable --now usbguard", "usbguard package installed (dnf list installed usbguard)"),
        ("RHEL-09-291020", "usbguard_active", ("services", "usbguard"), '_kw(["services", "usbguard"]) == "active"',
         {"services": {"usbguard": "active"}}, {"services": {"usbguard": "inactive"}}, "usbguard must be active (systemctl is-active usbguard)",
         "Enable and start USBGuard: systemctl enable --now usbguard", "systemctl is-active usbguard")):
    att = sid.lower().replace("-", "_") + "_peripherals_blocked"
    R("configuration_management", sid, name, [ev], [[cond]], green, [bad, dict(bad, virtual_machine=True, usb_peripherals=["Bus 001 Device 002: ID 0627:0001 QEMU USB Tablet"])],
      f"{what}, or the SA must show how unauthorized peripherals are blocked before a connection is established "
      f"(input.attest.{att}); not a finding on {VM_TEXT}",
      fix, comment=comment + "; SA evidence of another blocking method is an attestation",
      attest_alts=[[f'_attested("{att}")'], VM_NO_USB],
      pass_cases=[dict(bad, attest={att: True}), dict(bad, **VM_CASE)])

R("audit_logging", "RHEL-09-291025", "usbguard_audit_backend", [("usbguard_daemon_conf", "AuditBackend")],
  [['_str(["usbguard_daemon_conf", "AuditBackend"]) == "LinuxAudit"']],
  {"usbguard_daemon_conf": {"AuditBackend": "LinuxAudit"}},
  [{"usbguard_daemon_conf": {"AuditBackend": "FileAudit"}},
   {"usbguard_daemon_conf": {"AuditBackend": "FileAudit"}, "virtual_machine": True, "usb_peripherals": ["Bus 001 Device 002: ID 0627:0001 QEMU USB Tablet"]}],
  f"AuditBackend in /etc/usbguard/usbguard-daemon.conf must be LinuxAudit; not a finding on {VM_TEXT}",
  "Set AuditBackend=LinuxAudit in /etc/usbguard/usbguard-daemon.conf",
  comment="AuditBackend as set (uncommented) in /etc/usbguard/usbguard-daemon.conf, null when not set",
  attest_alts=[VM_NO_USB], pass_cases=[{"usbguard_daemon_conf": {"AuditBackend": "FileAudit"}, **VM_CASE}])
# the evidence-independent alternative above is an observed fact, not an attestation
RULES["RHEL-09-291025"]["kind"] = "machine"

R("configuration_management", "RHEL-09-291030", "usbguard_policy_configured", [("usbguard_rules",)],
  [["rs := input.usbguard_rules", "is_array(rs)", "count(rs) > 0"]],
  {"usbguard_rules": ["1: allow id 1d6b:0001 serial \"0000:00:01.2\""]}, [{"usbguard_rules": []}],
  "usbguard list-rules must return at least one rule, or the SA must show how unauthorized peripherals are blocked before "
  "a connection is established (input.attest.rhel_09_291030_peripherals_blocked)",
  "Create a USBGuard policy: usbguard generate-policy --no-hash > /etc/usbguard/rules.conf, then enable and start usbguard",
  comment="output lines of usbguard list-rules (null when the command returns an error); a virtual machine with no USB peripherals is Not Applicable",
  attest_alts=[['_attested("rhel_09_291030_peripherals_blocked")']],
  na=[VM_NO_USB], na_expect="the system is a virtual machine with no virtual or physical USB peripherals attached",
  pass_cases=[{"usbguard_rules": [], "attest": {"rhel_09_291030_peripherals_blocked": True}}],
  na_cases=[dict({"usbguard_rules": None}, **VM_CASE)])


# ── account_auth ────────────────────────────────────────────────────────────────────────────────
R("account_auth", "RHEL-09-411015", "existing_passwords_maxage_ok", [("shadow_maxdays_out_of_range",)],
  [["accts := input.shadow_maxdays_out_of_range", "is_array(accts)",
    "count([a | some a in accts; not a.system_account == true]) == 0"]],
  {"shadow_maxdays_out_of_range": []},
  [{"shadow_maxdays_out_of_range": [{"name": "alice", "max_days": "99999", "system_account": False}]},
   {"shadow_maxdays_out_of_range": [{"name": "bob", "max_days": ""}]}],
  "no /etc/shadow entry other than a system account may have a maximum password age (field 5) above 180, empty, or 0 or less",
  "Set a 180-day maximum for each listed account: passwd -x 180 <user>",
  comment="accounts printed by awk -F: '$5 > 180' and awk -F: '$5 <= 0' on /etc/shadow, each {name, max_days, system_account}",
  pass_cases=[{"shadow_maxdays_out_of_range": [{"name": "bin", "max_days": "99999", "system_account": True}]}])

R("account_auth", "RHEL-09-411020", "create_home_enabled", [("login_defs", "CREATE_HOME")],
  [['_kw(["login_defs", "CREATE_HOME"]) == "yes"']],
  {"login_defs": {"CREATE_HOME": "yes"}}, [{"login_defs": {"CREATE_HOME": "no"}}],
  "CREATE_HOME in /etc/login.defs must be yes", "Set CREATE_HOME yes in /etc/login.defs",
  comment="CREATE_HOME as configured in /etc/login.defs (null when missing or commented out)")

helpers("account_auth", r'''
# a umask value that is 077 or more restrictive: every group and other permission bit masked (077, 0077, 177 ...);
# a symbolic or unparsable value is not accepted
_umask_077(v) if {
	is_string(v)
	regex.match(`^0*[0-7]?77$`, trim_space(v))
}

# a temporary account's expiration date (chage -l -i "Account expires": YYYY-MM-DD) is set and no more than
# 72 hours ahead
_expires_within_72h(a) if {
	is_string(a.expires)
	d := trim_space(a.expires)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, d)
	t := time.parse_ns("2006-01-02", d)
	t <= time.now_ns() + 259200000000000
}

# an entry of a PATH statement that stays inside the user's home directory, or keeps the existing search path
_path_entry_ok(e, _) if e in {"$PATH", "${PATH}"}

_path_entry_ok(e, _) if regex.match(`^(\$HOME|\$\{HOME\}|~)(/.*)?$`, e)

_path_entry_ok(e, home) if {
	is_string(home)
	home != ""
	e == home
}

_path_entry_ok(e, home) if {
	is_string(home)
	home != ""
	startswith(e, concat("", [trim_right(home, "/"), "/"]))
}''')

R("account_auth", "RHEL-09-411025", "user_init_files_umask_ok", [("user_init_files", "umask_statements")],
  [["us := input.user_init_files.umask_statements", "is_array(us)", "every u in us {\n\t_umask_077(u.umask)\n}"]],
  {"user_init_files": {"umask_statements": [{"file": "/home/disauser/.bashrc", "umask": "077"}]}},
  [{"user_init_files": {"umask_statements": [{"file": "/home/disauser/.bashrc", "umask": "022"}]}},
   {"user_init_files": {"umask_statements": [{"file": "/home/disauser/.bashrc", "umask": "027"}]}},
   {"user_init_files": {"umask_statements": [{"file": "/home/disauser/.profile", "umask": "u=rwx,g=rx,o="}]}},
   {"user_init_files": {"umask_statements": [{"file": "/home/disauser/.bashrc"}]}}],
  "no local interactive user initialization file may set a umask less restrictive than 077",
  "Remove the umask statement from each listed initialization file",
  comment="uncommented umask statements in the interactive users' initialization files (find <home> -maxdepth 2 -type f "
          "-name '.[^.]*' ... grep -i umask, .bash_history excluded): [{file, umask}]",
  pass_cases=[{"user_init_files": {"umask_statements": []}},
              {"user_init_files": {"umask_statements": [{"file": "/home/disauser/.bashrc", "umask": "0177"}]}}])

empty_list_rule("account_auth", "RHEL-09-411035", "system_accounts_no_interactive_shell", ["system_accounts_with_interactive_shell"],
                "games:12:/bin/bash", "no system account (UID 1 to 999, other than halt, sync and shutdown) may have a login shell "
                "other than nologin or false",
                "Disable the shell of each listed account: usermod --shell /usr/sbin/nologin <user>",
                "output of awk -F: '(($3 > 0 && $3 < 1000) && $1 !~ /^(halt|sync|shutdown)$/ && $7 !~ /(nologin|false)$/) "
                "{print $1 \":\" $3 \":\" $7}' /etc/passwd")

R("account_auth", "RHEL-09-411040", "temporary_accounts_expire", [("temporary_accounts",)],
  [["accts := input.temporary_accounts", "is_array(accts)", "every a in accts {\n\t_expires_within_72h(a)\n}"]],
  {"temporary_accounts": [{"name": "tempuser", "expires": "2020-01-04"}]},
  [{"temporary_accounts": [{"name": "tempuser", "expires": "never"}]},
   {"temporary_accounts": [{"name": "tempuser", "expires": "2099-12-31"}]},
   {"temporary_accounts": [{"name": "tempuser"}]}],
  "every temporary account must have an account expiration date set, no more than 72 hours ahead (chage -l)",
  "Set the expiration: chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>",
  comment="the organization's temporary accounts with their expiration date (chage -l -i <name>, \"Account expires\": "
          "YYYY-MM-DD or never): [{name, expires}]; an empty list when there are none",
  pass_cases=[{"temporary_accounts": []}])

R("account_auth", "RHEL-09-411045", "interactive_users_primary_group_exists", [("pwck_no_group_accounts",)],
  [["accts := input.pwck_no_group_accounts", "is_array(accts)",
    "count([a | some a in accts; not a.interactive == false]) == 0"]],
  {"pwck_no_group_accounts": []},
  [{"pwck_no_group_accounts": [{"name": "alice", "gid": 1500, "interactive": True}]},
   {"pwck_no_group_accounts": [{"name": "alice", "gid": 1500}]}],
  "pwck -r must not report 'no group' for any interactive user",
  "Give each listed user a primary GID that is defined in /etc/group",
  comment="accounts pwck -r reports with \"no group <gid>\", each {name, gid, interactive}",
  pass_cases=[{"pwck_no_group_accounts": [{"name": "svc", "gid": 990, "interactive": False}]}])

_att = "rhel_09_411055_path_documented"
_PATHS = [{"file": "/home/disauser/.bash_profile", "home": "/home/disauser", "entries": ["$HOME/.local/bin", "$HOME/bin", "$PATH"]}]
R("account_auth", "RHEL-09-411055", "user_init_files_path_ok", [("user_init_files", "path_statements")],
  [["ps := input.user_init_files.path_statements", "is_array(ps)",
    'every p in ps {\n\tis_array(p.entries)\n\tevery e in p.entries {\n\t\t_path_entry_ok(e, object.get(p, "home", null))\n\t}\n}']],
  {"user_init_files": {"path_statements": _PATHS}},
  [{"user_init_files": {"path_statements": [dict(_PATHS[0], entries=["$HOME/bin", "/opt/app/bin", "$PATH"])]}},
   {"user_init_files": {"path_statements": [dict(_PATHS[0], entries=["/home/disauser2/bin", "$PATH"])]}},
   {"user_init_files": {"path_statements": [dict(_PATHS[0], entries=[".", "$PATH"])]}},
   {"user_init_files": {"path_statements": [{"file": "/home/disauser/.bashrc", "home": "/home/disauser"}]}}],
  "PATH statements in local interactive user initialization files may only add directories inside the user's home directory, "
  f"unless documented with the ISSO as an operational requirement (input.attest.{_att})",
  "Edit the listed initialization files so PATH statements reference only directories inside the user's home directory",
  comment="uncommented PATH= statements in the interactive users' initialization files (find <home> -maxdepth 2 -type f -name "
          "'.[^.]*' ... grep -iH path=): [{file, home, entries}], entries = the statement's value split on ':'",
  attest_alts=[[f'_attested("{_att}")']],
  pass_cases=[{"user_init_files": {"path_statements": []}},
              {"user_init_files": {"path_statements": [dict(_PATHS[0], entries=["/home/disauser/bin", "~/tools", "${HOME}", "${PATH}"])]}},
              {"user_init_files": {"path_statements": [dict(_PATHS[0], entries=["/opt/app/bin"])]}, "attest": {_att: True}}])

# input.interactive_users: the local interactive users (awk -F: '($3>=1000)&&($7 !~ /nologin/)' /etc/passwd), each
# {name, uid, primary_gid, shell, home, home_exists, home_gid}; home_exists / home_gid from stat of the home directory
_USER = {"name": "disauser", "uid": 1000, "primary_gid": 1002, "shell": "/bin/bash", "home": "/home/disauser",
         "home_exists": True, "home_gid": 1002}
_USERS = {"interactive_users": [_USER]}


def _users(**kw):
    return {"interactive_users": [dict(_USER, **kw)]}


R("account_auth", "RHEL-09-411060", "interactive_users_home_assigned", [("interactive_users",)],
  [["us := input.interactive_users", "is_array(us)",
    'every u in us {\n\tis_string(u.home)\n\ttrim_space(u.home) != ""\n}']],
  _USERS, [_users(home=""), _users(home=None)],
  "every local interactive user (UID >= 1000, shell not nologin) must have a home directory defined in /etc/passwd",
  "Assign a home directory to each listed user: usermod -d /home/<user> <user>",
  comment="home (field 6 of /etc/passwd) of each entry of input.interactive_users",
  pass_cases=[{"interactive_users": []}])

R("account_auth", "RHEL-09-411065", "interactive_users_home_exists", [("interactive_users",)],
  [["us := input.interactive_users", "is_array(us)", "every u in us {\n\tu.home_exists == true\n}"]],
  _USERS, [_users(home_exists=False), _users(home_exists=None)],
  "the home directory assigned to every local interactive user must exist (pwck -r reports none missing)",
  "Create the home directory of each listed user: mkdir <home>; chown <user> <home>; chgrp <group> <home>; chmod 0750 <home>",
  comment="home_exists of each entry of input.interactive_users (the directory pwck -r reports as \"does not exist\")",
  pass_cases=[{"interactive_users": []}])

helpers("file_permissions", r'''
# a numeric id (uid / gid) given as a number or a decimal string; undefined otherwise
_id_num(v) := v if is_number(v)

_id_num(v) := to_number(trim_space(v)) if {
	is_string(v)
	regex.match(`^\s*[0-9]+\s*$`, v)
}

# a login shell the home-directory group check leaves out: awk's $7 !~ /(nologin|false)$/
_no_login_shell(u) if {
	is_string(u.shell)
	regex.match(`(nologin|false)$`, u.shell)
}''')

R("file_permissions", "RHEL-09-411070", "home_dirs_group_owned_by_primary_group", [("interactive_users",)],
  [["us := input.interactive_users", "is_array(us)",
    "every u in us {\n\t_home_group_ok(u)\n}"]],
  _USERS, [_users(home_gid=100), _users(home_gid=None), _users(home_gid="users")],
  "the home directory of every local interactive user (UID >= 1000, shell not nologin or false) must be group-owned by "
  "the user's primary GID",
  "Set the group of each listed home directory: chgrp <primary group> <home>",
  comment="primary_gid (getent passwd field 4) against home_gid (stat -c %g <home>) for each entry of input.interactive_users",
  pass_cases=[{"interactive_users": []}, _users(home_gid="1002"), _users(shell="/bin/false", home_gid=100),
              _users(primary_gid="1002")])
helpers("file_permissions", r'''
_home_group_ok(u) if _no_login_shell(u)

_home_group_ok(u) if {
	not _no_login_shell(u)
	_id_num(u.home_gid) == _id_num(u.primary_gid)
}''')
