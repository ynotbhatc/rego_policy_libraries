#!/usr/bin/env python3
"""CIS Apple iOS 27 Benchmark v1.0.0 -> benchmarks/cis/mobile_devices/ios/ (replaces the hand-written module in place).

    /usr/bin/python3 tools/cis_generators/gen_ios_27.py <workbook.xlsx> <repo root>
    opa fmt -w benchmarks/cis/mobile_devices/ios

Needs openpyxl. Reads id, Automated/Manual status and the four profiles (Level 1/2 x end-user / institutionally
owned) from the CIS workbook (CIS-licensed, never committed). Each logic entry below carries a keyword that must
occur in the workbook title of its id; the run aborts on any count, id, status, profile or keyword mismatch.
Messages use our own wording (OWN), never the workbook title. Writes only the files it owns.

Facts are configuration-profile keys (payload key names) under input.ios_profile; on-device-only settings and
judgement items are attestation booleans under input.ios_profile.attest.
"""
import json
import os
import re
import sys

import openpyxl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import emit_control, rego_str, u  # noqa: E402

BENCH = "CIS Apple iOS 27 Benchmark v1.0.0"
PKG = "cis.mobile.ios"
FILE = "cis_mobile_ios"
ROOT = "input.ios_profile"
OWNERS = {"End-User": "end_user", "Institutionally": "institutional"}
EXPECT_IDS, EXPECT_PAIRS = 105, 122
EXPECT_PROFILE = {("end_user", 1): (26, 19), ("end_user", 2): (2, 6), ("institutional", 1): (36, 20), ("institutional", 2): (7, 6)}


def key(rid):
    return [int(p) for p in rid.split(".")]


def read_workbook(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    pairs, comb = {}, set()
    for sheet in wb.sheetnames:
        if sheet == "Overview":
            continue
        rows = list(wb[sheet].iter_rows(values_only=True))
        h = list(rows[0])
        for r in rows[1:]:
            d = dict(zip(h, r))
            rid = d.get("Recommendation #")
            if not rid:
                continue
            rid = str(rid).strip()
            title = " ".join(str(d["Title"]).split())
            if sheet == "Combined Profiles":
                m = re.match(r"Level (\d) - (End-User|Institutionally)", d["Profile"])
                comb.add((rid, OWNERS[m.group(2)], int(m.group(1))))
                continue
            m = re.match(r"Level (\d) - (End-User|Institutionally)", sheet)
            pairs[(rid, OWNERS[m.group(2)], int(m.group(1)))] = (title, d["Assessment Status"])
    if comb != set(pairs):
        raise SystemExit(f"Combined Profiles disagrees with the profile sheets: {sorted(comb ^ set(pairs))}")
    return pairs


def R(k):
    return f"{ROOT}.restrictions.{k}"


def PC(k):
    return f"{ROOT}.passcode.{k}"


def ptr(*parts):
    return "/ios_profile/" + "/".join(parts)


def rep(path, v):
    return [{"op": "replace", "path": path, "value": v}]


def rm(path):
    return [{"op": "remove", "path": path}]


def flag(group, k, want):
    """a boolean payload key that must equal want"""
    p = ROOT + "." + group + "." + k
    return {"kind": "fact", "ev": [f"is_boolean({p})"], "label": f"ios_profile.{group}.{k}", "ok": [[f"{p} == {str(want).lower()}"]],
            "fail": rep(ptr(group, k), not want), "miss": rm(ptr(group, k)),
            "g": [(group, k, want)]}


def rflag(k, want):
    return flag("restrictions", k, want)


def pnum(k, ok, bad, good):
    p = PC(k)
    return {"kind": "fact", "ev": [f"is_number({p})"], "label": f"ios_profile.passcode.{k}", "ok": [ok], "fail": rep(ptr("passcode", k), bad),
            "miss": rm(ptr("passcode", k)), "g": [("passcode", k, good)]}


def att(name):
    return {"kind": "attest", "attest": name, "attest_root": ROOT}


def mail(k, want):
    a = f"{ROOT}.mail_accounts"
    return {"kind": "fact", "ev": [f"is_array({a})"], "label": "ios_profile.mail_accounts",
            "ok": [[f'every acct in {a} {{ object.get(acct, "{k}", null) == {str(want).lower()} }}']],
            "fail": [{"op": "add", "path": ptr("mail_accounts", "0", k), "value": not want}], "miss": rm(ptr("mail_accounts")), "g": []}


# Apple's restrictions payload: safariAcceptCookies 0 = block all, 1 = current website only, 1.5 = websites
# visited, 2 = the unrestricted default. The recommendation accepts the two middle settings only.
def cookies():
    p = R("safariAcceptCookies")
    return {"kind": "fact", "ev": [f"is_number({p})"], "label": "ios_profile.restrictions.safariAcceptCookies", "ok": [[f"{p} in {{1, 1.5}}"]],
            "fail": rep(ptr("restrictions", "safariAcceptCookies"), 2), "miss": rm(ptr("restrictions", "safariAcceptCookies")),
            "g": [("restrictions", "safariAcceptCookies", 1)]}


def removal(want):
    p = f"{ROOT}.profile.removal"
    bad = "never" if want == "always" else "always"
    return {"kind": "fact", "ev": [f"is_string({p})"], "label": "ios_profile.profile.removal", "ok": [[f'lower({p}) == "{want}"']],
            "fail": rep(ptr("profile", "removal"), bad), "miss": rm(ptr("profile", "removal")), "g": []}


def consent():
    p = f"{ROOT}.profile.consent_message"
    return {"kind": "fact", "ev": [f"is_string({p})"], "label": "ios_profile.profile.consent_message", "ok": [[f'trim_space({p}) != ""']],
            "fail": rep(ptr("profile", "consent_message"), "  "), "miss": rm(ptr("profile", "consent_message")), "g": [("profile", "consent_message", "Authorised use only")]}


# setting -> (keyword in the workbook title, own wording, logic entry)
S = {
    "consent": ("consent message", "the profile must carry a consent message", consent()),
    "rm_always": ("always", "end-user profile removal must stay allowed", removal("always")),
    "rm_never": ("never", "the profile must not be removable by the user", removal("never")),
    "siri": ("siri", "Siri must be blocked on the lock screen", rflag("allowAssistantWhileLocked", False)),
    "mgd_cloud": ("managed apps to store", "managed apps must not sync data to iCloud", rflag("allowManagedAppsCloudSync", False)),
    "enc_backup": ("encrypted backups", "backups must be forced to encrypt", rflag("forceEncryptedBackup", True)),
    "ads": ("personalized ads", "Apple personalized advertising must be blocked", rflag("allowApplePersonalizedAdvertising", False)),
    "tls": ("untrusted tls", "the user must not be able to accept untrusted TLS certificates", rflag("allowUntrustedTLSPrompt", False)),
    "auto_time": ("automatic date", "automatic date and time must be forced", rflag("forceAutomaticDateAndTime", True)),
    "mgd_to_unmgd": ("managed sources in unmanaged", "documents must not open from managed into unmanaged destinations", rflag("allowOpenFromManagedToUnmanaged", False)),
    "unmgd_to_mgd": ("unmanaged sources in managed", "documents must not open from unmanaged into managed destinations", rflag("allowOpenFromUnmanagedToManaged", False)),
    "airdrop": ("airdrop", "AirDrop must be treated as an unmanaged destination", rflag("forceAirDropUnmanaged", True)),
    "handoff": ("handoff", "Handoff must be blocked", rflag("allowActivityContinuation", False)),
    "diag": ("diagnostic", "diagnostic and usage data must not be sent to Apple", rflag("allowDiagnosticSubmission", False)),
    "wrist": ("wrist detection", "Apple Watch wrist detection must be forced", rflag("forceWatchWristDetection", True)),
    "lock_cc": ("control center", "Control Center must be hidden on the lock screen", rflag("allowLockScreenControlCenter", False)),
    "lock_nc": ("notification center", "Notification Center must be hidden on the lock screen", rflag("allowLockScreenNotificationsView", False)),
    "fraud": ("fraud warning", "Safari fraud warning must be forced", rflag("safariForceFraudWarning", True)),
    "cookies": ("cookies", "Safari must accept cookies only from visited or the current site", cookies()),
    "simple": ("simple value", "simple passcodes must be blocked", flag("passcode", "allowSimple", False)),
    "alnum": ("alphanumeric", "an alphanumeric passcode must be required", flag("passcode", "requireAlphanumeric", True)),
    "minlen": ("minimum passcode length", "the passcode must be at least 6 characters", pnum("minLength", [f"{PC('minLength')} >= 6"], 4, 6)),
    "autolock": ("auto-lock", "auto-lock must be set and no longer than 2 minutes",
                 pnum("maxInactivity", [f"{PC('maxInactivity')} >= 1", f"{PC('maxInactivity')} <= 2"], 5, 2)),
    "grace": ("grace period", "the device lock grace period must be immediate", pnum("maxGracePeriod", [f"{PC('maxGracePeriod')} == 0"], 5, 0)),
    "attempts": ("failed attempts", "failed passcode attempts must be limited to 6", pnum("maxFailedAttempts", [f"{PC('maxFailedAttempts')} == 6"], 10, 6)),
    "mail_move": ("move messages", "mail messages must not be movable out of the managed account", mail("PreventMove", True)),
    "mail_drop": ("mail drop", "Mail Drop must be blocked", mail("allowMailDrop", False)),
    "ei": ("external intelligence", "external intelligence integrations and their sign-in must be blocked", None),
    "notes_ai": ("notes summarization", "Notes transcription and summaries must be blocked", None),
    "mail_sum": ("mail summarization", "Mail summaries must be blocked", rflag("allowMailSummary", False)),
    "writing": ("writing tools", "Writing Tools must be blocked", rflag("allowWritingTools", False)),
    "safari_sum": ("safari reader", "Safari summaries must be blocked", rflag("allowSafariSummary", False)),
    "smart_reply": ("smart replies", "Mail smart replies must be blocked", rflag("allowMailSmartReplies", False)),
    "screenshot": ("screenshots", "screenshots and screen recording must be blocked", rflag("allowScreenShot", False)),
    "icloud_bk": ("icloud backup", "iCloud backup must be blocked", rflag("allowCloudBackup", False)),
    "icloud_docs": ("documents & data", "iCloud documents and data must be blocked", rflag("allowCloudDocumentSync", False)),
    "icloud_kc": ("icloud keychain", "iCloud Keychain must be blocked", rflag("allowCloudKeychainSync", False)),
    "usb_files": ("usb drive", "USB drive access in Files must be blocked", rflag("allowFilesUSBDriveAccess", False)),
    "net_files": ("network drive", "network drive access in Files must be blocked", rflag("allowFilesNetworkDriveAccess", False)),
    "erase": ("erase all content", "Erase All Content and Settings must be blocked", rflag("allowEraseContentAndSettings", False)),
    "ent_trust": ("enterprise app authors", "trusting new enterprise app authors must be blocked", rflag("allowEnterpriseAppTrust", False)),
    "prof_install": ("installing configuration profiles", "installing configuration profiles must be blocked", rflag("allowUIConfigurationProfileInstallation", False)),
    "vpn_add": ("adding vpn", "adding VPN configurations must be blocked", rflag("allowVPNCreation", False)),
    "cell": ("cellular data app", "changing per-app cellular data settings must be blocked", rflag("allowAppCellularDataModification", False)),
    "usb_locked": ("usb accessories", "USB accessories must be blocked while the device is locked (USB restricted mode kept on)", rflag("allowUSBRestrictedMode", True)),
    "pairing": ("non-configurator", "pairing with hosts other than Configurator must be blocked", rflag("allowHostPairing", False)),
    "autofill": ("autofill", "biometric authentication must be required before AutoFill", rflag("forceAuthenticationBeforeAutoFill", True)),
    "nearby": ("nearby devices", "setting up new nearby devices must be blocked", rflag("allowProximitySetupToNewDevice", False)),
    "prox_pw": ("proximity based", "proximity password sharing requests must be blocked", rflag("allowPasswordProximityRequests", False)),
    "pw_share": ("password sharing", "password sharing must be blocked", rflag("allowPasswordSharing", False)),
}
# two-key settings: both keys must be false
for nm, ks in (("ei", ("allowExternalIntelligenceIntegrations", "allowExternalIntelligenceIntegrationsSignIn")),
               ("notes_ai", ("allowNotesTranscription", "allowNotesTranscriptionSummary"))):
    a, b = (rflag(k, False) for k in ks)
    S[nm] = (S[nm][0], S[nm][1], {"kind": "fact", "ev": a["ev"] + b["ev"], "label": a["label"] + " and " + b["label"],
                                   "ok": [a["ok"][0] + b["ok"][0]], "fail": a["fail"], "miss": a["miss"], "g": a["g"] + b["g"]})

# id -> setting (profile-decided)
IDS = {
    "2.1.1": "consent", "2.1.2": "rm_always", "3.1.1": "rm_never",
    "2.2.1.1": "siri", "2.2.1.2": "mgd_cloud", "2.2.1.3": "enc_backup", "2.2.1.4": "ads", "2.2.1.5": "tls", "2.2.1.6": "auto_time",
    "2.2.1.7": "mgd_to_unmgd", "2.2.1.8": "unmgd_to_mgd", "2.2.1.9": "airdrop", "2.2.1.10": "handoff", "2.2.1.11": "diag",
    "2.2.1.12": "wrist", "2.2.1.13": "lock_cc", "2.2.1.14": "lock_nc", "2.2.2.1": "fraud", "2.2.2.2": "cookies",
    "2.4.1": "simple", "2.4.2": "alnum", "2.4.3": "minlen", "2.4.4": "autolock", "2.4.5": "grace", "2.4.6": "attempts",
    "2.7.1": "mail_move", "2.7.2": "mail_drop",
    "2.9.1": "ei", "2.9.2": "notes_ai", "2.9.3": "mail_sum", "2.9.4": "writing", "2.9.5": "safari_sum", "2.9.6": "smart_reply",
    "3.2.1.1": "screenshot", "3.2.1.2": "siri", "3.2.1.3": "icloud_bk", "3.2.1.4": "icloud_docs", "3.2.1.5": "icloud_kc",
    "3.2.1.6": "mgd_cloud", "3.2.1.7": "usb_files", "3.2.1.8": "net_files", "3.2.1.9": "enc_backup", "3.2.1.10": "ads",
    "3.2.1.11": "erase", "3.2.1.12": "tls", "3.2.1.13": "ent_trust", "3.2.1.14": "prof_install", "3.2.1.15": "vpn_add",
    "3.2.1.16": "auto_time", "3.2.1.17": "cell", "3.2.1.18": "usb_locked", "3.2.1.19": "pairing", "3.2.1.20": "mgd_to_unmgd",
    "3.2.1.21": "unmgd_to_mgd", "3.2.1.22": "airdrop", "3.2.1.23": "handoff", "3.2.1.24": "diag", "3.2.1.25": "autofill",
    "3.2.1.26": "wrist", "3.2.1.27": "nearby", "3.2.1.28": "prox_pw", "3.2.1.29": "pw_share", "3.2.1.30": "lock_cc",
    "3.2.1.31": "lock_nc", "3.2.2.1": "fraud", "3.2.2.2": "cookies",
    "3.4.1": "simple", "3.4.2": "alnum", "3.4.3": "minlen", "3.4.4": "autolock", "3.4.5": "grace", "3.4.6": "attempts",
    "3.7.1": "mail_move", "3.7.2": "mail_drop",
    "3.10.1": "ei", "3.10.2": "notes_ai", "3.10.3": "mail_sum", "3.10.4": "writing", "3.10.5": "safari_sum", "3.10.6": "smart_reply",
}
# id -> (title keyword, own wording, attestation name)
ATT = {
    "2.3.1": ("safari web domains", "managed Safari web domains must be configured for the organisation", "managed_safari_domains"),
    "3.3.1": ("safari web domains", "managed Safari web domains must be configured for the organisation", "managed_safari_domains"),
    "2.5.1": ("mac randomization", "Wi-Fi MAC randomization must be disabled where the network needs it", "mac_randomization_reviewed"),
    "3.5.1": ("mac randomization", "Wi-Fi MAC randomization must be disabled where the network needs it", "mac_randomization_reviewed"),
    "2.6.1": ("vpn", "a VPN (per-app or system-wide) must be configured", "vpn_configured"),
    "3.6.1": ("vpn", "a VPN (per-app or system-wide) must be configured", "vpn_configured"),
    "2.8.1": ("notification settings", "every managed app must have a notification setting", "managed_app_notifications"),
    "3.8.1": ("notification settings", "every managed app must have a notification setting", "managed_app_notifications"),
    "3.9.1": ("if lost", "a return-if-found lock screen message must be configured", "lost_message_configured"),
    "4.1.1": ("sharing", "Manage Sharing and Access must be reviewed on the device", "sharing_access_reviewed"),
    "4.1.2": ("emergency reset", "Emergency Reset must be reviewed on the device", "emergency_reset_reviewed"),
    "4.1.3": ("lockdown", "Lockdown Mode must be reviewed for the user", "lockdown_mode_reviewed"),
    "4.1.4": ("app privacy report", "App Privacy Report must be turned on", "app_privacy_report_enabled"),
    "4.1.5": ("airprint", "AirPrint use must be reviewed on the device", "airprint_reviewed"),
    "4.1.6": ("stolen device", "Stolen Device Protection must be turned on", "stolen_device_protection_enabled"),
    "4.2": ("jailbroken", "the device must show no sign of jailbreak or compromise", "not_jailbroken"),
    "4.3": ("automatic updates", "automatic iOS update installation must be turned on", "auto_update_install_enabled"),
    "4.4": ("software update", "the device must be on the current iOS release", "software_up_to_date"),
    "4.5": ("private relay", "iCloud Private Relay must be reviewed on the device", "private_relay_reviewed"),
    "4.6": ("mail privacy", "Mail Privacy Protection must be reviewed on the device", "mail_privacy_reviewed"),
    "4.7": ("automatic downloads", "automatic app update downloads must be turned on", "auto_app_updates_enabled"),
    "4.8": ("find my", "Find My iPhone, Find My network and Send Last Location must be turned on", "find_my_enabled"),
    "4.9": ("architecture", "high-value targets must use the latest device hardware generation", "latest_hardware_for_high_value"),
    "4.10": ("iphone mirroring", "iPhone Mirroring must be reviewed on the device", "iphone_mirroring_reviewed"),
    "4.11": ("rcs", "RCS messaging must be turned on where available", "rcs_messaging_enabled"),
}
# end-user vs institutional green values of the one key that differs

PROFNAME = {"end_user": "End-User Owned Devices", "institutional": "Institutionally-Owned Devices"}


def build(pairs):
    """validate the workbook against the tables; return ordered ids, per-id facts and the control list"""
    ids = sorted({k[0] for k in pairs}, key=key)
    if len(ids) != EXPECT_IDS or len(pairs) != EXPECT_PAIRS:
        raise SystemExit(f"workbook has {len(ids)} ids / {len(pairs)} id-profile rows, expected {EXPECT_IDS} / {EXPECT_PAIRS}")
    logic = set(IDS) | set(ATT)
    if set(IDS) & set(ATT) or logic != set(ids):
        raise SystemExit(f"logic tables out of step with the workbook: missing {sorted(set(ids) - logic)} extra {sorted(logic - set(ids))}")
    for prof, (a, m) in EXPECT_PROFILE.items():
        rows = [v[1] for k, v in pairs.items() if (k[1], k[2]) == prof]
        if (rows.count("Automated"), rows.count("Manual")) != (a, m):
            raise SystemExit(f"profile {prof}: {rows.count('Automated')} Automated / {rows.count('Manual')} Manual, expected {a} / {m}")
    info = {}
    for rid in ids:
        rows = {k: v for k, v in pairs.items() if k[0] == rid}
        if len({v[0] for v in rows.values()}) != 1 or len({v[1] for v in rows.values()}) != 1:
            raise SystemExit(f"{rid}: title or status differs between profile rows")
        owners = [k[1] for k in rows]
        if len(owners) != len(set(owners)):
            raise SystemExit(f"{rid}: two levels for one ownership")
        title, status = next(iter(rows.values()))
        kw, own, entry = (S[IDS[rid]] if rid in IDS else (ATT[rid][0], ATT[rid][1], att(ATT[rid][2])))
        if kw.lower() not in title.lower():
            raise SystemExit(f"{rid}: keyword {kw!r} not in the workbook title")
        entry = dict(entry, id=rid)
        info[rid] = {"title": own, "assessment": status, "kind": entry["kind"], "entry": entry,
                     "profiles": sorted(({"ownership": k[1], "level": k[2]} for k in rows), key=lambda p: (p["ownership"], p["level"])),
                     "names": [f"Level {k[2]} - {PROFNAME[k[1]]}" for k in sorted(rows)]}
    return ids, info


def green(info, owner):
    g = {"restrictions": {}, "passcode": {}, "profile": {"consent_message": "Authorised use only", "removal": "always" if owner == "end_user" else "never"},
         "mail_accounts": [{"PreventMove": True, "allowMailDrop": False}], "attest": {}}
    for rid, x in info.items():
        e = x["entry"]
        if e["kind"] == "attest":
            g["attest"][e["attest"]] = True
        else:
            for grp, k, v in e.get("g", []):
                g[grp][k] = v
    return {"ios_profile": g, "cis_profile": {"level": 2, "ownership": owner}}


META = """# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_mobile_devices
#   source: cis
#   domains: [mobile, ios]
#   coverage:
#     checks: {checks}
#     cited: {checks}
#     density: {density}
#     basis: {basis}
#     tested: true
#     entrypoint: {entry}
#     guard: self
#     as_of: v2.4.2
"""
GEN = "tools/cis_generators/gen_ios_27.py"


def scope_count(info, owner, level):
    return sum(1 for x in info.values() if any(p["ownership"] == owner and p["level"] <= level for p in x["profiles"]))


def emit(ids, info, out):
    n_att = sum(1 for x in info.values() if x["kind"] == "attest")
    n_auto = sum(1 for x in info.values() if x["assessment"] == "Automated")
    sc = {(o, l): scope_count(info, o, l) for o in PROFNAME for l in (1, 2)}
    wb = {rid: {"title": x["title"], "assessment": x["assessment"], "profiles": x["names"], "level": 0} for rid, x in info.items()}
    L = [META.format(title=BENCH, checks=len(ids), density="sized", basis="size", entry="compliance_report").rstrip("\n"),
         f"package {PKG}", "",
         f"# {BENCH}.",
         f"# Rebuilt from the CIS workbook by {GEN}; it replaces the earlier hand-written module (24 checks, old numbering,",
         "# input.device_config) in place. Messages use our own wording, not CIS text.",
         f"# {len(ids)} recommendations ({n_auto} Automated, {len(ids) - n_auto} Manual) over four profiles: Level 1 / Level 2 for",
         "# end-user owned and institutionally owned devices. input.cis_profile.ownership (end_user | institutional, default",
         "# institutional) and input.cis_profile.level (1 | 2, default 2, includes Level 1) select the recommendations in scope:",
         f"# end_user {sc[('end_user', 1)]} / {sc[('end_user', 2)]}, institutional {sc[('institutional', 1)]} / {sc[('institutional', 2)]} at Level 1 / Level 2.",
         f"# {len(ids) - n_att} are decided from configuration-profile keys and fail closed ('<id>: evidence missing — <path> not collected');",
         f"# {n_att} are attestation booleans under input.ios_profile.attest (false or absent => violation): on-device settings and judgement",
         "# items. 4.8 and 4.11 are Automated in the workbook but are on-device settings with no profile key, so they are attested.",
         "# Manual recommendations that map to one profile key (for example 2.2.1.4, 2.4.2, 3.2.1.1) are checked like Automated ones.",
         "#",
         "# Input contract (input.ios_profile): the EFFECTIVE configuration-profile values, payload key names as in the Apple payloads:",
         "#   restrictions   : com.apple.applicationaccess keys (allowAssistantWhileLocked, forceEncryptedBackup, allowUntrustedTLSPrompt,",
         "#                    allowOpenFromManagedToUnmanaged, forceAirDropUnmanaged, safariForceFraudWarning, safariAcceptCookies, ...) as booleans/numbers",
         "#   passcode       : com.apple.mobiledevice.passwordpolicy keys (allowSimple, requireAlphanumeric, minLength, maxInactivity in minutes,",
         "#                    maxGracePeriod, maxFailedAttempts)",
         "#   profile        : {removal: always | with_authorization | never, consent_message: string}",
         "#   mail_accounts  : list of com.apple.mail.managed payloads {PreventMove, allowMailDrop}; an empty list passes",
         "#   attest         : attestation booleans",
         "# A key that is absent is evidence missing, never a pass (the Apple defaults are not assumed).", "",
         "import rego.v1", "",
         "default _cis_profile := {}", "", "_cis_profile := p if {", "\tp := input.cis_profile", "\tis_object(p)", "}", "",
         "default level := 2", "", "level := 1 if _cis_profile.level == 1", "",
         'default _ownership := "institutional"', "", "_ownership := o if {", "\to := _cis_profile.ownership", '\to in {"end_user", "institutional"}', "}", "",
         "_applies(id) if {", "\tsome p in recommendations[id].profiles", "\tp.ownership == _ownership", "\tp.level <= level", "}", "",
         "default compliant := false", "", "compliant if {", "\tinput.ios_profile", "\tcount(violations) == 0", "}", "",
         "violations := _v_2 | _v_3 | _v_4", ""]
    for sec in ("2", "3", "4"):
        L.append(f"# section {sec}")
        for rid in ids:
            if rid.split(".")[0] == sec:
                L.append(emit_control(info[rid]["entry"], wb, f"_v_{sec}", applies=True))
    rec = {rid: {"title": x["title"], "assessment": x["assessment"], "check": "attestation" if x["kind"] == "attest" else "configuration",
                 "profiles": x["profiles"]} for rid, x in info.items()}
    L += ["# Every recommendation: our title, workbook status, how it is checked, and the (ownership, level) profiles it belongs to.",
          "recommendations := " + json.dumps(rec, indent="\t", ensure_ascii=False), "",
          "in_scope := {id | some id, _ in recommendations; _applies(id)}", "",
          '_failed_ids := {id | some v in violations; id := split(v, ":")[0]; id in in_scope}', "",
          "compliance_report := {", f'\t"benchmark": "{BENCH}",', '\t"profile": {"level": level, "ownership": _ownership},',
          '\t"total_controls": count(in_scope),', f'\t"standard_total": {len(ids)},',
          f'\t"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",',
          '\t"failed_controls": count(_failed_ids),', '\t"passed_controls": count(in_scope) - count(_failed_ids),',
          '\t"compliant": compliant,', '\t"violation_count": count(violations),', '\t"violations": sort([v | some v in violations]),', "}", ""]
    open(f"{out}/{FILE}.rego", "w").write("\n".join(L))

    M = [META.format(title=f"{BENCH} - compliance_report entrypoint", checks=0, density="orchestrator", basis="role", entry="compliance_report").rstrip("\n"),
         f"package {PKG}.main", "", f"# OPA query path: /v1/data/{PKG.replace('.', '/')}/main/compliance_report",
         f"# Thin bridge over data.{PKG} (generated by {GEN}). That package fails closed per recommendation;",
         "# this adds the fields every cis_*.main report carries and an explicit notice on empty input.", "",
         f"import data.{PKG} as bench", "import rego.v1", "",
         "default _facts_supplied := false", "", "_facts_supplied if count(object.keys(input)) > 0", "",
         "_total := count(bench.in_scope)", "",
         '_failed_ids := {id | some v in bench.violations; id := split(v, ":")[0]; id in bench.in_scope}', "",
         "_failed := count(_failed_ids)", "",
         "default _pct := 0", "", "_pct := round(((_total - _failed) * 100) / _total) if _total > 0", "",
         f'_no_facts_msg := "FAIL-CLOSED: no facts supplied for {PKG} — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input."', "",
         "_report_violations := array.concat(sort([v | some v in bench.violations]), [_no_facts_msg]) if not _facts_supplied", "",
         "_report_violations := sort([v | some v in bench.violations]) if _facts_supplied", "",
         "compliant := bench.compliant", "", "violations := bench.violations", "",
         "compliance_report := object.union(bench.compliance_report, {",
         f'\t"framework": "{PKG}",', '\t"version": "v1.0.0",', '\t"facts_supplied": _facts_supplied,',
         f'\t"controls_basis": "recommendations of {BENCH} in the selected profile (input.cis_profile.ownership and level)",',
         '\t"total_controls": _total,', '\t"passed_controls": _total - _failed,', '\t"failed_controls": _failed,', '\t"compliance_percentage": _pct,',
         '\t"violations": _report_violations,', '\t"violation_count": count(_report_violations),', "})", ""]
    open(f"{out}/{FILE}_main.rego", "w").write("\n".join(M))
    return sc


def emit_tests(ids, info, out, sc):
    ATTSUF = "(manual review not attested)"
    greens = {o: green(info, o) for o in PROFNAME}
    T = [f"package {PKG}_test", "", "import rego.v1", "", f"import data.{PKG} as b", f"import data.{PKG}.main as m", "",
         f"# Generated per-recommendation tests for {BENCH} ({GEN}): a pass, a fail and, for configuration checks,",
         "# an evidence-missing case per recommendation; attestations fail when false or absent.", "",
         f"green_end_user := {json.dumps(greens['end_user'], indent=chr(9), ensure_ascii=False)}", "",
         f"green_institutional := {json.dumps(greens['institutional'], indent=chr(9), ensure_ascii=False)}", "",
         "_has_id(vs, id) if {", "\tsome v in vs", '\tstartswith(v, concat("", [id, ":"]))', "}", ""]
    for o in PROFNAME:
        T += [f"test_green_{o}_is_compliant if {{", f"\tvs := b.violations with input as green_{o}", "\tcount(vs) == 0",
              f"\tb.compliant with input as green_{o}", f"\tr := m.compliance_report with input as green_{o}",
              f"\tr.total_controls == {sc[(o, 2)]}", "\tr.failed_controls == 0", "}", ""]
        for l in (1, 2):
            T += [f"test_empty_input_fails_every_{o}_level_{l}_recommendation if {{",
                  f'\tr := m.compliance_report with input as {{"cis_profile": {{"ownership": "{o}", "level": {l}}}}}',
                  f"\tr.total_controls == {sc[(o, l)]}", f"\tr.failed_controls == {sc[(o, l)]}", "\tr.compliant == false", "}", ""]
    T += ["test_empty_object_input_contract if {", "\tr := m.compliance_report with input as {}", "\tr.compliant == false",
          f"\tr.total_controls == {sc[('institutional', 2)]}", "\tr.failed_controls == r.total_controls", "\tr.violation_count > 0", "}", "",
          "test_recommendation_counts_match_workbook if {", f"\tcount(b.recommendations) == {len(ids)}",
          f'\tcount([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {sum(1 for x in info.values() if x["assessment"] == "Automated")}',
          f'\tcount([id | some id, r in b.recommendations; r.check == "attestation"]) == {sum(1 for x in info.values() if x["kind"] == "attest")}', "}", "",
          "test_ownership_scopes_the_ids if {", '\tvs := b.violations with input as {"cis_profile": {"ownership": "end_user", "level": 2}}',
          '\t_has_id(vs, "2.4.3")', '\tnot _has_id(vs, "3.4.3")', "}", "",
          "test_level_1_skips_level_2_ids if {", '\tvs := b.violations with input as {"cis_profile": {"ownership": "institutional", "level": 1}}',
          '\tnot _has_id(vs, "3.2.1.1")', '\t_has_id(vs, "3.2.1.2")', "}", ""]
    for rid in ids:
        x = info[rid]
        e = x["entry"]
        o = x["profiles"][0]["ownership"]
        gname = f"green_{o}"
        i = u(rid)
        t = x["title"]
        T += [f"# {rid}", f"test_{i}_pass if {{", f"\tvs := b.violations with input as {gname}", f'\tnot _has_id(vs, "{rid}")', "}", ""]
        if e["kind"] == "attest":
            msg = f"{rid}: {t} {ATTSUF}"
            ops = rep("/ios_profile/attest/" + e["attest"], False)
            T += [f"test_{i}_fail if {{", f"\tinp := json.patch({gname}, {json.dumps(ops)})", "\tvs := b.violations with input as inp", f"\t{rego_str(msg)} in vs", "}", "",
                  f"test_{i}_not_attested_when_absent if {{", f"\tinp := json.patch({gname}, {json.dumps(rm('/ios_profile/attest/' + e['attest']))})",
                  "\tvs := b.violations with input as inp", f"\t{rego_str(msg)} in vs", "}", ""]
            continue
        msg = f"{rid}: {t}"
        mmsg = f"{rid}: evidence missing — {e['label']} not collected"
        T += [f"test_{i}_fail if {{", f"\tinp := json.patch({gname}, {json.dumps(e['fail'], ensure_ascii=False)})",
              "\tvs := b.violations with input as inp", f"\t{rego_str(msg)} in vs", "}", "",
              f"test_{i}_evidence_missing if {{", f"\tinp := json.patch({gname}, {json.dumps(e['miss'])})",
              "\tvs := b.violations with input as inp", f"\t{rego_str(mmsg)} in vs", f"\tnot {rego_str(msg)} in vs", "}", ""]
    os.makedirs(f"{out}/tests", exist_ok=True)
    open(f"{out}/tests/test_{FILE}_recommendations.rego", "w").write("\n".join(T))


def main(xlsx, root):
    out = os.path.join(root, "benchmarks", "cis", "mobile_devices", "ios")
    ids, info = build(read_workbook(xlsx))
    os.makedirs(out, exist_ok=True)
    sc = emit(ids, info, out)
    emit_tests(ids, info, out, sc)
    print(f"{FILE}: {len(ids)} recommendations; scope {sc}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
