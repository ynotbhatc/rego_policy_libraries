#!/usr/bin/env python3
"""Insert a `# METADATA` annotation block above `package` in policy files that lack one.

One-time backfill used for the 2026-10 rollout; kept so a new framework
directory can be bootstrapped the same way. It never touches a file that
already has a METADATA block, and never touches tests.

class / framework / source / domains are derived from the directory path via
the tables below; the title is taken from the file's first header comment
(falling back to a humanised package name). Review the result: the tables
encode the directory layout, and a new directory needs a row here first.

Usage: python3 scripts/backfill_metadata.py [--dry-run] [--only path ...]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT_DIRS = ["benchmarks", "frameworks", "governance", "enforcement", "threat_detection", "crosswalk"]

# class by top-level tree (frameworks/critical_infrastructure is the OT exception)
CLASS_BY_TREE = {
    "benchmarks": "security",
    "frameworks": "compliance",
    "governance": "governance",
    "enforcement": "enforcement",
    "threat_detection": "threat-detection",
    "crosswalk": "compliance",
}

# (source, domains) keyed by the framework directory, i.e. the path prefix up
# to and including the 3rd segment (2nd for governance/enforcement/threat_detection).
# Longer keys win, so a 4th-level directory can refine its parent.
TABLE: dict[str, tuple[str, list[str]]] = {
    # ---- benchmarks/cis ----
    "benchmarks/cis/aks": ("cis", ["kubernetes", "cloud", "azure"]),
    "benchmarks/cis/amazon_linux_2023": ("cis", ["linux", "amazon-linux"]),
    "benchmarks/cis/apache": ("cis", ["web-server"]),
    "benchmarks/cis/aws": ("cis", ["cloud", "aws"]),
    "benchmarks/cis/azure": ("cis", ["cloud", "azure"]),
    "benchmarks/cis/cloud": ("cis", ["cloud"]),
    "benchmarks/cis/cloud/aws": ("cis", ["cloud", "aws"]),
    "benchmarks/cis/cloud/azure": ("cis", ["cloud", "azure"]),
    "benchmarks/cis/cloud/gcp": ("cis", ["cloud", "gcp"]),
    "benchmarks/cis/containers": ("cis", ["container"]),
    "benchmarks/cis/containers/kubernetes": ("cis", ["container", "kubernetes"]),
    "benchmarks/cis/databases": ("cis", ["database"]),
    "benchmarks/cis/databases/oracle_legacy": ("cis", ["database", "oracle"]),
    "benchmarks/cis/debian_11": ("cis", ["linux", "debian"]),
    "benchmarks/cis/docker": ("cis", ["container"]),
    "benchmarks/cis/eks": ("cis", ["kubernetes", "cloud", "aws"]),
    "benchmarks/cis/gcp": ("cis", ["cloud", "gcp"]),
    "benchmarks/cis/gke": ("cis", ["kubernetes", "cloud", "gcp"]),
    "benchmarks/cis/kubernetes": ("cis", ["kubernetes", "container"]),
    "benchmarks/cis/mcp_server": ("cis", ["ai", "mcp"]),
    "benchmarks/cis/mobile_devices": ("cis", ["mobile"]),
    "benchmarks/cis/mobile_devices/android": ("cis", ["mobile", "android"]),
    "benchmarks/cis/mobile_devices/ios": ("cis", ["mobile", "ios"]),
    "benchmarks/cis/mysql": ("cis", ["database", "mysql"]),
    "benchmarks/cis/network": ("cis", ["network"]),
    "benchmarks/cis/network/cisco": ("cis", ["network", "cisco"]),
    "benchmarks/cis/network_devices": ("cis", ["network"]),
    "benchmarks/cis/network_devices/arista": ("cis", ["network", "arista"]),
    "benchmarks/cis/network_devices/cisco": ("cis", ["network", "cisco"]),
    "benchmarks/cis/network_devices/fortinet": ("cis", ["network", "fortinet"]),
    "benchmarks/cis/network_devices/juniper": ("cis", ["network"]),
    "benchmarks/cis/network_devices/palo_alto": ("cis", ["network", "palo-alto"]),
    "benchmarks/cis/network_devices/pfsense": ("cis", ["network", "pfsense"]),
    "benchmarks/cis/network_devices/vyos": ("cis", ["network"]),
    "benchmarks/cis/nginx": ("cis", ["web-server"]),
    "benchmarks/cis/openshift": ("cis", ["kubernetes", "openshift", "container"]),
    "benchmarks/cis/oracle": ("cis", ["database", "oracle"]),
    "benchmarks/cis/os": ("cis", ["linux"]),
    "benchmarks/cis/os/linux": ("cis", ["linux"]),
    "benchmarks/cis/os/windows": ("cis", ["windows"]),
    "benchmarks/cis/postgresql": ("cis", ["database", "postgresql"]),
    "benchmarks/cis/rhel_10": ("cis", ["linux", "rhel"]),
    "benchmarks/cis/rhel_8": ("cis", ["linux", "rhel"]),
    "benchmarks/cis/rhel_9": ("cis", ["linux", "rhel"]),
    "benchmarks/cis/rocky_linux_8": ("cis", ["linux", "rocky"]),
    "benchmarks/cis/rocky_linux_9": ("cis", ["linux", "rocky"]),
    "benchmarks/cis/saas": ("cis", ["saas"]),
    "benchmarks/cis/saas/m365": ("cis", ["saas", "m365"]),
    "benchmarks/cis/saas/m365_v7": ("cis", ["saas", "m365"]),
    "benchmarks/cis/ubuntu_20_04": ("cis", ["linux", "ubuntu"]),
    "benchmarks/cis/ubuntu_22_04": ("cis", ["linux", "ubuntu"]),
    "benchmarks/cis/ubuntu_24_04": ("cis", ["linux", "ubuntu"]),
    "benchmarks/cis/vmware": ("cis", ["virtualization", "vmware"]),
    "benchmarks/cis/web_servers": ("cis", ["web-server"]),
    "benchmarks/cis/web_servers/mysql": ("cis", ["database", "mysql"]),
    "benchmarks/cis/windows_10": ("cis", ["windows"]),
    "benchmarks/cis/windows_11": ("cis", ["windows"]),
    "benchmarks/cis/windows_server_2016": ("cis", ["windows"]),
    "benchmarks/cis/windows_server_2019_modular": ("cis", ["windows"]),
    "benchmarks/cis/windows_server_2022": ("cis", ["windows"]),
    "benchmarks/cis/windows_server_2022_modular": ("cis", ["windows"]),
    # ---- benchmarks/stig ----
    "benchmarks/stig/amazon_linux_2023": ("disa", ["linux", "amazon-linux"]),
    "benchmarks/stig/apache_2_4_unix": ("disa", ["web-server"]),
    "benchmarks/stig/cisco_ios_xe_router": ("disa", ["network", "cisco"]),
    "benchmarks/stig/kubernetes": ("disa", ["kubernetes", "container"]),
    "benchmarks/stig/ms_sql_2016": ("disa", ["database", "mssql"]),
    "benchmarks/stig/openshift_4": ("disa", ["kubernetes", "openshift", "container"]),
    "benchmarks/stig/postgresql_16": ("disa", ["database", "postgresql"]),
    "benchmarks/stig/rhel_8": ("disa", ["linux", "rhel"]),
    "benchmarks/stig/rhel_9": ("disa", ["linux", "rhel"]),
    "benchmarks/stig/sles_15": ("disa", ["linux", "sles"]),
    "benchmarks/stig/ubuntu_20_04": ("disa", ["linux", "ubuntu"]),
    "benchmarks/stig/ubuntu_22_04": ("disa", ["linux", "ubuntu"]),
    "benchmarks/stig/vmware_vsphere_8": ("disa", ["virtualization", "vmware"]),
    "benchmarks/stig/windows_10": ("disa", ["windows"]),
    "benchmarks/stig/windows_11": ("disa", ["windows"]),
    "benchmarks/stig/windows_server_2016": ("disa", ["windows"]),
    "benchmarks/stig/windows_server_2019": ("disa", ["windows"]),
    "benchmarks/stig/windows_server_2022": ("disa", ["windows"]),
    "benchmarks/stig/windows_server_2025": ("disa", ["windows"]),
    # ---- other benchmarks ----
    "benchmarks/scuba/m365": ("cisa", ["saas", "m365"]),
    "benchmarks/nsa_cisa/kubernetes": ("cisa", ["kubernetes", "container"]),
    "benchmarks/pss/kubernetes": ("kubernetes", ["kubernetes", "container"]),
    "benchmarks/supply_chain/_substrate": ("aac", ["supply-chain"]),
    "benchmarks/supply_chain/baseline": ("aac", ["supply-chain"]),
    "benchmarks/supply_chain/coverage": ("aac", ["supply-chain"]),
    "benchmarks/supply_chain/metrics": ("aac", ["supply-chain"]),
    "benchmarks/supply_chain/s2c2f": ("openssf", ["supply-chain", "secure-development"]),
    "benchmarks/supply_chain/scrm_800_161": ("nist", ["supply-chain", "us-federal"]),
    "benchmarks/supply_chain/slsa": ("openssf", ["supply-chain", "cicd"]),
    "benchmarks/supply_chain/ssdf": ("nist", ["supply-chain", "secure-development"]),
    "benchmarks/supply_chain/ssdf_genai": ("nist", ["supply-chain", "secure-development", "ai"]),
    # ---- frameworks ----
    "frameworks/compliance/cra": ("eu", ["eu", "product-security"]),
    "frameworks/compliance/ncsc_caf": ("uk-ncsc", ["uk", "critical-infrastructure"]),
    "frameworks/compliance/nis2": ("eu", ["eu", "critical-infrastructure"]),
    "frameworks/critical_infrastructure/ami": ("nist", ["ot", "energy", "smart-grid"]),
    "frameworks/critical_infrastructure/iec_62443": ("iec", ["ot", "industrial"]),
    "frameworks/critical_infrastructure/nerc_cip": ("nerc", ["ot", "energy", "bulk-electric"]),
    "frameworks/critical_infrastructure/nist_800_82": ("nist", ["ot", "industrial"]),
    "frameworks/critical_infrastructure/tsa_pipeline": ("tsa", ["ot", "pipeline"]),
    "frameworks/federal/cisa_cpg": ("cisa", ["us-federal", "critical-infrastructure"]),
    "frameworks/federal/cjis": ("fbi", ["us-federal", "justice"]),
    "frameworks/federal/cmmc": ("dod", ["us-federal", "defense"]),
    "frameworks/federal/fedramp": ("fedramp", ["us-federal", "cloud"]),
    "frameworks/federal/fedramp_20x": ("fedramp", ["us-federal", "cloud"]),
    "frameworks/federal/fisma": ("nist", ["us-federal"]),
    "frameworks/federal/irs_1075": ("irs", ["us-federal", "tax"]),
    "frameworks/federal/nist": ("nist", ["us-federal", "security-controls"]),
    "frameworks/federal/nist/ai_rmf": ("nist", ["us-federal", "ai"]),
    "frameworks/federal/nist_ssdf": ("nist", ["us-federal", "secure-development"]),
    "frameworks/federal/pqc": ("nist", ["us-federal", "cryptography"]),
    "frameworks/federal/zero_trust": ("nist", ["us-federal", "zero-trust"]),
    "frameworks/financial/dora": ("eu", ["financial", "eu"]),
    "frameworks/financial/glba": ("us-federal", ["financial", "banking"]),
    "frameworks/financial/ny_dfs": ("ny-dfs", ["financial", "us-state"]),
    "frameworks/financial/pci_dss": ("pci-ssc", ["financial", "payment-cards"]),
    "frameworks/financial/sec_cyber": ("sec", ["financial", "public-company"]),
    "frameworks/financial/sox": ("us-federal", ["financial", "public-company"]),
    "frameworks/financial/swift_csp": ("swift", ["financial", "banking"]),
    "frameworks/management/cis_controls_v8": ("cis", ["security-controls"]),
    "frameworks/management/cobit": ("isaca", ["it-governance"]),
    "frameworks/management/corporate": ("aac", ["corporate"]),
    "frameworks/management/csa_ccm": ("csa", ["cloud"]),
    "frameworks/management/hitrust": ("hitrust", ["healthcare"]),
    "frameworks/management/iso27001": ("iso", ["isms"]),
    "frameworks/management/soc2": ("aicpa", ["assurance"]),
    "frameworks/management/technical_debt": ("aac", ["technical-debt"]),
    "frameworks/management/tisax": ("enx", ["automotive"]),
    "frameworks/privacy/ccpa": ("us-state", ["privacy", "us-state"]),
    "frameworks/privacy/coppa": ("ftc", ["privacy", "children"]),
    "frameworks/privacy/ferpa": ("us-federal", ["privacy", "education"]),
    "frameworks/privacy/gdpr": ("eu", ["privacy", "eu"]),
    "frameworks/privacy/hipaa": ("hhs", ["privacy", "healthcare"]),
    "frameworks/privacy/iso27701": ("iso", ["privacy", "isms"]),
    "frameworks/regional/bsi_c5": ("bsi", ["germany", "cloud"]),
    "frameworks/regional/cyber_essentials": ("uk-ncsc", ["uk"]),
    "frameworks/regional/dcc": ("uk-mod", ["uk", "defense"]),
    "frameworks/regional/essential_eight": ("acsc", ["australia"]),
    "frameworks/regulatory/cfr_part_11": ("fda", ["life-sciences", "us-federal"]),
    "frameworks/regulatory/itar": ("us-state-dept", ["us-federal", "defense", "export-control"]),
    "frameworks/sovereignty/digital_sovereignty": ("aac", ["sovereignty", "data-residency"]),
    # ---- governance ----
    "governance/ai": ("aac", ["ai"]),
    "governance/eu_ai_act": ("eu", ["ai", "eu"]),
    "governance/exceptions": ("aac", ["exceptions"]),
    "governance/finops": ("finops-foundation", ["finops", "cost"]),
    "governance/geisa": ("geisa", ["ot", "energy", "smart-grid"]),
    "governance/iso_42001": ("iso", ["ai"]),
    "governance/iso_42005": ("iso", ["ai"]),
    "governance/mcp": ("aac", ["ai", "mcp"]),
    "governance/oidc": ("aac", ["identity"]),
    "governance/owasp_llm": ("owasp", ["ai"]),
    # ---- enforcement ----
    "enforcement/aap": ("aac", ["ansible", "aap"]),
    "enforcement/ansible": ("aac", ["ansible"]),
    "enforcement/cicd": ("aac", ["cicd"]),
    "enforcement/dockerfile": ("aac", ["container"]),
    "enforcement/git": ("aac", ["git"]),
    "enforcement/kubernetes": ("aac", ["kubernetes"]),
    "enforcement/repo": ("aac", ["git"]),
    "enforcement/supply_chain": ("aac", ["supply-chain"]),
    "enforcement/terraform": ("aac", ["iac", "terraform"]),
    # ---- other ----
    "threat_detection/crypto_mining": ("aac", ["threat", "cryptomining"]),
    "crosswalk": ("nist", ["crosswalk", "security-controls"]),
}

PKG_RE = re.compile(r"^package\s+([A-Za-z0-9_.]+)")


def is_test(p: Path) -> bool:
    return p.name.startswith("test_") or p.name.endswith("_test.rego") or "tests" in p.parts


def lookup(path: Path) -> tuple[str, str, str, list[str]]:
    parts = path.parts
    tree = parts[0]
    cls = CLASS_BY_TREE[tree]
    if tree == "frameworks" and parts[1] == "critical_infrastructure":
        cls = "ot"
    # longest matching prefix wins
    best = None
    for n in range(len(parts) - 1, 0, -1):
        key = "/".join(parts[:n])
        if key in TABLE:
            best = key
            break
    if best is None:
        raise KeyError(f"no TABLE row for {path}")
    source, domains = TABLE[best]
    # framework slug
    if tree == "benchmarks":
        fam = parts[1]
        if fam in ("cis", "stig", "supply_chain"):
            framework = f"{fam}_{parts[2].lstrip('_')}"
        else:
            framework = f"{fam}_{parts[2]}"
    elif tree == "frameworks":
        framework = parts[2]
        if parts[2] == "nist" and len(parts) > 4:
            framework = f"nist_{parts[3]}"
    elif tree == "crosswalk":
        framework = "crosswalk"
    elif tree == "enforcement":
        framework = f"enforcement_{parts[1]}"
    else:
        framework = parts[1]
    framework = re.sub(r"[^a-z0-9_]", "_", framework.lower())
    return cls, framework, source, list(domains)


def humanise(pkg: str) -> str:
    return " ".join(w.capitalize() for w in re.split(r"[._]", pkg) if w)


def derive_title(lines: list[str], pkg_idx: int, pkg: str) -> str:
    # first comment paragraph anywhere before the first rule; prefer header above package
    cand: list[str] = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("# METADATA"):
            break
        if s.startswith("#"):
            txt = s.lstrip("#").strip()
            if re.fullmatch(r"[=\-*_~\s]*", txt):
                if cand:
                    break
                continue
            if txt.lower().startswith(("package", "import", "opa ", "query", "input", "usage", "see ")):
                if cand:
                    break
                continue
            cand.append(txt)
            if len(cand) == 2 or not txt.endswith((":", ",", "(", "-", "—", "and", "of", "for", "from", "the", "a", "with", "via", "in", "to", "on")):
                break
        elif cand:
            break
        elif s and not s.startswith("#") and i > pkg_idx and not s.startswith("import"):
            break
    title = " ".join(cand).strip()
    title = re.sub(r"\s+", " ", title)
    title = title.strip("─━═│┃-—=*~ ").rstrip(":,(-—. ")
    if len(title) > 140:
        title = title[:137].rsplit(" ", 1)[0] + "..."
    return title or humanise(pkg)


def build_block(title: str, cls: str, framework: str, source: str, domains: list[str]) -> list[str]:
    return [
        "# METADATA",
        f"# title: {json.dumps(title, ensure_ascii=False)}",
        "# custom:",
        f"#   class: {cls}",
        f"#   framework: {framework}",
        f"#   source: {source}",
        f"#   domains: [{', '.join(domains)}]",
    ]


POINTER = "# Package-level METADATA for {pkg} is declared in {owner} (OPA allows one per package)."


def package_of(path: Path) -> str | None:
    for ln in path.read_text(encoding="utf-8").split("\n"):
        m = PKG_RE.match(ln)
        if m:
            return m.group(1)
    return None


def pick_owner(pkg: str, files: list[Path]) -> Path:
    """The one file per package that carries the package-scoped annotation."""
    last = pkg.split(".")[-1]

    def key(p: Path):
        stem = p.stem
        return (0 if stem == last else 1 if stem.endswith(("_main", "_complete")) else 2, str(p))

    return sorted(files, key=key)[0]


def process(path: Path, dry: bool, owner: Path | None = None) -> str:
    text = path.read_text(encoding="utf-8")
    if re.search(r"^# METADATA\s*$", text, re.M):
        return "skip(has METADATA)"
    lines = text.split("\n")
    pkg_idx = next((i for i, ln in enumerate(lines) if PKG_RE.match(ln)), None)
    if pkg_idx is None:
        return "skip(no package)"
    pkg = PKG_RE.match(lines[pkg_idx]).group(1)
    if owner is not None and owner != path:
        pointer = POINTER.format(pkg=pkg, owner=owner)
        if pointer in text:
            return f"skip(package owned by {owner})"
        insert = [pointer]
        if pkg_idx > 0 and lines[pkg_idx - 1].strip().startswith("#"):
            insert = [""] + insert
        new = lines[:pkg_idx] + insert + lines[pkg_idx:]
        if not dry:
            path.write_text("\n".join(new), encoding="utf-8")
        return f"pointer -> {owner}"
    cls, framework, source, domains = lookup(path)
    title = derive_title(lines, pkg_idx, pkg)
    block = build_block(title, cls, framework, source, domains)
    # If the line above `package` is a comment, separate it with a blank line so
    # the existing header does not get parsed as part of the annotation block.
    insert = block
    if pkg_idx > 0 and lines[pkg_idx - 1].strip().startswith("#"):
        insert = [""] + block
    new = lines[:pkg_idx] + insert + lines[pkg_idx:]
    if not dry:
        path.write_text("\n".join(new), encoding="utf-8")
    return f"{cls}/{framework}/{source}/{','.join(domains)} :: {title}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", nargs="*", default=None, help="restrict to these files/dirs")
    args = ap.parse_args()
    targets: list[Path] = []
    roots = [Path(p) for p in (args.only or ROOT_DIRS)]
    for r in roots:
        if r.is_file():
            targets.append(r)
        else:
            targets.extend(p for p in r.rglob("*.rego") if ".github" not in p.parts and not is_test(p))
    # One package-scoped annotation per package: group files by package first.
    by_pkg: dict[str, list[Path]] = {}
    for p in targets:
        pkg = package_of(p)
        if pkg:
            by_pkg.setdefault(pkg, []).append(p)
    owner_of: dict[Path, Path] = {}
    for pkg, files in by_pkg.items():
        if len(files) > 1:
            o = pick_owner(pkg, files)
            for f in files:
                owner_of[f] = o
    n = 0
    for p in sorted(targets):
        res = process(p, args.dry_run, owner_of.get(p))
        if not res.startswith("skip"):
            n += 1
        print(f"{p}: {res}")
    print(f"\n{'would annotate' if args.dry_run else 'annotated'} {n} files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
