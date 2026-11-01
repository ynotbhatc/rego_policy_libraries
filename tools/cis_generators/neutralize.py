#!/usr/bin/env python3
"""Turn a CIS recommendation title into original wording.

The benchmark text is licensed. Generators may read a workbook the operator
supplies locally, but what this repository stores is the control id plus a
short description of the check written here. ``neutralize_title`` is that
description. It keeps the technical tokens (setting names, paths, thresholds)
so a reader can see what is evaluated, and it does not keep the benchmark's
imperative sentence.

Idempotent: a string that is already in this voice is returned unchanged.
"""
from __future__ import annotations

import re
import sys

# Same stopword list as scripts/check_cis_ids.py. A rewritten message has to
# keep at least one of the benchmark title's remaining keywords when a module
# is checked against a keyword digest.
STOP = frozenset(
    """ensure is are be set to the a an of on off and or not with for in that
    only has have been configured enable enabled disable disabled restrict
    restricted allow allowed default defaults policy policies use used using
    all any from at by it its this these those than then which who whom""".split()
)

IMPERATIVES = frozenset(
    """disable enable configure review verify remove restrict create apply
    encrypt prefer minimize standardize consider lock detect limit block
    make set use allow""".split()
)

WORD = re.compile(r"[a-z0-9']+")
# Our sentences use one of these outside of quoted setting names.
OURS = re.compile(
    r"\b(must|required value|required entries|required contents|checked facts|checked condition|an audit rule)\b",
    re.I,
)

# Suffixes this library appends after a title. They are not benchmark text.
_SUFFIXES = (
    re.compile(r"\s+— requirement not met$"),
    re.compile(r"\s+— manual review not attested(?: \([^)]*\))?$"),
    re.compile(r"\s+\(manual review not attested\)$"),
    re.compile(r"\s+\((?:MS only|DC only)\)$"),
    # Library wrapper around an attestation key, not part of the recommendation.
    re.compile(r"\s+\(attest\.[A-Za-z0-9_]+\)\s*$"),
)


def _peel(text: str) -> tuple[str, str]:
    """Split library-added suffixes off the end. Returns (core, suffix)."""
    core, suffix = text.strip().rstrip("."), ""
    changed = True
    while changed:
        changed = False
        for rx in _SUFFIXES:
            m = rx.search(core)
            if m:
                suffix = m.group(0) + suffix
                core = core[: m.start()]
                changed = True
    return core, suffix


def _quotes_removed(text: str) -> str:
    text = re.sub(r"'[^']*'", " ", text)
    text = re.sub(r"`[^`]*`", " ", text)
    text = re.sub(r'\\"[^"\\]*\\"', " ", text)
    return text


def content_keywords(text: str) -> set[str]:
    out = set()
    for w in WORD.findall(text.lower().replace("\u2019", "'").replace("\u2018", "'")):
        w = w.strip("'")
        if w and w not in STOP and len(w) > 2:
            out.add(w)
    return out


def _scrub(text: str, keep: tuple[str, ...] = ()) -> str:
    """Drop quoted regions and any substrings the rewrite intentionally kept."""
    for g in keep:
        if g:
            text = text.replace(g, " ")
    return _quotes_removed(text)


def _shares_span(src: str, dst: str, n: int = 5, keep: tuple[str, ...] = ()) -> bool:
    """True when n consecutive words of src, outside quotes and kept groups, appear in dst.

    Setting names and the values we deliberately carry are not boilerplate, so
    they are removed before the comparison. What remains is the connective
    tissue of the benchmark sentence.
    """
    aw = WORD.findall(_scrub(src, keep).lower())
    bw = " ".join(WORD.findall(_scrub(dst, keep).lower()))
    for i in range(len(aw) - n + 1):
        if " ".join(aw[i : i + n]) in bw:
            return True
    return False


def _keyword_sentence(body: str) -> str:
    kws = sorted(content_keywords(body))
    if not kws:
        return "checked condition does not hold"
    return "checked facts: " + ", ".join(kws)


def _fallback(body: str) -> str:
    """Order-preserving restatement for titles no grammar rule claimed.

    Keeps the technical words in their original order so the message still
    says what is checked. The frame is ours: a copula becomes "must", and a
    title with no copula is marked as the checked condition.
    """
    text = re.sub(r"\s+", " ", body).strip().rstrip(".")
    m = re.match(r"(?i)^(?P<head>.+?)\s+(?P<verb>is|are|has|have|was|were)\s+(?P<rest>.+)$", text)
    if m:
        verb = {
            "is": "must be", "are": "must be", "was": "must be", "were": "must be",
            "has": "must have", "have": "must have",
        }[m.group("verb").lower()]
        return f"{m.group('head')} {verb} {m.group('rest')}"
    if not text:
        return "checked condition does not hold"
    return "checked condition — " + text


def _fmt(template: str, groups: dict[str, str]) -> str:
    out = template
    for key, val in groups.items():
        out = out.replace("{" + key + "}", val if val else "")
    out = re.sub(r"[ \t]{2,}", " ", out).strip()
    # "<x> is enabled on <y>" would otherwise render as "turned on on <y>"
    return out.replace(" must be turned on on ", " must be turned on for ")


# Applied to the clause with a leading "Ensure [that]" already removed.
# Longer / more specific patterns first.
_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)^(?P<s>.+?)\s+parameter is\s+(?!set\b)(?P<v>.+)$"),
     "required value of parameter {s} is {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+are encrypted with\s+(?P<v>.+)$"),
     "{s} must be encrypted with {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+are not assigned\s+(?P<v>.+)$"),
     "{s} must not be assigned {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) revoked on\s+(?P<w>.+)$"),
     "{s} must be revoked on {w}"),
    (re.compile(r"(?i)^password fields are not empty$"),
     "password fields must be populated"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is set to include\s+(?P<v>.+)$"),
     "required entries for {s} include {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+to include\s+(?P<v>.+)$"),
     "required entries for {s} include {v}"),
    (re.compile(r"(?i)^(?P<s>'[^']+')\s+includes\s+(?P<v>.+)$"),
     "required entries for {s} include {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is set to\s+(?P<v>.+)$"),
     "required value of {s} is {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is not set to\s+(?P<v>.+)$"),
     "{s} must not be {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is\s+(?P<v>'[^']+')(?P<r>.*)$"),
     "required value of {s} is {v}{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+are dropped from\s+(?P<w>.+)$"),
     "{s} must be removed from {w}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is set for\s+(?P<w>.+)$"),
     "{s} must be set for {w}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+has appropriate permissions$"),
     "owner and mode of {s} must be restrictive"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is less than or equal to\s+(?P<v>.+)$"),
     "{s} must be at most {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is greater than or equal to\s+(?P<v>.+)$"),
     "{s} must be at least {v}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) not set$"),
     "{s} must be unset"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is empty$"),
     "{s} must be blank"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) set (?:correctly|appropriately)$"),
     "{s} must match the approved value"),
    (re.compile(r"(?i)^(?P<s>'[^']+')\s+(?:is|are) set$"),
     "{s} must be populated"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+does not have unauthorized privileges$"),
     "{s} must not carry privileges beyond the approved set"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+privilege is restricted$"),
     "privilege {s} must be limited to approved grantees"),
    (re.compile(r"(?i)^(?P<a>.+?)\s+is not present in\s+(?P<b>.+)$"),
     "{b} must not contain {a}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is not granted$"),
     "permission {s} must not be granted"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is unchecked$"),
     "{s} must be cleared"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+kernel module is not available$"),
     "{s} kernel module must be blocked from loading"),
    (re.compile(r"(?i)^(?P<o>\S+)\s+option set on\s+(?P<p>.+?)(?:\s+partition)?$"),
     "{p} must be mounted with the {o} option"),
    (re.compile(r"(?i)^separate partition exists for\s+(?P<p>.+)$"),
     "{p} must be its own filesystem"),
    (re.compile(r"(?i)^permissions on\s+(?P<s>.+?)\s+are configured$"),
     "owner, group, and mode of {s} must be tightened"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+permissions are configured$"),
     "owner, group, and mode of {s} must be tightened"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) revoked from unauthorized\s+(?P<w>.+)$"),
     "{s} must be removed from unauthorized {w}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is not available$"),
     "{s} must be blocked from use"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) not installed$"),
     "{s} must not be present"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) not in use$"),
     "{s} must not be running"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is not disabled(?P<r>.*)$"),
     "{s} must stay in effect{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is not enabled(?P<r>.*)$"),
     "{s} must stay off{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) disabled(?P<r>.*)$"),
     "{s} must be turned off{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) enabled(?P<r>.*)$"),
     "{s} must be turned on{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) not configured(?P<r>.*)$"),
     "{s} must be left unconfigured{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:are|is) configured correctly$"),
     "{s} must match the approved configuration"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:are|is) properly configured$"),
     "{s} must match the approved configuration"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:are|is) collected$"),
     "an audit rule must record {s}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) configured(?P<r>.*)$"),
     "{s} must be explicitly configured{r}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+(?:is|are) installed$"),
     "{s} must be present"),
    (re.compile(r"(?i)^no duplicate\s+(?P<s>.+?)\s+exist$"),
     "the local account database must not contain duplicate {s}"),
    (re.compile(r"(?i)^accounts in\s+(?P<p>\S+)\s+use shadowed passwords$"),
     "password hashes must be stored outside {p}"),
    (re.compile(r"(?i)^(?P<p>\S+)\s+password fields are not empty$"),
     "password fields in {p} must be populated"),
    (re.compile(r"(?i)^root is the only uid 0 account$"),
     "uid 0 must belong only to root"),
    (re.compile(r"(?i)^all groups in\s+(?P<a>\S+)\s+exist in\s+(?P<b>\S+)$"),
     "every group named in {a} must also exist in {b}"),
    (re.compile(r"(?i)^no local interactive user has\s+(?P<f>.+)$"),
     "local interactive users must not have {f}"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+use pty$"),
     "{s} must allocate a pseudo-terminal"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+has an invalid shell$"),
     "{s} must use a non-login shell"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is locked$"),
     "{s} must be locked"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is limited$"),
     "{s} must be limited to named principals"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+is appropriate$"),
     "{s} must use an approved value"),
    (re.compile(r"(?i)^(?P<s>.+?)\s+log file exists$"),
     "a log file for {s} must exist"),
    # Imperative recommendation titles that do not start with "Ensure".
    (re.compile(r"(?i)^do not allow\s+(?P<s>.+)$"),
     "{s} is prohibited"),
    (re.compile(r"(?i)^do not\s+(?P<s>.+)$"),
     "{s} is prohibited"),
    (re.compile(r"(?i)^minimize(?:\s+the)?\s+(?P<s>.+)$"),
     "{s} must be held to the smallest scope the platform allows"),
    (re.compile(r"(?i)^disable\s+(?P<s>.+)$"),
     "{s} must be turned off"),
    (re.compile(r"(?i)^enable\s+(?P<s>.+)$"),
     "{s} must be turned on"),
    (re.compile(r"(?i)^configure\s+(?P<s>.+)$"),
     "{s} must be set to the approved value"),
    (re.compile(r"(?i)^review\s+(?P<s>.+)$"),
     "{s} requires a recorded review"),
    (re.compile(r"(?i)^verify(?:\s+that)?\s+(?P<s>.+)$"),
     "{s} must be confirmed from collected state"),
    (re.compile(r"(?i)^remove\s+(?P<s>.+)$"),
     "{s} must be removed"),
    (re.compile(r"(?i)^limit\s+(?P<s>.+)$"),
     "{s} must be limited"),
    (re.compile(r"(?i)^restrict\s+(?P<s>.+)$"),
     "{s} must be restricted"),
    (re.compile(r"(?i)^allow only\s+(?P<s>.+)$"),
     "only {s} may be permitted"),
    (re.compile(r"(?i)^create\s+(?P<s>.+)$"),
     "{s} must exist"),
    (re.compile(r"(?i)^apply\s+(?P<s>.+)$"),
     "{s} must be applied"),
    (re.compile(r"(?i)^encrypt\s+(?P<s>.+)$"),
     "{s} must be encrypted in transit or at rest"),
    (re.compile(r"(?i)^prefer\s+(?P<s>.+)$"),
     "{s} is the approach this check requires"),
    (re.compile(r"(?i)^lock out\s+(?P<s>.+)$"),
     "{s} must be locked when unused"),
    (re.compile(r"(?i)^make use of\s+(?P<s>.+)$"),
     "{s} must be used"),
    (re.compile(r"(?i)^use\s+(?P<s>.+)$"),
     "{s} is required"),
    (re.compile(r"(?i)^set\s+(?P<s>.+)$"),
     "{s} must be applied"),
    (re.compile(r"(?i)^block\s+(?P<s>.+)$"),
     "{s} must be blocked"),
    (re.compile(r"(?i)^detect\s+(?P<s>.+)$"),
     "{s} must be detected and recorded"),
    (re.compile(r"(?i)^the\s+(?P<s>.+?)\s+should not be used$"),
     "{s} must not be used"),
    (re.compile(r"(?i)^understanding\s+(?P<s>.+)$"),
     "{s} must be reviewed before the service is treated as configured"),
    (re.compile(r"(?i)^consider\s+(?P<s>.+)$"),
     "{s} must be evaluated and the decision recorded"),
    (re.compile(r"(?i)^standardize\s+(?P<s>.+)$"),
     "{s} must follow one approved pattern"),
]


def _restate(body: str) -> str:
    body = body.replace("\u2019", "'").replace("\u2018", "'").strip()
    for rx, template in _RULES:
        m = rx.match(body)
        if not m:
            continue
        kept = tuple(g for g in (m.groups() or ()) if g)
        sentence = _fmt(template, {k: (v or "") for k, v in m.groupdict().items()})
        if _shares_span(body, sentence, keep=kept):
            return _fallback(body)
        return sentence
    return _fallback(body)


def _already(text: str) -> bool:
    if re.match(r"(?i)^ensure\b", text):
        return False
    return OURS.search(_quotes_removed(text)) is not None


def neutralize_title(text: str) -> str:
    """Return original wording for one recommendation title.

    ``text`` may be a bare title or a title plus a library suffix such as
    ``— requirement not met`` or ``(MS only)``. The suffix is preserved.
    """
    if not text or not text.strip():
        return text
    core, suffix = _peel(text)
    if _already(core):
        return core + suffix
    body = re.sub(r"(?i)^ensure(?:\s+that)?\s+", "", core).strip()
    if not body:
        return core + suffix
    new = _restate(body)
    if re.search(r"(?<![A-Za-z])Ensure\b", new):
        new = re.sub(r"(?<![A-Za-z])Ensure\b", "require", new)
    src_kw = content_keywords(core)
    have = content_keywords(new)
    missing = sorted(src_kw - have)
    if src_kw and not (src_kw & have):
        new = new + " [" + " ".join(missing[:4]) + "]"
    return new + suffix


def publish_titles(recs: dict) -> dict:
    """Copy a workbook record map, replacing each ``title`` with original wording.

    Call this after keyword checks against the raw workbook title and pass the
    copy to emitters. Leave the caller's map intact so a keyword digest can
    still be built from the benchmark title.
    """
    out = {}
    for rid, rec in recs.items():
        if isinstance(rec, dict) and "title" in rec:
            copied = dict(rec)
            copied["title"] = neutralize_title(rec["title"])
            out[rid] = copied
        elif isinstance(rec, tuple) and rec:
            out[rid] = (neutralize_title(rec[0]),) + tuple(rec[1:])
        else:
            out[rid] = rec
    return out


def _ensure_spans(line: str):
    """Yield (start, end, phrase) for each CIS-style 'Ensure ...' span on a line."""
    i = 0
    while True:
        j = line.find("Ensure", i)
        if j < 0:
            return
        if j > 0 and (line[j - 1].isalnum() or line[j - 1] == "_"):
            i = j + 6
            continue
        head = line[:j]
        hashpos = head.rfind("#")
        in_comment = False
        if hashpos >= 0:
            between = head[hashpos:]
            # a quote between '#' and the word means the '#' is inside a string
            if between.count('"') % 2 == 0:
                in_comment = True
        if in_comment:
            k = len(line.rstrip("\r\n"))
        else:
            k = j + 6
            while k < len(line):
                if line[k] == "\\" and k + 1 < len(line):
                    k += 2
                    continue
                if line[k] == '"':
                    break
                if line[k] == "\n":
                    break
                k += 1
        phrase = line[j:k].strip()
        if len(phrase) > len("Ensure ") + 2:
            yield j, k, phrase
        i = max(k, j + 6)


def rewrite_line(line: str) -> str:
    spans = list(_ensure_spans(line))
    if not spans:
        return line
    out = line
    for start, end, phrase in reversed(spans):
        new = neutralize_title(phrase)
        # keep a single trailing space that belonged to the raw span if the
        # closer sits immediately after it; phrase was stripped
        out = out[:start] + new + out[end:]
    return out


def rewrite_text(text: str) -> str:
    return "".join(rewrite_line(line) for line in text.splitlines(keepends=True))


def _self_check() -> None:
    samples = {
        "Ensure 'Enforce password history' is set to '24 or more password(s)'":
            "password",
        "Ensure cramfs kernel module is not available": "cramfs",
        "Ensure nodev option set on /tmp partition": "nodev",
        "Ensure SSH root login is disabled": "ssh",
        "Ensure no duplicate UIDs exist": "duplicate",
        "Enable EKS control plane logging": "eks",
        "Ensure 'Enforce password history' is set to '24 or more password(s)' (MS only)":
            "history",
    }
    for src, needle in samples.items():
        dst = neutralize_title(src)
        if re.search(r"(?<![A-Za-z])Ensure\b", dst):
            raise SystemExit(f"still imperative: {dst}")
        if needle not in dst.lower() and not (content_keywords(src) & content_keywords(dst)):
            raise SystemExit(f"lost {needle}: {src} -> {dst}")
        if _shares_span(re.sub(r"(?i)^ensure(?:\s+that)?\s+", "", src), dst):
            raise SystemExit(f"span leak: {src} -> {dst}")
        again = neutralize_title(dst)
        if again != dst:
            raise SystemExit(f"not idempotent: {dst} -> {again}")
    line = 'violations contains "1.1.1.1: not met — Ensure cramfs kernel module is not available" if {'
    got = rewrite_line(line)
    if "Ensure" in got or "cramfs" not in got:
        raise SystemExit(f"line rewrite failed: {got}")
    comment = '# Ensure kernel "init_module" and "finit_module" loading is collected\n'
    got = rewrite_line(comment)
    if "Ensure" in got or not got.endswith("\n"):
        raise SystemExit(f"comment rewrite failed: {got!r}")


def _recommendation_titles(text: str) -> set[str]:
    """Titles stored on a recommendation object (one that also carries assessment)."""
    found = set()
    lines = text.splitlines()
    title_rx = re.compile(r'"title":\s*"((?:\\.|[^"\\])*)"')
    for i, line in enumerate(lines):
        m = title_rx.search(line)
        if not m:
            continue
        window = "\n".join(lines[i : i + 12])
        if re.search(r'"assessment":\s*"(?:Automated|Manual)"', window):
            found.add(m.group(1).encode("utf-8").decode("unicode_escape") if False else m.group(1))
    return found


def apply_tree(root: str = ".") -> dict:
    """Rewrite recommendation titles under benchmarks/cis plus the README example.

    Returns counts for the pull-request summary.
    """
    import pathlib

    rootp = pathlib.Path(root)
    targets = []
    cis = rootp / "benchmarks" / "cis"
    for p in cis.rglob("*"):
        if p.suffix.lower() not in {".rego", ".md"}:
            continue
        if "cis_" in p.name and p.suffix == ".json":
            continue
        targets.append(p)
    for extra in (rootp / "README.md", rootp / "docs" / "CONTROL_CORRELATION_PATTERN.md"):
        if extra.exists():
            targets.append(extra)

    free: set[str] = set()
    for p in targets:
        if p.suffix != ".rego":
            continue
        for t in _recommendation_titles(p.read_text(encoding="utf-8", errors="ignore")):
            if not t.startswith("Ensure") and not t.startswith("ensure"):
                free.add(t)
    # Longest first so a shorter title cannot eat part of a longer one.
    free_pairs = []
    for t in sorted(free, key=len, reverse=True):
        new = neutralize_title(t)
        if new != t and "Ensure" not in new:
            free_pairs.append((t, new))

    files_changed = 0
    ensure_before = 0
    ensure_after = 0
    free_repls = 0
    for p in targets:
        text = p.read_text(encoding="utf-8", errors="ignore")
        ensure_before += text.count("Ensure")
        orig = text
        for old, new in free_pairs:
            if old in text:
                free_repls += text.count(old)
                text = text.replace(old, new)
        text = rewrite_text(text)
        ensure_after += text.count("Ensure")
        if text != orig:
            p.write_text(text, encoding="utf-8")
            files_changed += 1
    return {
        "files_changed": files_changed,
        "files_seen": len(targets),
        "ensure_before": ensure_before,
        "ensure_after": ensure_after,
        "free_titles": len(free_pairs),
        "free_replacements": free_repls,
    }


if __name__ == "__main__":
    _self_check()
    print("neutralize self-check ok")
    if "--apply" in sys.argv:
        stats = apply_tree()
        for k, v in stats.items():
            print(f"{k}: {v}")
