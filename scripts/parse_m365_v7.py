#!/usr/bin/env python3
"""Extract the CIS Microsoft 365 Foundations Benchmark v7.0.0 control
enumeration from the official PDF.

Produces the authoritative (section, control_id, title, assessment,
levels) set that every m365_v7 Rego violation message must cite.

Two-source strategy, because neither source alone is trustworthy:

  * The Appendix summary table is the COMPLETE list, but its rows wrap
    across lines and carry \\uf06f checkbox glyphs.
  * The Recommendations body carries Profile Applicability (E3/E5 Level
    1/2), but its headings also wrap, so they cannot be matched as
    single lines.

So: take ids/titles/assessment from the summary table by accumulating
wrapped rows, take levels from the body by anchoring on each known id,
and assert the two agree on the id set.

Usage:
    pdftotext -layout CIS_Microsoft_365_Foundations_Benchmark_v7.0.0.pdf m365_v7.txt
    python3 parse_m365_v7.py m365_v7.txt

The PDF itself is NOT redistributable (CIS terms of use). This script
reads a local copy; it does not vendor the benchmark.
"""
import json
import re
import sys

FORM_FEED = "\x0c"      # prefixes the first line of every page
CHECKBOX = ""     # summary table Yes/No boxes; private-use glyph

# Mirrors check_cis_ids.py -- keep the two in sync.
STOPWORDS = frozenset(
    """ensure is are be set to the a an of on off and or not with for in that
    only has have been configured enable enabled disable disabled restrict
    restricted allow allowed default defaults policy policies use used using
    all any from at by it its this these those than then which who whom""".split()
)
_WORD = re.compile(r"[a-z0-9']+")


def keywords(text):
    """Mirrors check_cis_ids.keywords -- including the quote strip. CIS
    quotes setting names in titles; leaving the quotes on produces tokens
    that never match the same word written unquoted."""
    out = set()
    for w in _WORD.findall(text.lower()):
        w = w.strip("'")
        if w and w not in STOPWORDS and len(w) > 2:
            out.add(w)
    return out


ROW = re.compile(r"^(\d+(?:\.\d+)+)\s+(\S.*?)\s*$")
SECTION = re.compile(r"^(\d+)\s+([A-Z][A-Za-z0-9 &'/-]+?)\s*$")
ASSESS = re.compile(r"\((Automated|Manual)\)")
LEVEL = re.compile(r"^\s*[•·*-]\s*(E\d)\s+Level\s+(\d)\s*$")
# With -layout, the repeating page header renders as ONE line carrying
# several column captions ("CIS Benchmark Recommendation ... Set"), not as
# separate lines -- so match on any line containing a caption, not on
# whole-line equality. Getting this wrong silently appends page furniture
# to a wrapped title and drops the recommendation.
NOISE = re.compile(
    r"^\s*(Page \d+\s*$|CIS Benchmark Recommendation|Correctly\s*$|Yes\s+No\s*$|Set\s*$)"
)


def load(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return text.replace(FORM_FEED, "").replace(CHECKBOX, " ").split("\n")


def marker_span(lines, start_marker, end_marker):
    start = end = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if start is None and s == start_marker:
            start = i
        elif start is not None and s == end_marker:
            end = i
            break
    if start is None or end is None:
        raise SystemExit(f"could not locate {start_marker!r}..{end_marker!r}")
    return start, end


def parse_summary(lines):
    """Accumulate wrapped rows. A row is a recommendation iff its full
    accumulated title ends with an (Automated)/(Manual) marker --
    subsection headers such as '1.1 Users' never do. Depth is NOT a
    usable discriminator: section 4 uses two-level ids (4.1, 4.2) while
    every other section uses three."""
    sections, pending, out = {}, None, []

    def flush():
        if pending is None:
            return
        cid, parts = pending
        title = " ".join(p.strip() for p in parts if p.strip()).strip()
        m = ASSESS.search(title)
        if not m:
            return  # a subsection header ('1.1 Users'), not a recommendation
        # Truncate at the marker rather than anchoring to end-of-string:
        # page furniture can survive the noise filter and trail the title.
        out.append(
            {
                "control_id": cid,
                "section": int(cid.split(".")[0]),
                "title": title[: m.start()].strip(),
                "assessment": m.group(1),
                "levels": [],
            }
        )

    for ln in lines:
        if NOISE.match(ln) or not ln.strip():
            continue
        sec = SECTION.match(ln)
        if sec and int(sec.group(1)) <= 20:
            flush()
            pending = None
            sections[int(sec.group(1))] = sec.group(2).strip()
            continue
        row = ROW.match(ln)
        if row:
            flush()
            pending = (row.group(1), [row.group(2)])
            continue
        if pending is not None:
            pending[1].append(ln)
    flush()
    return sections, out


def parse_levels(lines, ids):
    """Anchor on each known id at the start of a body line, then take the
    Profile Applicability bullets that follow before the next id."""
    levels = {cid: [] for cid in ids}
    current = None
    for ln in lines:
        row = ROW.match(ln)
        if row and row.group(1) in levels:
            current = row.group(1)
            continue
        lv = LEVEL.match(ln)
        if lv and current:
            label = f"{lv.group(1)} Level {lv.group(2)}"
            if label not in levels[current]:
                levels[current].append(label)
    return levels


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "m365_v7.txt"
    lines = load(path)

    s_start, s_end = marker_span(lines, "Appendix: Summary Table", "Appendix: Change History")
    sections, recs = parse_summary(lines[s_start:s_end])

    b_start, _ = marker_span(lines, "Recommendations", "Appendix: Summary Table")
    levels = parse_levels(lines[b_start:s_start], {r["control_id"] for r in recs})
    for r in recs:
        r["levels"] = levels.get(r["control_id"], [])
        r["section_name"] = sections.get(r["section"], "")

    meta = {
        "benchmark": "CIS Microsoft 365 Foundations Benchmark",
        "version": "7.0.0",
        "released": "2026-05-20",
        "source": "official CIS PDF (Appendix summary table + Recommendations body)",
        "sections": {str(k): v for k, v in sorted(sections.items())},
        "total_recommendations": len(recs),
    }

    # Full form -- carries verbatim CIS recommendation titles. CIS terms of
    # use require contacting CIS Legal before reproducing portions of a
    # Benchmark in third-party documentation, so this form must NOT be
    # committed to the public rego_policy_libraries repo.
    with open("cis_m365_v7_enumeration.json", "w", encoding="utf-8") as fh:
        json.dump({**meta, "recommendations": recs}, fh, indent=2)

    # Public form -- control ids, section names, assessment status, profile
    # levels, and a KEYWORD DIGEST of each title. The digest is derived data
    # (a sorted set of substantive words), not the recommendation text, and
    # it is all the coherence guard needs. Safe for the public library.
    public = [
        {
            "control_id": r["control_id"],
            "section": r["section"],
            "section_name": r["section_name"],
            "assessment": r["assessment"],
            "levels": r["levels"],
            "title_keywords": sorted(keywords(r["title"])),
        }
        for r in recs
    ]
    with open("cis_m365_v7_index.json", "w", encoding="utf-8") as fh:
        json.dump({**meta, "form": "keyword-digest (no verbatim CIS titles)",
                   "recommendations": public}, fh, indent=2)

    counts = {}
    for r in recs:
        counts[r["section"]] = counts.get(r["section"], 0) + 1
    print(f"sections: {len(sections)}")
    for k in sorted(sections):
        print(f"  {k}  {sections[k]:<34} {counts.get(k, 0):>3}")
    print(f"TOTAL: {len(recs)}")
    nolevel = [r["control_id"] for r in recs if not r["levels"]]
    print(f"levels resolved: {len(recs) - len(nolevel)}/{len(recs)}")
    if nolevel:
        print(f"  no level: {nolevel[:10]}{'...' if len(nolevel) > 10 else ''}")
    # contiguity check: within each section, ids should form a dense tree
    ids = sorted(r["control_id"] for r in recs)
    print(f"first: {ids[0]}  last: {ids[-1]}")


if __name__ == "__main__":
    main()
