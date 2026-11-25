#!/usr/bin/env python3
"""Bad input never passes (issue #301): every compliance_report entrypoint, evaluated on input that is empty,
missing fields, null, or carries strings where numbers or booleans belong, must not report a pass.

Entrypoints come from the wasm build's discovery (the same list `make check-no-data` uses). Per entrypoint:

  base cases (every entrypoint)
    empty            {}
    no_input         no input document at all
    keys_null        every top-level input key the module's own files read (input.<key>) set to null
    keys_str_true    ... set to the string "true"
    keys_str_num     ... set to the string "1"

  reference cases (every entrypoint whose sources read at least one input path; no fixture needed)
    The module's own source says which facts it reads. scripts/input_refs.py walks OPA's parse of the module's
    files (its directory, plus every package those files reference) and collects each `input.a.b.c` path,
    following local and rule aliases, helper parameters, object.get and keys taken from literal tables. One
    document is built in which every leaf path holds the same bad value; a path the rule iterates
    (`input.items[_].x`) is a one-element list.
    refs_str_false   every leaf the string "false"
    refs_str_true    every leaf the string "true"
    refs_str_no      every leaf the string "no"
    refs_null        every leaf null
    The same document with every leaf the boolean false is evaluated as the control (it is not a case: all
    false is a legitimate answer). A reference case fails when the report passes (kind pass), and also when
    it holds FEWER violations or failed controls than the control does (kind fewer-findings): a string or a
    null made findings that boolean false produces go away, while one or two unrelated findings keep
    `compliant` false. That is the shape `not input.x` leaves behind, since `not "false"` is false. The count
    compared is len(violations), else violation_count; failed_controls / failed is compared as well when the
    report carries it. fewer-findings is a kind of its own, not a pass: the verdict is still "not compliant",
    and what is wrong is the per-control result. A presence test on a fact that really is a string
    (`not input.dpo_contact`) reads the same way; such an entry stays listed until the module types the fact.

  fixture cases (entrypoints whose tests hold an all-pass fixture)
    Fixtures are found by evaluation, not by reading literals: every complete rule of the test packages under
    the module's directory is fetched from an OPA server that has the library and its tests loaded (test
    packages never share a name with a library package), and every object-valued one on which the entrypoint
    reports a pass is an all-pass fixture. Comments and string contents are not read as rules, and a rule that
    only aliases a package (`pkg := data.sentinel.terraform`) is not a candidate.
      primary      the object with the most leaves, taken from rules whose name does not suggest a failing case
                   (BAD_NAME: bad_*, missing_*, invalid_* ...) when there is one. Its cases keep plain names.
      secondaries  up to FIXTURE_CAP - 1 further distinct objects, each chosen for the most (path, value)
                   leaves no chosen fixture holds: a second level or profile (CIS Level 2, FedRAMP Moderate)
                   differs in its selector and in the facts only it carries. A copy or a subset is not run,
                   and neither is an object that is not a variant of the primary (fewer than
                   VARIANT_OVERLAP of its leaf paths are the primary's): a neighbour module's green input
                   that this entrypoint passes as "not applicable" is not a second level of this module.
                   Their cases are named <case>@<rule name>, so adding a fixture renames nothing. A secondary
                   gets cases only for the fields and leaves it holds with a value no earlier fixture has
                   (a second fixture costs what it adds; running every case on every fixture multiplied the
                   run). A fact both hold is judged on the primary, and, when the primary does not depend
                   on it, on the others through the probes below.
    Single-key wrappers ({"bsi_c5": {...}}) are descended, so "fields" are the keys of the first object with
    more than one key.
    drop:<field>     that field removed
    null:<field>     that field set to null
    boolstr:<path>   one boolean leaf replaced by its string form ("true" / "false")
    boolopp:<path>   ... by the opposite string (true -> "false", false -> "true")
    boolno:<path>    ... by the string "no"
    null:<path>      ... by null (the leaf itself, not its top-level field)
    drop:<path>      ... removed
    numstr:<path>    one number leaf replaced by its string form (90 -> "90")
    The five boolean mutations are tried on the same sampled leaves.
    A field or leaf is skipped when the module's code cannot name it (class Names): its key must be an
    identifier in code, a whole string literal, or a segment of a string literal without white space. A word
    in a comment, a title or a message is not a way to read a fact. Report metadata fields (META_FIELD: ids,
    timestamps, names, profile and level selectors) are skipped for drop/null; their leaves are still
    type-swapped. Leaf swaps and fields are capped per fixture (LEAF_CAP, FIELD_CAP) so the run stays CI-sized;
    the sample is chosen by a stable hash of the case id, not by position, so editing a fixture does not
    reshuffle the known-failures list.

  does the fixture depend on the fact? (every fixture case that passes)
    A badly typed fact that still passes is a hole only if the fixture depends on the fact. So the same fact is
    tried at an honestly bad value (probes): a boolean at its opposite, a number at 0 and at +/- 10^9, an
    object whose every leaf is a boolean with all of them flipped. The probes are compared with the fixture's
    own report (output that differs between two evaluations of the unchanged fixture is ignored):
      decisive  a probe fails, or changes any output that is not advisory: the case is a failure (kind pass).
                No probe exists for a string-typed field or an object holding more than booleans: also a failure.
      unscored  every probe passes and only output under a key named advisor* changes (`advisories`,
                `advisory_count`): the module reads the fact and, by its own report, does not score it. Not a
                failure; counted and printed.
      inert     every probe passes and the report does not change: on this fixture nothing reads the fact (its
                level or profile does not evaluate the control, or an alternative already satisfies an
                either-or rule). The same mutation is then tried on every other all-pass fixture of the
                entrypoint that holds the fact. If one of them depends on the fact and fails the mutated
                document, the case is `scoped`: not a failure; counted and printed. If none does, the case
                stays a failure and its detail says "inert": nothing shows the fact is ever read. That is a
                fixture to add (the level that reads it), a field to take out of the fixture, or a line for
                the accepted list, never something to wave through. That holds for the primary fixture. On a
                secondary the same finding is `unread` and is not a failure: a secondary is extra coverage,
                often an input written for another purpose (a not-applicable input, another module's green
                input that this entrypoint also passes), and only what it positively shows counts.
    This is sound for what the check asserts (bad evidence must not pass where good evidence is required). It
    does not judge whether a control should be scored or should apply at a level: that is the module's design,
    stated by its own output. A report with per-control results but no advisory key is not treated specially:
    any change in it makes the fact decisive.

A report passes if compliant == true, or its score (compliance_percentage / compliance_score / score) is
>= 100, or, with neither field, it has no violations and no failed controls. A mutated fixture also fails
the check if its score rises above the fixture's own (kind score-rise). Undefined reports and evaluation errors are recorded
as their own kinds: they are not passes, but the product drops the row, so they are tracked too.

Kinds: pass, fewer-findings (reference cases), score-rise (fixture cases), undefined, error.

Two lists, and a case is never in both:
  scripts/bad_input_known_failures.txt   TO FIX. Generated (--write-known), one `<package> <case> <kind>: <detail>`
      per line. The target fails only on a failure that is not listed, and prints every listed entry that now
      holds (stale) so the list can be regenerated.
  scripts/bad_input_accepted.txt         REVIEWED AND RIGHT. Written by hand, one `<package> <case>: <reason>` per
      line (optionally `<package> <case> <kind>: <reason>`). The reason is mandatory, at least MIN_REASON
      characters, and not "by design" / "n/a" / "the harness cannot tell": it says which rule id, procedure or
      collector contract makes the behaviour right. `*` in the case accepts a family (`stig.rhel_9.main numstr:*`)
      and then the reason must cite a document: a URL or the path of a file in this repository. An accepted
      failure is not a failure and is never written to the known list; the count is printed. Only kinds pass,
      fewer-findings and score-rise can be accepted. Under --check an entry is an error when its case no longer
      exists, no longer fails (fixed, or now unscored / scoped), matches nothing (pattern), names a package
      that is no entrypoint, or is also in the known list. The file's header repeats these rules.

    python3 scripts/check_bad_input_fails.py                 # report
    python3 scripts/check_bad_input_fails.py --check         # exit 1 on an unlisted failure or a bad accepted entry
    python3 scripts/check_bad_input_fails.py --write-known   # rewrite the known-failures list (accepted left out)
    python3 scripts/check_bad_input_fails.py --lint-accepted # form of the accepted file only; no OPA
    python3 scripts/check_bad_input_fails.py --accepted merged.txt --check   # try a merged accepted list first
    python3 scripts/check_bad_input_fails.py --only cmmc.main --verbose   # fixtures, known entries that still
                                                             # fail, accepted and excused cases with reasons
    python3 scripts/check_bad_input_fails.py --summary new.txt   # unlisted failures per package, by kind
    python3 scripts/check_bad_input_fails.py --json out.json     # everything, for tooling

The logic of this script and of scripts/input_refs.py is unit-tested in scripts/tests/ (`make check-bad-input`
runs those first).
"""
from __future__ import annotations
import argparse, collections, concurrent.futures as cf, hashlib, json, os, pathlib, re, socket, subprocess, sys
import tempfile, time
import urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_no_data_fails as nodata  # noqa: E402
import input_refs  # noqa: E402

KNOWN = ROOT / "scripts" / "bad_input_known_failures.txt"
ACCEPTED = ROOT / "scripts" / "bad_input_accepted.txt"
TREES = ["benchmarks", "frameworks", "governance", "threat_detection", "crosswalk", "enforcement"]
TEST_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.rego)$|/tests/")
SCORE_KEYS = ("compliance_percentage", "compliance_score", "score")
LEAF_CAP = 40
FIELD_CAP = 40
# drop/null of report metadata (ids, timestamps, names, profile/level selectors) is not evidence going missing
META_FIELD = re.compile(r"(^|_)(id|time|timestamp|date|as_of|name|hostname|version|profile|level)$", re.I)
WORKERS = max(2, min(16, (os.cpu_count() or 4)))
# reference cases: (case id, value every leaf holds). CONTROL is evaluated for the comparison only.
REF_VALUES = [("refs_str_false", "false"), ("refs_str_true", "true"), ("refs_str_no", "no"), ("refs_null", None)]
CONTROL = "~refs_bool_false"
PARSE_CHUNK = 40
RETRIES = 4          # a query whose connection fails is sent again; an HTTP error from OPA is an answer
# fixtures: the primary plus up to FIXTURE_CAP - 1 further all-pass fixtures get the fixture cases
FIXTURE_CAP = 4
VARIANT_OVERLAP = 0.5
# a test object whose rule name says it is a failing case is not an all-pass fixture when another object passes
BAD_NAME = re.compile(r"(^|_)(bad|fail(s|ed|ing|ure)?|non_?compliant|violat\w*|invalid|missing|broken|wrong|den(y|ied)|"
                      r"insecure|weak|empty|partial|incomplete|negative|without|no|not|malformed|drift\w*)(_|$)", re.I)
# probes: a number leaf is tried at these values; a report key with this in its name is advisory output
NUM_PROBES = (0, -10**9, 10**9)
ADVISORY_KEY = re.compile(r"advisor", re.I)
# accepted cases
MIN_REASON = 25
ACCEPT_KINDS = ("pass", "fewer-findings", "score-rise")
TRIVIAL_REASON = re.compile(
    r"^\W*(correct |working |works )?(by design|as designed|as intended|n/?a|none|intended|expected( behaviou?r)?|ok(ay)?|fine|"
    r"accepted|reviewed|see (the )?(report|above|below)|todo|tbd|wont ?fix|won't fix|false positive|"
    r"not a (defect|bug|hole))\W*$", re.I)
NO_REASON = re.compile(r"harness (cannot|can ?not|can't|could not|couldn't) (tell|know|see|distinguish)", re.I)


# ---------------------------------------------------------------- discovery
def rego_files():
    for t in TREES:
        for f in sorted((ROOT / t).rglob("*.rego")):
            yield f


def module_layout(eps):
    """{entrypoint: (module_dir, source_text_of_module_files, [test files])}"""
    pkg_file = {}
    srcs, tests = [], []
    for f in rego_files():
        rel = f.relative_to(ROOT).as_posix()
        (tests if TEST_RE.search(rel) else srcs).append(f)
    for f in srcs:
        m = re.search(r"^package\s+([\w.]+)", f.read_text(errors="ignore"), re.M)
        if m:
            pkg_file.setdefault(m.group(1), f)
    out = {}
    for e in eps:
        pkg = e.rsplit("/", 1)[0].replace("/", ".")
        f = pkg_file.get(pkg)
        if f is None:
            continue
        d = f.parent
        if d.name in ("main", "lib"):
            d = d.parent
        text = "\n".join(s.read_text(errors="ignore") for s in srcs if d in s.parents)
        out[e] = (d, text, [t for t in tests if d in t.parents])
    return out


def input_keys(text):
    keys = set(re.findall(r"\binput\.([A-Za-z_][A-Za-z0-9_]*)", text))
    keys |= set(re.findall(r"\binput\[\"([^\"]+)\"\]", text))
    keys |= set(re.findall(r"object\.get\(\s*input\s*,\s*\"([^\"]+)\"", text))
    return sorted(keys)


RULE_RE = re.compile(r"^([a-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*[^=]", re.M)
ALIAS_RE = re.compile(r"^([a-z_][A-Za-z0-9_]*)\s*:?=\s*data((?:\.[A-Za-z_][A-Za-z0-9_]*)+)[ \t]*$", re.M)


_TOKEN = re.compile(r'#[^\n]*|"((?:\\.|[^"\\\n])*)"?|`([^`]*)`?')


def strip_rego(text):
    """(code, strings): the source with comments removed and every string literal blanked to "" (newlines are
    kept, so line anchors still work), and the contents of the string literals."""
    strings = []

    def blank(m):
        tok = m.group(0)
        if tok[0] == "#":
            return ""
        if tok[0] == '"':
            strings.append(re.sub(r"\\(.)", r"\1", m.group(1)))
            return '""'
        strings.append(m.group(2))
        return '""' + "\n" * m.group(2).count("\n")

    return _TOKEN.sub(blank, text), strings


class Names:
    """The names a module's own code can read a fact by: identifiers in code (not in comments, not inside
    titles or messages), string literals taken whole ("net.ipv4.ip_forward", "Audit Logon"), and the segments of
    a string literal that holds no white space ("sshd.permit_root_login", "a/b"). A word that appears only in a
    comment or in the middle of a sentence is not a way to read a fact."""

    def __init__(self, text):
        code, strings = strip_rego(text)
        self.idents = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code))
        self.strings = set(strings)
        self.segments = {seg for st in strings if st and not re.search(r"\s", st)
                         for seg in re.split(r"[./\[\]]", st) if seg}

    def has(self, name):
        return name in self.idents or name in self.strings or name in self.segments


def as_names(src):
    return src if isinstance(src, Names) else Names(src)


_PACKAGES = None


def all_packages():
    """Every package path in the trees, tests included, and every prefix of one."""
    global _PACKAGES
    if _PACKAGES is None:
        out = set()
        for f in rego_files():
            m = re.search(r"^package\s+([\w.]+)", f.read_text(errors="ignore"), re.M)
            if m:
                parts = m.group(1).split(".")
                out |= {".".join(parts[:i]) for i in range(1, len(parts) + 1)}
        _PACKAGES = out
    return _PACKAGES


def candidate_names(src, packages=()):
    """Names of the complete rules (not tests, not functions) in one test file that can hold a fixture. Comments
    and string contents are not read as rules, and `pkg := data.some.package` is an alias of a package, not an
    object a test wrote."""
    code, _ = strip_rego(src)
    alias = {name for name, ref in ALIAS_RE.findall(code) if ref[1:] in packages}
    return sorted(n for n in set(RULE_RE.findall(code)) if not n.startswith("test_") and n != "default" and n not in alias)


def candidate_rules(test_files, packages=None):
    """[(test_package_path, rule)] for complete rules (not tests, not functions) in these test files."""
    packages = all_packages() if packages is None else packages
    out = []
    for t in test_files:
        src = t.read_text(errors="ignore")
        m = re.search(r"^package\s+([\w.]+)", src, re.M)
        if not m:
            continue
        out += [(m.group(1).replace(".", "/"), name) for name in candidate_names(src, packages)]
    return out


def select_fixtures(passing, cap=None):
    """The all-pass fixtures of one entrypoint, primary first. `passing` is [(candidate, value, leaves, score,
    report)] in candidate order, every one an object the entrypoint passes on.
      primary      the object with the most leaves (the first such in candidate order), taken from the rules
                   whose name does not suggest a failing case (BAD_NAME) when there is one
      secondaries  further distinct objects from those rules, each chosen for the most (path, value) leaves no
                   fixture chosen so far holds (a second level or profile differs in its selector and in the
                   facts only it carries); an object that adds nothing is not run. At most cap - 1.
                   A secondary is a variant of the primary: at least VARIANT_OVERLAP of its leaf paths are
                   paths of the primary. A neighbour module's green input that this entrypoint happens to
                   pass (because it says "not applicable") shares almost none and is not a second level.
    Returns [(label, candidate, value, leaves, score, report)]; the primary's label is "", a secondary's is its
    rule name, qualified by the test package when two chosen rules (the primary included) share a name."""
    cap = FIXTURE_CAP if cap is None else cap
    seen, uniq = set(), []
    for t in sorted(passing, key=lambda t: bool(BAD_NAME.search(t[0][1]))):       # stable: good names first
        key = json.dumps(t[1], sort_keys=True)
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    order = {id(t): i for i, t in enumerate(passing)}
    uniq.sort(key=lambda t: order[id(t)])
    good = [t for t in uniq if not BAD_NAME.search(t[0][1])]
    pool = good or uniq
    if not pool:
        return []
    primary = max(pool, key=lambda t: (t[2], -order[id(t)]))
    chosen = [primary]
    have = {(p, json.dumps(v, sort_keys=True)) for p, v in leaves(primary[1])}
    shape = {p for p, _ in leaves(primary[1])}
    rest = [t for t in good if t is not primary
            and sum(1 for p, _ in leaves(t[1]) if p in shape) >= VARIANT_OVERLAP * t[2]]
    pairs = {id(t): {(p, json.dumps(v, sort_keys=True)) for p, v in leaves(t[1])} for t in rest}
    while rest and len(chosen) < cap:
        best = max(rest, key=lambda t: (len(pairs[id(t)] - have), t[2], tuple(-ord(ch) for ch in "/".join(t[0]))))
        if not pairs[id(best)] - have:
            break
        chosen.append(best)
        have |= pairs[id(best)]
        rest.remove(best)
    names = collections.Counter(t[0][1] for t in chosen)
    out = [("",) + tuple(primary)]
    for t in chosen[1:]:
        label = t[0][1] if names[t[0][1]] == 1 else f"{t[0][0].replace('/', '.')}.{t[0][1]}"
        out.append((label,) + tuple(t))
    return out


def good_fixtures(passing):
    """Every distinct all-pass object of an entrypoint from a rule whose name does not suggest a failing case."""
    seen, out = set(), []
    for t in passing:
        key = json.dumps(t[1], sort_keys=True)
        if key not in seen and not BAD_NAME.search(t[0][1]):
            seen.add(key)
            out.append(t)
    return out


# ---------------------------------------------------------------- server
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class External:
    """An already-running OPA server that has the library and its tests loaded (--server URL)."""
    def __init__(self, base):
        self.base = base.rstrip("/")

    def wait(self):
        return self

    def stop(self):
        pass

    def query(self, *a, **k):
        return Server.query(self, *a, **k)

    def parse_modules(self, sources):
        return Server.parse_modules(self, sources)


class Server:
    def __init__(self, with_tests):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        cmd = [os.environ.get("OPA", "opa"), "run", "--server", "--addr", f"127.0.0.1:{self.port}", "--log-level", "error"]
        if not with_tests:
            cmd += ["--ignore", "tests", "--ignore", "test_*", "--ignore", "*_test.rego"]
        cmd += [str(ROOT / t) for t in TREES if (ROOT / t).exists()]
        self.log = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT)

    def wait(self):
        deadline = time.time() + float(os.environ.get("BAD_INPUT_START_TIMEOUT", "900"))
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.log.seek(0)
                sys.exit("OPA server exited early:\n" + self.log.read().decode(errors="replace")[-3000:])
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=2) as r:
                    if r.status == 200:
                        return self
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.3)
        sys.exit("OPA server did not become healthy")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def query(self, path, inp=None, has_input=True):
        """('ok', value) | ('undefined', None) | ('error', message)"""
        body = json.dumps({"input": inp} if has_input else {}).encode()
        req = urllib.request.Request(f"{self.base}/v1/data/{path}", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        for attempt in range(RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    res = json.loads(r.read())
            except urllib.error.HTTPError as e:      # the server answered: an evaluation error, not retried
                try:
                    msg = json.loads(e.read()).get("errors", [{}])[0].get("message") or str(e)
                except Exception:  # noqa: BLE001
                    msg = str(e)
                return "error", msg.splitlines()[0][:160]
            except Exception as e:  # noqa: BLE001   a broken pipe or a reset under load says nothing about the module
                if attempt == RETRIES - 1:
                    return "error", str(e)[:160]
                time.sleep(0.5 * (attempt + 1))
                continue
            return ("ok", res["result"]) if "result" in res else ("undefined", None)

    def parse_modules(self, sources):
        """{name: AST} through the server's rego.parse_module: the parse `opa parse --format json` prints."""
        body = json.dumps({"query": input_refs.PARSE_QUERY, "input": sources}).encode()
        req = urllib.request.Request(f"{self.base}/v1/query", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["result"][0]["x"]


# ---------------------------------------------------------------- verdicts
def score(r):
    for k in SCORE_KEYS:
        v = r.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return None


def passes(r):
    if not isinstance(r, dict):
        return False
    if r.get("compliant") is True:
        return True
    s = score(r)
    if s is not None and s >= 100:
        return True
    if "compliant" in r or s is not None:
        return False
    v = r.get("violations")
    n = len(v) if isinstance(v, (list, dict)) else r.get("violation_count", 1)
    return n == 0 and r.get("failed_controls", 0) in (0, None)


def findings(r):
    """(violations, failed controls) a report holds; None for a count the report does not carry."""
    if not isinstance(r, dict):
        return None, None
    v = r.get("violations")
    n = len(v) if isinstance(v, (list, dict)) else r.get("violation_count")
    f = next((r[k] for k in ("failed_controls", "failed") if k in r), None)
    num = lambda x: x if isinstance(x, (int, float)) and not isinstance(x, bool) else None  # noqa: E731
    return num(n), num(f)


def fewer(case, control):
    """Why a reference case holds fewer findings than its control, or None."""
    (cv, cf_), (bv, bf) = findings(case), findings(control)
    if cv is not None and bv is not None and cv < bv:
        return f"{cv} violations, {bv} with every fact boolean false"
    if cf_ is not None and bf is not None and cf_ < bf:
        return f"{cf_} failed controls, {bf} with every fact boolean false"
    return None


def leaves(o, path=()):
    if isinstance(o, dict):
        if not o:
            return
        for k in sorted(o):
            yield from leaves(o[k], path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, path + (i,))
    else:
        yield path, o


def fmt(path):
    """Stable case id for a path; spaces and % are percent-encoded so an id is one token in the known list."""
    s = ""
    for p in path:
        s += f"[{p}]" if isinstance(p, int) else (("." if s else "") + str(p))
    return s.replace("%", "%25").replace(" ", "%20")


def setp(o, path, value, drop=False):
    o = json.loads(json.dumps(o))
    cur = o
    for p in path[:-1]:
        cur = cur[p]
    if drop:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return o


def field_root(fx):
    """Descend single-key object wrappers; return the path of the first object with more than one key."""
    path, cur = (), fx
    while isinstance(cur, dict) and len(cur) == 1 and isinstance(next(iter(cur.values())), dict):
        k = next(iter(cur))
        path, cur = path + (k,), cur[k]
    return path, cur


def spread(items, cap, key):
    """Up to cap items, chosen by a stable hash of each case id: adding or removing one leaf in a fixture
    changes at most one sampled case, so the known-failures list does not churn."""
    if len(items) <= cap:
        return items
    ranked = sorted(items, key=lambda it: hashlib.sha1(key(it).encode()).hexdigest())[:cap]
    return sorted(ranked, key=key)


def get(o, path):
    """The value at a path, or the sentinel get.MISSING."""
    for p in path:
        if isinstance(o, dict) and p in o:
            o = o[p]
        elif isinstance(o, list) and isinstance(p, int) and p < len(o):
            o = o[p]
        else:
            return get.MISSING
    return o


get.MISSING = object()


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def mutate(fx, family, path, v):
    """The fixture with one mutation applied; v is the value the fixture holds at the path."""
    if family == "drop":
        return setp(fx, path, None, drop=True)
    if family == "null":
        return setp(fx, path, None)
    if family == "numstr":
        return setp(fx, path, str(v))
    if family == "boolstr":
        return setp(fx, path, "true" if v else "false")
    if family == "boolopp":
        return setp(fx, path, "false" if v else "true")
    if family == "boolno":
        return setp(fx, path, "no")
    raise ValueError(family)


def case_specs(fx, src, earlier=()):
    """[(case id, family, path)] for one fixture: which mutation each fixture case applies, and where.
    `earlier` holds the fixtures already given their cases (the primary, for a secondary): a field or leaf that
    one of them holds with the same value is not tried again, so a second fixture costs what it adds."""
    names = as_names(src)
    specs = []
    root, obj = field_root(fx)
    old = lambda p: any(get(e, p) == get(fx, p) and type(get(e, p)) is type(get(fx, p)) for e in earlier)  # noqa: E731
    if isinstance(obj, dict):
        named = [k for k in sorted(obj) if names.has(k) and not META_FIELD.search(k) and not old(root + (k,))]
        for k in spread(named, FIELD_CAP, lambda k: fmt(root + (k,))):
            specs.append((f"drop:{fmt(root + (k,))}", "drop", root + (k,)))
            specs.append((f"null:{fmt(root + (k,))}", "null", root + (k,)))
    bools, nums = [], []
    for p, v in leaves(fx):
        name = next((k for k in reversed(p) if isinstance(k, str)), None)
        if name is None or not names.has(name) or old(p):
            continue  # the module's code never names this leaf, so it cannot read it: swapping it is no test
        if isinstance(v, bool):
            bools.append(p)
        elif isinstance(v, (int, float)):
            nums.append(p)
    for p in spread(nums, LEAF_CAP, fmt):
        specs.append((f"numstr:{fmt(p)}", "numstr", p))
    seen = {c for c, _, _ in specs}
    for p in spread(bools, LEAF_CAP, fmt):
        for family in ("boolstr", "boolopp", "boolno", "null", "drop"):
            cid = f"{family}:{fmt(p)}"
            if cid not in seen:      # a boolean that is itself a top-level field already has drop: / null:
                seen.add(cid)
                specs.append((cid, family, p))
    return specs


def fixture_cases(fx, src):
    return [(cid, mutate(fx, family, path, get(fx, path))) for cid, family, path in case_specs(fx, src)]


# ---------------------------------------------------------------- probes
def probes(fx, path):
    """Documents that put an honestly bad value where a mutation put a badly typed one, or None when there is no
    such value to try. A boolean becomes its opposite; a number is tried at 0 and at +/- 10^9 (no threshold,
    range or equality holds for all three); an object whose every leaf is a boolean has them all flipped.
    If the report cannot tell these from the fixture, the fixture does not depend on the fact."""
    v = get(fx, path)
    if isinstance(v, bool):
        return [setp(fx, path, not v)]
    if is_num(v):
        return [setp(fx, path, x) for x in NUM_PROBES if x != v]
    if isinstance(v, dict) and v:
        lv = list(leaves(v))
        if lv and all(isinstance(x, bool) for _, x in lv):
            doc = fx
            for sub, x in lv:
                doc = setp(doc, tuple(path) + sub, not x)
            return [doc]
    return None


def diff_paths(a, b, path=()):
    """Paths at which two reports differ. Objects are descended; anything else is compared whole."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(path + (k,))
            else:
                out += diff_paths(a[k], b[k], path + (k,))
        return out
    return [] if a == b else [path]


def probe_verdict(base, results, volatile=()):
    """What the probes of one fact show about one fixture.
      decisive  a probe fails, errors, or changes the report somewhere that is not advisory output: the fixture
                depends on the fact, so a badly typed value that passes is a hole
      unscored  every probe passes and the only output that changes sits under a key named advisor*: the module
                reads the fact and, by its own report, does not score it
      inert     every probe passes and the report is the same: on this fixture nothing reads the fact (its level
                or profile does not evaluate the control, or an alternative already satisfies the rule)
    `volatile` holds report paths that differ between two evaluations of the unchanged fixture (timestamps)."""
    verdict = "inert"
    for kind, r in results:
        if kind != "ok" or not passes(r):
            return "decisive"
        changed = [d for d in diff_paths(base, r) if not any(d[:len(v)] == v for v in volatile)]
        if not changed:
            continue
        if all(any(ADVISORY_KEY.search(str(k)) for k in d) for d in changed):
            verdict = "unscored"
        else:
            return "decisive"
    return verdict


def ref_cases(paths):
    """[(case id, document)] for the reference cases, the control first; nothing when no path was found."""
    if not paths:
        return []
    return [(CONTROL, input_refs.document(paths, False))] + [(c, input_refs.document(paths, v)) for c, v in REF_VALUES]


def module_refs(eps, layout, ev):
    """{entrypoint: [leaf input paths]} from the sources of each entrypoint's module and what they reference."""
    files = [f for f in rego_files() if not TEST_RE.search(f.relative_to(ROOT).as_posix())]
    chunks = [files[i:i + PARSE_CHUNK] for i in range(0, len(files), PARSE_CHUNK)]
    asts = {}
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        for chunk, res in zip(chunks, ex.map(
                lambda ch: ev.parse_modules({str(f): f.read_text(errors="ignore") for f in ch}), chunks)):
            for f in chunk:
                asts[f] = res[str(f)]
    scan = input_refs.Scan(asts).run()
    out = {}
    for e in eps:
        if e not in layout:
            continue
        d = layout[e][0]
        cl = input_refs.closure(scan, [f for f in files if d in f.parents])
        out[e] = input_refs.maximal(set().union(*(scan.paths[f] for f in cl)) if cl else set())
    return out


def base_cases(keys):
    cases = [("empty", {}), ("no_input", None)]
    if keys:
        cases += [("keys_null", {k: None for k in keys}), ("keys_str_true", {k: "true" for k in keys}),
                  ("keys_str_num", {k: "1" for k in keys})]
    return cases


# ---------------------------------------------------------------- accepted cases
def glob_re(pattern):
    """`*` is the only wildcard: case ids hold `[0]`, `?` and `.` as plain text."""
    return re.compile("^" + ".*".join(re.escape(x) for x in pattern.split("*")) + "$")


def cites_document(reason, root=ROOT):
    """A reason cites a document when it holds a URL or the path of a file in this repository."""
    if re.search(r"https?://\S+\.\S+", reason):
        return True
    for tok in reason.split():
        tok = re.split(r"[#:]", tok.strip("`'\"()[]<>,;."))[0].rstrip(".,;")
        if "/" in tok and not tok.startswith("/") and ".." not in tok and (root / tok).is_file():
            return True
    return False


def parse_accepted(text, root=ROOT):
    """([(line number, package, case, kind or None, reason)], [error]) from the accepted-cases file."""
    entries, errors, seen = [], [], {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\S+) (\S+?)(?: (" + "|".join(ACCEPT_KINDS) + r"))?: (.*)$", line)
        if not m:
            errors.append(f"line {n}: not `<package> <case>: <reason>`: {line[:80]}")
            continue
        pkg, case, kind, reason = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        if len(reason) < MIN_REASON:
            errors.append(f"line {n}: {pkg} {case}: the reason is {len(reason)} characters; say why the behaviour "
                          f"is right, citing the rule id, procedure or contract (at least {MIN_REASON})")
        elif TRIVIAL_REASON.match(reason) or NO_REASON.search(reason):
            errors.append(f"line {n}: {pkg} {case}: `{reason[:60]}` is not a reason; say why the behaviour is right")
        if "*" in pkg:
            errors.append(f"line {n}: the package cannot be a pattern: {pkg}")
        if "*" in case:
            if len(case.replace("*", "")) < 4:
                errors.append(f"line {n}: {pkg} {case}: the pattern is too wide; name the mutation family or the fact")
            if not cites_document(reason, root):
                errors.append(f"line {n}: {pkg} {case}: a pattern accepts a family of cases, so its reason must cite "
                              "a document: a URL, or the path of a file in this repository that states the contract")
        if (pkg, case) in seen:
            errors.append(f"line {n}: {pkg} {case}: already listed on line {seen[(pkg, case)]}")
        seen[(pkg, case)] = n
        entries.append((n, pkg, case, kind, reason))
    return entries, errors


def load_accepted(path=None):
    path = ACCEPTED if path is None else path
    return parse_accepted(path.read_text()) if path.exists() else ([], [])


def kind_of(detail):
    return detail.split(":", 1)[0]


def apply_accepted(entries, failures, cases, scope, excused=None, known=()):
    """(accepted {(package, case): reason}, [error]). An accepted failure is not a failure. An entry is an error
    when its case is gone, when its case no longer fails (the list must not outlive what it describes), when it
    names an error or an undefined report (those are never correct), when its kind is pinned and differs, when
    its package is not an entrypoint, and when the case is also in the known-failures list.
      failures  {(package, case): "<kind>: <detail>"} as evaluated
      cases     {(package, case)} every case that was run
      scope     packages evaluated in this run (entries for other packages are left alone, for --only)
      excused   {(package, case): why} cases a probe showed not to be failures"""
    excused = excused or {}
    accepted, errors = {}, []
    for n, pkg, case, kind, reason in entries:
        where = f"{ACCEPTED.name} line {n}: {pkg} {case}"
        if pkg not in scope:
            if scope.all:
                errors.append(f"{where}: no entrypoint has this package")
            continue
        if "*" in case:
            rx = glob_re(case)
            hits = [k for k in failures if k[0] == pkg and rx.match(k[1]) and kind_of(failures[k]) in ACCEPT_KINDS
                    and (kind is None or kind_of(failures[k]) == kind)]
            if not hits:
                errors.append(f"{where}: the pattern matches no failing case; remove the line")
        else:
            k = (pkg, case)
            hits = []
            if k not in cases:
                errors.append(f"{where}: the case no longer exists (fixture or fact changed); remove the line")
            elif k in excused:
                errors.append(f"{where}: the harness no longer counts this as a failure ({excused[k]}); remove the line")
            elif k not in failures:
                errors.append(f"{where}: the case no longer fails; remove the line")
            elif kind_of(failures[k]) not in ACCEPT_KINDS:
                errors.append(f"{where}: {failures[k].split(' (')[0][:90]} cannot be accepted; fix the module")
            elif kind is not None and kind_of(failures[k]) != kind:
                errors.append(f"{where}: accepted as {kind}, now {kind_of(failures[k])}; review it again")
            else:
                hits = [k]
        for k in hits:
            accepted.setdefault(k, reason)
    both = sorted(k for k in accepted if k in known)
    if both:
        errors.append(f"{len(both)} accepted cases are still in {KNOWN.name} (first: {both[0][0]} {both[0][1]}); a case "
                      "is to fix or accepted, not both: run --write-known")
    return accepted, errors


class Scope(set):
    """The packages of a run; .all is False under --only, when entries for other packages cannot be judged."""
    all = True


# ---------------------------------------------------------------- main
def pkg_of(e):
    return e.rsplit("/", 1)[0].replace("/", ".")


def run(args):
    eps = nodata.entrypoints()
    if args.only:
        eps = [e for e in eps if pkg_of(e) in args.only]
    layout = module_layout(eps)
    # one server with the tests loaded: fixtures are test-package rules, and test packages never share a
    # name with a library package, so the entrypoints evaluate as they do under `opa test`
    ev = ts = External(args.server) if args.server else Server(True)

    def evaluate(jobs):
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            return list(ex.map(lambda j: ev.query(j[0], j[1], has_input=j[1] is not NO_INPUT), jobs))

    try:
        ev.wait()
        t0 = time.time()
        # 1. candidate fixture values (tests loaded)
        cands = {e: candidate_rules(layout[e][2]) for e in eps if e in layout}
        allc = sorted({c for v in cands.values() for c in v})
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            vals = dict(zip(allc, ex.map(lambda c: ts.query(f"{c[0]}/{c[1]}", has_input=False), allc)))
        # 2. which candidates pass their entrypoint
        trials = []
        for e, cl in cands.items():
            for c in cl:
                kind, v = vals[c]
                if kind == "ok" and isinstance(v, dict) and v and len(json.dumps(v)) < 2_000_000:
                    trials.append((e, c, v))
        res = evaluate([(t[0], t[2]) for t in trials])
        passing = collections.defaultdict(list)
        for (e, c, v), (kind, r) in zip(trials, res):
            if kind == "ok" and passes(r):
                passing[e].append((c, v, sum(1 for _ in leaves(v)), score(r), r))
        fixtures = {e: select_fixtures(p) for e, p in passing.items()}
        t_fix = time.time()
        # 3. the input paths each module reads (parsed by the same server)
        refs = module_refs(eps, layout, ev)
        t_refs = time.time()
        # 4. cases. A job is (entrypoint, case id, input, fixture score, fixture label, family, path)
        jobs = []
        for e in eps:
            names = Names(layout[e][1] if e in layout else "")
            text = layout[e][1] if e in layout else ""
            for cid, inp in base_cases(input_keys(text)):
                jobs.append((e, cid, NO_INPUT if cid == "no_input" else inp, None, None, None, None))
            for cid, inp in ref_cases(refs.get(e)):
                jobs.append((e, cid, inp, None, None, None, None))
            done = []
            for label, _, fx, _, base, _ in fixtures.get(e, []):
                specs = case_specs(fx, names, done)
                done.append(fx)
                for cid, family, path in specs:
                    jobs.append((e, cid + (f"@{label}" if label else ""), mutate(fx, family, path, get(fx, path)),
                                 base, label, family, path))
        out = evaluate([(j[0], j[2]) for j in jobs])
        t_cases = time.time()
        # 5. verdicts
        failures, spec = {}, {}
        control = {e: (kind, r) for (e, cid, *_), (kind, r) in zip(jobs, out) if cid == CONTROL}
        for (e, cid, inp, base, label, family, path), (kind, r) in zip(jobs, out):
            pkg = pkg_of(e)
            if cid == CONTROL:
                continue
            if kind == "error":
                failures[(pkg, cid)] = f"error: {r}"
            elif kind == "undefined":
                failures[(pkg, cid)] = "undefined: compliance_report is undefined"
            elif passes(r):
                failures[(pkg, cid)] = f"pass: compliant={json.dumps(r.get('compliant'))} score={json.dumps(score(r))}"
                if cid.startswith("refs_") and control.get(e, ("", None))[0] == "ok" and passes(control[e][1]):
                    failures[(pkg, cid)] += " (every fact boolean false passes too)"
                elif family is not None:
                    spec[(pkg, cid)] = (e, label, family, path)
            elif base is not None and score(r) is not None and score(r) > base:
                failures[(pkg, cid)] = f"score-rise: {score(r)} > fixture {base}"
            elif cid.startswith("refs_") and control.get(e, ("", None))[0] == "ok" and fewer(r, control[e][1]):
                failures[(pkg, cid)] = f"fewer-findings: {fewer(r, control[e][1])}"
        # 6. a fixture case that passes: does this fixture depend on the fact at all?
        excused = excuse(spec, failures, fixtures, passing, evaluate)
    finally:
        ev.stop()
    for k in excused:
        del failures[k]
    cases = {(pkg_of(j[0]), j[1]) for j in jobs if j[1] != CONTROL}
    stats = {"entrypoints": len(eps), "with_fixture": len(fixtures), "cases": len(cases),
             "fixtures": sum(len(v) for v in fixtures.values()),
             "with_refs": sum(1 for e in eps if refs.get(e)), "leaves": sum(len(v) for v in refs.values()),
             "seconds": round(time.time() - t0, 1), "fixture_seconds": round(t_fix - t0, 1),
             "scan_seconds": round(t_refs - t_fix, 1), "case_seconds": round(t_cases - t_refs, 1),
             "probe_seconds": round(time.time() - t_cases, 1)}
    return Run(eps, fixtures, failures, stats, refs, cases, excused)


NO_INPUT = object()
Run = collections.namedtuple("Run", "eps fixtures failures stats refs cases excused")


def excuse(spec, failures, fixtures, passing, evaluate):
    """{(package, case): why} for the passing fixture cases that are not passes on bad evidence.

    A badly typed fact that still passes is a hole only if the fixture depends on the fact. Each such case gets
    probes (see probes): the same fact at an honestly bad value. Then, per probe_verdict:
      decisive  the case stays a failure
      unscored  excused: the module's own report shows the fact feeds advisory output only
      inert     the fact decides nothing on this fixture. The same mutation is then tried on every other
                all-pass fixture of the entrypoint that holds the fact; where one of them depends on the fact
                (decisive there) and fails the mutated document, the case is excused as scoped: the module
                reads the fact strictly where its level, profile or rule calls for it. If no fixture depends on
                the fact, a case of the primary fixture stays a failure and its detail says so: nothing shows
                the fact is ever read, which is a fixture to add or a line for the accepted list, not something
                to wave through. On a secondary fixture the same finding is `unread` and is not a failure: a
                secondary is extra coverage, often written for another purpose (a not-applicable input, another
                module's green input that this entrypoint also passes), and only what it positively shows counts.
    A case with no probe (a string-typed field, an object holding anything but booleans) stays a failure.
    `evaluate` takes [(entrypoint, input)] and returns [(kind, report)]."""
    by_label = {e: {t[0]: t for t in fx} for e, fx in fixtures.items()}
    # the probes of each (entrypoint, fixture, path), and the unchanged fixture once more for volatile output
    want = {}
    for k, (e, label, family, path) in spec.items():
        fx = by_label[e][label][2]
        docs = probes(fx, path)
        if docs is not None:
            want[(e, label, path)] = docs
    keys = sorted(want, key=lambda t: (t[0], t[1], fmt(t[2])))
    again = sorted({(e, label) for e, label, _ in keys})
    res = evaluate([(e, by_label[e][label][2]) for e, label in again] + [(e, d) for (e, l, p) in keys for d in want[(e, l, p)]])
    volatile = {}
    for (e, label), (kind, r) in zip(again, res):
        volatile[(e, label)] = [tuple(d) for d in diff_paths(by_label[e][label][5], r)] if kind == "ok" else [()]
    verdicts, i = {}, len(again)
    for key in keys:
        n = len(want[key])
        verdicts[key] = probe_verdict(by_label[key[0]][key[1]][5], res[i:i + n], volatile[(key[0], key[1])])
        i += n
    excused, inert = {}, []
    for k, (e, label, family, path) in sorted(spec.items()):
        v = verdicts.get((e, label, path))
        if v == "unscored":
            excused[k] = "unscored: the honestly bad value changes advisory output only"
        elif v == "inert":
            inert.append(k)
    # inert here: is the fact read, and the mutation caught, on another all-pass fixture?
    others, trial = {}, []
    for k in inert:
        e, label, family, path = spec[k]
        here = json.dumps(by_label[e][label][2], sort_keys=True)
        for c, fx, _, _, rep in good_fixtures(passing[e]):
            if json.dumps(fx, sort_keys=True) == here:
                continue
            docs = probes(fx, path)
            v = get(fx, path)
            if docs is None or (family == "numstr" and not is_num(v)) or (family.startswith("bool") and not isinstance(v, bool)):
                continue
            others.setdefault(k, []).append((c, rep, len(trial), len(docs)))
            trial += [(e, fx)] + [(e, d) for d in docs] + [(e, mutate(fx, family, path, v))]
    res = evaluate(trial) if trial else []
    for k in inert:
        for c, rep, i, n in others.get(k, []):
            vol = [tuple(d) for d in diff_paths(rep, res[i][1])] if res[i][0] == "ok" else [()]
            kind, r = res[i + 1 + n]
            if probe_verdict(rep, res[i + 1:i + 1 + n], vol) == "decisive" and kind == "ok" and not passes(r):
                excused[k] = f"scoped: nothing reads the fact on this fixture; data.{c[0].replace('/', '.')}.{c[1]} depends on it and fails this mutation"
                break
        else:
            if spec[k][1]:
                excused[k] = "unread: nothing reads the fact on this secondary fixture or on any other"
            else:
                failures[k] += " (inert: the honestly bad value passes too, and no all-pass fixture depends on the fact)"
    return excused


def load_known():
    known = {}
    if KNOWN.exists():
        for line in KNOWN.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                pkg, cid, reason = line.split(" ", 2)
                known[(pkg, cid)] = reason
    return known


def write_known(failures, fixtures, eps, stats, accepted=0):
    pkgs = {pkg_of(e) for e in eps}
    withfx = {pkg_of(e) for e in fixtures}
    lines = ["# Generated by scripts/check_bad_input_fails.py --write-known. Known bad-input failures (issue #301):",
             "# entrypoints that pass, go undefined or error on empty / missing / null / string-typed input.",
             "# `make check-bad-input` fails only on a failure NOT listed here. Fix the module, then regenerate.",
             "# This is the list TO FIX. Behaviour that was reviewed and is right is in bad_input_accepted.txt",
             "# (written by hand, one reason per line) and is never written here.",
             "# Format: <package> <case> <kind>: <detail>. Kinds: pass, fewer-findings, score-rise, undefined, error.",
             f"# {stats['entrypoints']} entrypoints, {stats['with_fixture']} with an all-pass fixture "
             f"({stats['fixtures']} fixtures), {stats['cases']} cases, {len(failures)} failures in "
             f"{len({p for p, _ in failures})} packages; {accepted} more accepted.",
             "# Entrypoints without an all-pass fixture (base and reference cases only): "
             + str(len(pkgs - withfx)) + f"; entrypoints with reference cases: {stats['with_refs']}", ""]
    lines += [f"{p} {c} {r}" for (p, c), r in sorted(failures.items())]
    KNOWN.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write-known", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--summary", help="write the new failures per package, split by kind, to this file")
    ap.add_argument("--json", help="write every failure, accepted and excused case and the fixtures to this file")
    ap.add_argument("--lint-accepted", action="store_true",
                    help="check the form of the accepted-cases file and stop (no OPA; run it after editing the file)")
    ap.add_argument("--server", help="use this running OPA server (library + tests loaded) instead of starting one")
    ap.add_argument("--accepted", help="read accepted cases from this file instead (to try a merged list before committing it)")
    args = ap.parse_args()
    if args.accepted:
        global ACCEPTED
        ACCEPTED = pathlib.Path(args.accepted).resolve()
        if not ACCEPTED.exists():
            sys.exit(f"no such file: {args.accepted}")
    entries, form_errors = load_accepted()
    for msg in form_errors:
        print(f"  ACCEPTED {ACCEPTED.name} {msg}")
    if args.lint_accepted or form_errors:
        print(f"{ACCEPTED}: {len(entries)} entries, {len(form_errors)} errors" + (
            "; fix the form before the cases can be judged" if form_errors and not args.lint_accepted else ""))
        return 1 if form_errors else 0
    r = run(args)
    eps, fixtures, stats, refs = r.eps, r.fixtures, r.stats, r.refs
    scope = Scope(pkg_of(e) for e in eps)
    scope.all = not args.only
    known = {} if args.write_known else load_known()
    accepted, acc_errors = apply_accepted(entries, r.failures, r.cases, scope, r.excused, known)
    failures = {k: v for k, v in r.failures.items() if k not in accepted}
    if args.write_known:
        write_known(failures, fixtures, eps, stats, len(accepted))
        print(f"wrote {KNOWN.relative_to(ROOT)}: {len(failures)} failures ({len(accepted)} accepted, not written)")
        for msg in acc_errors:
            print(f"  ACCEPTED {msg}")
        return 1 if acc_errors else 0
    new = {k: v for k, v in failures.items() if k not in known}
    stale = sorted(k for k in known if k[0] in scope and k not in failures)
    why = collections.Counter(v.split(":", 1)[0] for v in r.excused.values())
    print(f"bad input: {stats['entrypoints']} entrypoints, {stats['with_fixture']} with an all-pass fixture "
          f"({stats['fixtures']} fixtures), {stats['with_refs']} with reference cases ({stats['leaves']} input paths), "
          f"{stats['cases']} cases in {stats['seconds']}s (fixtures {stats['fixture_seconds']}s, source scan "
          f"{stats['scan_seconds']}s, cases {stats['case_seconds']}s, probes {stats['probe_seconds']}s); "
          f"{len(failures)} failures ({len(failures) - len(new)} known, {len(new)} new); {len(stale)} known entries now hold")
    kinds = collections.Counter(kind_of(v) for v in failures.values())
    print("  by kind: " + (", ".join(f"{k} {n}" for k, n in sorted(kinds.items())) or "none"))
    print(f"  not failures: {len(accepted)} accepted with a reason ({ACCEPTED.name}); {len(r.excused)} passing fixture "
          f"cases where the fixture does not depend on the fact ({why['unscored']} unscored, {why['scoped']} scoped, "
          f"{why['unread']} unread on a secondary fixture)")
    for (p, c), v in sorted(new.items()):
        print(f"  NEW {p} {c} {v}")
    for msg in acc_errors:
        print(f"  ACCEPTED {msg}")
    if stale:
        print("  stale known entries (module fixed, case gone, accepted or excused; run --write-known):")
        for p, c in stale:
            note = " (accepted)" if (p, c) in accepted else f" ({r.excused[(p, c)].split(':')[0]})" if (p, c) in r.excused \
                else "" if (p, c) in r.cases else " (no such case now)"
            print(f"    {p} {c}{note}")
    if args.verbose:
        for (p, c), v in sorted(failures.items()):
            if (p, c) in known:
                print(f"  known {p} {c} {v}")
        for (p, c), v in sorted(accepted.items()):
            print(f"  accepted {p} {c} {kind_of(r.failures[(p, c)])}: {v}")
        for (p, c), v in sorted(r.excused.items()):
            print(f"  excused {p} {c} {v}")
        for e, fxs in sorted(fixtures.items()):
            for label, c, _, n, s, _ in fxs:
                print(f"  fixture {e}{' @' + label if label else ''}: data.{c[0].replace('/', '.')}.{c[1]} ({n} leaves, score {s})"
                      + (" (rule name suggests a failing case; no other object passes)" if BAD_NAME.search(c[1]) else ""))
        for e in eps:
            print(f"  refs {e}: {len(refs.get(e) or [])} input paths")
    if args.summary:
        per = collections.defaultdict(collections.Counter)
        for (pk, _), v in new.items():
            per[pk][kind_of(v)] += 1
        lines = [f"{pk} " + " ".join(f"{k}={n}" for k, n in sorted(c.items())) for pk, c in sorted(per.items())]
        pathlib.Path(args.summary).write_text("\n".join(lines) + "\n")
    if args.json:
        doc = {"stats": stats,
               "fixtures": {e: [{"label": t[0], "rule": f"data.{t[1][0].replace('/', '.')}.{t[1][1]}", "leaves": t[3]}
                                for t in fxs] for e, fxs in sorted(fixtures.items())},
               "failures": {f"{p} {c}": v for (p, c), v in sorted(failures.items())},
               "accepted": {f"{p} {c}": v for (p, c), v in sorted(accepted.items())},
               "excused": {f"{p} {c}": v for (p, c), v in sorted(r.excused.items())},
               "new": sorted(f"{p} {c}" for p, c in new), "stale": [f"{p} {c}" for p, c in stale],
               "accepted_errors": acc_errors,
               # line numbers of accepted entries that are not needed (fixed, gone, excused, matching nothing)
               "accepted_unneeded_lines": sorted({int(m.group(1)) for m in (re.search(r" line (\d+): .*remove the line", e)
                                                                           for e in acc_errors) if m})}
        pathlib.Path(args.json).write_text(json.dumps(doc, indent=1) + "\n")
    return 1 if args.check and (new or acc_errors) else 0


if __name__ == "__main__":
    sys.exit(main())
