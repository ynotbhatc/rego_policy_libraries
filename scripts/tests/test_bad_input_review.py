#!/usr/bin/env python3
"""Unit tests for what lets the bad-input check tell a defect from behaviour that is right: the accepted-cases
file, fixture selection (several all-pass fixtures, no package aliases, no failing-case objects), the names a
module's code reads a fact by, the probes that show whether a fixture depends on a fact, and the small repo
checks added with them (library test_* rules, declared totals behind a named constant).

    python3 -m unittest discover -s scripts/tests        (run by `make check-bad-input`)

No OPA is needed: evaluation is replaced by a function that plays a module.
"""
import pathlib, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_bad_input_fails as bad  # noqa: E402
import check_no_library_test_rules as libtests  # noqa: E402
import rego_ast  # noqa: E402

GOOD = "the fact is a decimal string by the collector contract, see section 4 of the STIG contract"


def scope(*pkgs, whole=True):
    s = bad.Scope(pkgs)
    s.all = whole
    return s


class AcceptedFormTest(unittest.TestCase):
    def parse(self, text):
        return bad.parse_accepted(text, ROOT)

    def test_a_line_is_package_case_reason(self):
        entries, errs = self.parse(f"# header\n\na.main numstr:x.y[0].z: {GOOD}\n")
        self.assertEqual(errs, [])
        self.assertEqual(entries, [(3, "a.main", "numstr:x.y[0].z", None, GOOD)])

    def test_the_kind_may_be_pinned(self):
        entries, errs = self.parse(f"a.main refs_null fewer-findings: {GOOD}\n")
        self.assertEqual(errs, [])
        self.assertEqual(entries[0][2:4], ("refs_null", "fewer-findings"))

    def test_a_reason_is_mandatory_and_not_trivial(self):
        for reason in ("", "by design", "By design.", "n/a", "N/A", "correct by design", "expected behaviour",
                       "works as intended", "too short to say why", "wontfix", "see report"):
            _, errs = self.parse(f"a.main drop:x: {reason}\n")
            self.assertEqual(len(errs), 1, reason)
        _, errs = self.parse("a.main drop:x: the harness cannot tell an advisory fact from a scored one here\n")
        self.assertIn("not a reason", errs[0])
        _, errs = self.parse("a.main drop:x:\n")
        self.assertEqual(len(errs), 1)

    def test_a_malformed_line_and_a_duplicate_are_errors(self):
        _, errs = self.parse("just some words\n")
        self.assertIn("not `<package> <case>: <reason>`", errs[0])
        _, errs = self.parse(f"a.main drop:x: {GOOD}\na.main drop:x: {GOOD}\n")
        self.assertIn("already listed on line 1", errs[0])
        _, errs = self.parse(f"a.* drop:x: {GOOD}\n")
        self.assertIn("package cannot be a pattern", errs[0])

    def test_a_pattern_must_cite_a_document_and_not_be_everything(self):
        _, errs = self.parse(f"a.main numstr:*: {GOOD}\n")
        self.assertEqual(len(errs), 1)
        self.assertIn("must cite a document", errs[0])
        _, errs = self.parse("a.main numstr:*: decimal strings are the documented contract, CONTRIBUTING.md is not a path with a slash\n")
        self.assertEqual(len(errs), 1)
        _, errs = self.parse("a.main numstr:*: decimal strings are the contract in scripts/bad_input_accepted.txt.\n")
        self.assertEqual(errs, [])
        _, errs = self.parse("a.main numstr:*: decimal strings per https://example.org/contract.html section 4\n")
        self.assertEqual(errs, [])
        _, errs = self.parse("a.main *: everything is fine, see scripts/bad_input_accepted.txt for the contract\n")
        self.assertIn("too wide", errs[0])
        _, errs = self.parse("a.main numstr:*: the contract is in scripts/no_such_file.txt, which does not exist\n")
        self.assertEqual(len(errs), 1)

    def test_cites_document(self):
        self.assertTrue(bad.cites_document("see `scripts/bad_input_accepted.txt#rules`.", ROOT))
        self.assertTrue(bad.cites_document("(scripts/bad_input_accepted.txt:12)", ROOT))
        self.assertFalse(bad.cites_document("see ../outside/file.txt and /etc/hosts", ROOT))
        self.assertFalse(bad.cites_document("NIST SP 800-171 3.5.8", ROOT))

    def test_the_committed_file_is_well_formed(self):
        entries, errs = bad.load_accepted()
        self.assertEqual(errs, [])

    def test_glob_star_is_the_only_wildcard(self):
        rx = bad.glob_re("numstr:users[0].*")
        self.assertTrue(rx.match("numstr:users[0].uid"))
        self.assertFalse(rx.match("numstr:users0.uid"))          # [0] is text, not a character class
        self.assertFalse(rx.match("boolstr:users[0].uid"))
        self.assertTrue(bad.glob_re("*:a.b").match("drop:a.b"))
        self.assertFalse(bad.glob_re("*:a.b").match("drop:aXb"))  # . is text


class AcceptedApplyTest(unittest.TestCase):
    FAIL = {("a.main", "numstr:x"): "pass: compliant=true score=100",
            ("a.main", "numstr:y@l2"): "pass: compliant=true score=100",
            ("a.main", "refs_null"): "fewer-findings: 1 violations, 5 with every fact boolean false",
            ("a.main", "empty"): "undefined: compliance_report is undefined",
            ("b.main", "drop:f"): "pass: compliant=true score=null"}
    CASES = set(FAIL) | {("a.main", "numstr:z"), ("a.main", "drop:adv")}

    def apply(self, lines, **kw):
        entries, errs = bad.parse_accepted("\n".join(lines) + "\n", ROOT)
        self.assertEqual(errs, [])
        kw.setdefault("scope", scope("a.main", "b.main"))
        return bad.apply_accepted(entries, self.FAIL, self.CASES, kw["scope"], kw.get("excused"), kw.get("known", ()))

    def test_an_accepted_failure_is_taken(self):
        acc, errs = self.apply([f"a.main numstr:x: {GOOD}", f"b.main drop:f: {GOOD}"])
        self.assertEqual(errs, [])
        self.assertEqual(set(acc), {("a.main", "numstr:x"), ("b.main", "drop:f")})
        self.assertEqual(acc[("a.main", "numstr:x")], GOOD)

    def test_a_case_that_no_longer_fails_is_an_error(self):
        acc, errs = self.apply([f"a.main numstr:z: {GOOD}"])
        self.assertEqual(acc, {})
        self.assertIn("no longer fails", errs[0])

    def test_a_case_that_no_longer_exists_is_an_error(self):
        acc, errs = self.apply([f"a.main numstr:gone: {GOOD}"])
        self.assertEqual(acc, {})
        self.assertIn("no longer exists", errs[0])

    def test_a_case_the_harness_now_excuses_is_an_error(self):
        _, errs = self.apply([f"a.main drop:adv: {GOOD}"], excused={("a.main", "drop:adv"): "unscored: advisory only"})
        self.assertIn("no longer counts this as a failure (unscored", errs[0])

    def test_an_undefined_report_cannot_be_accepted(self):
        acc, errs = self.apply([f"a.main empty: {GOOD}"])
        self.assertEqual(acc, {})
        self.assertIn("cannot be accepted", errs[0])

    def test_a_pinned_kind_must_still_be_the_kind(self):
        acc, errs = self.apply([f"a.main refs_null fewer-findings: {GOOD}"])
        self.assertEqual((len(acc), errs), (1, []))
        acc, errs = self.apply([f"a.main refs_null pass: {GOOD}"])
        self.assertEqual(acc, {})
        self.assertIn("accepted as pass, now fewer-findings", errs[0])

    def test_a_pattern_takes_the_family_and_must_match_something(self):
        cite = "decimal strings are the contract in scripts/bad_input_accepted.txt for this family"
        acc, errs = self.apply([f"a.main numstr:*: {cite}"])
        self.assertEqual(errs, [])
        self.assertEqual(set(acc), {("a.main", "numstr:x"), ("a.main", "numstr:y@l2")})     # not numstr:z: it holds
        acc, errs = self.apply([f"a.main boolstr:*: {cite}"])
        self.assertEqual(acc, {})
        self.assertIn("matches no failing case", errs[0])
        acc, errs = self.apply([f"a.main empt*: {cite}"])                                   # undefined is never taken
        self.assertEqual(acc, {})

    def test_the_fixture_suffix_is_part_of_the_case(self):
        acc, errs = self.apply([f"a.main numstr:y@l2: {GOOD}"])
        self.assertEqual((set(acc), errs), ({("a.main", "numstr:y@l2")}, []))
        _, errs = self.apply([f"a.main numstr:y: {GOOD}"])
        self.assertIn("no longer exists", errs[0])

    def test_an_unknown_package_is_an_error_unless_the_run_is_partial(self):
        _, errs = self.apply([f"c.main drop:f: {GOOD}"])
        self.assertIn("no entrypoint has this package", errs[0])
        acc, errs = self.apply([f"b.main drop:f: {GOOD}"], scope=scope("a.main", whole=False))
        self.assertEqual((acc, errs), ({}, []))

    def test_a_case_is_to_fix_or_accepted_not_both(self):
        _, errs = self.apply([f"a.main numstr:x: {GOOD}"], known={("a.main", "numstr:x"): "pass"})
        self.assertIn("not both", errs[0])
        cite = "decimal strings are the contract in scripts/bad_input_accepted.txt for this family"
        known = {("a.main", "numstr:x"): "pass", ("a.main", "numstr:y@l2"): "pass"}
        acc, errs = self.apply([f"a.main numstr:*: {cite}"], known=known)
        self.assertEqual(len(errs), 1)                               # one line for the lot, not one per case
        self.assertIn("2 accepted cases are still in", errs[0])
        self.assertEqual(len(acc), 2)


class NamesTest(unittest.TestCase):
    SRC = '''package m
# uid of the user, and loaded modules      (a comment names nothing)
v contains msg if {
	input.sshd.permit_root_login != false
	object.get(input, ["net", "ip_forward"], null) != 0
	input.sysctl["net.ipv4.conf.all.rp_filter"] == 1
	some name in {"Audit Logon", "aide"}
	fact("crypto.fips_mode")
	msg := "Ensure password expiry is 365 days # not a comment"
	raw := `title: gui is removed`
}
'''

    def setUp(self):
        self.n = bad.Names(self.SRC)

    def test_code_identifiers_whole_strings_and_path_segments_are_names(self):
        for name in ("sshd", "permit_root_login", "ip_forward", "net.ipv4.conf.all.rp_filter", "Audit Logon", "aide",
                     "fips_mode", "crypto"):
            self.assertTrue(self.n.has(name), name)

    def test_comments_titles_and_messages_are_not(self):
        for name in ("uid", "loaded", "modules", "password", "expiry", "gui", "title", "comment", "days"):
            self.assertFalse(self.n.has(name), name)

    def test_strip_keeps_lines_and_a_hash_inside_a_string(self):
        code, strings = bad.strip_rego('a := "x # y" # gone\nb := `r1\nr2`\nc := "q\\"t"\n')
        self.assertEqual(code.count("\n"), 4)
        self.assertNotIn("gone", code)
        self.assertEqual(strings, ["x # y", "r1\nr2", 'q"t'])
        self.assertIn("c :=", code)

    def test_fixture_cases_skip_a_leaf_named_only_in_a_comment_or_a_title(self):
        fx = {"m": {"uid": 0, "gui": True, "permit_root_login": False, "other": 1}}
        src = 'x if input.m.permit_root_login == false # uid\nt := "Ensure gui is removed"\ny if input.m.other'
        ids = [c for c, _ in bad.fixture_cases(fx, src)]
        self.assertTrue(any(c.endswith("permit_root_login") for c in ids))
        self.assertFalse(any("uid" in c or "gui" in c for c in ids))


class CandidateTest(unittest.TestCase):
    SRC = '''package sentinel.terraform_test
import rego.v1
pkg := data.sentinel.terraform
other := data.fixtures.shared.good
good_plan := {"format_version": "1.2"}
# commented := {"a": 1}
derived := object.union(good_plan, {"x": 1})
helper(x) := x
test_it if pkg.allow with input as good_plan
text := `
hidden := {"in": "a raw string"}
`
'''

    def test_a_package_alias_is_not_a_candidate(self):
        got = bad.candidate_names(self.SRC, {"sentinel", "sentinel.terraform"})
        self.assertEqual(got, ["derived", "good_plan", "other", "text"])

    def test_a_reference_to_a_rule_of_another_package_stays(self):
        self.assertIn("other", bad.candidate_names(self.SRC, {"sentinel.terraform", "fixtures.shared"}))
        self.assertNotIn("other", bad.candidate_names(self.SRC, {"fixtures.shared.good"}))


def fx_tuple(pkg, rule, value):
    return ((pkg, rule), value, sum(1 for _ in bad.leaves(value)), 100, {"compliant": True})


class SelectFixturesTest(unittest.TestCase):
    L1 = {"level": 1, "a": True, "b": True, "c": 5}
    L2 = {"level": 2, "a": True, "b": True, "d": True}

    def labels(self, passing, **kw):
        return [(t[0], t[1][1]) for t in bad.select_fixtures(passing, **kw)]

    def test_the_largest_is_primary_and_a_second_level_is_run_too(self):
        got = self.labels([fx_tuple("t", "l2_input", self.L2), fx_tuple("t", "l1_input", self.L1)])
        self.assertEqual(got, [("", "l2_input"), ("l1_input", "l1_input")])

    def test_first_of_equal_size_stays_primary(self):
        got = self.labels([fx_tuple("t", "zz", self.L1), fx_tuple("t", "aa", self.L2)])
        self.assertEqual(got[0], ("", "zz"))

    def test_an_object_named_as_a_failing_case_is_not_preferred(self):
        big_bad = dict(self.L1, extra=1, more=2)
        got = self.labels([fx_tuple("t", "bad_container", big_bad), fx_tuple("t", "good_input", self.L1)])
        self.assertEqual(got, [("", "good_input")])
        # ... but it is used, and marked, when nothing else passes
        self.assertEqual(self.labels([fx_tuple("t", "bad_container", big_bad)]), [("", "bad_container")])

    def test_bad_name(self):
        for name in ("bad_container", "noncompliant_input", "input_missing_mfa", "failing_fixture", "no_mfa",
                     "invalid_plan", "empty_input", "without_tls"):
            self.assertTrue(bad.BAD_NAME.search(name), name)
        for name in ("good_input", "_green", "all_pass_input", "fx", "_low", "full_input", "nominal", "notebook",
                     "baddie"):
            self.assertFalse(bad.BAD_NAME.search(name), name)

    def test_a_copy_or_a_subset_is_not_run_again(self):
        subset = {"level": 1, "a": True}
        got = self.labels([fx_tuple("t", "l1", self.L1), fx_tuple("t", "copy", dict(self.L1)), fx_tuple("t", "sub", subset)])
        self.assertEqual(got, [("", "l1")])

    def test_the_cap_holds_and_the_most_different_come_first(self):
        many = [fx_tuple("t", f"f{i}", dict(self.L1, **{f"k{i}": True, **({"big": 1, "bigger": 2} if i == 7 else {})}))
                for i in range(10)]
        got = self.labels([fx_tuple("t", "base", dict(self.L1, z1=1, z2=2, z3=3, z4=4))] + many, cap=3)
        self.assertEqual(len(got), 3)
        self.assertEqual(got[0], ("", "base"))
        self.assertEqual(got[1][0], "f7")

    def test_two_chosen_rules_of_one_name_are_qualified(self):
        got = self.labels([fx_tuple("t/a", "base", dict(self.L1, more=1)), fx_tuple("t/a", "green", self.L1 | {"p": 1}),
                           fx_tuple("t/b", "green", self.L2)])
        self.assertEqual({l for l, _ in got[1:]}, {"t.a.green", "t.b.green"})
        # ... and so is a secondary that shares the primary's rule name
        got = self.labels([fx_tuple("m/main_test", "_green", dict(self.L1, more=1)), fx_tuple("o/main_test", "_green", self.L2)])
        self.assertEqual(got, [("", "_green"), ("o.main_test._green", "_green")])

    def test_a_secondary_is_a_variant_of_the_primary(self):
        other = {"scope": {"applies": False}, "govern": {"a": True, "b": True}, "map": {"c": True}}
        passing = [fx_tuple("m/main_test", "green", dict(self.L1, more=1)), fx_tuple("m/main_test", "l2", self.L2),
                   fx_tuple("other/main_test", "na_for_m", other)]
        self.assertEqual(self.labels(passing), [("", "green"), ("l2", "l2")])        # L2 shares 3 of its 4 paths
        half = {"level": 3, "a": True, "q": 1, "r": 2}                                 # exactly half: taken
        self.assertIn(("half", "half"), self.labels(passing + [fx_tuple("m/main_test", "half", half)]))

    def test_a_secondary_gets_cases_only_for_what_it_adds(self):
        src = "input.a input.b input.c input.d input.level"
        ids = [c for c, _, _ in bad.case_specs(self.L2, src, [self.L1])]
        self.assertEqual(sorted({c.split(":")[1] for c in ids}), ["d", "level"])      # a, b: same value in L1
        self.assertIn("boolstr:d", ids)
        self.assertIn("numstr:level", ids)
        flipped = dict(self.L1, a=False)
        self.assertIn("boolstr:a", [c for c, _, _ in bad.case_specs(flipped, src, [self.L1])])
        one = {"a": 1}
        self.assertIn("numstr:a", [c for c, _, _ in bad.case_specs(one, src, [self.L1])])  # 1 is not true

    def test_good_fixtures_are_distinct_and_well_named(self):
        got = bad.good_fixtures([fx_tuple("t", "a", self.L1), fx_tuple("t", "b", dict(self.L1)),
                                 fx_tuple("t", "bad_x", self.L2)])
        self.assertEqual([t[0][1] for t in got], ["a"])


class ProbeTest(unittest.TestCase):
    def test_probe_documents(self):
        fx = {"m": {"flag": True, "n": 5, "zero": 0, "s": "x", "grp": {"a": True, "b": {"c": False}}, "mixed": {"a": True, "n": 1}}}
        self.assertEqual([d["m"]["flag"] for d in bad.probes(fx, ("m", "flag"))], [False])
        self.assertEqual([d["m"]["n"] for d in bad.probes(fx, ("m", "n"))], [0, -10**9, 10**9])
        self.assertEqual([d["m"]["zero"] for d in bad.probes(fx, ("m", "zero"))], [-10**9, 10**9])
        self.assertEqual(bad.probes(fx, ("m", "grp"))[0]["m"]["grp"], {"a": False, "b": {"c": True}})
        self.assertIsNone(bad.probes(fx, ("m", "s")))            # no honestly bad string to try
        self.assertIsNone(bad.probes(fx, ("m", "mixed")))        # dropping it removes more than booleans
        self.assertIsNone(bad.probes(fx, ("m", "absent")))
        self.assertTrue(fx["m"]["flag"])                         # the fixture is not changed

    def test_diff_paths(self):
        a = {"compliant": True, "advisories": ["x"], "s": {"n": 1, "t": 2}}
        b = {"compliant": True, "advisories": [], "s": {"n": 1, "t": 3}, "new": 1}
        self.assertEqual(bad.diff_paths(a, b), [("advisories",), ("new",), ("s", "t")])
        self.assertEqual(bad.diff_paths(a, a), [])

    def test_verdicts(self):
        base = {"compliant": True, "violations": [], "advisories": [], "advisory_count": 0, "generated": "t1"}
        same = dict(base)
        adv = dict(base, advisories=["weak"], advisory_count=1)
        echo = dict(base, summary={"mfa": False})
        self.assertEqual(bad.probe_verdict(base, [("ok", same)]), "inert")
        self.assertEqual(bad.probe_verdict(base, [("ok", adv)]), "unscored")
        self.assertEqual(bad.probe_verdict(base, [("ok", same), ("ok", adv)]), "unscored")
        self.assertEqual(bad.probe_verdict(base, [("ok", echo)]), "decisive")        # other output changed: not shown unscored
        self.assertEqual(bad.probe_verdict(base, [("ok", dict(base, compliant=False))]), "decisive")
        self.assertEqual(bad.probe_verdict(base, [("ok", adv), ("ok", dict(base, violations=["v"], compliant=False))]), "decisive")
        self.assertEqual(bad.probe_verdict(base, [("undefined", None)]), "decisive")
        self.assertEqual(bad.probe_verdict(base, [("error", "boom")]), "decisive")
        # a finding beside a still-passing verdict is scored output
        self.assertEqual(bad.probe_verdict(base, [("ok", dict(base, violations=["v"]))]), "decisive")
        # a timestamp differs on every evaluation: it is not output of the fact
        self.assertEqual(bad.probe_verdict(base, [("ok", dict(base, generated="t2"))]), "decisive")
        self.assertEqual(bad.probe_verdict(base, [("ok", dict(base, generated="t2"))], [("generated",)]), "inert")


def module(doc):
    """A module with two levels. Level 1 scores `mfa` and `days <= 90`; level 2 also scores `fips`, strictly, and
    `banner` laxly (a string passes: a hole); `note` only ever feeds advisories; `x or y` is an either-or rule."""
    if doc is bad.NO_INPUT or not isinstance(doc, dict):
        return "ok", {"compliant": False, "violations": ["no input"], "advisories": []}
    v = []
    if doc.get("mfa") is not True:
        v.append("mfa")
    if not bad.is_num(doc.get("days")) or doc["days"] > 90:
        v.append("days")
    if doc.get("x") is not True and doc.get("y") is not True:
        v.append("x or y")
    if doc.get("level") == 2:
        if doc.get("fips") is not True:
            v.append("fips")
        if doc.get("banner") is False or "banner" not in doc:
            v.append("banner")
        if bad.is_num(doc.get("depth")) and doc["depth"] < 3:        # a decimal string is let through: a hole
            v.append("depth")
    adv = ["note"] if doc.get("note") is not True else []
    return "ok", {"compliant": not v, "violations": v, "advisories": adv, "advisory_count": len(adv)}


class ExcuseTest(unittest.TestCase):
    L1 = {"level": 1, "mfa": True, "days": 30, "x": True, "y": True, "fips": True, "banner": True, "depth": 5, "note": True}
    L2 = dict(L1, level=2)
    ONLY_X = {"level": 1, "mfa": True, "days": 30, "x": True}

    def run_module(self, fixtures_values, primary_cases, on=0):
        """Run the given (family, path) cases on one chosen fixture the way run() does; return (failures, excused)."""
        e = "m/main/compliance_report"
        evaluate = lambda jobs: [module(doc) for _, doc in jobs]  # noqa: E731
        passing = {e: []}
        for name, v in fixtures_values:
            kind, r = module(v)
            assert bad.passes(r), name
            passing[e].append((("m_test", name), v, sum(1 for _ in bad.leaves(v)), None, r))
        fixtures = {e: bad.select_fixtures(passing[e])}
        label, fx = fixtures[e][on][0], fixtures[e][on][2]
        failures, spec = {}, {}
        for family, path in primary_cases:
            cid = f"{family}:{bad.fmt(path)}" + (f"@{label}" if label else "")
            kind, r = module(bad.mutate(fx, family, path, bad.get(fx, path)))
            if bad.passes(r):
                failures[("m.main", cid)] = "pass: compliant=true score=null"
                spec[("m.main", cid)] = (e, label, family, path)
        excused = bad.excuse(spec, failures, fixtures, passing, evaluate)
        return failures, excused

    def test_a_strictly_read_fact_does_not_fail_at_all(self):
        failures, excused = self.run_module([("l1", self.L1)], [("boolstr", ("mfa",)), ("numstr", ("days",))])
        self.assertEqual((failures, excused), ({}, {}))

    def test_an_advisory_only_fact_is_unscored(self):
        failures, excused = self.run_module([("l1", self.L1)], [("boolstr", ("note",)), ("drop", ("note",)), ("null", ("note",))])
        self.assertEqual(len(failures), 3)
        self.assertEqual({v.split(":")[0] for v in excused.values()}, {"unscored"})
        self.assertEqual(set(excused), set(failures))

    def test_a_level_2_fact_on_a_level_1_fixture_is_scoped_when_level_2_reads_it_strictly(self):
        failures, excused = self.run_module([("l1", self.L1), ("l2", self.L2)], [("boolstr", ("fips",)), ("drop", ("fips",))])
        # (l1 and l2 are the same size; l1 is first, so it is the primary)
        self.assertEqual(set(excused), set(failures))
        self.assertTrue(all(v.startswith("scoped:") and "data.m_test.l2" in v for v in excused.values()))

    def test_without_a_level_2_fixture_it_stays_a_failure_and_says_inert(self):
        failures, excused = self.run_module([("l1", self.L1)], [("boolstr", ("fips",))])
        self.assertEqual(excused, {})
        self.assertIn("inert", failures[("m.main", "boolstr:fips")])

    def test_a_hole_at_level_2_is_not_excused_by_being_unread_at_level_1(self):
        failures, excused = self.run_module([("l1", self.L1), ("l2", self.L2)], [("boolstr", ("banner",)), ("numstr", ("depth",))])
        self.assertEqual(excused, {})                 # level 2 depends on both and lets the bad value through
        self.assertEqual(len(failures), 2)

    def test_a_hole_on_the_fixture_that_reads_the_fact_stays_a_failure(self):
        failures, excused = self.run_module([("l2", self.L2)], [("boolstr", ("banner",)), ("numstr", ("depth",))])
        self.assertEqual(excused, {})
        self.assertEqual(len(failures), 2)
        self.assertNotIn("inert", failures[("m.main", "boolstr:banner")])

    def test_on_a_secondary_an_unread_fact_is_not_a_failure_and_a_hole_still_is(self):
        na = dict(self.L1, level=1, other_module={"flag": True}, fips=False)       # holds facts nothing reads
        fixtures = [("l2", dict(self.L2, more=1)), ("na", na)]
        failures, excused = self.run_module(fixtures, [("boolstr", ("other_module", "flag")), ("boolstr", ("fips",))], on=1)
        self.assertEqual(set(failures), {("m.main", "boolstr:other_module.flag@na"), ("m.main", "boolstr:fips@na")})
        self.assertTrue(excused[("m.main", "boolstr:other_module.flag@na")].startswith("unread:"))
        self.assertTrue(excused[("m.main", "boolstr:fips@na")].startswith("scoped:"))      # level 2 reads it strictly
        # a secondary that depends on the fact and lets the bad value through is a failure like any other
        fixtures = [("l1", dict(self.L1, more=1, again=2)), ("l2", self.L2)]
        failures, excused = self.run_module(fixtures, [("boolstr", ("banner",))], on=1)
        self.assertEqual((set(failures), excused), ({("m.main", "boolstr:banner@l2")}, {}))

    def test_an_either_or_fact_is_scoped_when_a_fixture_holds_one_alternative(self):
        failures, excused = self.run_module([("l1", self.L1), ("only_x", self.ONLY_X)], [("boolopp", ("x",)), ("null", ("x",))])
        self.assertEqual(set(excused), set(failures))
        failures, excused = self.run_module([("l1", self.L1)], [("boolopp", ("x",))])
        self.assertEqual(excused, {})


class MutateTest(unittest.TestCase):
    def test_case_specs_and_mutate_agree_with_fixture_cases(self):
        fx = {"mod": {"mfa": {"enabled": True}, "days": 90, "flag": False}}
        src = "input.mod.mfa.enabled input.mod.days input.mod.flag"
        specs = bad.case_specs(fx, src)
        self.assertEqual([c for c, _, _ in specs], [c for c, _ in bad.fixture_cases(fx, src)])
        fam = {c: (f, p) for c, f, p in specs}
        self.assertEqual(fam["numstr:mod.days"], ("numstr", ("mod", "days")))
        self.assertEqual(fam["drop:mod.flag"], ("drop", ("mod", "flag")))
        self.assertEqual(bad.mutate(fx, "boolopp", ("mod", "flag"), False)["mod"]["flag"], "true")
        self.assertEqual(bad.mutate(fx, "boolno", ("mod", "flag"), False)["mod"]["flag"], "no")
        self.assertEqual(bad.mutate(fx, "numstr", ("mod", "days"), 90)["mod"]["days"], "90")
        self.assertIs(bad.get(fx, ("mod", "nope")), bad.get.MISSING)
        self.assertIs(bad.get({"a": [1]}, ("a", 3)), bad.get.MISSING)


class LibraryTestRulesTest(unittest.TestCase):
    def test_rule_heads_are_found_and_text_is_not(self):
        src = ('package p\n# test_in_comment if true\nmsg := "test_in_string if x"\ntest_a if { true }\n'
               'test_b := 1\ntest_c contains x if x := 1\ndefault test_d := false\ntest_e(x) := x\n'
               'testing := 1\nnot_test_f := 2\n\ttest_g := 3\nraw := `\ntest_h if true\n`\ntest_a if { false }\n')
        self.assertEqual(libtests.test_rules(src), ["test_a", "test_b", "test_c", "test_d", "test_e"])

    def test_which_files_are_library_files(self):
        self.assertTrue(libtests.is_library("frameworks/x/policy.rego"))
        self.assertTrue(libtests.is_library("frameworks/x/latest_rules.rego"))
        for rel in ("frameworks/x/tests/policy.rego", "frameworks/x/test_policy.rego", "frameworks/x/policy_test.rego"):
            self.assertFalse(libtests.is_library(rel), rel)

    def test_scan_and_the_allow_list(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "lib" / "tests").mkdir(parents=True)
            (root / "lib" / "policy.rego").write_text("package p\ntest_self if true\nok := 1\n")
            (root / "lib" / "tests" / "test_policy.rego").write_text("package p_test\ntest_fine if true\n")
            found = libtests.scan(root, ["lib"])
        self.assertEqual(found, [("lib/policy.rego", "test_self")])
        self.assertEqual(len(libtests.problems(found, {})), 1)
        self.assertEqual(libtests.problems(found, {("lib/policy.rego", "test_self"): "why"}), [])
        stale = libtests.problems(found, {("lib/policy.rego", "test_self"): "why", ("lib/gone.rego", "test_x"): "why"})
        self.assertEqual(len(stale), 1)
        self.assertIn("matches no rule now", stale[0])

    def test_the_tree_is_clean(self):
        self.assertEqual(libtests.problems(libtests.scan()), [])


def num(n):
    return {"type": "number", "value": n}


def var(name):
    return {"type": "var", "value": name}


def call(fn, *args):
    return {"type": "call", "value": [{"type": "ref", "value": [var(fn)]}, *args]}


class DeclaredNumberTest(unittest.TestCase):
    CONSTS = {"_declared_controls": 175, "other": 3}

    def test_literal_named_constant_and_floor(self):
        d = rego_ast.declared_number
        self.assertEqual(d(num(172), {}), 172)
        self.assertEqual(d(var("_declared_controls"), self.CONSTS), 175)
        floor = call("max", {"type": "array", "value": [var("_declared_controls"), call("count", var("all_violations"))]})
        self.assertEqual(d(floor, self.CONSTS), 175)
        self.assertEqual(d(call("max", {"type": "array", "value": [num(40), call("count", var("v"))]}), {}), 40)

    def test_a_computed_total_declares_nothing(self):
        d = rego_ast.declared_number
        self.assertIsNone(d(call("count", var("v")), self.CONSTS))
        self.assertIsNone(d(var("computed"), self.CONSTS))
        self.assertIsNone(d(call("max", {"type": "array", "value": [var("_declared_controls"), var("other")]}), self.CONSTS))
        self.assertIsNone(d(call("sum", {"type": "array", "value": [var("_declared_controls")]}), self.CONSTS))
        self.assertIsNone(d(num(1.5), {}))

    def test_constants_reads_only_plain_integer_rules(self):
        true_body = [{"index": 0, "generated": True, "terms": {"type": "boolean", "value": True}}]
        cond_body = [{"index": 0, "terms": [{"type": "ref", "value": [var("eq")]}, var("x"), num(1)]}]
        ast = {"rules": [
            {"head": {"name": "_declared_controls", "value": num(175), "assign": True}, "body": true_body},
            {"head": {"name": "when", "value": num(9), "assign": True}, "body": cond_body},
            {"head": {"name": "fallback", "value": num(1)}, "body": true_body, "default": True},
            {"head": {"name": "f", "args": [var("x")], "value": num(2)}, "body": true_body},
            {"head": {"name": "s", "value": {"type": "string", "value": "x"}}, "body": true_body},
        ]}
        self.assertEqual(rego_ast.constants(ast), {"_declared_controls": 175})


if __name__ == "__main__":
    unittest.main()
