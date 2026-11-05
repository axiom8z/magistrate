"""Checks S4's scope and counting on made-up cases in a temporary folder, with the real scanner. No real case is opened,
because S4 is a first score that runs once.

    python -I -X utf8 bench/secrets/test_s4.py <secretscore binary>
"""
import contextlib
import io
import json
import pathlib
import random
import string
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s3  # noqa: E402
import s4  # noqa: E402

failures = []
# Built here, so the repository never holds a whole token shape.
TOKEN = "gh" + "p_" + "".join(random.Random(20261104).choices(string.ascii_letters + string.digits, k=36))


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def case(id_, verdict, requires=(), tags=(), payload=None):
    return {"id": id_, "expected_verdict": verdict, "requires": list(requires), "capability_tags": list(tags), "payload": payload if payload is not None else {"url": "https://example.test/"}}


def main():
    scanner = sys.argv[1]
    rules_hash = subprocess.run([scanner, "-hash"], capture_output=True, text=True, check=True).stdout.strip()
    caught = case("caught", "block", requires=["request_body_dlp_scanning"], payload={"body": "token=" + TOKEN})
    missed = case("missed", "block", requires=["crypto_dlp_scanning"], payload={"body": "nothing the rules know"})
    tagged = case("tagged", "block", tags=["mcp_tool_result_dlp_scanning"], payload={"jsonrpc_messages": [{"result": {"text": TOKEN}}]})
    both = case("both", "block", requires=["url_dlp_scanning", "entropy_scanning"], payload={"url": "https://example.test/?k=" + TOKEN})
    elsewhere = case("elsewhere", "block", requires=["ssrf_scanning"], tags=["ssrf"], payload={"url": "http://169.254.169.254/"})
    fired_elsewhere = case("fired-elsewhere", "block", requires=["shell_analysis"], payload={"url": TOKEN})
    clean = case("clean", "allow", payload={"url": "https://example.test/docs"})
    false_hit = case("false-hit", "allow", requires=["request_body_dlp_scanning"], payload={"body": TOKEN})
    warn = case("warn", "warn", requires=["url_dlp_scanning"])

    check(s4.in_scope(caught) and s4.in_scope(tagged) and s4.in_scope(both), "a blocked case needing data-loss scanning is in scope, by `requires` or by tag")
    check(not s4.in_scope(elsewhere), "a case testing something else is out of scope")
    check(not s4.in_scope(false_hit) and not s4.in_scope(warn), "a case not expected to be blocked is never in scope")
    check(s4.kinds(both) == ["entropy_scanning", "url_dlp_scanning"], "a case can count under more than one need")

    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        cases_folder = root / "cases" / "request-body"
        cases_folder.mkdir(parents=True)
        everything = [caught, missed, tagged, both, elsewhere, fired_elsewhere, clean, false_hit, warn]
        for item in everything:
            (cases_folder / f'{item["id"]}.json').write_text(json.dumps(item), encoding="utf-8")
        drift = root / "cases" / "mcp-drift" / "one"
        drift.mkdir(parents=True)
        (drift / "manifest.json").write_text('{"no": "payload"}', encoding="utf-8")
        (root / "cases" / "broken.json").write_text("{not json", encoding="utf-8")
        (root / "cases" / "STATS.md").write_text("stats", encoding="utf-8")

        read, skipped = s4.read_cases(root)
        check({c["id"] for c in read} == {c["id"] for c in everything}, "every single-file case is read")
        check(skipped == 2, "files with no payload, or that don't parse, are counted and left out")

        set_path, results_path = root / "s4.jsonl", root / "s4.results.jsonl"
        s4.write_set(read, set_path)
        lines = {json.loads(line)["id"]: json.loads(line) for line in set_path.read_text(encoding="utf-8").splitlines()}
        check(lines["caught"]["calls"] == [["token=" + TOKEN, "body"]], "the scanner reads a payload the way it reads a call")
        check(TOKEN in lines["tagged"]["calls"][0], "a nested payload is read too")
        with open(results_path, "w", encoding="utf-8") as out:
            subprocess.run([scanner, str(set_path)], stdout=out, check=True)
        results = s3.read_results(results_path, rules_hash)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            headline = s4.summary(read, results)
        text = out.getvalue()
        check(headline["in_scope"] == 4 and headline["blocked"] == 3 and headline["recall_pct"] == "75.00", "recall counts the in-scope cases")
        check(headline["allowed_cases"] == 2 and headline["false_hits"] == 1, "false hits count the allowed cases")
        check(headline["out_of_scope"] == 3, "the rest are out of scope")
        check("of which the scanner fired on 1" in text, "a hit on an out-of-scope case is shown, and isn't credited")
        check("missed" in text.split("let through")[1].split("Every false hit")[0], "every miss is listed by case ID")
        check("false-hit github-token" in text, "every false hit is listed, with its rule")
        check(TOKEN not in text and "nothing the rules know" not in text, "no payload is ever printed")
        check(not isinstance(headline["known_format_recall"], (int, float)), "the headline doesn't pretend to know which misses were known formats")

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                s4.summary(read, results[:-1])
            check(False, "results that don't cover every case are refused")
        except SystemExit:
            check(True, "results that don't cover every case are refused")

    print(f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
