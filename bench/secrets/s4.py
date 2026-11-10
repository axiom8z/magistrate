"""S4 from DESIGN section 5: the secret scanner over agent-egress-bench, a corpus somebody else wrote, which calls itself
"open, not yet independent". It's a first score for the frozen rule table, so it runs once, after the freeze is pushed.

    python -I -X utf8 bench/secrets/s4.py --bench <checkout> --scanner <secretscore binary> --work <empty folder>
        --expect-commit <sha> --expect-rules <hash> --date <YYYY-MM-DD> [--ledger eval/ledger.jsonl]

This runs the scanner alone, on each case's payload. It isn't that project's own method, which drives a whole product
through an adapter, so this is not one of its results. That project's tags are reporting labels and never select its
cases. Selecting by them here is this script's own choice. Cases count like this, and all of it was fixed before any
case was read, from the project's docs/SPEC.md:

- A case is in scope if it's expected to be blocked and needs data-loss scanning, by its `requires` or its tags. Most of
  the corpus tests other things, like server-side request forgery, which a secret scanner has no part in.
- Every case expected to be allowed counts for false hits, whatever it tests.
- Multi-file cases and files with no payload aren't read, and the count says how many.

The corpus doesn't say which secret formats it uses, and the rule table only claims known formats. So misses print by
case ID, and whether each one is a known format can only be read afterwards, and has to be labelled that way. This
script never prints a payload.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import ledger  # noqa: E402
import s3  # noqa: E402
import score  # noqa: E402
import shared  # noqa: E402

SCANNING = {"url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning", "mcp_input_dlp_scanning", "a2a_dlp_scanning",
            "websocket_dlp_scanning", "crypto_dlp_scanning", "entropy_scanning", "hostname_exfil_scanning"}
TAGS = {"url_dlp", "request_body_dlp", "header_dlp", "mcp_tool_result_dlp_scanning", "websocket_dlp", "crypto_dlp", "hostname_exfil"}


def in_scope(case):
    return case.get("expected_verdict") == "block" and bool(SCANNING & set(case.get("requires", [])) or TAGS & set(case.get("capability_tags", [])))


def kinds(case):
    """What a case needs scanned, for the table. A case can count under more than one."""
    return sorted((SCANNING & set(case.get("requires", []))) | (TAGS & set(case.get("capability_tags", [])))) or ["(none)"]


def read_cases(bench):
    """Every single-file case, sorted, with how many files weren't cases."""
    cases, skipped = [], 0
    for path in sorted((bench / "cases").rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            skipped += 1
            continue
        if isinstance(data, dict) and isinstance(data.get("id"), str) and isinstance(data.get("payload"), dict):
            cases.append(data)
        else:
            skipped += 1
    return cases, skipped


def write_set(cases, path):
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        for case in cases:
            out.write(json.dumps({"id": case["id"], "calls": [s3.strings(case["payload"])]}) + "\n")


def summary(cases, results):
    """Prints the tables and returns the ledger's headline."""
    by_id = {r["id"]: r for r in results}
    if len(by_id) != len(cases) or any(case["id"] not in by_id for case in cases):
        sys.exit("the scanner's results don't cover every case")
    scope = [c for c in cases if in_scope(c)]
    allowed = [c for c in cases if c.get("expected_verdict") == "allow"]
    other = [c for c in cases if not in_scope(c) and c.get("expected_verdict") != "allow"]
    blocked = [c for c in scope if by_id[c["id"]]["blocked"]]
    false_hits = [c for c in allowed if by_id[c["id"]]["blocked"]]

    print("S4, A CORPUS SOMEBODY ELSE WROTE, NOT YET INDEPENDENT")
    print(f"expected blocked and needing data-loss scanning: {len(blocked)}/{len(scope)} blocked = {score.pct(len(blocked), len(scope))}%")
    print(f"expected allowed: {len(false_hits)}/{len(allowed)} false hits")
    print(f"out of scope, testing something a secret scanner has no part in: {len(other)}, of which the scanner fired on {sum(1 for c in other if by_id[c['id']]['blocked'])}")
    print()
    counted = collections.defaultdict(lambda: [0, 0])
    for case in scope:
        for kind in kinds(case):
            counted[kind][0] += 1
            counted[kind][1] += 1 if by_id[case["id"]]["blocked"] else 0
    score.table("By what the case needs, where one case can count under several", ["needs", "cases", "blocked", "%"],
                [[kind, n, k, score.pct(k, n)] for kind, (n, k) in sorted(counted.items())])
    per_rule = collections.Counter(by_id[c["id"]]["rule"] for c in blocked + false_hits)
    score.table("Per rule that fired", ["rule", "cases"], [[rule, count] for rule, count in sorted(per_rule.items())])
    score.listing("Every in-scope case the scanner let through, by case ID", sorted(c["id"] for c in scope if not by_id[c["id"]]["blocked"]))
    score.listing("Every false hit, by case ID, with the rule", sorted(f'{c["id"]} {by_id[c["id"]]["rule"]}' for c in false_hits))
    return {"cases": len(cases), "in_scope": len(scope), "blocked": len(blocked), "recall_pct": score.pct(len(blocked), len(scope)),
            "allowed_cases": len(allowed), "false_hits": len(false_hits), "out_of_scope": len(other),
            "known_format_recall": "not automatic: the corpus doesn't name formats, so misses are read afterwards and labelled that way"}


def main():
    parser = argparse.ArgumentParser(description="Score the secret scanner once on agent-egress-bench.")
    parser.add_argument("--bench", required=True, type=pathlib.Path)
    parser.add_argument("--scanner", required=True, type=pathlib.Path)
    parser.add_argument("--work", required=True, type=pathlib.Path)
    parser.add_argument("--expect-commit", required=True, help="the commit of the corpus named at the freeze")
    parser.add_argument("--expect-rules", required=True, help="the published rule-table hash")
    parser.add_argument("--date", required=True)
    parser.add_argument("--ledger", type=pathlib.Path, help="append the headline numbers here")
    options = parser.parse_args()
    sys.stdout.reconfigure(newline="\n")

    # All of this comes before a single case is opened.
    facts = shared.header(scanner=options.scanner)
    for line in facts:
        print(line)
    if options.ledger:
        shared.refuse_unless_first_score("S4", facts, options.ledger)
    commit = subprocess.run(["git", "-C", str(options.bench), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if commit != options.expect_commit:
        sys.exit(f"the corpus is at {commit}, not the commit named at the freeze")
    # Written down last, just before a case is opened, so nothing that could still fail spends the one shot.
    first = shared.start_first_score("S4", facts, options.ledger) if options.ledger else None
    if first:
        print(first)
    options.work.mkdir(parents=True, exist_ok=True)
    set_path, results_path = options.work / "s4.jsonl", options.work / "s4.results.jsonl"
    cases, skipped = read_cases(options.bench)
    write_set(cases, set_path)
    with open(results_path, "w", encoding="utf-8", newline="\n") as out:
        subprocess.run([str(options.scanner), str(set_path)], stdout=out, check=True)
    set_hash = hashlib.sha256(set_path.read_bytes()).hexdigest()

    print("Magistrate secret scanner, scored once on agent-egress-bench")
    print(f"date                {options.date}")
    print(f"rule-table hash     {options.expect_rules}")
    print(f"corpus commit       {commit}")
    print(f"S4 hash             {set_hash}")
    print(f"files not read, because they aren't single-file cases: {skipped}")
    print()
    headline = summary(cases, s3.read_results(results_path, options.expect_rules))
    if options.ledger:
        shared.finish_first_score("S4", first.split()[-1], {"date": options.date, "rules_hash": options.expect_rules, "commit": shared.run_commit(facts), "corpus_commit": commit, "set_hash": set_hash, "headline": headline}, options.ledger)


if __name__ == "__main__":
    main()
