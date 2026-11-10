"""Records a first score from a run that has no ledger step of its own, like T0 and T1. The ledger keeps the output's hash,
so the saved output can be checked against it later, and it refuses a second line for the same set unless that line says
it's post-hoc. A first score stays, and anything measured on the same data afterwards is labelled. It also reads the output's
own account of what ran, and refuses one that came from changed code, an unstamped binary or the wrong benchmark. The commit
it records is the one the run came from, and the rule hash comes from the scanner built from that commit.

    python -I -X utf8 bench/ledger.py --ledger eval/ledger.jsonl --set T1-value --date <YYYY-MM-DD> --scanner <secretscore binary> --output value.out [--post-hoc]
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "secrets"))
import score  # noqa: E402
import shared  # noqa: E402


already_scored = shared.already_scored


def add(path, name, date, rules, output, commit, post_hoc):
    if already_scored(path, name) and not post_hoc:
        sys.exit(f"{name} already has a first score. A later run has to say --post-hoc")
    if post_hoc and not already_scored(path, name):
        sys.exit(f"{name} has no first score for this to come after")
    entry = {"set": name, "date": date, "rules_hash": rules, "commit": commit, "set_hash": hashlib.sha256(output.read_bytes()).hexdigest()}
    if post_hoc:
        entry["label"] = "post-hoc"
    score.append_ledger(path, [entry])
    return entry


def main():
    parser = argparse.ArgumentParser(description="Record one scored run in the ledger.")
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--set", required=True, dest="name")
    parser.add_argument("--date", required=True)
    parser.add_argument("--scanner", required=True, help="a secretscore binary built from the same commit, for the rule-table hash")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--post-hoc", action="store_true")
    options = parser.parse_args()
    lines = options.output.read_text(encoding="utf-8").splitlines()
    problems = shared.evidence_problems(lines)
    if problems:
        sys.exit(f"this output can't stand as a score: {problems}")
    scanner_line = shared.binary_line("scanner", options.scanner)
    if shared.evidence_problems([f"repo commit {shared.run_commit(lines)} clean", scanner_line]):
        sys.exit(f"the scanner isn't from the commit that ran: {scanner_line}")
    rules = subprocess.run([options.scanner, "-hash"], capture_output=True, text=True, check=True).stdout.strip()
    print(json.dumps(add(options.ledger, options.name, options.date, rules, options.output, shared.run_commit(lines), options.post_hoc)))


if __name__ == "__main__":
    main()
