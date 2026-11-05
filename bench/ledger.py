"""Records a first score from a run that has no ledger step of its own, like T0 and T1. The ledger keeps the output's hash,
so the saved output can be checked against it later, and it refuses a second line for the same set unless that line says
it's post-hoc. A first score stays, and anything measured on the same data afterwards is labelled.

    python -I -X utf8 bench/ledger.py --ledger eval/ledger.jsonl --set T1-value --date <YYYY-MM-DD> --rules <hash> --output value.out [--post-hoc]
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "secrets"))
import score  # noqa: E402


def already_scored(path, name):
    if not path.exists():
        return False
    return any(entry["set"] == name and "label" not in entry for entry in map(json.loads, path.read_text(encoding="utf-8").splitlines()))


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
    parser.add_argument("--rules", required=True, help="the rule-table hash of the binary that ran")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--post-hoc", action="store_true")
    options = parser.parse_args()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    print(json.dumps(add(options.ledger, options.name, options.date, options.rules, options.output, commit, options.post_hoc)))


if __name__ == "__main__":
    main()
