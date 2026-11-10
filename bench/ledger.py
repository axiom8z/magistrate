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


def add(path, name, date, rules, output, lines, data=None, post_hoc=False):
    """Records one output. A first score needs the token of the run that started as it. A comparison needs every input to be
    the data of a recorded first score. A post-hoc line needs a first score to come after."""
    entry = {"set": name, "date": date, "rules_hash": rules, "commit": shared.run_commit(lines), "set_hash": shared.file_hash(output)}
    recorded = [line.split()[-1] for line in lines if line.startswith("results sha256 ")]
    if data is not None:
        if [shared.file_hash(data)] != recorded:
            sys.exit("the data file isn't the one this output says it wrote")
        entry["data_hash"] = shared.file_hash(data)
    elif recorded:
        sys.exit("this output wrote a data file, so pass it with --data")
    if post_hoc:
        if not already_scored(path, name):
            sys.exit(f"{name} has no first score for this to come after")
        entry["label"] = "post-hoc"
        shared.append(path, entry)
        return entry
    first = shared.first_score_of(lines)
    inputs = [line.split()[-1] for line in lines if line.startswith("input ") and " sha256 " in line]
    if first:
        if first[0] != name:
            sys.exit(f"this output ran as {first[0]}, not {name}")
        shared.finish_first_score(name, first[1], entry, path)
        return dict(entry, token=first[1])
    if inputs:
        known = {e.get("data_hash") for e in shared.entries(path) if "label" not in e}
        if not set(inputs) <= known:
            sys.exit("this compares files that aren't the data of recorded first scores")
        if already_scored(path, name):
            sys.exit(f"{name} already has a first score")
        entry["inputs"] = inputs
        shared.append(path, entry)
        return entry
    sys.exit("this output didn't run as a first score, and isn't a comparison of first scores")


def main():
    parser = argparse.ArgumentParser(description="Record one scored run in the ledger.")
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--set", required=True, dest="name")
    parser.add_argument("--date", required=True)
    parser.add_argument("--scanner", help="a secretscore binary built from the same commit, for the rule-table hash")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--data", type=pathlib.Path, help="the results file the run wrote, which its output names by hash")
    parser.add_argument("--post-hoc", action="store_true")
    parser.add_argument("--abandon", metavar="TOKEN", help="record that the run that started with this token produced nothing that stands")
    parser.add_argument("--why", help="with --abandon: what happened")
    options = parser.parse_args()
    if options.abandon:
        if not options.why:
            parser.error("--abandon needs --why")
        shared.abandon(options.ledger, options.name, options.abandon, options.why, options.date)
        print(f"recorded {options.name} run {options.abandon} as abandoned")
        return
    if not options.output or not options.scanner:
        parser.error("recording a score needs --output and --scanner")
    lines = options.output.read_text(encoding="utf-8").splitlines()
    problems = shared.evidence_problems(lines)
    if problems:
        sys.exit(f"this output can't stand as a score: {problems}")
    scanner_line = shared.binary_line("scanner", options.scanner)
    if shared.evidence_problems([f"repo commit {shared.run_commit(lines)} clean", scanner_line]):
        sys.exit(f"the scanner isn't from the commit that ran: {scanner_line}")
    rules = subprocess.run([options.scanner, "-hash"], capture_output=True, text=True, check=True).stdout.strip()
    print(json.dumps(add(options.ledger, options.name, options.date, rules, options.output, lines, options.data, options.post_hoc)))


if __name__ == "__main__":
    main()
