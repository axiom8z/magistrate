"""Checks that the ledger keeps a first score first.

    python -I -X utf8 bench/test_ledger.py
"""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ledger  # noqa: E402

failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def refused(action):
    try:
        action()
    except SystemExit:
        return True
    return False


def main():
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        path = root / "eval" / "ledger.jsonl"
        one, two = root / "one.out", root / "two.out"
        one.write_text("first", encoding="utf-8")
        two.write_text("second", encoding="utf-8")

        check(refused(lambda: ledger.add(path, "T1-value", "2026-11-05", "r", one, "c", True)), "a post-hoc line needs a first score before it")
        entry = ledger.add(path, "T1-value", "2026-11-05", "r", one, "c", False)
        check("label" not in entry and entry["commit"] == "c" and entry["rules_hash"] == "r", "a first score is recorded with its commit and rules")
        check(refused(lambda: ledger.add(path, "T1-value", "2026-11-05", "r", two, "c", False)), "a second first score for a set is refused, even with new output")
        check(refused(lambda: ledger.add(path, "T1-value", "2026-11-05", "r", one, "c", True)), "the same output can't be recorded twice")
        later = ledger.add(path, "T1-value", "2026-11-06", "r2", two, "d", True)
        check(later["label"] == "post-hoc", "a later run is labelled post-hoc")
        check(ledger.add(path, "T0-value", "2026-11-05", "r", root.joinpath("eval", "ledger.jsonl"), "c", False)["set"] == "T0-value", "another set gets its own first score")
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        check([e["set"] for e in lines] == ["T1-value", "T1-value", "T0-value"], "lines only ever go on the end")

        old = root / "old.jsonl"
        old.write_text('{"set":"S1","label":"post-hoc","set_hash":"a"}\n', encoding="utf-8")
        check(not ledger.already_scored(old, "S1"), "a post-hoc line alone isn't a first score")

    print(f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
