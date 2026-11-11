"""Checks that the ledger keeps a first score first: a run has to start before it reads anything, its output has to carry
that start, and nothing gets a second look without it showing.

    python -I -X utf8 bench/test_ledger.py
"""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ledger  # noqa: E402
import shared  # noqa: E402

failures = []
CLEAN = ["repo commit abc clean", "gateway built from abc unmodified", "agentdojo checkout x pinned"]


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

        def output(name, lines):
            file = root / name
            file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return file

        def record(name, file, data=None, post_hoc=False):
            return ledger.add(path, name, "2026-11-10", "r", file, file.read_text(encoding="utf-8").splitlines(), data, post_hoc)

        first = shared.start_first_score("T1-value", CLEAN, path)
        token = first.split()[-1]
        check(first.startswith("first score T1-value, run ") and len(token) == 16, "a first score starts with a line its output carries")
        check(json.loads(path.read_text(encoding="utf-8").splitlines()[0])["label"] == "started", "the start is written down before anything is read")
        check(refused(lambda: shared.start_first_score("T1-value", CLEAN, path)), "a second start of the same set is refused, before it reads anything")

        data = root / "value.jsonl"
        data.write_text('{"x": 1}\n', encoding="utf-8")
        out = output("value.out", CLEAN + [first, "results...", shared.results_line(data)])
        check(refused(lambda: record("T1-value", out)), "an output that wrote data can't be recorded without its data")
        other = root / "other.jsonl"
        other.write_text('{"x": 2}\n', encoding="utf-8")
        check(refused(lambda: record("T1-value", out, other)), "or with a data file it didn't write")
        check(refused(lambda: record("T1-none", out, data)), "an output is recorded only under the set it ran as")
        entry = record("T1-value", out, data)
        check(entry["token"] == token and entry["data_hash"] == shared.file_hash(data) and entry["commit"] == "abc", "the first score is recorded with its start, its data and its commit")
        check(refused(lambda: record("T1-value", out, data)), "and only once")
        forged = output("forged.out", CLEAN + ["first score T1-value, run 0123456789abcdef", shared.results_line(data)])
        check(refused(lambda: record("T1-value", forged, data)), "an output naming a run that never started is refused")
        never = output("never.out", CLEAN + ["no first-score line"])
        check(refused(lambda: record("T0-value", never)), "an output that didn't run as a first score can't be recorded as one")

        later = record("T1-value", output("later.out", CLEAN + ["rerun after a fix"]), post_hoc=True)
        check(later["label"] == "post-hoc", "a later run on the same data is labelled post-hoc")
        check(refused(lambda: record("T0-session", output("x.out", CLEAN), post_hoc=True)), "a post-hoc line needs a first score to come after")

        none_start = shared.start_first_score("T1-none", CLEAN, path)
        none_data = root / "none.jsonl"
        none_data.write_text('{"n": 1}\n', encoding="utf-8")
        record("T1-none", output("none.out", CLEAN + [none_start, shared.results_line(none_data)]), none_data)
        compare = output("compare.out", CLEAN + [shared.input_line(none_data), shared.input_line(data), "0 differences"])
        check(record("T1-compare", compare)["inputs"] == [shared.file_hash(none_data), shared.file_hash(data)], "a comparison of recorded first scores is recorded, tied to its inputs")
        practice = root / "practice.jsonl"
        practice.write_text('{"p": 1}\n', encoding="utf-8")
        check(refused(lambda: record("T0-compare-arms", output("p.out", CLEAN + [shared.input_line(practice), shared.input_line(data)]))), "a comparison of anything else isn't")

        dead = shared.start_first_score("S3", CLEAN, path)
        dead_token = dead.split()[-1]
        check(refused(lambda: shared.start_first_score("S3", CLEAN, path)), "a run that started and died still blocks a quiet second try")
        shared.abandon(path, "S3", dead_token, "the PC shut down partway", "2026-11-10")
        again = shared.start_first_score("S3", CLEAN, path)
        check(again != dead, "once it's recorded as abandoned, with why, another run can start")
        check(refused(lambda: shared.finish_first_score("S3", dead_token, {"set_hash": "x"}, path)), "and the abandoned run can't be recorded after all")
        check(refused(lambda: shared.abandon(path, "S3", "0123456789abcdef", "made up", "2026-11-10")), "only a run that really started can be abandoned")
        shared.finish_first_score("S3", again.split()[-1], {"set_hash": "y"}, path)
        check(refused(lambda: shared.abandon(path, "S3", again.split()[-1], "too late", "2026-11-10")), "and not once its score is recorded")
        check(refused(lambda: shared.start_first_score("S4", ["repo commit abc MODIFIED"], path)), "a run from changed code can't start as a first score")

        labels = [json.loads(line).get("label") for line in path.read_text(encoding="utf-8").splitlines()]
        check(labels.count("started") == 4 and labels.count("abandoned") == 1, "every start and every abandoned run stays on record")
        check(shared.already_scored(path, "S3") and not shared.already_scored(path, "S4"), "a set counts as scored only once its score is recorded")

        # A run that finished can't be abandoned for what it showed, and only what it finished with can be recorded.
        done = shared.start_first_score("T2-goals", CLEAN, path).split()[-1]
        shared.mark_finished("T2-goals", done, "a" * 64, path)
        check(refused(lambda: shared.abandon(path, "T2-goals", done, "didn't like it", "2026-11-10")), "a finished run can't be abandoned")
        check(refused(lambda: shared.mark_finished("T2-goals", done, "b" * 64, path)), "and finishes only once")
        check(refused(lambda: shared.finish_first_score("T2-goals", done, {"set_hash": "z", "data_hash": "b" * 64}, path)),
              "data other than what it finished with can't be recorded as its score")
        shared.finish_first_score("T2-goals", done, {"set_hash": "z", "data_hash": "a" * 64}, path)
        check(shared.already_scored(path, "T2-goals"), "what it finished with can")
        check(refused(lambda: shared.mark_finished("T2-ungated", "0123456789abcdef", "a" * 64, path)), "only a run that started can finish")

        # A run that died is kept, with what it left, and only that one run can be finished by a retry.
        died = shared.start_first_score("T2-ungated", CLEAN, path).split()[-1]
        check(shared.dead_run(path, "T2-ungated") is None, "a run that started hasn't died until it's abandoned")
        check(refused(lambda: shared.abandon(path, "T2-ungated", died, "made up", "2026-11-10", partial_hash="c" * 64)),
              "a run that wrote no progress line can't be abandoned with results")
        for n, digest in ((1, "c" * 64), (2, "d" * 64)):
            shared.progress("T2-ungated", died, n, digest, path)
        check(refused(lambda: shared.abandon(path, "T2-ungated", died, "made up", "2026-11-10", partial_hash="e" * 64)),
              "nor with data no progress line of it vouches for")
        shared.abandon(path, "T2-ungated", died, "the PC shut down, and lost its last case", "2026-11-10", partial_hash="c" * 64)
        dead_line = shared.dead_run(path, "T2-ungated")
        check(dead_line and dead_line["partial_hash"] == "c" * 64 and dead_line["cases"] == 1 and dead_line["claimed"] == 2,
              "an abandoned run keeps the hash of what it left, and how many cases it had claimed, so a lost one counts as died")
        check(refused(lambda: shared.progress("T2-ungated", died, 3, "f" * 64, path)), "and a run once abandoned can't go on")
        shared.start_first_score("T2-ungated", CLEAN, path)
        check(shared.dead_run(path, "T2-ungated") is None, "a set started twice has no one dead run for a retry to finish")

    print(f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
