"""Checks the parts of the log replay that first scores depend on, without opening a single real log: the choice of
models runs against made-up folders, and the reader of trusted results against text written here.

    python -I -X utf8 bench/test_replay.py
"""
import io
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import replay_logs as replay  # noqa: E402

failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def test_models():
    check(replay.models_for("opened", pathlib.Path("no-such-folder")) == replay.OPENED, "by default only the six opened models are read, and the folder isn't listed")
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        for model, logs in (("gpt-4o-2024-05-13", 2), ("new-model", 3), ("new-model-tool_filter", 1), ("new-model-repeat_user_prompt", 1),
                            ("new-model-spotlighting_with_delimiting", 1), ("new-model-transformers_pi_detector", 1), ("Meta-SecAlign-70B", 2)):
            for number in range(logs):
                path = root / "runs" / model / "slack" / f"user_task_{number}" / "important_instructions" / "injection_task_1.json"
                path.parent.mkdir(parents=True)
                path.write_text("{}", encoding="utf-8")
        chosen = replay.models_for("new", root)
        check("gpt-4o-2024-05-13" not in chosen, "an opened model is never counted as new")
        check(not any(name.endswith(replay.DEFENDED) for name in chosen), "a pipeline with a defense added is never counted as new")
        check(chosen.get("new-model") == 3 and chosen.get("Meta-SecAlign-70B") == 2, "new models come with their attack log counts")
        check(set(chosen) == {"new-model", "Meta-SecAlign-70B"}, "nothing else is picked up")


def test_trusted_value():
    for text, want, what in (
        ("{'first_name': 'Emma', 'age': 30}", {"first_name": "Emma", "age": "30"}, "the text of a Python dict"),
        ("2024-05-15", {"result": "2024-05-15"}, "one plain value"),
        ("'DE89370400440532013000'", {"result": "DE89370400440532013000"}, "one quoted value"),
        ("1810.0", {"result": "1810.0"}, "a number"),
        ("- general\n- random\n- 'private'", {"result": ["general", "random", "private"]}, "a YAML list of strings"),
        ("- id_: '3'\n  name: report\n- id_: '4'\n  name: notes", {"result": [{"id_": "3", "name": "report"}, {"id_": "4", "name": "notes"}]}, "a YAML list of records"),
        ("- id_: '3'\n  tags:\n  - a\n  name: report", {"result": [{"id_": "3", "name": "report"}]}, "nested parts of a record are skipped"),
        ("id_: '3'\nname: report", {"id_": "3", "name": "report"}, "a flat YAML record"),
        ("Note: call alice\nand then bob", {"result": "Note: call alice\nand then bob"}, "text that only looks partly like a record stays one string"),
        ("{not python", {"result": "{not python"}, "broken dict text stays one string"),
        ("", {"result": ""}, "an empty result"),
    ):
        got = replay.trusted_value(text)
        check(got == want, f"{what}: {json.dumps(got)}")


def test_structured():
    check(replay.structured("get_iban", "'DE89'") == {"result": "DE89"}, "a tool the forecast trusts parses by default")
    check(replay.structured("get_channels", "- general") is None, "a tool nobody trusts sends no structured content")
    check(replay.structured("get_channels", "- general", {"get_channels"}) == {"result": ["general"]}, "a tool the labellers trust parses")
    check(replay.structured("get_iban", "'DE89'", {"get_channels"}) is None, "a tool the labellers don't trust doesn't")
    check(replay.structured("search_files", "- id_: '3'\n  name: a\n- id_: '4'\n  name: b") == {"result": [{"id_": "3"}, {"id_": "4"}]}, "a lookup still gives its IDs")
    check(replay.structured("search_files", "[]") == {"result": []}, "an empty lookup gives none")
    logged = replay.logged_result("get_channels", "- general", False, {"get_channels"})
    check(logged["structuredContent"] == {"result": ["general"]}, "logged_result takes the labels' trusted set")
    check("structuredContent" not in replay.logged_result("get_channels", "- general", True, {"get_channels"}), "an error sends no structured content")


def test_report():
    models = {"m": 629, "Meta-SecAlign-70B": 949}
    case = {"model": "m", "suite": "slack", "user_task": "user_task_1", "injection": 1, "calls": [], "prompt": ""}
    benign = dict(case, injection=None)
    out = io.StringIO()
    replay.report("value", [case, benign], [([], 0, 0), ([], 0, 0)], out, models, "merged labellers' answers", "first score, same tasks on new models")
    text = out.getvalue()
    check("labels: merged labellers' answers" in text and "first score, same tasks on new models" in text, "a first score says what it is and which labels it used")
    check("logged attacks not interrupted: 1" in text and "m/slack/user_task_1/injection_task_1" in text, "a first score lists every miss by name")
    check("per model" in text, "a first score gives each model its own line")
    opened = io.StringIO()
    replay.report("value", [dict(case, model="gpt-4o-2024-05-13")], [([], 0, 0)], opened)
    check("per model" not in opened.getvalue() and "six opened models" in opened.getvalue() and "forecast labels" in opened.getvalue(), "a development run prints as it always did")
    only_attacks = io.StringIO()
    replay.report("value", [case], [([], 0, 0)], only_attacks, models, None, "first score")
    check("kept 0.0-0.0" in only_attacks.getvalue(), "a model with no benign logs doesn't stop the report")
    empty = io.StringIO()
    replay.report("value", [], [], empty, models, None, "first score")
    check("logs 0," in empty.getvalue(), "a group with no logs doesn't stop the report")


def main():
    test_models()
    test_trusted_value()
    test_structured()
    test_report()
    print(f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
