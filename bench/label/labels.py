"""Turns labellers' answers into a policy, the way DESIGN section 3 says: labellers answer the rubric from the tool
schemas alone, the stricter answer wins, and the number of disagreements gets published. Standard library only.

An answer file looks like this. docs/labels/RUBRIC.md is what a labeller reads.

    {"labeller": "author", "tools": {"send_note": {
        "outsiders_write_output": "no", "changes_or_reaches": "yes", "undoable": "no", "sensitive": "no", "store": "notes",
        "args": {"to": "control", "body": "content", "amount": "quantity", "when": "date", "mode": "enum:r,rw"}}}}

    python -I -X utf8 bench/label/labels.py check <answers.json> --schemas docs/labels/schemas.json
    python -I -X utf8 bench/label/labels.py merge <answers.json> <answers.json> --out merged.json
"""
import argparse
import json
import pathlib
import sys

# How much each kind of argument answer restricts, least first. Data roles sit between content and quantity, because a
# data value that fails its type counts as control. Two data types that disagree become control.
ORDER = {"content": 0, "data": 1, "quantity": 2, "control": 3, "credential": 4}
DATA_TYPES = {"number", "boolean", "date"}

# Lookups that can bind IDs, which arguments accept them, and the ceiling on amounts. These are design decisions fixed at
# F1, because the rubric's questions can't answer them from a schema.
BINDS = {"search_files": ("id_", "file"), "search_files_by_filename": ("id_", "file"), "get_file_by_id": ("id_", "file"),
         "search_emails": ("id_", "email"), "search_calendar_events": ("id_", "event"),
         "get_most_recent_transactions": ("id", "transaction"), "get_scheduled_transactions": ("id", "transaction")}
BIND_ARGS = {"file_id": "file", "event_id": "event", "email_id": "email", "id": "transaction"}
# What a lookup's arguments do. Labellers only answer for tools that act, but a lookup binds only if the user named what it
# searched for, so its arguments have roles too.
LOOKUP_ARGS = {"search_files": {"query": "control"}, "search_files_by_filename": {"filename": "control"}, "get_file_by_id": {"file_id": "control"},
               "search_emails": {"query": "control", "sender": "control"}, "search_calendar_events": {"query": "control", "date": "date"},
               "get_most_recent_transactions": {"n": "number"}, "get_scheduled_transactions": {}}
QUANTITY_MAX = 100
QUESTIONS = ("outsiders_write_output", "changes_or_reaches", "undoable", "sensitive")


def kind_of(answer):
    if answer.startswith("enum:") or answer in DATA_TYPES:
        return "data"
    if answer not in ORDER:
        raise ValueError(f"{answer!r} isn't an argument answer")
    return answer


def stricter_arg(a, b):
    """The stricter of two answers about one argument. Unsure and missing both mean control, as the rubric says."""
    if a == b:
        return a
    if kind_of(a) == "data" and kind_of(b) == "data":
        if a.startswith("enum:") and b.startswith("enum:"):
            # Both think it's a short list, so only what both allow passes.
            shared = [v for v in a[5:].split(",") if v in b[5:].split(",")]
            if shared:
                return "enum:" + ",".join(shared)
        return "control"
    return a if ORDER[kind_of(a)] > ORDER[kind_of(b)] else b


def not_clearly(value, safe):
    """Anything but the clearly safe answer counts against the tool, so "unsure" always lands on the strict side."""
    return value != safe


def merge(first, second):
    """Returns the merged answers and every disagreement, by tool and question."""
    if set(first["tools"]) != set(second["tools"]):
        raise ValueError(f'the labellers answered different tools: {sorted(set(first["tools"]) ^ set(second["tools"]))}')
    merged, disagreements = {}, []
    for name in sorted(first["tools"]):
        a, b = first["tools"][name], second["tools"][name]
        tool = {}
        for question, safe in (("outsiders_write_output", "no"), ("changes_or_reaches", "no"), ("undoable", "yes"), ("sensitive", "no")):
            answer_a, answer_b = a.get(question, "unsure"), b.get(question, "unsure")
            if not_clearly(answer_a, safe) != not_clearly(answer_b, safe):
                disagreements.append(f"{name}: {question}: {answer_a} against {answer_b}")
            tool[question] = safe if not (not_clearly(answer_a, safe) or not_clearly(answer_b, safe)) else ("yes" if safe == "no" else "no")
        if a.get("store") != b.get("store"):
            disagreements.append(f'{name}: store: {a.get("store")} against {b.get("store")}')
            # Nobody can say which writes reach it, so its output can't be vouched for.
            tool["outsiders_write_output"] = "yes"
            tool["store"] = a.get("store") or b.get("store")
        elif a.get("store"):
            tool["store"] = a["store"]
        args_a, args_b = a.get("args", {}), b.get("args", {})
        tool["args"] = {}
        for arg in sorted(set(args_a) | set(args_b)):
            answer_a, answer_b = args_a.get(arg, "control"), args_b.get(arg, "control")
            if answer_a != answer_b:
                disagreements.append(f"{name}.{arg}: {answer_a} against {answer_b}")
            tool["args"][arg] = stricter_arg(answer_a, answer_b)
        merged[name] = tool
    return merged, disagreements


def arg_label(answer, tool_name, arg_name, irreversible):
    """One argument as the policy file spells it."""
    if answer == "quantity":
        return {"role": "quantity", "max": QUANTITY_MAX}
    if answer.startswith("enum:"):
        return {"role": "data", "type": "enum", "values": answer[5:].split(",")}
    if answer in DATA_TYPES:
        return {"role": "data", "type": answer}
    if answer == "control" and arg_name in BIND_ARGS and not irreversible:
        return {"role": "control", "bind": BIND_ARGS[arg_name]}
    return answer


def tool_label(name, answers):
    """One tool as the policy file spells it, with no pin yet. The gateway's own lint has the last word on it."""
    acts = answers.get("changes_or_reaches", "unsure") != "no"
    label = {"effect": "act" if acts else "read"}
    if answers.get("outsiders_write_output", "unsure") == "no":
        label["output"] = "trusted"
    irreversible = acts and answers.get("undoable", "unsure") != "yes"
    if irreversible:
        label["irreversible"] = True
    if answers.get("sensitive", "unsure") != "no":
        label["sensitive"] = True
    if answers.get("store"):
        label["store"] = answers["store"]
    if acts:
        label["args"] = {arg: arg_label(answer, name, arg, irreversible) for arg, answer in answers.get("args", {}).items()}
    elif name in BINDS:
        # A read with no args block takes anything, and its arguments only matter if it can bind. Only a read can bind, so a
        # labeller who says a lookup acts turns its binding off, which is the strict side.
        label["binds"] = {"path": "result[*]." + BINDS[name][0], "kind": BINDS[name][1]}
        label["args"] = {arg: arg_label(answer, name, arg, False) for arg, answer in LOOKUP_ARGS[name].items()}
    return label


def settle(labels):
    """The gateway refuses a policy that promises what it can't keep, and labellers can't be expected to know that. So where
    their answers meet one of those refusals, the promise goes. Each change here only ever makes a tool stricter."""
    kinds = {label["binds"]["kind"] for label in labels.values() if "binds" in label}
    written = {label["store"] for label in labels.values() if label["effect"] == "act" and label.get("store")}
    for label in labels.values():
        # Output somebody can write by steering an act can't be trusted.
        if label.get("output") == "trusted" and label.get("store") in written:
            del label["output"]
        # An ID with no lookup left to bind it just has to trace to a source, like any other control value.
        for name, arg in label.get("args", {}).items():
            if isinstance(arg, dict) and arg.get("bind") and arg["bind"] not in kinds:
                label["args"][name] = "control"
    return labels


def policy_for(arm, tools, draft):
    """The draft keeps its pins and servers. `tools` holds the merged answers. Arms are the ones in DESIGN section 8."""
    if arm == "unreviewed":
        return draft
    policy = dict(draft, mode={"session": "session", "pass": "pass"}.get(arm, "value"), bound_ids=arm != "value-noids", tools={})
    for name, label in settle({name: tool_label(name, answers) for name, answers in tools.items()}).items():
        label["pin"] = draft["tools"]["s__" + name]["pin"]
        if arm == "value-noids":
            label.pop("binds", None)
            for arg in label.get("args", {}).values():
                if isinstance(arg, dict):
                    arg.pop("bind", None)
        policy["tools"]["s__" + name] = label
    return policy


def problems(answers, schemas):
    """What's wrong with one labeller's file, before anything gets merged. A tool that acts needs a role for every argument,
    because the gateway refuses an argument its label doesn't name."""
    found = []
    tools = answers.get("tools", {})
    found += [f"{name}: not answered" for name in sorted(set(schemas) - set(tools))]
    found += [f"{name}: not in the schema file" for name in sorted(set(tools) - set(schemas))]
    for name in sorted(set(tools) & set(schemas)):
        tool = tools[name]
        for question in QUESTIONS:
            if tool.get(question, "unsure") not in ("yes", "no", "unsure"):
                found.append(f'{name}: {question}: {tool[question]!r} is not yes, no or unsure')
        given = tool.get("args", {})
        found += [f"{name}.{arg}: not in the schema file" for arg in sorted(set(given) - set(schemas[name]["args"]))]
        for arg, answer in sorted(given.items()):
            try:
                kind_of(answer)
            except ValueError as problem:
                found.append(f"{name}.{arg}: {problem}")
        if tool.get("changes_or_reaches", "unsure") != "no":
            found += [f"{name}.{arg}: the tool acts, and this argument has no role" for arg in sorted(set(schemas[name]["args"]) - set(given))]
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("merge", "check"))
    parser.add_argument("answers", nargs="+", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--schemas", type=pathlib.Path)
    options = parser.parse_args()
    if options.command == "check":
        if len(options.answers) != 1 or not options.schemas:
            parser.error("check takes one answer file and --schemas")
        found = problems(json.loads(options.answers[0].read_text(encoding="utf-8")), json.loads(options.schemas.read_text(encoding="utf-8")))
        print(f"{len(found)} problems")
        for line in found:
            print("  " + line)
        return 1 if found else 0
    if len(options.answers) != 2 or not options.out:
        parser.error("merge takes two answer files and --out")
    first, second = (json.loads(path.read_text(encoding="utf-8")) for path in options.answers)
    merged, disagreements = merge(first, second)
    options.out.write_text(json.dumps({"labellers": [first["labeller"], second["labeller"]], "tools": merged, "disagreements": disagreements}, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f'{first["labeller"]} and {second["labeller"]}: {len(merged)} tools, {len(disagreements)} disagreements')
    for line in disagreements:
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
