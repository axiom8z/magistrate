"""Writes what a labeller may see of AgentDojo's tools, and nothing else: each tool's name, description and parameters.
DESIGN section 3 keeps labellers away from the task files, so that labels come from the tools and not from the tests.

A tool that several suites share is listed once, with the suites that have it. It stops if a shared tool differs between
suites, because then one label couldn't fit both. It reads the checkout's source as text and runs none of it. Standard
library only.

    python -I -X utf8 bench/label/dump_schemas.py --clone <agentdojo checkout> --out docs/labels/schemas.json
    python -I -X utf8 bench/label/dump_schemas.py --clone <agentdyn checkout> --suites shopping,github,dailylife --out docs/labels/agentdyn-schemas.json

AgentDyn is a fork of AgentDojo with three new suites, and the same layout, so the same reading works on its tools.
"""
import argparse
import ast
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import shared  # noqa: E402

SUITES = ("banking", "slack", "travel", "workspace")
PARAM = re.compile(r"^\s*:param\s+(\w+):\s*(.*)$")


def type_name(node):
    if node is None:
        return "any"
    return ast.unparse(node)


def enum_values(tree):
    """The fixed lists a schema shows a model, from classes like `class SharingPermission(StrEnum)`."""
    found = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(getattr(base, "id", "") == "StrEnum" for base in node.bases):
            found[node.name] = [item.value.value for item in node.body if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant)]
    return found


def describe(function, enums):
    """A tool as a model would see it. Annotated[...] parameters are filled in by AgentDojo, so a model never sees them."""
    doc = ast.get_docstring(function) or ""
    described, summary = {}, []
    current = None
    for line in doc.splitlines():
        match = PARAM.match(line)
        if match:
            current = match.group(1)
            described[current] = match.group(2).strip()
        elif line.strip().startswith(":"):
            current = None
        elif current:
            described[current] += " " + line.strip()
        elif line.strip():
            summary.append(line.strip())
    args = {}
    for parameter in function.args.args:
        annotation = parameter.annotation
        if isinstance(annotation, ast.Subscript) and getattr(annotation.value, "id", "") == "Annotated":
            continue
        # Some suites give that type a name, like AnnotatedSlack.
        if getattr(annotation, "id", "").startswith("Annotated"):
            continue
        args[parameter.arg] = {"type": type_name(annotation), "description": described.get(parameter.arg, "")}
        if type_name(annotation) in enums:
            args[parameter.arg]["one_of"] = enums[type_name(annotation)]
    return {"description": " ".join(summary), "args": args}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clone", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--suites", default=",".join(SUITES), help="comma-separated suite names")
    options = parser.parse_args()
    suites = tuple(options.suites.split(","))
    base = options.clone / "src" / "agentdojo" / "default_suites" / "v1"
    enums = {}
    for path in sorted((base / "tools").glob("*.py")):
        enums.update(enum_values(ast.parse(path.read_text(encoding="utf-8"))))
    uses = {}
    for suite in suites:
        for name, function in shared.suite_functions(options.clone, suite).items():
            uses.setdefault(name, []).append((suite, describe(function, enums)))
    tools, split = {}, []
    for name, found in uses.items():
        if all(described == found[0][1] for _, described in found):
            tools[name] = {**found[0][1], "suites": [suite for suite, _ in found]}
        else:
            # The same name for different tools in different suites. One label couldn't fit both, so each gets its own,
            # and bench/label/labels.py looks for name@suite before name.
            split.append(name)
            for suite, described in found:
                tools[f"{name}@{suite}"] = {**described, "suites": [suite]}
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(dict(sorted(tools.items())), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(tools)} tools and {sum(len(t['args']) for t in tools.values())} arguments")
    for suite in suites:
        print(f"  {suite}: {sum(1 for t in tools.values() if suite in t['suites'])} tools")
    print(f"  in more than one suite: {sum(1 for t in tools.values() if len(t['suites']) > 1)}")
    if split:
        print(f"  names that mean different tools in different suites, so labelled per suite: {sorted(split)}")


if __name__ == "__main__":
    main()
