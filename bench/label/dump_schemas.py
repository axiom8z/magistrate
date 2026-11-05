"""Writes what a labeller may see of AgentDojo's tools, and nothing else: each tool's name, description and parameters.
DESIGN section 3 keeps labellers away from the task files, so that labels come from the tools and not from the tests.

A tool that several suites share is listed once, with the suites that have it. It stops if a shared tool differs between
suites, because then one label couldn't fit both. It reads the checkout's source as text and runs none of it. Standard
library only.

    python -I -X utf8 bench/label/dump_schemas.py --clone <agentdojo checkout> --out docs/labels/schemas.json
"""
import argparse
import ast
import json
import pathlib
import re

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
    options = parser.parse_args()
    base = options.clone / "src" / "agentdojo" / "default_suites" / "v1"
    functions, enums = {}, {}
    trees = [ast.parse(path.read_text(encoding="utf-8")) for path in sorted((base / "tools").glob("*.py"))]
    for tree in trees:
        enums.update(enum_values(tree))
    for tree in trees:
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                if node.name in functions and describe(functions[node.name], enums) != describe(node, enums):
                    raise SystemExit(f"two different tools are both called {node.name}")
                functions[node.name] = node
    tools = {}
    for suite in SUITES:
        tree = ast.parse((base / suite / "task_suite.py").read_text(encoding="utf-8"))
        names = []
        for node in tree.body:
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "TOOLS":
                names = [element.id for element in node.value.elts]
        for name in names:
            tools.setdefault(name, {**describe(functions[name], enums), "suites": []})["suites"].append(suite)
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(dict(sorted(tools.items())), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(tools)} tools and {sum(len(t['args']) for t in tools.values())} arguments")
    for suite in SUITES:
        print(f"  {suite}: {sum(1 for t in tools.values() if suite in t['suites'])} tools")
    print(f"  in more than one suite: {sum(1 for t in tools.values() if len(t['suites']) > 1)}")


if __name__ == "__main__":
    main()
