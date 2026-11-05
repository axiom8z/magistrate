"""Writes what a labeller may see of AgentDojo's tools, and nothing else: each tool's name, description and parameters.
DESIGN section 3 keeps labellers away from the task files, so that labels come from the tools and not from the tests.

It reads the checkout's source as text and runs none of it. Standard library only.

    python -I -X utf8 bench/label/dump_schemas.py --clone <agentdojo checkout> --out <file.json>
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


def describe(function):
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
        args[parameter.arg] = {"type": type_name(annotation), "description": described.get(parameter.arg, "")}
    return {"description": " ".join(summary), "args": args}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clone", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    options = parser.parse_args()
    base = options.clone / "src" / "agentdojo" / "default_suites" / "v1"
    functions = {}
    for path in sorted((base / "tools").glob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.FunctionDef):
                functions[node.name] = node
    suites = {}
    for suite in SUITES:
        tree = ast.parse((base / suite / "task_suite.py").read_text(encoding="utf-8"))
        names = []
        for node in tree.body:
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "TOOLS":
                names = [element.id for element in node.value.elts]
        suites[suite] = {name: describe(functions[name]) for name in names}
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(suites, indent=1) + "\n", encoding="utf-8", newline="\n")
    total = sum(len(tools) for tools in suites.values())
    args = sum(len(tool["args"]) for tools in suites.values() for tool in tools.values())
    print(f"{total} tools and {args} arguments across {len(suites)} suites")
    for suite, tools in suites.items():
        print(f"  {suite}: {len(tools)} tools, {sum(len(t['args']) for t in tools.values())} arguments")


if __name__ == "__main__":
    main()
