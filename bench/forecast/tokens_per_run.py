"""Model calls and estimated tokens per run from the six opened models' logs. Reads JSON as data, imports nothing from the clone.
Tokens are estimated as characters / 4, a stated heuristic; tool schemas are estimated from the clone's docstrings by ast (nothing run).
Usage: python -I -X utf8 tokens_per_run.py <clone_root>"""
import ast, collections, json, pathlib, re, statistics as st, sys

ROOT = pathlib.Path(sys.argv[1])
RUNS = ROOT / "runs"
MODELS = ["gpt-4o-2024-05-13", "gpt-4o-mini-2024-07-18", "gemini-2.0-flash-001",
          "meta-llama_Llama-3.3-70B-Instruct", "claude-3-7-sonnet-20250219", "claude-3-5-sonnet-20241022"]
SUITES = ("banking", "slack", "travel", "workspace")

# --- tool schema size per suite, from ast
TOOLS_DIR = ROOT / "src/agentdojo/default_suites/v1/tools"
fn_doc = {}
for f in TOOLS_DIR.glob("*.py"):
    tree = ast.parse(f.read_text(encoding="utf-8"))
    for n in tree.body:
        if isinstance(n, ast.FunctionDef):
            params = [a.arg for a in n.args.args]
            fn_doc[n.name] = (ast.get_docstring(n) or "", params)
schema_chars = {}
ntools = {}
for s in SUITES:
    txt = (ROOT / f"src/agentdojo/default_suites/v1/{s}/task_suite.py").read_text(encoding="utf-8")
    m = re.search(r"TOOLS\s*=\s*\[(.*?)\]", txt, re.S)
    names = re.findall(r"\b([a-z_]+)\b", m.group(1)) if m else []
    names = [n for n in names if n in fn_doc]
    total = 0
    for n in names:
        doc, params = fn_doc[n]
        # a JSON function schema: docstring plus about 90 characters of wrapper per tool and 60 per parameter
        total += len(doc) + 90 + 60 * len(params)
    schema_chars[s] = total
    ntools[s] = len(names)
print("tools per suite", ntools, "estimated schema chars", schema_chars, "est tokens", {k: v // 4 for k, v in schema_chars.items()})


def clen(c):
    if isinstance(c, list):
        return sum(len(str(b.get("content", ""))) if isinstance(b, dict) else len(str(b)) for b in c)
    return len(c) if c else 0


def measure(d, suite):
    msgs = d["messages"]
    so_far = 0
    calls = 0
    inp = 0
    out = 0
    for x in msgs:
        size = clen(x.get("content"))
        tc = x.get("tool_calls") or []
        tcs = sum(len(json.dumps(t.get("args", {}))) + len(t.get("function", "")) for t in tc)
        if x["role"] == "assistant":
            calls += 1
            inp += so_far + schema_chars[suite]
            out += size + tcs
        so_far += size + tcs
    return calls, inp, out


rows = collections.defaultdict(list)
for m in MODELS:
    for s in SUITES:
        for kind, pat in (("attack", "user_task_*/important_instructions/injection_task_*.json"), ("benign", "user_task_*/none/none.json")):
            for f in (RUNS / m / s).glob(pat):
                d = json.load(open(f, encoding="utf-8"))
                rows[(s, kind)].append(measure(d, s))
                rows[("ALL", kind)].append(measure(d, s))
                rows[(m, kind)].append(measure(d, s))


def fmt(v):
    c = [a for a, _, _ in v]; i = [b / 4 for _, b, _ in v]; o = [z / 4 for _, _, z in v]
    i2 = sorted(i)
    return (f"n={len(v)} calls mean {st.mean(c):.2f} median {st.median(c)} p90 {sorted(c)[int(.9*len(c))]} max {max(c)} | input tokens/run mean {st.mean(i):.0f} "
            f"median {st.median(i):.0f} p90 {i2[int(.9*len(i2))]:.0f} max {max(i):.0f} | output tokens/run mean {st.mean(o):.0f} p90 {sorted(o)[int(.9*len(o))]:.0f}")


for k in sorted(rows, key=str):
    print(k, fmt(rows[k]))
