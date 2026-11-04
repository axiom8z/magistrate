"""Which tasks depend on bound IDs, and what tightening costs. Six opened models only; reads JSON as data."""
import collections, pathlib, re, runpy, sys, io, contextlib
scripts, runs, judge = sys.argv[1:4]
sys.argv = ["revised.py", scripts, runs, judge]
src = (pathlib.Path(__file__).parent / "revised.py").read_text(encoding="utf-8").rsplit("table(\"A. old FINAL", 1)[0]
ns = {"__name__": "rev", "__file__": str(pathlib.Path(__file__).parent / "revised.py")}
exec(compile(src, "revised_defs", "exec"), ns)
Rev, tp, STRICT, data, BASE, run, table = ns["Rev"], ns["tp"], ns["STRICT"], ns["data"], ns["BASE"], ns["run"], ns["table"]
O = dict(BASE, rev=dict(matcher="all"))
NOBIND = dict(O, bind=False)
# which benign runs are kept only because of bound ids, and which act tools they use
dep = collections.Counter(); tools = collections.Counter()
for m, (b, a) in data.items():
    for (s, task), d in b.items():
        if d.get("utility") and not run(d, O) and run(d, NOBIND):
            dep[(s, task)] += 1
            for tool, args, r in run(d, NOBIND):
                tools[tool] += 1
print("kept only through bound ids:", sum(dep.values()), "runs;", sorted(dep.items()))
print("act tools those runs need ids for:", tools.most_common())


class NoIrrev(Rev):
    IRREV = ("delete_", "cancel_", "share_", "remove_", "send_", "update_")
    def bound_ok(self, tool, key, v):
        if tool.startswith(("delete_", "cancel_", "share_", "remove_")):
            return False
        return super().bound_ok(tool, key, v)


class MinN(Rev):
    N = 5
    def grounded_prompt(self, v):
        c = tp.canon(v)
        if c and not c.isdigit() and " " not in c and "@" not in c and "." not in c and len(c) < self.N and getattr(self, "_in_lookup", False):
            return False
        return super().grounded_prompt(v)
    def observe(self, tool, args, text):
        self._in_lookup = True
        try:
            super().observe(tool, args, text)
        finally:
            self._in_lookup = False


class Min6(MinN):
    N = 6


table("D. revised baseline", O)
table("no bound IDs for delete/cancel/share/remove", O, cls=NoIrrev)
table("lookup word at least 5 chars", O, cls=MinN)
table("lookup word at least 6 chars", O, cls=Min6)
table("amount free", dict(O, ceil=None))
table("amount always asks", dict(O, ceil=0))
