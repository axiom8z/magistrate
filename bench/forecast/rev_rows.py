"""Recheck of the decision-table rows under the REVISED rules, with bound IDs refused on irreversible acts. Six opened models only; reads JSON as data."""
import pathlib, sys
scripts, runs, judge = sys.argv[1:4]
sys.argv = ["revised.py", scripts, runs, judge]
src = (pathlib.Path(__file__).parent / "revised.py").read_text(encoding="utf-8").rsplit("table(\"A. old FINAL", 1)[0]
ns = {"__name__": "rev", "__file__": str(pathlib.Path(__file__).parent / "revised.py")}
exec(compile(src, "revised_defs", "exec"), ns)
Rev, tp, BASE, table = ns["Rev"], ns["tp"], ns["BASE"], ns["table"]
O = dict(BASE, rev=dict(matcher="all"))


class Final2(Rev):
    def bound_ok(self, tool, key, v):
        if tool.startswith(("delete_", "cancel_", "share_", "remove_")):
            return False
        return super().bound_ok(tool, key, v)


class Fetch(Final2):
    def check(self, tool, args):
        if tool == "get_webpage" and self.seen_anywhere(args.get("url", "")):
            return []
        return super().check(tool, args)


table("FINAL2: revised, no bound ids on irreversible acts, broad matcher", O, cls=Final2)
table("record limit removed", dict(O, reclimit=10**9), cls=Final2)
table("links off (no content matcher at all)", dict(BASE, emb=False, rev=dict()), cls=Final2)
table("links only on acts with a destination, old regexes", dict(BASE, emb_all=False, rev=dict()), cls=Final2)
table("follow seen URLs", O, cls=Fetch)
table("latch on, prompt known", dict(O, latch=True), cls=Final2)
table("no sensitive registry", dict(O, sens=False), cls=Final2)
