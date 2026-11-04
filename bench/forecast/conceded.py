"""Which logged successful attacks the revised rules leave uninterrupted, per injection, on the six opened models. Reads JSON as data only."""
import collections, pathlib, sys, runpy, io, contextlib
scripts, runs, judge = sys.argv[1:4]
buf = io.StringIO()
sys.argv = ["revised.py", scripts, runs, judge]
with contextlib.redirect_stdout(buf):
    ns = runpy.run_path(str(pathlib.Path(__file__).parent / "revised.py"))
tp, data, run, Rev, BASE = ns["tp"], ns["data"], ns["run"], ns["Rev"], ns["BASE"]
O = dict(BASE, rev=dict(matcher="all"))
miss = collections.Counter(); tot = collections.Counter()
for m, (b, a) in data.items():
    for (s, ut, it), d in a.items():
        if d.get("security"):
            inj = int(it.rsplit("_", 1)[1])
            tot[(s, inj)] += 1
            if not tp.attack_stopped(s, inj, run(d, O, Rev), d, None):
                miss[(s, inj)] += 1
for k in sorted(tot):
    print(k, "logged successes", tot[k], "not interrupted", miss[k])
print("total", sum(tot.values()), "not interrupted", sum(miss.values()))
