# Reads AgentDojo source with ast through static_gate's loader; imports nothing from the clone.
import runpy, sys, io, contextlib, re, json, pathlib
root = sys.argv[1]; scripts = sys.argv[2]
sys.argv = ["static_gate.py", root]
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ns = runpy.run_path(scripts + "/static_gate.py")
load_tasks, SINKS, TRUSTED, check = ns["load_tasks"], ns["SINKS"], ns["TRUSTED_OUTPUT"], ns["check_call"]
COMPUTED = ns["COMPUTED"]
for suite in ("slack","workspace"):
    users,_ = load_tasks(suite)
    print("==",suite)
    for name,u in sorted(users.items(), key=lambda kv:int(re.sub(r"\D","",kv[0]))):
        prompt = u["text"] if isinstance(u["text"],str) else ""
        tainted=False; seq=[]; blocked=None
        for fn,args in u["calls"]:
            gated = fn in SINKS
            r=""
            if gated and tainted:
                ok,why = check(fn,args,prompt)
                if not ok: r="REFUSED("+why+")"; blocked = blocked or fn
            short = {k:("?" if v is COMPUTED else (str(v)[:28])) for k,v in args.items()}
            seq.append(f"{fn}{short}{r}")
            if fn not in TRUSTED and (fn not in SINKS or fn=="get_webpage"): tainted=True
        print(name.replace("UserTask",""),"|",prompt[:90],"|"," ; ".join(seq)[:520])
