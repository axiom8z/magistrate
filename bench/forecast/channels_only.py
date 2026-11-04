"""Judge's check: effect of dropping only the labels the clone's own code contradicts. Six already-opened models only. Reads JSON logs as data."""
import collections, importlib.util, json, pathlib, sys

SCRIPTS = pathlib.Path(sys.argv[1]); RUNS = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("trace_policy", SCRIPTS / "trace_policy.py")
tp = importlib.util.module_from_spec(spec); spec.loader.exec_module(tp)
MODELS = ["gpt-4o-2024-05-13", "gpt-4o-mini-2024-07-18", "gemini-2.0-flash-001",
          "meta-llama_Llama-3.3-70B-Instruct", "claude-3-7-sonnet-20250219", "claude-3-5-sonnet-20241022"]
FULL = set(tp.TRUSTED_TOOLS)
OPT = tp.Options(**tp.H)
CONFIGS = [
    ("as published", FULL),
    ("minus get_channels", FULL - {"get_channels"}),
    ("minus contacts", FULL - {"search_contacts_by_name", "search_contacts_by_email"}),
    ("minus get_channels and contacts", FULL - {"get_channels", "search_contacts_by_name", "search_contacts_by_email"}),
    ("minus get_channels, get_users_in_channel, contacts", FULL - {"get_channels", "get_users_in_channel", "search_contacts_by_name", "search_contacts_by_email"}),
]
for label, tools in CONFIGS:
    tp.TRUSTED_TOOLS = tools
    ks, ss = [], []
    tot_k = tot = 0
    for m in MODELS:
        root = RUNS / m
        k = t = st = su = 0
        for s in ("banking", "slack", "travel", "workspace"):
            for f in (root / s).glob("user_task_*/none/none.json"):
                d = json.load(open(f, encoding="utf-8"))
                if d.get("utility"):
                    t += 1
                    if not tp.apply(OPT, d):
                        k += 1
            for f in (root / s).glob("user_task_*/important_instructions/injection_task_*.json"):
                d = json.load(open(f, encoding="utf-8"))
                if d.get("security"):
                    su += 1
                    inj = int(f.stem.rsplit("_", 1)[1])
                    if tp.attack_stopped(s, inj, tp.apply(OPT, d), d, OPT):
                        st += 1
        ks.append(100 * k / max(t, 1))
        if su >= 47:
            ss.append(100 * st / su)
        tot_k += k; tot += t
    print(f"{label:52} kept {min(ks):5.1f}-{max(ks):5.1f} stop {min(ss):5.1f}-{max(ss):5.1f} pooled kept {tot_k}/{tot}")
