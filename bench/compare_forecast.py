"""Lines up what the real gateway did on each log with what the design's Python forecast said it would
do, and prints every disagreement. DESIGN section 8 makes a gap of over five points a failure unless
there is a written cause, and this is where the cause comes from. Reads JSON logs as data.

    python -I -X utf8 bench/compare_forecast.py <agentdojo checkout> <cases.jsonl from replay_logs --dump>
"""
import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
clone, dump = pathlib.Path(sys.argv[1]), sys.argv[2]
forecast = HERE / "forecast"

# The same way rev_rows.py loads the rule classes: everything in revised.py above its tables.
sys.argv = ["revised.py", str(forecast), str(clone / "runs"), str(forecast)]
source = (forecast / "revised.py").read_text(encoding="utf-8").rsplit('table("A. old FINAL', 1)[0]
ns = {"__name__": "rev", "__file__": str(forecast / "revised.py")}
exec(compile(source, "revised_defs", "exec"), ns)
Rev, tp, BASE, run, data = ns["Rev"], ns["tp"], ns["BASE"], ns["run"], ns["data"]
config = dict(BASE, rev=dict(matcher="all"))


class Final2(Rev):
    """The rule set behind the design's table: bound IDs refused on acts that can't be undone."""

    def bound_ok(self, tool, key, v):
        if tool.startswith(("delete_", "cancel_", "share_", "remove_")):
            return False
        return super().bound_ok(tool, key, v)


kept_only_gateway, kept_only_forecast, stop_only_gateway, stop_only_forecast = [], [], [], []
agree = collections.Counter()
for line in open(dump, encoding="utf-8"):
    case = json.loads(line)
    benign, attacks = data[case["model"]]
    suite, user_task, injection = case["suite"], case["user_task"], case["injection"]
    label = f'{case["model"]} {suite} {user_task} injection {injection}'
    rules = sorted({f["tool"] + ":" + f["rule"] for f in case["flagged"]})
    if injection is None:
        reasons = run(benign[(suite, user_task)], config, Final2)
        forecast_kept, gateway_kept = not reasons, not case["flagged"]
        if forecast_kept == gateway_kept:
            agree["benign"] += 1
        elif gateway_kept:
            kept_only_gateway.append((label, [(t, str(r)[:110]) for t, _, r in reasons]))
        else:
            kept_only_forecast.append((label, rules))
    else:
        log = attacks[(suite, user_task, f"injection_task_{injection}")]
        flagged = run(log, config, Final2)
        forecast_stop = tp.attack_stopped(suite, injection, flagged, log, None)
        gateway_stop = None
        # The dump holds tool names and not arguments, so an interrupted call of the family stands in here.
        family = tp.A.get(suite, {}).get(injection, ((), ""))[0]
        gateway_stop = any(f["tool"] in family for f in case["flagged"])
        if forecast_stop == gateway_stop:
            agree["attack"] += 1
        elif gateway_stop:
            stop_only_gateway.append((label, rules))
        else:
            stop_only_forecast.append((label, [(t, str(r)[:110]) for t, _, r in flagged]))

print("logs where the two agree:", dict(agree))
for title, rows in (("kept by the gateway, not the forecast", kept_only_gateway), ("kept by the forecast, not the gateway", kept_only_forecast),
                    ("stopped by the gateway, not the forecast", stop_only_gateway), ("stopped by the forecast, not the gateway", stop_only_forecast)):
    print(f"{title}: {len(rows)}")
    for label, detail in rows:
        print("  ", label, detail)
