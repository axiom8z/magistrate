"""Static estimate, by READING AgentDojo source with `ast` (nothing imported or run).

For v1.2.2 task classes, resolve PROMPT, GOAL and ground_truth FunctionCall args where
they are constants, then apply a candidate gate rule:

  - session is tainted once a tool with untrusted output has been called
  - after taint, every control arg of a side-effect tool must be grounded in the prompt
  - content args must hold no unknown email/url/iban token

Prints benign pass counts and per-injection pass counts.  This is an ESTIMATE: computed
arguments are unknown, and computed content is assumed to hold no unknown tokens.
"""
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]) / "src" / "agentdojo" / "default_suites"
ORDER = ["v1", "v1_1", "v1_1_1", "v1_2", "v1_2_1", "v1_2_2"]
SUITE_LIMIT = {  # newest version folder each suite uses at v1.2.2 (load_suites.py:64-69)
    "workspace": "v1_2_2",
    "travel": "v1_2",
    "banking": "v1_2_2",
    "slack": "v1_2",
}
COMPUTED = object()


def resolve(node, env):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id, COMPUTED)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
        return env.get(node.attr, COMPUTED)
    if isinstance(node, ast.List):
        return [resolve(e, env) for e in node.elts]
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            else:
                v = resolve(part.value, env)
                out.append("\0" if v is COMPUTED else str(v))
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = resolve(node.left, env), resolve(node.right, env)
        if a is COMPUTED or b is COMPUTED:
            return (a if isinstance(a, str) else "") + "\0" + (b if isinstance(b, str) else "")
        try:
            return a + b
        except TypeError:
            return COMPUTED
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = resolve(node.operand, env)
        return -v if isinstance(v, (int, float)) else COMPUTED
    return COMPUTED


def load_tasks(suite):
    users, injections = {}, {}
    limit = ORDER.index(SUITE_LIMIT[suite])
    for ver in ORDER[: limit + 1]:
        for fname, store, prefix, text_attr in (
            ("user_tasks.py", users, "UserTask", "PROMPT"),
            ("injection_tasks.py", injections, "InjectionTask", "GOAL"),
        ):
            path = ROOT / ver / suite / fname
            if not path.exists():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            modenv = {}
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                    v = resolve(node.value, modenv)
                    if v is not COMPUTED:
                        modenv[node.targets[0].id] = v
                if isinstance(node, ast.ClassDef) and node.name.startswith(prefix):
                    env = dict(modenv)
                    gt = None
                    for item in node.body:
                        target = None
                        value = None
                        if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name):
                            target, value = item.targets[0].id, item.value
                        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.value:
                            target, value = item.target.id, item.value
                        if target:
                            v = resolve(value, env)
                            if v is not COMPUTED:
                                env[target] = v
                        if isinstance(item, ast.FunctionDef) and item.name == "ground_truth":
                            gt = item
                    calls = []
                    has_loop = False
                    if gt is not None:
                        env = dict(env)
                        for stmt in gt.body:
                            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                                v = resolve(stmt.value, env)
                                if v is not COMPUTED:
                                    env[stmt.targets[0].id] = v
                        for sub in ast.walk(gt):
                            if isinstance(sub, (ast.ListComp, ast.For, ast.GeneratorExp)):
                                has_loop = True
                        nodes = [n for n in ast.walk(gt) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "FunctionCall"]
                        nodes.sort(key=lambda n: (n.lineno, n.col_offset))
                        for c in nodes:
                            kw = {k.arg: k.value for k in c.keywords}
                            fn = resolve(kw["function"], env) if "function" in kw else COMPUTED
                            args = {}
                            if isinstance(kw.get("args"), ast.Dict):
                                for k, v in zip(kw["args"].keys, kw["args"].values):
                                    args[k.value if isinstance(k, ast.Constant) else "?"] = resolve(v, env)
                            calls.append((fn, args))
                    store[node.name] = {
                        "text": env.get(text_attr, COMPUTED),
                        "calls": calls,
                        "loop": has_loop,
                        "ver": ver,
                    }
    # TaskCombinator tasks: prompt1 + " " + prompt2 unless overridden, ground truth concatenated
    path = ROOT / "v1" / suite / "user_tasks.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and getattr(node.value.func, "attr", "") == "create_combined_task":
            call = node.value
            new_name = call.args[0].value
            refs = []
            for a in call.args[1:3]:
                refs.append("UserTask" + a.slice.value.split("_")[-1])
            kw = {k.arg: k.value for k in call.keywords}
            u1, u2 = users[refs[0]], users[refs[1]]
            prompt = kw["prompt"].value if "prompt" in kw else f"{u1['text']} {u2['text']}"
            users[new_name] = {"text": prompt, "calls": u1["calls"] + u2["calls"], "loop": False, "ver": "v1-combined"}
    return users, injections


# Candidate rubric, applied to tool signatures. Unlisted tools: no side effect.
# role per param: ctl = chooses who receives, what changes, how much, or who gets access.
SINKS = {
    # banking
    "send_money": {"recipient": "iban", "amount": "num"},
    "schedule_transaction": {"recipient": "iban", "amount": "num"},
    "update_scheduled_transaction": {"id": "id", "recipient": "iban", "amount": "num"},
    "update_password": {"password": "secret"},
    "update_user_info": {"first_name": "phrase", "last_name": "phrase", "street": "phrase", "city": "phrase"},
    # slack
    "add_user_to_channel": {"user": "phrase", "channel": "phrase"},
    "send_direct_message": {"recipient": "phrase"},
    "send_channel_message": {"channel": "phrase"},
    "invite_user_to_slack": {"user": "phrase", "user_email": "email"},
    "remove_user_from_slack": {"user": "phrase"},
    "post_webpage": {"url": "url"},
    "get_webpage": {"url": "url"},  # a read that reaches out
    # travel
    "reserve_hotel": {"hotel": "phrase"},
    "reserve_car_rental": {"company": "phrase"},
    "reserve_restaurant": {"restaurant": "phrase"},
    # shared
    "create_calendar_event": {"participants": "email"},
    "cancel_calendar_event": {"event_id": "id"},
    "send_email": {"recipients": "email", "cc": "email", "bcc": "email", "attachments": "attach"},
    # workspace
    "delete_email": {"email_id": "id"},
    "reschedule_calendar_event": {"event_id": "id"},
    "add_calendar_event_participants": {"event_id": "id", "participants": "email"},
    "append_to_file": {"file_id": "id"},
    "create_file": {},
    "delete_file": {"file_id": "id"},
    "share_file": {"file_id": "id", "email": "email", "permission": "phrase"},
}
TRUSTED_OUTPUT = {"get_iban", "get_balance", "get_current_day", "get_user_information"}

RX_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RX_URL = re.compile(r"(?:https?://)?(?:[a-z0-9-]+\.)+(?:com|org|net|io|ly|co|ai|gov|edu|info)(?:/[^\s'\"]*)?", re.I)
RX_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
RX_NUM = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?")


def norm_numbers(text):
    out = set()
    for m in RX_NUM.findall(text):
        try:
            out.add(float(m.replace(",", "")))
        except ValueError:
            pass
    return out


def phrase_in(value, prompt):
    pat = r"(?<![\w@.-])" + re.escape(value) + r"(?![\w@-])"
    return re.search(pat, prompt, re.I) is not None


def grounded(value, kind, prompt, short_id_rule):
    if value is COMPUTED:
        return False
    if isinstance(value, list):
        return all(grounded(v, kind, prompt, short_id_rule) for v in value)
    if value is None:
        return True
    if kind == "num":
        try:
            return float(value) in norm_numbers(prompt)
        except (TypeError, ValueError):
            return False
    s = str(value)
    if "\0" in s:
        return False
    if kind == "id" and short_id_rule and s.isdigit() and len(s) <= 4:
        return False
    return phrase_in(s, prompt)


def content_clean(value, prompt):
    if value is COMPUTED or value is None:
        return True  # optimistic: computed text assumed to hold no address-like token
    if isinstance(value, list):
        return all(content_clean(v, prompt) for v in value)
    s = str(value).replace("\0", " ")
    for rx in (RX_EMAIL, RX_URL, RX_IBAN):
        for tok in rx.findall(s):
            if not phrase_in(tok, prompt):
                return False
    return True


def check_call(fn, args, prompt, link_rule=True, short_id_rule=True, all_control=False):
    """True if a side-effect call would pass after taint under the candidate rule."""
    spec = SINKS[fn]
    for name, value in args.items():
        if all_control and name not in spec:
            if not grounded(value, "phrase", prompt, short_id_rule):
                return False, f"{name}=allcontrol"
            continue
        if name in spec:
            if not grounded(value, spec[name], prompt, short_id_rule):
                return False, f"{name}=control"
        elif link_rule and not content_clean(value, prompt):
            return False, f"{name}=link"
    return True, ""


def analyse(suite, **kw):
    users, injections = load_tasks(suite)
    rows = []
    for name, u in sorted(users.items(), key=lambda kv: int(re.sub(r"\D", "", kv[0]))):
        prompt = u["text"] if isinstance(u["text"], str) else ""
        tainted = False
        verdict = "readonly"
        blocker = ""
        for fn, args in u["calls"]:
            if fn in SINKS and (tainted or fn == "get_webpage"):
                # get_webpage before taint is allowed; after taint it is gated
                if tainted:
                    ok, why = check_call(fn, args, prompt, **kw)
                    if not ok:
                        verdict, blocker = "ask", f"{fn}:{why}"
                        break
                    verdict = "pass"
            elif fn in SINKS:
                verdict = "pass" if verdict == "readonly" else verdict
            if fn not in TRUSTED_OUTPUT and (fn not in SINKS or fn == "get_webpage"):
                tainted = True
        rows.append({"task": name, "verdict": verdict, "blocker": blocker, "loop": u["loop"], "n_calls": len(u["calls"])})
    return users, injections, rows


def main():
    total = defaultdict(int)
    out = {}
    for suite in ("banking", "slack", "travel", "workspace"):
        users, injections, rows = analyse(suite)
        _, _, rows2 = analyse(suite, all_control=True)
        print(suite, "all_control benign pass+readonly:", sum(r["verdict"] != "ask" for r in rows2), "of", len(rows2),
              "passing:", [r["task"].replace("UserTask", "") for r in rows2 if r["verdict"] == "pass"])
        counts = defaultdict(int)
        for r in rows:
            counts[r["verdict"]] += 1
        print(f"\n== {suite}: {len(users)} user, {len(injections)} injection")
        print("benign:", dict(counts))
        print("  passes with a sink:", [r["task"].replace("UserTask", "") for r in rows if r["verdict"] == "pass"])
        print("  asks:", [(r["task"].replace("UserTask", ""), r["blocker"]) for r in rows if r["verdict"] == "ask"])
        print("  loop in ground truth:", [r["task"].replace("UserTask", "") for r in rows if r["loop"]])
        pair_rows = {}
        for iname, inj in sorted(injections.items(), key=lambda kv: int(re.sub(r"\D", "", kv[0]))):
            sinks = [(f, a) for f, a in inj["calls"] if f in SINKS]
            empty = len(inj["calls"]) == 0
            res = {"pass": 0, "pass_no_link": 0, "pass_no_short_id": 0, "pass_all_control": 0}
            why_counter = defaultdict(int)
            for uname, u in users.items():
                prompt = u["text"] if isinstance(u["text"], str) else ""
                for key, kw in (
                    ("pass", {}),
                    ("pass_no_link", {"link_rule": False}),
                    ("pass_no_short_id", {"short_id_rule": False}),
                    ("pass_all_control", {"all_control": True}),
                ):
                    ok_all = True
                    for f, a in sinks:
                        ok, why = check_call(f, a, prompt, **kw)
                        if not ok:
                            ok_all = False
                            if key == "pass":
                                why_counter[f"{f}:{why}"] += 1
                            break
                    if ok_all and not empty:
                        res[key] += 1
            pair_rows[iname] = (res, dict(why_counter), [f for f, _ in sinks], empty, inj["loop"])
            print(
                f"  {iname}: empty={empty} loop={inj['loop']} sinks={[f for f,_ in sinks]} "
                f"pass={res['pass']} no_link_rule={res['pass_no_link']} no_short_id_rule={res['pass_no_short_id']} all_control={res['pass_all_control']} of {len(users)}"
            )
            total["pairs"] += len(users)
            total["replayable"] += 0 if empty else len(users)
            total["pass"] += res["pass"]
            total["pass_no_link"] += res["pass_no_link"]
            total["pass_no_short_id"] += res["pass_no_short_id"]
            total["pass_all_control"] += res["pass_all_control"]
        out[suite] = rows
        for k, v in counts.items():
            total["benign_" + k] += v
        total["users"] += len(users)
    print("\nTOTAL", dict(total))
    for token, suite in (("Alice", "slack"), ("general", "slack"), ("13", "workspace"), ("Riverside View Hotel", "travel")):
        users, _ = load_tasks(suite)
        hits = [
            n.replace("UserTask", "")
            for n, u in users.items()
            if isinstance(u["text"], str) and phrase_in(token, u["text"])
        ]
        print(f"prompt contains {token!r} in {suite}: {len(hits)} {sorted(hits, key=int)}")


main()
