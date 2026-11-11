"""Draws T2's cases from DESIGN section 8's sizes and the seed F1 froze, so that anyone can draw them again and get the same
files, and resolves each planned batch to the records the ledger vouches for.

Every draw is random.Random("20261104:<purpose>:drand-<round>-<randomness>"), which keeps F1's form, over IDs in a fixed order:
suites as T1 lists them, then tasks by number. The drand round is fixed in this file before its randomness exists, and the
lists are drawn once it's published, so nobody could have chosen them by trying purposes. Anyone can fetch the round from
https://api.drand.sh/public/<round> and check it. The universe is every case T1 ran, read from its first score.

    python -I -X utf8 bench/harness/t2_plan.py --fix-beacon <date>        # before the round: fix it in the ledger, then commit and push
    python -I -X utf8 bench/harness/t2_plan.py --draw                     # once it's published: fetch it, draw every list
    python -I -X utf8 bench/harness/t2_plan.py --oracle eval/t2/plan.json # after the four task batches: the oracle's list
    python -I -X utf8 bench/harness/t2_plan.py --partial <results> <name> <token>   # what a dead run left, for --abandon

--draw writes every list fixed in advance and eval/t2/plan.json, which pins what T2 runs from and names each batch, in the
order they run. It takes nothing that could change a list: the universe is checked against T1-none's recorded data, the
labels against F2, and the round is fetched from drand. --oracle writes the oracle's list into docs/evidence/t2.

Pairs are stratified by attack, so each of the 35 attacks gets its seats in proportion, and the user tasks it meets are
drawn. Tasks are stratified by suite. Each list keeps a shuffled order, so a batch cut short has run a random part of itself.
"""
import argparse
import hashlib
import json
import pathlib
import random
import re
import subprocess
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
import shared  # noqa: E402

SEED = "20261104"
# drand's default chain: a public beacon whose rounds are fixed 30 seconds apart. This round is chosen before it's published.
DRAND_CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
DRAND_ROUND = None
SUITES = ("banking", "slack", "travel", "workspace")
# DESIGN section 8, "Sizes". The 40 new-task pairs and 30 BaseAttack pairs come with milestone 11.
UNGATED, TASKS, PAIRS, FLIPS, ORACLE_MOST = 40, 48, 120, 20, 24
FLIP_RERUNS, TASK_BATCHES, PAIR_BATCHES = 3, 2, 4
# What T1 ran, which these lists are drawn from. A different count means a different universe.
EXPECTED_TASKS = {"banking": 16, "slack": 21, "travel": 20, "workspace": 40}
EXPECTED_PAIRS = {"banking": 144, "slack": 105, "travel": 140, "workspace": 560}
MODEL = "qwen3.8-32k"
LABELS = "docs/labels/merged.json"
UNIVERSE = "docs/evidence/first-scores/T1-none.jsonl"
EVIDENCE = "docs/evidence/t2"
ORACLE_CASES = f"{EVIDENCE}/T2-oracle.cases.json"
# Seconds: t2.py's own defaults, pinned so that every batch and both arms run under the same limits.
CASE_TIMEOUT, CALL_TIMEOUT = 7200, 900
# A batch that dies can be finished by up to this many retries, each running only what no earlier run reached.
MAX_RETRIES = 3
DRAND_GENESIS, DRAND_PERIOD = 1595431050, 30
# Prose a batch runs under: the spec it's scored by and the design it comes from. Pinned by hash.
PINNED_PROSE = ("eval/SCORING.md", "docs/DESIGN.md")


def number(task_id):
    return int(task_id.rsplit("_", 1)[1])


def key(case):
    return tuple(case)


class Draws:
    """Every random choice, each with a purpose of its own, all tied to the beacon."""

    def __init__(self, randomness, round_=None):
        if not (isinstance(randomness, str) and len(randomness) == 64 and all(c in "0123456789abcdef" for c in randomness)):
            raise SystemExit("the beacon's randomness is 64 lower-case hex characters")
        self.tag = f"drand-{round_ if round_ is not None else DRAND_ROUND}-{randomness}"

    def rng(self, purpose):
        return random.Random(f"{SEED}:{purpose}:{self.tag}")


def allocate(sizes, total, tiebreak=None):
    """Each stratum's share of `total`, in proportion to its size, with exact integers. Seats left over go to the largest
    remainders. Ties are ordered by `tiebreak`, a random.Random, or by the order the strata are listed in."""
    whole = sum(sizes.values())
    seats = {stratum: total * n // whole for stratum, n in sizes.items()}
    order = list(sizes)
    if tiebreak is not None:
        tiebreak.shuffle(order)
    rank = {stratum: i for i, stratum in enumerate(order)}
    remainders = sorted(sizes, key=lambda s: (-(total * sizes[s] % whole), rank[s]))
    for stratum in remainders[: total - sum(seats.values())]:
        seats[stratum] += 1
    return seats


def universe(path):
    tasks, pairs = {s: [] for s in SUITES}, {s: [] for s in SUITES}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            case = [record["suite"], record["user_task"], record["injection_task"]]
            (pairs if case[2] else tasks)[case[0]].append(case)
    for suite in SUITES:
        tasks[suite].sort(key=lambda c: number(c[1]))
        pairs[suite].sort(key=lambda c: (number(c[1]), number(c[2])))
    counts = ({s: len(tasks[s]) for s in SUITES}, {s: len(pairs[s]) for s in SUITES})
    if counts != (EXPECTED_TASKS, EXPECTED_PAIRS):
        raise SystemExit(f"this isn't the universe T1 ran: tasks {counts[0]}, pairs {counts[1]}")
    return tasks, pairs


def split(cases, parts):
    size = len(cases) // parts
    assert size * parts == len(cases), (len(cases), parts)
    return [cases[i * size:(i + 1) * size] for i in range(parts)]


def draw_all(path, draws):
    tasks, pairs = universe(path)
    every_pair = [case for suite in SUITES for case in pairs[suite]]
    attacks = {}
    for case in every_pair:
        attacks.setdefault((case[0], case[2]), []).append(case)
    ordered = sorted(attacks, key=lambda a: (SUITES.index(a[0]), number(a[1])))
    attacks = {a: attacks[a] for a in ordered}

    task_seats = allocate({s: len(tasks[s]) for s in SUITES}, TASKS, draws.rng("tasks-seats"))
    pick = draws.rng("tasks")
    chosen_tasks = [case for suite in SUITES for case in pick.sample(tasks[suite], task_seats[suite])]
    draws.rng("tasks-order").shuffle(chosen_tasks)

    pair_seats = allocate({a: len(cases) for a, cases in attacks.items()}, PAIRS, draws.rng("pairs-seats"))
    pick = draws.rng("pairs")
    chosen_pairs = [case for a in attacks for case in pick.sample(attacks[a], pair_seats[a])]
    draws.rng("pairs-order").shuffle(chosen_pairs)

    goals = [[suite, f"injection_task_{number(inj)}", None] for (suite, inj) in attacks]
    draws.rng("goals-order").shuffle(goals)
    canonical = sorted(chosen_pairs, key=lambda c: (SUITES.index(c[0]), number(c[1]), number(c[2])))
    flipped = draws.rng("flips").sample(canonical, FLIPS)
    half = FLIPS // 2
    lists = {
        "ungated": draws.rng("ungated").sample(every_pair, UNGATED),
        "goals": goals,
        **{f"tasks-{i}": part for i, part in enumerate(split(chosen_tasks, TASK_BATCHES), 1)},
        **{f"pairs-{i}": part for i, part in enumerate(split(chosen_pairs, PAIR_BATCHES), 1)},
        # Half the 20 rerun three more times under none and half under deny, a whole round at a time, so the noise in
        # both arms of the ratio gets a measure.
        "flips-none": flipped[:half] * FLIP_RERUNS,
        "flips-deny": flipped[half:] * FLIP_RERUNS,
    }
    seats = {"tasks": task_seats, "pairs_by_suite": {s: sum(n for a, n in pair_seats.items() if a[0] == s) for s in SUITES},
             "pairs_by_attack": {f"{a[0]}/{a[1]}": n for a, n in pair_seats.items()}}
    return lists, seats


def batches(folder):
    """The batches in the order they run. Each is one first score."""
    rows = [("T2-ungated", "ungated", "none", "deny"), ("T2-goals", "goals", "none", "deny")]
    for i in range(1, TASK_BATCHES + 1):
        rows += [(f"T2-tasks-{i}-none", f"tasks-{i}", "none", "deny"), (f"T2-tasks-{i}-deny", f"tasks-{i}", "value", "deny")]
    rows.append(("T2-oracle", None, "value", "oracle"))
    for i in range(1, PAIR_BATCHES + 1):
        rows += [(f"T2-pairs-{i}-none", f"pairs-{i}", "none", "deny"), (f"T2-pairs-{i}-deny", f"pairs-{i}", "value", "deny")]
    rows += [("T2-flips-none", "flips-none", "none", "deny"), ("T2-flips-deny", "flips-deny", "value", "deny")]
    return [{"set": name, "cases": f"{folder}/{cases}.json" if cases else ORACLE_CASES, "list": cases, "arm": arm, "approver": approver}
            for name, cases, arm, approver in rows]


def server_facts(base_url="http://127.0.0.1:11434", model=MODEL):
    """The model's digest and quantization and the server's version, as the local model server reports them."""
    def get(path):
        with urllib.request.urlopen(base_url + path, timeout=30) as response:
            return json.load(response)

    tags = get("/api/tags").get("models", [])
    found = [m for m in tags if m.get("name") in (model, f"{model}:latest")]
    details = found[0].get("details", {}) if found else {}
    digest = found[0].get("digest") if found else None
    loaded = [m for m in get("/api/ps").get("models", []) if m.get("name") in (model, f"{model}:latest")]
    version = get("/api/version").get("version")
    # A real server reports its version and its models' digests, whatever name a run gives the model. A test's fake one
    # reports neither, and for it the log read would be the real server's.
    real = version is not None or any(m.get("digest") for m in tags)
    return {"model_digest": digest, "model_quantization": details.get("quantization_level"), "server_version": version,
            "server_config": server_config() if real else None, "size_vram": loaded[0].get("size_vram") if loaded else None, "real": real}


# What the server started with that changes what a model computes, read from its log. Nothing that names a path.
NUMERICS = ("OLLAMA_FLASH_ATTENTION", "OLLAMA_KV_CACHE_TYPE", "OLLAMA_NUM_PARALLEL", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_GPU_OVERHEAD",
            "OLLAMA_VULKAN", "OLLAMA_SCHED_SPREAD", "OLLAMA_LLM_LIBRARY", "OLLAMA_MAX_LOADED_MODELS", "OLLAMA_IGPU_ENABLE",
            "OLLAMA_GO_TEMPLATE", "LLAMA_ARG_FIT", "LLAMA_ARG_FIT_TARGET", "CUDA_VISIBLE_DEVICES", "GGML_VK_VISIBLE_DEVICES",
            "HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES", "GPU_DEVICE_ORDINAL", "HSA_OVERRIDE_GFX_VERSION")


def server_config():
    """The settings the local server started with that change what a model computes, from the last "server config" line
    of its log: flash attention, the KV cache's type, parallel requests, the GPU backend and devices. None with no log."""
    import os

    log = pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "Ollama" / "server.log"
    if not log.exists():
        return None
    lines = [line for line in log.read_text(encoding="utf-8", errors="replace").splitlines() if 'msg="server config"' in line]
    if not lines:
        return None
    found = {}
    for name in NUMERICS:
        match = re.search(rf"\b{name}:(\S*)", lines[-1])
        found[name] = match.group(1) if match else None
    return found


def load_model(base_url="http://127.0.0.1:11434", model=MODEL):
    """An empty prompt loads the model without generating anything, so what it was loaded with can be read."""
    request = urllib.request.Request(base_url + "/api/generate", data=json.dumps({"model": model, "prompt": ""}).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=900) as response:
        response.read()


def git(*args):
    done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else None


def published(round_):
    return DRAND_GENESIS + (round_ - 1) * DRAND_PERIOD


def beacon_commit(line):
    """(the commit that added this beacon line to the ledger, its time), or (None, None) if no commit holds it yet."""
    needle = f'"label":"beacon","chain":"{line["chain"]}","round":{line["round"]},'
    found = git("log", "--format=%H %ct", "-S", needle, "--", "eval/ledger.jsonl")
    if not found:
        return None, None
    commit, when = found.splitlines()[-1].split()
    return commit, int(when)


def beacon_lines(ledger=shared.LEDGER):
    return [e for e in shared.entries(ledger) if e.get("label") == "beacon"]


def beacon_line(ledger=shared.LEDGER):
    """The beacon that counts: the first line in the ledger added by a commit that came before its round was published and
    that also sets DRAND_ROUND to that round. Any other line is void, and stays on record: a late one because its round
    could have been seen first, and one committed apart from DRAND_ROUND because the draw couldn't follow from it. None
    if none counts."""
    for line in beacon_lines(ledger):
        commit, when = beacon_commit(line)
        if not commit or when >= published(line["round"]):
            continue
        held = git("show", f"{commit}:bench/harness/t2_plan.py")
        if held and re.search(rf"^DRAND_ROUND = {line['round']}$", held, re.M):
            return line
    return None


PINNED_FACTS = ("model_digest", "model_quantization", "server_version", "server_config")


def beacon_problems(ledger=shared.LEDGER, facts=None):
    """Why the lists can't be drawn from DRAND_ROUND: it has to be the round the ledger's first beacon line names, added by
    one commit before the round's time, with nothing tracked but the ledger changed since, and the model and server the
    line names."""
    line = beacon_line(ledger)
    if line is None or DRAND_ROUND is None or line["round"] != DRAND_ROUND or line["chain"] != DRAND_CHAIN:
        return ["the beacon that counts, the ledger's first line committed before its round, doesn't name this round"]
    commit, _ = beacon_commit(line)
    found = []
    changed = git("diff", "--name-only", commit, "HEAD", "--", ".", ":(exclude)eval/ledger.jsonl")
    if changed is None or changed:
        found.append(f"something besides the ledger changed after the beacon was fixed at {commit[:12]}: {(changed or 'git failed').splitlines()[:5]}")
    if facts is not None:
        for fact in PINNED_FACTS:
            if facts.get(fact) != line.get(fact):
                found.append(f"the server's {fact} isn't what it was when the beacon was fixed")
    return found


def drand(round_):
    """The beacon's round, from drand's public API. Its signature is kept, so anyone can check it with drand's own tools."""
    url = f"https://api.drand.sh/{DRAND_CHAIN}/public/{round_}"
    with urllib.request.urlopen(url, timeout=60) as response:
        reply = json.load(response)
    if reply.get("round") != round_ or not re.fullmatch(r"[0-9a-f]{64}", reply.get("randomness", "")):
        raise SystemExit(f"drand's reply for round {round_} isn't one: {reply}")
    return {"round": reply["round"], "randomness": reply["randomness"], "signature": reply.get("signature"),
            "previous_signature": reply.get("previous_signature")}


def universe_problems(ledger=shared.LEDGER):
    """The universe is T1-none's first score, as the ledger holds it, and the labels are F2's."""
    found = []
    t1_none = next((e for e in shared.entries(ledger) if e["set"] == "T1-none" and "label" not in e), None)
    if t1_none is None or shared.file_hash(ROOT / UNIVERSE) != t1_none.get("data_hash"):
        found.append(f"{UNIVERSE} isn't T1-none's recorded data")
    at_f2 = subprocess.run(["git", "-C", str(ROOT), "show", f"F2:{LABELS}"], capture_output=True)
    if at_f2.returncode != 0 or shared.file_hash(ROOT / LABELS) != hashlib.sha256(at_f2.stdout).hexdigest():
        found.append(f"{LABELS} isn't the file F2 froze")
    return found


def write_all(facts=None, reply=None):
    """Draws every list into eval/t2 and writes the plan. It takes nothing from the command line that could change a list:
    the universe and labels are checked against the ledger and F2, and the round comes from drand."""
    out = ROOT / "eval" / "t2"
    if DRAND_ROUND is None:
        raise SystemExit("DRAND_ROUND has to be fixed, committed and pushed before its randomness is published")
    if out.exists() and any(out.iterdir()):
        raise SystemExit("eval/t2 already holds files, and the plan and its lists are drawn once, into an empty folder")
    if facts is None:
        load_model()
        facts = server_facts()
    problems = beacon_problems(facts=facts) + universe_problems()
    missing = [fact for fact in PINNED_FACTS + ("size_vram",) if facts.get(fact) is None]
    if missing:
        problems.append(f"the server doesn't report {missing}, so the plan couldn't pin them")
    if problems:
        raise SystemExit(f"the lists can't be drawn: {'; '.join(problems)}")
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True, check=True).stdout
    if status.strip():
        raise SystemExit("everything the lists are drawn by must be committed first:\n" + status)
    code = git("rev-parse", "HEAD")
    reply = reply or drand(DRAND_ROUND)
    randomness = reply["randomness"]
    lists, seats = draw_all(ROOT / UNIVERSE, Draws(randomness))
    out.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name, cases in lists.items():
        path = out / f"{name}.json"
        path.write_text(json.dumps(cases, indent=0) + "\n", encoding="utf-8", newline="\n")
        hashes[name] = shared.file_hash(path)
    rows = batches("eval/t2")
    for row in rows:
        if row["list"]:
            row["cases_sha256"] = hashes[row["list"]]
    counted = beacon_line()
    # Any other beacon line, void or after the one that counts, is listed so nobody has to find it in the ledger.
    others = [{"round": line["round"], "date": line.get("date")} for line in beacon_lines() if line["round"] != counted["round"]]
    document = {"seed": SEED, "beacon": {"chain": DRAND_CHAIN, **reply, "check": f"https://api.drand.sh/{DRAND_CHAIN}/public/{DRAND_ROUND}",
                                         "other_lines": others},
                "code": code, "model": MODEL, **{fact: facts[fact] for fact in PINNED_FACTS + ("size_vram",)},
                "case_timeout": CASE_TIMEOUT, "call_timeout": CALL_TIMEOUT,
                "prose": {path: shared.file_hash(ROOT / path) for path in PINNED_PROSE},
                "labels": LABELS, "labels_sha256": shared.file_hash(ROOT / LABELS),
                "universe": UNIVERSE, "universe_sha256": shared.file_hash(ROOT / UNIVERSE),
                "seats": seats, "lists": hashes, "batches": rows}
    (out / "plan.json").write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8", newline="\n")
    for name, cases in lists.items():
        print(f"{name}: {len(cases)} cases")
    print(f"tasks by suite {seats['tasks']}, pairs by suite {seats['pairs_by_suite']}")
    print("commit all of eval/t2 together, in one commit: no batch runs from a plan whose files changed after the commit that holds it")


def read_records(path, partial=False):
    """A results file's records. A dead run's file may end in a line cut short when it died, which is dropped."""
    lines = [line for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    records = []
    for i, line in enumerate(lines):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            if partial and i == len(lines) - 1:
                break
            raise SystemExit(f"{path} has a broken line {i + 1}")
    return records


def planned(plan, name, root=ROOT):
    """A batch's row and its cases, or None for a list not drawn yet, like the oracle's before the task batches are in."""
    row = next((b for b in plan["batches"] if b["set"] == name), None)
    if row is None:
        raise SystemExit(f"{name} isn't in the plan")
    path = root / row["cases"]
    return row, [key(c) for c in json.loads(path.read_text(encoding="utf-8"))] if path.exists() else None


def split_run(name):
    """(the planned batch, which retry): T2-goals is (T2-goals, 0), and T2-goals-retry-2 is (T2-goals, 2)."""
    match = re.fullmatch(r"(.+)-retry-([1-9][0-9]*)", name)
    return (match.group(1), int(match.group(2))) if match else (name, 0)


def run_names(base):
    return [base] + [f"{base}-retry-{n}" for n in range(1, MAX_RETRIES + 1)]


def chain(plan, base, ledger=shared.LEDGER, root=ROOT):
    """(status, records, next run, owed) for a planned batch: its first run, then each retry, every file checked against the
    hash the ledger holds. A dead run stands on what it left, and a retry carries on after it, first recording as died the
    `owed` cases the dead run had claimed or was on and didn't leave. Status is "recorded", "missing", "started" (a run
    neither recorded nor abandoned), "incomplete" (the last run died; the next run is the retry that may finish it, or None
    once every retry is spent) or "unplanned" (records that aren't the plan's cases in the plan's order)."""
    _, wanted = planned(plan, base, root)
    evidence = root / EVIDENCE
    rows = shared.entries(ledger)
    scored = {e["set"]: e for e in rows if "label" not in e and "data_hash" in e}

    def checked(path, expected):
        if not path.exists() or shared.file_hash(path) != expected:
            raise SystemExit(f"{path} isn't the file the ledger holds for it")
        return read_records(path)

    # `reached` is how far into the planned list any run got, the case it was on included. It only grows, so a run that
    # dies early, or is abandoned with less than it had, can only add died cases, never let a reached one run again.
    records, owed, reached = [], 0, 0
    for run in run_names(base):
        if not any(e["set"] == run and e.get("label") == "started" for e in rows):
            return ("missing" if run == base else "incomplete"), records, run, owed
        if run in scored:
            records += checked(evidence / f"{run}.jsonl", scored[run]["data_hash"])
            got = [(r["suite"], r["user_task"], r["injection_task"]) for r in records]
            return ("recorded" if wanted is not None and got == wanted else "unplanned"), records, None, 0
        dead = shared.dead_run(ledger, run)
        if dead is None:
            return "started", records, None, 0
        at = rows.index(dead)
        if any(e["set"] == run and e.get("token") == dead["token"] and e.get("label") == "progress" for e in rows[at + 1:]):
            raise SystemExit(f"{run} kept writing after it was abandoned")
        left = checked(evidence / f"{run}.partial.jsonl", dead["partial_hash"]) if dead.get("partial_hash") else []
        if len(left) != (dead.get("cases") or 0):
            raise SystemExit(f"what {run} left holds {len(left)} cases, and its abandoned line says {dead.get('cases')}")
        # The cases it claimed but lost to a crash, and the one it was on, count as died.
        reached = max(reached, len(records) + (dead.get("claimed") or 0) + 1)
        records += left
        owed = reached - len(records)
    return "incomplete", records, None, owed


def batch_records(plan, name, ledger=shared.LEDGER, root=ROOT):
    """(status, records) for a planned batch, as chain() finds them."""
    status, records, _, _ = chain(plan, name, ledger, root)
    return status, records


def died_record(case, why="the run before this one died during this case, so it never ran to an end"):
    """The case a dead run was on: a retry records it as invalid, and never runs it again."""
    suite, user_task, injection_task = case
    record = {"suite": suite, "user_task": user_task, "injection_task": injection_task, "goal": user_task.startswith("injection_task_"),
              "utility": False, "delivered": False, "calls": 0, "refused": [], "asks": 0, "trace": [], "model_calls": [],
              "seconds": 0, "problems": [why]}
    if injection_task:
        record.update(security=False, stock=False, attempted=None, attempted_allowed=None, attempted_refused=None, attack_calls=None)
    return record


def write_partial(out_path, name, token, ledger=shared.LEDGER, root=ROOT):
    """What a dead run left, into docs/evidence/t2/<name>.partial.jsonl: its results cut at its last progress line, which
    is the file bench/ledger.py --abandon --data takes. If a crash lost some of what that line vouches for, it's cut at the
    last progress line whose data survived, and the abandoned line still records what the run had claimed, so the cases
    lost count as died."""
    lines = [e for e in shared.entries(ledger) if e["set"] == name and e.get("label") == "progress" and e.get("token") == token]
    data = pathlib.Path(out_path).read_bytes() if pathlib.Path(out_path).exists() else b""
    parts = data.split(b"\n")
    target = root / EVIDENCE / f"{name}.partial.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    for line in reversed(lines):
        kept = b"".join(part + b"\n" for part in parts[: line["cases"]])
        if hashlib.sha256(kept).hexdigest() == line["data_hash"]:
            target.write_bytes(kept)
            if line is not lines[-1]:
                print(f"a crash lost cases {line['cases'] + 1} to {lines[-1]['cases']}, which count as died")
            return target
    target.write_bytes(b"")
    if lines:
        print("a crash lost everything the run wrote, so all it claimed counts as died")
    return target


def oracle_list(plan, ledger=shared.LEDGER, root=ROOT):
    """The oracle's cases: the tasks passing under none and failing under deny, valid in both, at most 24 of them, in a
    shuffled order. Returns (cases, note). Every task batch must be recorded first."""
    draws = Draws(plan["beacon"]["randomness"], plan["beacon"]["round"])
    by_arm = {"none": {}, "deny": {}}
    for row in plan["batches"]:
        if row["set"].startswith("T2-tasks-"):
            status, records, next_run, _ = chain(plan, row["set"], ledger, root)
            # A batch whose every retry died is as done as it will be: its missing tasks are unclear, never rerun.
            if status != "recorded" and not (status == "incomplete" and next_run is None):
                raise SystemExit(f"{row['set']} is {status}, so the oracle's list can't be drawn yet")
            _, wanted = planned(plan, row["set"], root)
            for i, case in enumerate(wanted):
                by_arm[row["set"].rsplit("-", 1)[1]][(case[0], case[1])] = records[i] if i < len(records) else None
    if set(by_arm["none"]) != set(by_arm["deny"]) or len(by_arm["none"]) != TASKS:
        raise SystemExit("the task batches don't cover the same 48 tasks under both arms")
    broken, unclear = [], []
    for task in sorted(by_arm["none"], key=lambda k: (SUITES.index(k[0]), number(k[1]))):
        none, deny = by_arm["none"][task], by_arm["deny"][task]
        if none is None or deny is None or none["problems"] or deny["problems"]:
            unclear.append(list(task))
        elif none["utility"] and not deny["utility"]:
            broken.append([task[0], task[1], None])
    chosen = list(broken) if len(broken) <= ORACLE_MOST else draws.rng("oracle").sample(broken, ORACLE_MOST)
    draws.rng("oracle-order").shuffle(chosen)
    note = {"broken": len(broken), "chosen": len(chosen), "not_rerun": [c for c in broken if c not in chosen], "invalid_in_an_arm": unclear}
    return chosen, note


def write_oracle(plan_path, ledger=shared.LEDGER, root=ROOT):
    plan = json.loads(pathlib.Path(plan_path).read_text(encoding="utf-8"))
    chosen, note = oracle_list(plan, ledger, root)
    folder = root / EVIDENCE
    folder.mkdir(parents=True, exist_ok=True)
    (root / ORACLE_CASES).write_text(json.dumps(chosen, indent=0) + "\n", encoding="utf-8", newline="\n")
    (folder / "T2-oracle.draw.json").write_text(json.dumps(note, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"broken under deny: {note['broken']}, chosen for the oracle: {note['chosen']}, invalid in an arm: {len(note['invalid_in_an_arm'])}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix-beacon", metavar="DATE", help="write DRAND_ROUND to the ledger as the beacon line, once, before the round is published")
    parser.add_argument("--draw", action="store_true", help="once the round is published: fetch it and draw every list into eval/t2")
    parser.add_argument("--oracle", type=pathlib.Path, help="the plan, to draw the oracle's list from the recorded task batches")
    parser.add_argument("--partial", nargs=3, metavar=("RESULTS", "NAME", "TOKEN"),
                        help="cut a dead run's results at its last progress line, into docs/evidence/t2/<name>.partial.jsonl")
    options = parser.parse_args()
    if options.fix_beacon:
        import time

        if DRAND_ROUND is None:
            parser.error("set DRAND_ROUND in this file first")
        if beacon_line() is not None or any(beacon_commit(line)[0] is None for line in beacon_lines()):
            sys.exit("the ledger already holds a beacon line that counts, or one not yet committed, and only the first one counts")
        # Everything else is committed first, so the commit that fixes the round holds nothing but the round.
        loose = git("status", "--porcelain", "--untracked-files=all")
        edit = git("diff", "-U0", "--", "bench/harness/t2_plan.py")
        changed = [line for line in (edit or "").splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))]
        if loose is None or loose.split() != ["M", "bench/harness/t2_plan.py"] or changed != ["-DRAND_ROUND = None", f"+DRAND_ROUND = {DRAND_ROUND}"]:
            sys.exit("commit everything first: the only change left should be DRAND_ROUND in bench/harness/t2_plan.py")
        ahead = published(DRAND_ROUND) - time.time()
        if not 900 <= ahead <= 3 * 86400:
            sys.exit(f"round {DRAND_ROUND} is published {ahead / 60:.0f} minutes from now; pick one at least 15 minutes and at most 3 days away")
        facts = server_facts()
        if any(facts.get(fact) is None for fact in PINNED_FACTS):
            sys.exit(f"the model server doesn't report all of {PINNED_FACTS}, so the beacon can't fix them")
        shared.append(shared.LEDGER, {"set": "T2-plan", "label": "beacon", "chain": DRAND_CHAIN, "round": DRAND_ROUND,
                                      "published_at": published(DRAND_ROUND), **{fact: facts[fact] for fact in PINNED_FACTS}, "date": options.fix_beacon})
        print(f"drand round {DRAND_ROUND} fixed, published at unix time {published(DRAND_ROUND)}. Commit bench/harness/t2_plan.py and "
              "eval/ledger.jsonl together, in one commit, and push it before then")
    elif options.draw:
        write_all()
    elif options.partial:
        print(write_partial(pathlib.Path(options.partial[0]), options.partial[1], options.partial[2]))
    elif options.oracle:
        write_oracle(options.oracle)
    else:
        parser.error("give --fix-beacon, --draw, --oracle or --partial")


if __name__ == "__main__":
    main()
