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
    python -I -X utf8 bench/harness/t2_plan.py --supersede <date> --expect <test loads>  # write plan 2, before any batch, from a live session
    python -I -X utf8 bench/harness/t2_plan.py --supersede-record <date> --sha256 <hash> # after plan 2's commit: the ledger line, once

--draw writes every list fixed in advance and eval/t2/plan.json, which pins what T2 runs from and names each batch, in the
order they run. It takes nothing that could change a list: the universe is checked against T1-none's recorded data, the
labels against F2, and the round is fetched from drand. --oracle writes the oracle's list into docs/evidence/t2.

Pairs are stratified by attack, so each of the 35 attacks gets its seats in proportion, and the user tasks it meets are
drawn. Tasks are stratified by suite. Each list keeps a shuffled order, so a batch cut short has run a random part of itself.
"""
import argparse
import hashlib
import http.client
import json
import os
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
DRAND_ROUND = 6632078
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


def http_json(url, body=None, timeout=30):
    """A GET, or a POST of `body` as JSON, and the JSON that comes back. The one place this file talks to the model server,
    so a test can stand in for it."""
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                     headers={} if body is None else {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def server_facts(base_url="http://127.0.0.1:11434", model=MODEL, log=None):
    """The model's digest and quantization and the server's version, as the local model server reports them, with the load
    facts the server's log holds for the model's last load. `log` is the log's path, the server's own by default."""
    def get(path):
        return http_json(base_url + path)

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
            "server_config": server_config(log) if real else None, "size_vram": loaded[0].get("size_vram") if loaded else None,
            "loaded": bool(loaded), "real": real, **(load_reading(base_url, model, log) if real else dict.fromkeys(READING, None))}


# What the server started with that changes what a model computes, read from its log. Nothing that names a path.
NUMERICS = ("OLLAMA_FLASH_ATTENTION", "OLLAMA_KV_CACHE_TYPE", "OLLAMA_NUM_PARALLEL", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_GPU_OVERHEAD",
            "OLLAMA_VULKAN", "OLLAMA_SCHED_SPREAD", "OLLAMA_LLM_LIBRARY", "OLLAMA_MAX_LOADED_MODELS", "OLLAMA_IGPU_ENABLE",
            "OLLAMA_GO_TEMPLATE", "LLAMA_ARG_FIT", "LLAMA_ARG_FIT_TARGET", "CUDA_VISIBLE_DEVICES", "GGML_VK_VISIBLE_DEVICES",
            "HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES", "GPU_DEVICE_ORDINAL", "HSA_OVERRIDE_GFX_VERSION")


def server_log():
    """Where the local model server writes its log."""
    return pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "Ollama" / "server.log"


def server_config(log=None):
    """The settings the local server started with that change what a model computes, from the last "server config" line
    of its log: flash attention, the KV cache's type, parallel requests, the GPU backend and devices. None with no log."""
    log = pathlib.Path(log) if log else server_log()
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


# What a load fixes about the computation that /api/ps's size_vram doesn't: the runner's flags, the lines llama-server logs
# about how it set the model up (the split, the buffers, the kernels and threads it chose), and the GPU. Plan 2 pins them.
LOAD_FACTS = ("runner_flags", "load_config", "gpu_layers", "gpu_device")
# server_facts' keys for them, and what the start check needs beyond the facts: where the load's block begins in the log,
# the log's first line, and why they couldn't be read, if they couldn't.
READING = LOAD_FACTS + ("load_offset", "log_first_line", "load_problem")
START_LINE = 'msg="starting llama-server"'
# A configuration line starts, after an optional `cmn` and spaces, with one of these.
CONFIG_LINE = re.compile(r"(?:cmn\s+)?((?:load_tensors:|llama_context:|llama_kv_cache:|llama_memory_recurrent:|resolve_fused_ops:|warmup:"
                         r"|llama_model_loader:|print_info:|common_param: common_params_print_info: build|common_param: system_info:"
                         r"|init: llama threadpool init).*)")
OFFLOADED = re.compile(r"load_tensors: offloaded (\d+)/(\d+) layers to GPU")
# Every model file Ollama starts the runner with is a blob named by its hash. Paths are masked so the facts name no machine.
BLOB_PATH = re.compile(r"(?:[A-Za-z]:\\|(?<=\s)/)[^\n\"]*?sha256-[0-9a-f]{64}")
OTHER_PATH = re.compile(r"[A-Za-z]:\\\S+")


def model_blob(base_url="http://127.0.0.1:11434", model=MODEL):
    """The sha256 of the model's blob, from the first FROM line of the modelfile /api/show gives. The runner's --model names
    it, so it's what tells this model's loads from another's. None if the server won't say."""
    try:
        reply = http_json(base_url + "/api/show", {"model": model})
    except (OSError, ValueError, http.client.HTTPException):
        return None
    source = re.search(r"^FROM\s+(.*)$", reply.get("modelfile") or "", re.M) if isinstance(reply, dict) else None
    digest = re.search(r"sha256-([0-9a-f]{64})", source.group(1)) if source else None
    return digest.group(1) if digest else None


def read_log(log=None):
    """The server's log as bytes, or None if it can't be read."""
    try:
        return pathlib.Path(log if log else server_log()).read_bytes()
    except OSError:
        return None


def first_line(data):
    return data.split(b"\n", 1)[0].removesuffix(b"\r")


def split_log(data):
    """[(byte offset, line)], splitting only on the newline byte and dropping a trailing carriage return: at verbosity 4 the
    log holds chat text, and str.splitlines would split on other characters that text can hold."""
    found, at = [], 0
    for raw in data.split(b"\n"):
        found.append((at, raw.removesuffix(b"\r").decode("utf-8", errors="replace")))
        at += len(raw) + 1
    return found


def mask_paths(text):
    return OTHER_PATH.sub("<path>", BLOB_PATH.sub("<path>", text))


def runner_command(start):
    """(runner_flags, blob digest) from a start line: its cmd, unescaped, from the first ` --model ` on so a space in the
    executable's path can't break it, with paths and the port masked. (None, None) if no --model names a blob."""
    quoted = re.search(r'cmd="((?:[^"\\]|\\.)*)"', start)
    command = re.sub(r'\\(["\\])', r"\1", quoted.group(1)) if quoted else ""
    at = command.find(" --model ")
    named = re.match(r"--model .*?sha256-([0-9a-f]{64})(?= |$)", command[at + 1:]) if at >= 0 else None
    if named is None:
        return None, None
    return re.sub(r"--port \d+", "--port <port>", mask_paths(command[at + 1:])), named.group(1)


def read_blocks(data):
    """([(start offset, lines, the --model blob digest or None)], the `inference compute` lines). A block runs from a start
    line to the next one, or to the end. The compute lines lose `available`, which changes with what else holds the GPU."""
    lines = split_log(data)
    starts = [i for i, (_, text) in enumerate(lines) if START_LINE in text]
    blocks = [(lines[a][0], [text for _, text in lines[a:b]]) for a, b in zip(starts, starts[1:] + [len(lines)])]
    devices = [re.sub(r' available="[^"]*"', "", text[text.index('msg="inference compute"'):]).rstrip()
               for _, text in lines if 'msg="inference compute"' in text]
    return [(at, text, runner_command(text[0])[1]) for at, text in blocks], devices


def block_facts(block, devices):
    """(the LOAD_FACTS of one block, None), or (None, why they can't be read). A load logs exactly one `offloaded` line."""
    flags, _ = runner_command(block[0])
    config = [mask_paths(found.group(1)) for found in map(CONFIG_LINE.match, block) if found]
    split = [found.groups() for found in map(OFFLOADED.match, config) if found]
    if flags is None:
        return None, "the block's start line has no command that names a model"
    if len(split) != 1:
        return None, f"the block holds {len(split)} offloaded lines, and a load holds exactly one"
    if not devices:
        return None, "the log has no inference compute line"
    return {"runner_flags": flags, "load_config": config, "gpu_layers": "/".join(split[0]), "gpu_device": devices}, None


def start_reading(data, blob):
    """(facts, the block's start offset, the log's first line, None) for the start check: the last block of the model whose
    blob is `blob`. Or (None, None, None, why), never an error: no log, an empty one, no block of this model, a block with
    no offloaded line or more than one, a fact's lines missing."""
    if not blob:
        return None, None, None, "the model's blob isn't known, so its loads can't be told from another's"
    if not data or not data.strip():
        return None, None, None, "the server's log is missing or empty"
    blocks, devices = read_blocks(data)
    mine = [block for block in blocks if block[2] == blob]
    if not mine:
        return None, None, None, "no load in the server's log belongs to this model"
    facts, why = block_facts(mine[-1][1], devices)
    return (facts, mine[-1][0], first_line(data), None) if facts else (None, None, None, why)


def scan_blocks(data, blob, expected, offset, first):
    """(problems, how many blocks matched) for the loads since the start check: every block of this model from `offset` on
    must give `expected`, and a failed load Ollama retried with another split is one of them. Other models' blocks are
    skipped, and a block whose --model can't be read stops the run. A model unloaded since gives no new block, which isn't a
    problem. A log shorter than the offset, with another first line, or with no block at the offset was rotated."""
    if not blob:
        return ["the model's blob isn't known, so its loads can't be told from another's"], 0
    if data is None:
        return ["the server's log can't be read"], 0
    if len(data) < offset or first_line(data) != first:
        return ["the server's log was rotated or replaced since the run started"], 0
    blocks, devices = read_blocks(data)
    if offset not in [at for at, _, _ in blocks]:
        return ["the load the run started on isn't in the server's log where it was"], 0
    problems, matched = [], 0
    for at, block, digest in blocks:
        if at < offset or (digest is not None and digest != blob):
            continue
        if digest is None:
            problems.append(f"the load at byte {at} has no --model that names a blob, so it can't be told from this model's")
            continue
        facts, why = block_facts(block, devices)
        if facts is None:
            problems.append(f"the load at byte {at}: {why}")
        elif facts != {fact: expected.get(fact) for fact in LOAD_FACTS}:
            problems.append(f"the load at byte {at} differs in {[fact for fact in LOAD_FACTS if facts[fact] != expected.get(fact)]}")
        else:
            matched += 1
    return problems, matched


def load_reading(base_url, model, log=None):
    """server_facts' READING keys: the load facts of the model's last load in the log, where its block begins, and the log's
    first line. The facts None and `load_problem` set to why, if they can't be read. It never raises."""
    facts, offset, first, why = start_reading(read_log(log), model_blob(base_url, model))
    return {**(facts or dict.fromkeys(LOAD_FACTS)), "load_offset": offset, "log_first_line": first, "load_problem": why}


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


# Plan 2 supersedes plan 1 before any batch ran: the same sample, and a closed set of keys that change.
PLAN_1, PLAN_2 = "eval/t2/plan.json", "eval/t2-plan-2.json"
SCORING = "eval/SCORING.md"
LEDGER_FILE = "eval/ledger.jsonl"
# What may change in the repository after a plan's code commit: what scored runs write, the plans and their lists, and prose
# (t2.py's own check of the code freeze takes this tuple).
AFTER_PLAN = ("eval/ledger.jsonl", "docs/evidence/", "eval/t2/", PLAN_2)
# What plan 2's code may change from plan 1's, besides AFTER_PLAN's paths and .md files. The gateway, shared.py and
# t2_lines.py, which prints the verdicts, stay as plan 1 had them.
CODE_FILES = ("bench/harness/t2.py", "bench/harness/t2_plan.py", "bench/harness/test_t2.py", "bench/harness/test_t2_plan.py",
              "bench/harness/test_t2_git.py", ".github/workflows/ci.yml")
CODE_FOLDERS = ("bench/harness/testdata/",)
# The keys plan 2 may change from plan 1. Of `prose`, only SCORING.md's hash.
SUPERSEDE_KEYS = ("code", *LOAD_FACTS, "size_vram", "prose", "supersedes")
SUPERSEDE_REASON = ("Plan 1 pinned size_vram, read at the draw after a load-only request. Batch T2-ungated, which loads with a chat, "
                    "read 127.73 MiB more and refused before any case. Test loads on 2026-11-11 read 5,016,660,212 bytes after a chat on "
                    "each of three loads, and 4,882,725,599, plan 1's figure, after the one load-only request, with the same load "
                    "facts at every reading. So size_vram changes with the first chat while the load facts don't. Before any case "
                    "ran, the pin was replaced by the load facts.")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
COMMIT = re.compile(r"[0-9a-f]{40}")
HASH = re.compile(r"[0-9a-f]{64}")


def committed_bytes(root, commit, path):
    """A file's bytes as `commit` holds them, or None. Raw, since shared.git decodes and strips what it returns."""
    try:
        done = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{path}"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def holders(root, path):
    """The commits that touch a file, or None if git can't say."""
    found = shared.git("log", "--format=%H", "--", path, cwd=root)
    return None if found is None else found.split()


def ledger_line(entry):
    """The bytes shared.append writes for an entry."""
    return (json.dumps(entry, separators=(",", ":")) + "\n").encode()


def supersede_line(date, digest):
    return {"set": "T2-plan", "label": "supersede", "plan": PLAN_2, "plan_sha256": digest, "date": date}


def started_lines(rows):
    """[(index, line)] for each T2 batch's started line: the label `started` and a set beginning `T2-`, other than T2-plan."""
    return [(i, row) for i, row in enumerate(rows) if row.get("label") == "started"
            and str(row.get("set", "")).startswith("T2-") and row["set"] != "T2-plan"]


def supersede_problems(plan_1, plan_2):
    """Check 1: plan 2 equals plan 1 outside SUPERSEDE_KEYS, holds well-formed values in them, and says why it supersedes."""
    found = [f"plan 2's {name} isn't plan 1's" for name in sorted((set(plan_1) | set(plan_2)) - set(SUPERSEDE_KEYS))
             if name not in plan_1 or name not in plan_2 or plan_1[name] != plan_2[name]]
    if "supersedes" in plan_1:
        found.append("plan 1 is itself a superseding plan")
    whole = [plan["prose"] if isinstance(plan.get("prose"), dict) else {} for plan in (plan_1, plan_2)]
    prose = [{k: v for k, v in p.items() if k != SCORING} for p in whole]
    if prose[0] != prose[1] or SCORING not in whole[0] or not HASH.fullmatch(str(whole[1].get(SCORING))):
        found.append("plan 2's prose is plan 1's, apart from SCORING.md's hash, which has to be one")
    code, size = plan_2.get("code"), plan_2.get("size_vram")
    if not (isinstance(code, str) and COMMIT.fullmatch(code)):
        found.append("plan 2's code names no commit")
    if not (isinstance(size, int) and not isinstance(size, bool)):
        found.append("plan 2's size_vram isn't a number")
    flags, config, layers, device = (plan_2.get(fact) for fact in LOAD_FACTS)
    if not (isinstance(flags, str) and flags and isinstance(layers, str) and re.fullmatch(r"\d+/\d+", layers)
            and all(isinstance(v, list) and v and all(isinstance(line, str) for line in v) for v in (config, device))):
        found.append("plan 2's load facts aren't a runner command, configuration lines, a layer split and devices")
    why = plan_2.get("supersedes")
    if not isinstance(why, dict) or set(why) != {"plan", "commit", "lists_drawn_by", "reason", "date"}:
        found.append("plan 2's supersedes doesn't hold exactly plan, commit, lists_drawn_by, reason and date")
    elif (why["plan"], why["lists_drawn_by"], why["reason"]) != (PLAN_1, plan_1.get("code"), SUPERSEDE_REASON) \
            or not (isinstance(why["commit"], str) and COMMIT.fullmatch(why["commit"])) or not DATE.fullmatch(str(why["date"])):
        found.append("plan 2's supersedes doesn't name plan 1, the code its lists were drawn by, the reason and a date")
    return found


def holder_problems(root, plan_2):
    """Check 2: exactly one commit holds each plan's file, nothing under eval/t2 (or plan 2's file) changed after it, and
    plan 2 names plan 1's holder. Anything git can't say is a problem."""
    found = []
    for path, scope in ((PLAN_1, "eval/t2"), (PLAN_2, PLAN_2)):
        held = holders(root, path)
        if held is None or len(held) != 1:
            found.append(f"exactly one commit should hold {path}, and {len(held or [])} do")
            continue
        moved = shared.git("diff", "--name-only", held[0], "HEAD", "--", scope, cwd=root)
        loose = shared.git("status", "--porcelain", "--untracked-files=all", "--", scope, cwd=root)
        if moved is None or loose is None or moved or loose:
            found.append(f"{scope} changed after the commit that holds {path}")
        why = plan_2.get("supersedes")
        if path == PLAN_1 and (why.get("commit") if isinstance(why, dict) else None) != held[0]:
            found.append("plan 2 doesn't name the commit that holds plan 1")
    return found


def ledger_problems(root, rows):
    """Check 3: the ledger holds exactly one supersede line, no T2 batch started before it, every started line's commit
    descends from the commit that holds plan 2, and the line names plan 2's file and the hash of its bytes, as HEAD holds
    them and as they are on disk, so a changed plan 2 committed later is refused."""
    marks = [i for i, row in enumerate(rows) if row.get("set") == "T2-plan" and row.get("label") == "supersede"]
    if len(marks) != 1:
        return [f"the ledger should hold exactly one supersede line, and holds {len(marks)}"]
    line, found = rows[marks[0]], []
    if line.get("plan") != PLAN_2:
        found.append(f"the supersede line names {line.get('plan')}, not {PLAN_2}")
    disk = (pathlib.Path(root) / PLAN_2).read_bytes() if (pathlib.Path(root) / PLAN_2).is_file() else None
    for where, data in (("HEAD", committed_bytes(root, "HEAD", PLAN_2)), ("disk", disk)):
        if data is None or hashlib.sha256(data).hexdigest() != line.get("plan_sha256"):
            found.append(f"plan 2 as {where} holds it isn't the file the supersede line hashes")
    held = holders(root, PLAN_2)
    started = started_lines(rows)
    if [row["set"] for i, row in started if i < marks[0]]:
        found.append("a T2 batch started before the supersede line")
    if started and (held is None or len(held) != 1):
        return found + ["no one commit holds plan 2, so a started batch can't be tied to it"]
    for _, row in started:
        commit = row.get("commit")
        if not (isinstance(commit, str) and COMMIT.fullmatch(commit)):
            found.append(f"{row['set']} started from {commit!r}, which names no commit")
        elif shared.git("merge-base", "--is-ancestor", held[0], commit, cwd=root) is None:
            found.append(f"{row['set']} started from {commit[:12]}, which doesn't descend from plan 2's commit, or doesn't resolve")
    return found


def code_problems(root, plan_1, plan_2):
    """Check 4: the code diff from plan 1's code commit to plan 2's names only the harness, its tests and test data, CI, and
    what the freeze already lets change."""
    codes = (plan_1.get("code"), plan_2.get("code"))
    if not all(isinstance(code, str) and COMMIT.fullmatch(code) for code in codes):
        return ["a plan's code names no commit"]
    changed = shared.git("diff", "--name-only", *codes, cwd=root)
    if changed is None:
        return [f"plan 2's code {codes[1][:12]} can't be compared with plan 1's {codes[0][:12]}"]
    stray = [path for path in changed.splitlines() if path and path not in CODE_FILES
             and not path.startswith(CODE_FOLDERS + AFTER_PLAN) and not path.endswith(".md")]
    return [f"plan 2's code differs from plan 1's in files the freeze doesn't let change: {stray[:5]}"] if stray else []


def prefix_problems(root, working, commits):
    """Check 5, and the ledger-prefix check it extends: the ledger as it is, `working`, starts with the ledger as each
    commit held it, so lines were only added."""
    return [f"the ledger isn't what it was at {commit} with lines added after it" for commit in commits
            if (held := committed_bytes(root, commit, LEDGER_FILE)) is None or not working.startswith(held)]


def supersede_checks(root, ledger, plan_1, plan_2, extra=None):
    """Checks 1-5 for plan 2: every problem, none when it stands. `ledger` is the ledger's path, and `extra` a line not
    written yet, added in memory: as an entry for check 3, and as bytes for check 5."""
    path = pathlib.Path(ledger)
    working = path.read_bytes() if path.exists() else b""
    if extra is not None:
        working += ledger_line(extra)
    rows = [json.loads(line) for line in working.decode("utf-8").splitlines() if line.strip()]
    return (supersede_problems(plan_1, plan_2) + holder_problems(root, plan_2) + ledger_problems(root, rows)
            + code_problems(root, plan_1, plan_2) + prefix_problems(root, working, ("HEAD", plan_1.get("code"), plan_2.get("code"))))


def common_refusals(root, ledger):
    """(problems, the commit that holds plan 1, plan 1) for what both commands refuse over: a tree that isn't clean, plan 1
    not held by exactly one commit, a supersede line already in the ledger, or a T2 batch that has started."""
    found = []
    status = shared.git("status", "--porcelain", "--untracked-files=all", cwd=root)
    if status is None or status:
        found.append("the tree isn't clean")
    held = holders(root, PLAN_1)
    data = committed_bytes(root, held[0], PLAN_1) if held and len(held) == 1 else None
    if data is None:
        found.append(f"exactly one commit should hold {PLAN_1}, and {len(held or [])} do")
    rows = shared.entries(ledger)
    if any(row.get("set") == "T2-plan" and row.get("label") == "supersede" for row in rows):
        found.append("the ledger already holds a supersede line")
    if started_lines(rows):
        found.append("a T2 batch has started")
    return found, held[0] if data is not None else None, json.loads(data) if data is not None else None


def expected_facts(path):
    """The LOAD_FACTS the test loads gave, from a test-loads file: every reading of every load, all of them the same."""
    try:
        loads = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))["loads"]
        readings = [{fact: reading["facts"][fact] for fact in LOAD_FACTS} for load in loads for reading in load["readings"]]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"{path} isn't a file of test loads: {error!r}")
    if not readings or any(reading != readings[0] for reading in readings):
        raise SystemExit(f"{path} holds no readings, or readings that differ, so it doesn't say what to expect")
    return readings[0]


def load_session(base_url, model, log, plan_1, expected):
    """Step 8's session, on the live server: load with a chat and read the facts and where the load began, three more chats,
    an unload, a reload with a chat, and the shipped every-load scan from the first offset, which has to find two blocks
    and match both. Returns (the facts read after the first chat, problems). Stops at the first problem."""
    def chat():
        http_json(base_url + "/v1/chat/completions", {"model": model, "messages": [{"role": "user", "content": "Reply with OK."}],
                                                      "max_tokens": 2}, timeout=900)

    try:
        chat()
        first = server_facts(base_url, model, log)
        if first["load_problem"] or not first["loaded"]:
            return first, [first["load_problem"] or "the model isn't loaded right after a chat"]
        moved = [fact for fact in PINNED_FACTS if first[fact] != plan_1.get(fact)]
        moved += [fact for fact in LOAD_FACTS if first[fact] != expected[fact]]
        if moved:
            return first, [f"the server's {moved} aren't plan 1's pins and the test loads' facts"]
        for _ in range(3):
            chat()
        http_json(base_url + "/api/generate", {"model": model, "keep_alive": 0}, timeout=900)
        chat()
        problems, matched = scan_blocks(read_log(log), model_blob(base_url, model), expected, first["load_offset"], first["log_first_line"])
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise SystemExit(f"the model server failed during the session: {error!r}")
    if not problems and matched != 2:
        problems.append(f"the scan from the first load found {matched} matching loads, and the session made two")
    return first, problems


def plan_two(plan_1, holder, code, facts, scoring_hash, date):
    """Plan 2: plan 1's keys in their order, the load facts after server_config, and the keys SUPERSEDE_KEYS lets change."""
    document = {}
    for name, value in plan_1.items():
        document[name] = value
        if name == "server_config":
            document.update({fact: facts[fact] for fact in LOAD_FACTS})
    document.update(code=code, size_vram=facts["size_vram"], prose={**plan_1["prose"], SCORING: scoring_hash},
                    supersedes={"plan": PLAN_1, "commit": holder, "lists_drawn_by": plan_1["code"], "reason": SUPERSEDE_REASON, "date": date})
    return document


def supersede(date, expect, root=ROOT, ledger=shared.LEDGER, base_url="http://127.0.0.1:11434", model=MODEL, log=None):
    """--supersede: writes plan 2 and prints its sha256, or refuses and writes nothing. It refuses over what
    common_refusals names, an existing plan 2, a HEAD it can't read, facts that aren't plan 1's pins and the expected load
    facts, a session whose scan doesn't match two loads, and a plan 2 that fails check 1."""
    problems, holder, plan_1 = common_refusals(root, ledger)
    if (pathlib.Path(root) / PLAN_2).exists():
        problems.append(f"{PLAN_2} exists already")
    if not DATE.fullmatch(date):
        problems.append("the date is YYYY-MM-DD")
    code = shared.git("rev-parse", "HEAD", cwd=root)
    if code is None:
        problems.append("HEAD can't be read")
    if problems:
        raise SystemExit(f"--supersede refuses, and wrote nothing: {'; '.join(problems)}")
    facts, problems = load_session(base_url, model, log, plan_1, expected_facts(expect))
    if problems:
        raise SystemExit(f"--supersede refuses, and wrote nothing: {'; '.join(problems)}")
    document = plan_two(plan_1, holder, code, facts, shared.file_hash(pathlib.Path(root) / SCORING), date)
    problems = supersede_problems(plan_1, document)
    if problems:
        raise SystemExit(f"--supersede refuses, and wrote nothing: {'; '.join(problems)}")
    text = json.dumps(document, indent=1) + "\n"
    (pathlib.Path(root) / PLAN_2).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {PLAN_2}, uncommitted. sha256 {hashlib.sha256(text.encode()).hexdigest()}")


def supersede_record(date, digest, root=ROOT, ledger=shared.LEDGER):
    """--supersede-record: appends the supersede line, once, after plan 2's commit, or refuses and writes nothing. It refuses
    over what common_refusals names, a HEAD that isn't the one commit holding plan 2 and changing only that file from its
    code, bytes that don't hash to `digest`, and any problem in checks 1-5 with the line added in memory. Nothing is written
    until all of them pass, and there is no dry run."""
    problems, holder, plan_1 = common_refusals(root, ledger)
    if not DATE.fullmatch(date):
        problems.append("the date is YYYY-MM-DD")
    if not HASH.fullmatch(digest):
        problems.append("--sha256 is 64 lower-case hex characters")
    data, head, plan_2 = committed_bytes(root, "HEAD", PLAN_2), shared.git("rev-parse", "HEAD", cwd=root), None
    try:
        plan_2 = json.loads(data)
    except (TypeError, ValueError):
        pass
    if not isinstance(plan_2, dict):
        problems.append(f"HEAD holds no {PLAN_2} that can be read")
    else:
        if holders(root, PLAN_2) != [head]:
            problems.append(f"HEAD isn't the one commit that holds {PLAN_2}")
        if shared.git("diff", "--name-only", str(plan_2.get("code")), "HEAD", cwd=root) != PLAN_2:
            problems.append(f"HEAD should change only {PLAN_2} from plan 2's code")
        if hashlib.sha256(data).hexdigest() != digest:
            problems.append("plan 2 as HEAD holds it doesn't hash to --sha256")
        if plan_1 is not None:
            problems += supersede_checks(root, ledger, plan_1, plan_2, extra=supersede_line(date, digest))
    if problems:
        raise SystemExit(f"--supersede-record refuses, and wrote nothing: {'; '.join(problems)}")
    shared.append(ledger, supersede_line(date, digest))
    print(f"appended the supersede line for plan 2, sha256 {digest}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix-beacon", metavar="DATE", help="write DRAND_ROUND to the ledger as the beacon line, once, before the round is published")
    parser.add_argument("--draw", action="store_true", help="once the round is published: fetch it and draw every list into eval/t2")
    parser.add_argument("--oracle", type=pathlib.Path, help="the plan, to draw the oracle's list from the recorded task batches")
    parser.add_argument("--supersede", metavar="DATE", help="before any batch: run the live session and write eval/t2-plan-2.json, uncommitted")
    parser.add_argument("--expect", type=pathlib.Path, help="with --supersede: the test loads' file, whose load facts the session has to give")
    parser.add_argument("--supersede-record", metavar="DATE", help="after plan 2's commit: append the supersede line to the ledger, once")
    parser.add_argument("--sha256", help="with --supersede-record: the hash of plan 2, as --supersede printed it")
    parser.add_argument("--partial", nargs=3, metavar=("RESULTS", "NAME", "TOKEN"),
                        help="cut a dead run's results at its last progress line, into docs/evidence/t2/<name>.partial.jsonl")
    options = parser.parse_args()
    if bool(options.expect) != bool(options.supersede) or bool(options.sha256) != bool(options.supersede_record):
        parser.error("--expect goes with --supersede, and --sha256 with --supersede-record, and each needs the other")
    if options.supersede and options.supersede_record:
        parser.error("give --supersede or --supersede-record, not both")
    if options.supersede:
        supersede(options.supersede, options.expect)
    elif options.supersede_record:
        supersede_record(options.supersede_record, options.sha256)
    elif options.fix_beacon:
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
        parser.error("give --fix-beacon, --draw, --oracle, --partial, --supersede or --supersede-record")


if __name__ == "__main__":
    main()
