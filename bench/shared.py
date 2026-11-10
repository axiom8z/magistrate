"""What the scored runs share: which of the gateway's refusals are decisions, and proof of what ran. Standard library only.

A first score runs once, so its saved output has to show what produced it. Every scored run prints these lines at the top,
and bench/ledger.py refuses an output whose lines don't check out.
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "eval" / "ledger.jsonl"
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
# AgentDyn, the blind benchmark: a fork of AgentDojo whose three new suites nobody here has read.
AGENTDYN_COMMIT = "5353cf7615b135cace8d07c8f12dac53a16b6db3"
AGENTDYN_SUITES = ("shopping", "github", "dailylife")
# What scored runs write into the repository. Changing these changes nothing that runs, so they don't make it unclean.
OUTPUTS = ("eval/ledger.jsonl", "docs/evidence")
# A run on made-up data, to test the scoring itself. Its output says so, and nothing will record it.
PRACTICE = "practice run, never a score"
EVIDENCE_LINES = ("repo commit", "gateway built from", "scanner built from", "agentdojo checkout", "agentdojo installed")

# Refusals that mean something broke, or that the harness can't cause when it works. They aren't the gateway deciding, so a
# case that gets one is invalid, and DESIGN section 8 says errors never count as stops. bench/test_replay.py checks this list
# and the next against the rule IDs in the Go source, so a new rule can't go unclassified.
BROKEN = {"upstream-dead", "upstream-timeout", "upstream-error", "result-block-type", "result-malformed", "audit-failed", "latch-failed",
          "too-many-calls", "malformed-call", "not-initialized", "tool-not-in-policy", "pin-mismatch",
          "ask-cancelled", "ask-timeout", "ask-malformed", "ask-no-dialog"}
# The gateway deciding, apart from the secret rules, which have IDs of their own.
DECISIONS = {"unknown-tool", "unknown-argument", "session-exposed", "ask-declined", "ask-budget-spent", "ask-already-refused", "scan-over-budget",
             "unsourced-control", "credential-not-in-prompt", "quantity-invalid", "unsourced-link", "registered-sensitive-value"}
# A logged call that failed anyway because no such tool or argument exists, or it could not be read. Refusing it takes nothing
# away from a run, because the same failure reaches the model either way.
NEVER_RAN = {"unknown-tool", "unknown-argument", "malformed-call"}


def suite_functions(clone, suite):
    """{tool name: its definition} for one suite, read from source as text, in the order of the suite's TOOLS list. Names
    resolve through the suite file's own imports, because a fork like AgentDyn defines some names in more than one module.
    A name imported from nowhere falls back to the one module that defines it, and two candidates stop the run."""
    import ast

    base = pathlib.Path(clone) / "src" / "agentdojo" / "default_suites" / "v1"
    modules = {path.stem: {node.name: node for node in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(node, ast.FunctionDef)}
               for path in sorted((base / "tools").glob("*.py"))}
    tree = ast.parse((base / suite / "task_suite.py").read_text(encoding="utf-8"))
    imported, names = {}, []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("agentdojo.default_suites.v1.tools."):
            stem = node.module.rsplit(".", 1)[1]
            for alias in node.names:
                if alias.name in modules.get(stem, {}):
                    imported[alias.asname or alias.name] = modules[stem][alias.name]
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "TOOLS":
            if not all(isinstance(element, ast.Name) for element in node.value.elts):
                raise SystemExit(f"{suite}: TOOLS holds something other than plain names, so it can't be read as text")
            names = [element.id for element in node.value.elts]
    local = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    found = {}
    for name in names:
        candidates = [module[name] for module in modules.values() if name in module]
        if name in local:
            found[name] = local[name]
        elif name in imported:
            found[name] = imported[name]
        elif len(candidates) == 1:
            found[name] = candidates[0]
        else:
            raise SystemExit(f"{suite}: can't tell which {name} the suite uses")
    return found


def git(*args, cwd=ROOT):
    try:
        done = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def repo_line(root=ROOT):
    commit = git("rev-parse", "HEAD", cwd=root)
    # Only tracked files matter, and not the ones scored runs write. A work folder or a result changes nothing that ran.
    changed = git("status", "--porcelain", "--untracked-files=no", "--", ".", *(f":(exclude){path}" for path in OUTPUTS), cwd=root)
    return f'repo commit {commit or "unknown"} {"clean" if changed == "" else "MODIFIED"}'


def binary_line(label, binary):
    """Go stamps a binary with the commit it was built from, so this proves it instead of assuming it."""
    try:
        text = subprocess.run(["go", "version", "-m", str(binary)], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        text = ""
    revision = re.search(r"vcs\.revision=(\w+)", text)
    modified = re.search(r"vcs\.modified=(\w+)", text)
    state = "unmodified" if modified and modified.group(1) == "false" else "MODIFIED"
    return f'{label} built from {revision.group(1) if revision else "unknown"} {state}'


def tree_hash(folder):
    """The source files under a folder, by path and content, so that two copies can be compared."""
    digest = hashlib.sha256()
    folder = pathlib.Path(folder)
    for path in sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix in (".py", ".yaml") and "__pycache__" not in p.parts):
        digest.update(path.relative_to(folder).as_posix().encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return digest.hexdigest()


def checkout_line(clone, benchmark="agentdojo"):
    commit = git("rev-parse", "HEAD", cwd=clone)
    pinned = AGENTDYN_COMMIT if benchmark == "agentdyn" else AGENTDOJO_COMMIT
    return f'{benchmark} checkout {commit or "unknown"} {"pinned" if commit == pinned else "NOT THE PINNED COMMIT"}'


def installed_line(clone, installed):
    same = tree_hash(pathlib.Path(clone) / "src" / "agentdojo") == tree_hash(installed)
    return f'agentdojo installed copy {"matches the checkout" if same else "DIFFERS FROM THE CHECKOUT"}'


def header(gateway=None, scanner=None, clone=None, installed=None, benchmark="agentdojo"):
    lines = [repo_line()]
    if gateway:
        lines.append(binary_line("gateway", gateway))
    if scanner:
        lines.append(binary_line("scanner", scanner))
    if clone:
        lines.append(checkout_line(clone, benchmark))
        if installed:
            lines.append(installed_line(clone, installed))
    lines.append(f"python {sys.version.split()[0]}")
    return lines


def evidence_problems(lines):
    """What's wrong with a run's own account of what ran. Anything named here means it can't stand as a score."""
    found = []
    commit = None
    seen = False
    for line in lines:
        if line == PRACTICE:
            found.append("it was a practice run")
        elif line.startswith("repo commit"):
            seen = True
            parts = line.split()
            commit = parts[2]
            if parts[-1] != "clean":
                found.append("the repository had changes in it")
        elif line.startswith(("gateway built from", "scanner built from")):
            parts = line.split()
            if parts[-1] != "unmodified":
                found.append(f"the {parts[0]} wasn't built from a clean commit")
            elif commit and parts[3] != commit:
                found.append(f"the {parts[0]} was built from another commit")
        elif line.startswith(("agentdojo checkout", "agentdyn checkout")) and "NOT THE PINNED COMMIT" in line:
            found.append(f"{line.split()[0]} isn't at the pinned commit")
        elif line.startswith("agentdojo installed") and "DIFFERS" in line:
            found.append("the installed AgentDojo isn't the checkout")
    if not seen:
        found.append("the output doesn't say what ran")
    return found


def entries(path):
    path = pathlib.Path(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []


def already_scored(path, name):
    """Whether the ledger holds a first score for this set. Post-hoc, started and abandoned lines don't count as one."""
    return any(entry["set"] == name and "label" not in entry for entry in entries(path))


def already_started(path, name):
    """Whether a run started as this set and wasn't recorded as abandoned."""
    abandoned = {e.get("token") for e in entries(path) if e["set"] == name and e.get("label") == "abandoned"}
    return any(e["set"] == name and e.get("label") == "started" and e.get("token") not in abandoned for e in entries(path))


def append(path, entry):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as ledger:
        ledger.write(json.dumps(entry, separators=(",", ":")) + "\n")


def refuse_unless_first_score(name, facts, ledger=LEDGER):
    """Stops a one-shot run before it opens anything, unless what's about to run could stand as a score, and the ledger has
    neither a first score for this set nor a run that started as one. Finding out afterwards would have spent the one shot."""
    problems = evidence_problems(facts)
    if already_scored(ledger, name):
        problems.append(f"{name} already has a first score")
    elif already_started(ledger, name):
        problems.append(f"a run already started as {name}, so this would be a second look")
    if problems:
        sys.exit(f"this can't run as the first score {name}: {'; '.join(problems)}")


def start_first_score(name, facts, ledger=LEDGER):
    """Refuses as above, then writes down that the run started. Called last, just before the data is opened, so that nothing
    which could still fail spends the one shot, and a run that dies later is still on record. Returns the line its output
    must carry, which ties that output to this start."""
    refuse_unless_first_score(name, facts, ledger)
    token = os.urandom(8).hex()
    append(ledger, {"set": name, "label": "started", "token": token, "commit": run_commit(facts)})
    return f"first score {name}, run {token}"


def first_score_of(lines):
    """(name, token) from a run's output, or None if it didn't run as a first score."""
    for line in lines:
        match = re.fullmatch(r"first score (\S+), run ([0-9a-f]{16})", line)
        if match:
            return match.group(1), match.group(2)
    return None


def finish_first_score(name, token, entry, ledger=LEDGER):
    """Records the score of the run that started with this token, once. Any other run is refused."""
    if not any(e["set"] == name and e.get("label") == "started" and e.get("token") == token for e in entries(ledger)):
        sys.exit(f"no run started as {name} with this output's token, so it can't be that first score")
    if any(e["set"] == name and e.get("label") == "abandoned" and e.get("token") == token for e in entries(ledger)):
        sys.exit("that run was recorded as abandoned")
    if already_scored(ledger, name):
        sys.exit(f"{name} already has a first score")
    append(ledger, dict(entry, set=name, token=token))


def abandon(path, name, token, why, date):
    """Records that a started run produced nothing that stands, and why, so that another can start. Never quietly."""
    if not any(e["set"] == name and e.get("label") == "started" and e.get("token") == token for e in entries(path)):
        sys.exit(f"no run started as {name} with that token")
    if any(e["set"] == name and e.get("token") == token and "label" not in e for e in entries(path)):
        sys.exit("that run's score is already recorded, so it can't be abandoned")
    append(path, {"set": name, "label": "abandoned", "token": token, "why": why, "date": date})


def file_hash(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def input_line(path):
    return f"input {pathlib.Path(path).name} sha256 {file_hash(path)}"


def results_line(path):
    return f"results sha256 {file_hash(path)}"


def practice_allowed(clone, benchmark="agentdojo"):
    """A practice run is for made-up data. On the pinned benchmark it would read what's held back and print its scores."""
    return git("rev-parse", "HEAD", cwd=clone) != (AGENTDYN_COMMIT if benchmark == "agentdyn" else AGENTDOJO_COMMIT)


def run_commit(lines):
    for line in lines:
        if line.startswith("repo commit"):
            return line.split()[2]
    return None
