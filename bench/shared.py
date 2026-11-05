"""What the scored runs share: which of the gateway's refusals are decisions, and proof of what ran. Standard library only.

A first score runs once, so its saved output has to show what produced it. Every scored run prints these lines at the top,
and bench/ledger.py refuses an output whose lines don't check out.
"""
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
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


def git(*args, cwd=ROOT):
    try:
        done = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def repo_line():
    commit = git("rev-parse", "HEAD")
    # Only tracked files matter. A work folder or a result next to the code changes nothing that ran.
    changed = git("status", "--porcelain", "--untracked-files=no")
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


def checkout_line(clone):
    commit = git("rev-parse", "HEAD", cwd=clone)
    return f'agentdojo checkout {commit or "unknown"} {"pinned" if commit == AGENTDOJO_COMMIT else "NOT THE PINNED COMMIT"}'


def installed_line(clone, installed):
    same = tree_hash(pathlib.Path(clone) / "src" / "agentdojo") == tree_hash(installed)
    return f'agentdojo installed copy {"matches the checkout" if same else "DIFFERS FROM THE CHECKOUT"}'


def header(gateway=None, scanner=None, clone=None, installed=None):
    lines = [repo_line()]
    if gateway:
        lines.append(binary_line("gateway", gateway))
    if scanner:
        lines.append(binary_line("scanner", scanner))
    if clone:
        lines.append(checkout_line(clone))
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
        if line.startswith("repo commit"):
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
        elif line.startswith("agentdojo checkout") and "NOT THE PINNED COMMIT" in line:
            found.append("AgentDojo isn't at the pinned commit")
        elif line.startswith("agentdojo installed") and "DIFFERS" in line:
            found.append("the installed AgentDojo isn't the checkout")
    if not seen:
        found.append("the output doesn't say what ran")
    return found


def run_commit(lines):
    for line in lines:
        if line.startswith("repo commit"):
            return line.split()[2]
    return None
