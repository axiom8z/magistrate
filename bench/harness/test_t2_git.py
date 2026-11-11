"""Checks the parts of plan 2 that read git, in throwaway repositories: checks 1-5 of the supersession, the ledger's prefix, and
every refusal of --supersede and --supersede-record that comes from git or the ledger, each refusing once and passing once. A
fake stands in for the model server and its log, so nothing loads a model or opens a socket. No test reads this repository's
history, and git is told who it is with -c, never through config. No AgentDojo.

    python -I -X utf8 bench/harness/test_t2_git.py
"""
import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import shared  # noqa: E402
import t2_plan  # noqa: E402
import test_t2_plan as fixtures  # noqa: E402

GIT = ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false",
       "-c", "init.defaultBranch=main"]
DATE = "2026-11-12"
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def git(repo, *args):
    return subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def commit(repo, message, files=None):
    """Writes `files` ({path: text}), commits everything, and returns the new commit."""
    for name, text in (files or {}).items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def attempt(action):
    """(what a refusal said or None, what was printed)."""
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            action()
    except SystemExit as stop:
        return str(stop.code), out.getvalue()
    return None, out.getvalue()


def build_template(folder, already_superseding=False):
    """A repository with a ledger, the code at commit 1, plan 1 in one commit, and later code at commit 2 (HEAD, clean), beside a
    server log with only its startup lines and a file of the load facts a test load gave, as the real run has them."""
    folder.mkdir()
    repo = folder / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    log = folder / "server.log"
    log.write_bytes(fixtures.STARTUP)
    code = commit(repo, "code", {"bench/harness/t2.py": "v1\n", "bench/harness/t2_plan.py": "v1\n", "bench/shared.py": "v1\n", "eval/SCORING.md": "scoring v1\n",
                                 "eval/ledger.jsonl": '{"set":"S1","date":"2026-11-04"}\n{"set":"S2","date":"2026-11-04"}\n'})
    server = fixtures.FakeServer(log)
    server(server.BASE + "/v1/chat/completions", {})
    facts = fixtures.faked(server, lambda: t2_plan.server_facts(server.BASE, t2_plan.MODEL, log))
    plan_1, _ = fixtures.in_memory_plans()
    plan_1.update(code=code, **{fact: facts[fact] for fact in t2_plan.PINNED_FACTS})
    plan_1["prose"]["eval/SCORING.md"] = shared.file_hash(repo / "eval" / "SCORING.md")
    if already_superseding:
        plan_1["supersedes"] = {}
    commit(repo, "plan 1", {t2_plan.PLAN_1: json.dumps(plan_1, indent=1) + "\n", "eval/t2/ungated.json": "[]\n"})
    commit(repo, "later code", {"bench/harness/t2.py": "v2\n", "bench/harness/test_t2_git.py": "v1\n", "bench/harness/testdata/x.log": "x\n",
                                ".github/workflows/ci.yml": "ci\n", "eval/SCORING.md": "scoring v2\n"})
    loads = {"loads": [{"readings": [{"facts": {fact: facts[fact] for fact in t2_plan.LOAD_FACTS}}]}]}
    (folder / "expect.json").write_text(json.dumps(loads), encoding="utf-8")
    return plan_1


class Scene:
    """A copy of the template to do one thing in."""

    def __init__(self, template, parent, name):
        self.root = parent / name
        shutil.copytree(template, self.root)
        self.repo, self.log, self.expect = self.root / "repo", self.root / "server.log", self.root / "expect.json"
        self.ledger = self.repo / "eval" / "ledger.jsonl"
        self.plan_path = self.repo / t2_plan.PLAN_2

    def supersede(self, expect=None, date=DATE, **server):
        fake = fixtures.FakeServer(self.log, **server)
        return attempt(lambda: fixtures.faked(fake, lambda: t2_plan.supersede(date, expect or self.expect, self.repo, self.ledger,
                                                                              fake.BASE, t2_plan.MODEL, self.log)))

    def record(self, digest, date=DATE):
        return attempt(lambda: t2_plan.supersede_record(date, digest, self.repo, self.ledger))

    def commit(self, message, files=None):
        return commit(self.repo, message, files)

    def append(self, entry):
        """Adds a line to the ledger, committed."""
        self.add_line(entry)
        return self.commit("ledger")

    def snapshot(self):
        return self.ledger.read_bytes(), self.plan_path.exists()

    def plan_two(self):
        return json.loads(self.plan_path.read_text(encoding="utf-8"))

    def digest(self):
        return shared.file_hash(self.plan_path)

    def with_plan_two(self, after=None):
        """Runs --supersede, lets `after` change the files, commits it all with plan 2, and returns plan 2's hash."""
        message, _ = self.supersede()
        assert message is None, message
        digest = self.digest()
        if after:
            after(self)
        self.commit("plan 2")
        return digest

    def write(self, files):
        for name, text in files.items():
            (self.repo / name).write_text(text, encoding="utf-8", newline="\n")

    def add_line(self, entry):
        """Adds a line to the ledger, uncommitted."""
        self.write({"eval/ledger.jsonl": self.ledger.read_text(encoding="utf-8") + json.dumps(entry, separators=(",", ":")) + "\n"})


def refuses(result, text, snapshot, scene, what):
    """A refusal that says `text` and left the ledger and plan 2 as they were."""
    message, _ = result
    check(message is not None and text in message and scene.snapshot() == snapshot, f"{what}: refused, and wrote nothing")
    if message is None or text not in message:
        print(f"     said: {message}")


def supersede_command(template, parent, plan_1):
    scene = Scene(template, parent, "supersede-pass")
    before = scene.snapshot()
    message, out = scene.supersede()
    plan_2 = scene.plan_two() if scene.plan_path.exists() else {}
    expected = json.loads(scene.expect.read_text(encoding="utf-8"))["loads"][0]["readings"][0]["facts"]
    check(message is None and before[1] is False and scene.plan_path.exists() and scene.ledger.read_bytes() == before[0],
          "--supersede with a clean tree and the session matching writes plan 2, and not a ledger line")
    check(scene.digest() in out and b"\r" not in scene.plan_path.read_bytes() and scene.plan_path.read_bytes().endswith(b"\n"),
          "it prints plan 2's sha256, and the file has LF line ends")
    check(t2_plan.supersede_problems(plan_1, plan_2) == [] and plan_2["code"] == git(scene.repo, "rev-parse", "HEAD")
          and all(plan_2[fact] == expected[fact] for fact in t2_plan.LOAD_FACTS) and plan_2["size_vram"] == 5016660212
          and plan_2["supersedes"]["commit"] == git(scene.repo, "log", "--format=%H", "--", t2_plan.PLAN_1), "and it's plan 1 with the closed keys changed, from fake server facts")
    scene.commit("plan 2")
    message, out = scene.record(scene.digest())
    check(message is None and scene.ledger.read_text(encoding="utf-8").splitlines()[-1] == json.dumps(
        t2_plan.supersede_line(DATE, scene.digest()), separators=(",", ":")), "--supersede-record then appends exactly one supersede line")
    check(t2_plan.supersede_checks(scene.repo, scene.ledger, plan_1, scene.plan_two()) == [], "and checks 1-5 pass on plan 2, made by --supersede's own code")

    def trial(name, text, what, setup=None, **server):
        scene = Scene(template, parent, name)
        if setup:
            setup(scene)
        before = scene.snapshot()
        refuses(scene.supersede(**server), text, before, scene, what)

    trial("s-exists", "exists already", "--supersede with a plan 2 already there", lambda s: s.commit("early plan 2", {t2_plan.PLAN_2: "{}\n"}))
    trial("s-dirty", "tree isn't clean", "--supersede with an untracked file", lambda s: (s.repo / "stray.txt").write_text("x", encoding="utf-8"))
    trial("s-dirty-tracked", "tree isn't clean", "--supersede with a changed tracked file", lambda s: (s.repo / "eval" / "SCORING.md").write_text("edit\n", encoding="utf-8"))
    trial("s-two-plans", "exactly one commit should hold", "--supersede with two commits holding plan 1",
          lambda s: s.commit("plan 1 again", {t2_plan.PLAN_1: s.repo.joinpath(t2_plan.PLAN_1).read_text(encoding="utf-8") + "\n"}))
    trial("s-line", "already holds a supersede line", "--supersede with a supersede line in the ledger", lambda s: s.append(t2_plan.supersede_line(DATE, "0" * 64)))
    trial("s-started", "a T2 batch has started", "--supersede with a T2 started line",
          lambda s: s.append({"set": "T2-ungated", "label": "started", "token": "t", "commit": git(s.repo, "rev-parse", "HEAD")}))
    scene = Scene(template, parent, "s-date")
    refuses(scene.supersede(date="yesterday"), "date is YYYY-MM-DD", scene.snapshot(), scene, "--supersede with a date that isn't one")
    trial("s-version", "server_version", "--supersede when the server's version isn't plan 1's", version="9.9.9")
    trial("s-no-log", "missing or empty", "--supersede on a real server with no log", lambda s: s.log.unlink(), blocks=())
    trial("s-not-loaded", "isn't loaded right after a chat", "--supersede when /api/ps shows the model isn't loaded after a chat", shows_loaded=False)

    scene = Scene(template, parent, "s-expect")
    other = json.loads(scene.expect.read_text(encoding="utf-8"))
    other["loads"][0]["readings"][0]["facts"]["gpu_layers"] = "13/66"
    scene.expect.write_text(json.dumps(other), encoding="utf-8")
    refuses(scene.supersede(), "gpu_layers", scene.snapshot(), scene, "--supersede when the load facts aren't the expected ones")
    scene = Scene(template, parent, "s-expect-differ")
    other["loads"][0]["readings"].append({"facts": {fact: "different" for fact in t2_plan.LOAD_FACTS}})
    scene.expect.write_text(json.dumps(other), encoding="utf-8")
    refuses(scene.supersede(), "differ", scene.snapshot(), scene, "--supersede with test loads that disagree with each other")
    changed = fixtures.edited(fixtures.BLOCK, fixtures.OFFLOADED_LINE, b"load_tensors: offloaded 13/66 layers to GPU\n")
    trial("s-split", "differs in", "--supersede when the reload has another split", blocks=(fixtures.BLOCK, changed))
    trial("s-one-load", "found 1 matching", "--supersede when the unload and reload leave no second block", blocks=(fixtures.BLOCK,))


def committed_state(template, parent, plan_1):
    """The checks 2-5 on a repository where plan 2 is committed and recorded, each shown refusing once and passing once."""
    scene = Scene(template, parent, "checks")
    scene.with_plan_two()
    plan_2 = scene.plan_two()
    digest = scene.digest()
    message, _ = scene.record(digest)
    assert message is None, message
    repo, rows = scene.repo, shared.entries(scene.ledger)
    head = git(repo, "rev-parse", "HEAD")
    problem_with = fixtures.problem_with

    check(t2_plan.holder_problems(repo, plan_2) == [], "check 2: one commit holds each plan and nothing changed after it")
    wrong = {**plan_2, "supersedes": {**plan_2["supersedes"], "commit": "0" * 40}}
    check(problem_with(t2_plan.holder_problems(repo, wrong), "doesn't name the commit that holds plan 1"), "check 2: plan 2 naming another commit for plan 1 refuses")
    check(t2_plan.ledger_problems(repo, rows) == [], "check 3: one supersede line tied to plan 2's bytes, and no batch started")
    check(t2_plan.code_problems(repo, plan_1, plan_2) == [], "check 4: the code diff names only files the freeze allows")
    working = scene.ledger.read_bytes()
    at_head = t2_plan.committed_bytes(repo, "HEAD", t2_plan.LEDGER_FILE)
    check(t2_plan.prefix_problems(repo, working, ("HEAD", plan_1["code"], plan_2["code"])) == [], "check 5: the ledger only grew from each commit")
    check(t2_plan.prefix_problems(repo, working + b'{"set":"x"}\n', ("HEAD", plan_1["code"])) == [], "and lines added after it keep that so")
    check(problem_with(t2_plan.prefix_problems(repo, at_head[:-10], ("HEAD",)), "isn't what it was at HEAD"), "check 5: a ledger shorter than HEAD's refuses")
    check(problem_with(t2_plan.prefix_problems(repo, working, ("HEAD", "0" * 40)), "0" * 40), "and a commit that doesn't resolve refuses")

    side = git(repo, "rev-parse", plan_2["code"])
    git(repo, "checkout", "-q", "-b", "side", side)
    stray = commit(repo, "a file the freeze keeps", {"bench/shared.py": "v2\n"})
    git(repo, "checkout", "-q", "main")
    check(problem_with(t2_plan.code_problems(repo, plan_1, {**plan_2, "code": stray}), "bench/shared.py"), "check 4: a code diff that touches another file refuses")
    check(problem_with(t2_plan.code_problems(repo, plan_1, {**plan_2, "code": "main"}), "names no commit"), "and a code that names no commit")
    check(problem_with(t2_plan.code_problems(repo, plan_1, {**plan_2, "code": "1" * 40}), "can't be compared"), "and one git can't resolve")

    started = lambda commit_: {"set": "T2-ungated", "label": "started", "token": "t", "commit": commit_}
    line = next(i for i, row in enumerate(rows) if row.get("label") == "supersede")
    after = rows + [started(head)]
    check(t2_plan.ledger_problems(repo, after) == [], "check 3: a batch started from a commit that descends from plan 2's passes")
    check(problem_with(t2_plan.ledger_problems(repo, rows[:line] + rows[line + 1:]), "exactly one supersede line"), "check 3: no supersede line refuses")
    check(problem_with(t2_plan.ledger_problems(repo, rows + [rows[line]]), "exactly one supersede line"), "and two")
    check(problem_with(t2_plan.ledger_problems(repo, [started(head)] + rows), "started before the supersede line"), "and a batch started before the line")
    check(problem_with(t2_plan.ledger_problems(repo, after[:-1] + [started(stray)]), "doesn't descend"), "and one started from a commit that doesn't descend from plan 2's")
    check(problem_with(t2_plan.ledger_problems(repo, after[:-1] + [started("unknown")]), "names no commit"), "and one whose commit is unknown")
    check(problem_with(t2_plan.ledger_problems(repo, after[:-1] + [started(None)]), "names no commit"), "and one whose commit is None")
    check(problem_with(t2_plan.ledger_problems(repo, after[:-1] + [started("2" * 40)]), "doesn't resolve"), "and one whose commit doesn't resolve")
    check(problem_with(t2_plan.ledger_problems(repo, [dict(row, plan="eval/t2/plan.json") if i == line else row for i, row in enumerate(rows)]), "not eval/t2-plan-2.json"),
          "and a line that names another file")
    check(problem_with(t2_plan.ledger_problems(repo, [dict(row, plan_sha256="3" * 64) if i == line else row for i, row in enumerate(rows)]), "isn't the file the supersede line hashes"),
          "and a line whose hash isn't plan 2's")

    plan_path = repo / t2_plan.PLAN_2
    original = plan_path.read_text(encoding="utf-8")
    plan_path.write_text(original.replace(DATE, "2026-12-31"), encoding="utf-8", newline="\n")
    check(problem_with(t2_plan.ledger_problems(repo, rows), "as disk holds it") and not problem_with(t2_plan.ledger_problems(repo, rows), "as HEAD holds it"),
          "check 3's tie: plan 2 changed on disk only, and the run refuses")
    check(problem_with(t2_plan.holder_problems(repo, plan_2), "changed after the commit"), "and check 2 sees it too")
    commit(repo, "a different plan 2, under the same line")
    plan_path.write_text(original, encoding="utf-8", newline="\n")
    tied = t2_plan.ledger_problems(repo, rows)
    check(problem_with(tied, "as HEAD holds it") and not problem_with(tied, "as disk holds it"),
          "check 3's tie: a changed plan 2 committed under the same line refuses, though the file on disk is the one the line hashes")
    check(problem_with(t2_plan.holder_problems(repo, plan_2), "exactly one commit should hold eval/t2-plan-2.json, and 2"), "and check 2 sees two commits hold plan 2")

    ungated = repo / "eval" / "t2" / "ungated.json"
    ungated.write_text("[1]\n", encoding="utf-8")
    check(problem_with(t2_plan.holder_problems(repo, plan_2), "eval/t2 changed"), "check 2: a list changed after plan 1's commit refuses")


def record_command(template, parent):
    """--supersede-record's refusals that come from git or the ledger, each in a copy of the repository before the record."""
    def trial(name, text, what, before=None, after=None, digest=None, date=DATE):
        """`before` changes the repository before --supersede runs, committed, and `after` changes files with plan 2's commit."""
        scene = Scene(template, parent, name)
        if before:
            before(scene)
        right = scene.with_plan_two(after)
        snapshot = scene.snapshot()
        refuses(scene.record(digest or right, date), text, snapshot, scene, what)

    trial("r-badhash", "doesn't hash to --sha256", "--supersede-record with a hash that isn't plan 2's", digest="4" * 64)
    trial("r-hashform", "64 lower-case hex", "--supersede-record with a hash that isn't a hash", digest="plan")
    trial("r-date", "date is YYYY-MM-DD", "--supersede-record with a date that isn't one", date="soon")
    trial("r-more", "should change only", "--supersede-record when HEAD changes more than plan 2", after=lambda s: s.write({"other.txt": "x\n"}))
    trial("r-line", "already holds a supersede line", "--supersede-record with a line already in the ledger", after=lambda s: s.add_line(t2_plan.supersede_line(DATE, "0" * 64)))
    trial("r-started", "a T2 batch has started", "--supersede-record with a T2 started line",
          after=lambda s: s.add_line({"set": "T2-goals", "label": "started", "token": "t", "commit": git(s.repo, "rev-parse", "HEAD")}))
    trial("r-two-plans", "exactly one commit should hold", "--supersede-record with two commits holding plan 1",
          after=lambda s: s.write({t2_plan.PLAN_1: s.repo.joinpath(t2_plan.PLAN_1).read_text(encoding="utf-8") + "\n"}))
    trial("r-prefix", "isn't what it was at", "--supersede-record when plan 1's code commit held a ledger this one doesn't extend (check 5)",
          before=lambda s: s.commit("ledger rewritten", {"eval/ledger.jsonl": '{"set":"S1","date":"1999"}\n{"set":"S2","date":"2026-11-04"}\n'}))
    trial("r-code", "files the freeze doesn't let change", "--supersede-record when the code diff touches a file the freeze keeps (check 4)",
          before=lambda s: s.commit("gateway", {"bench/shared.py": "v2\n"}))

    scene = Scene(template, parent, "r-dirty")
    scene.with_plan_two()
    (scene.repo / "stray.txt").write_text("x", encoding="utf-8")
    refuses(scene.record(scene.digest()), "tree isn't clean", scene.snapshot(), scene, "--supersede-record with an untracked file")
    scene = Scene(template, parent, "r-head")
    digest = scene.with_plan_two()
    scene.commit("something after", {"bench/harness/t2.py": "v3\n"})
    refuses(scene.record(digest), "isn't the one commit that holds", scene.snapshot(), scene, "--supersede-record when HEAD isn't plan 2's commit")

    def altered(change, name, text, what):
        scene = Scene(template, parent, name)
        message, _ = scene.supersede()
        assert message is None, message
        plan_2 = scene.plan_two()
        change(plan_2)
        scene.plan_path.write_text(json.dumps(plan_2, indent=1) + "\n", encoding="utf-8", newline="\n")
        digest = scene.digest()
        scene.commit("plan 2, altered")
        refuses(scene.record(digest), text, scene.snapshot(), scene, what)

    altered(lambda p: p["lists"].update(a="9" * 64), "r-check1", "lists isn't plan 1's", "--supersede-record with a plan 2 whose list hashes changed (check 1)")
    altered(lambda p: p["supersedes"].update(commit="5" * 40), "r-check2", "doesn't name the commit that holds plan 1",
            "--supersede-record with a plan 2 that names another commit for plan 1 (check 2)")
    scene = Scene(template, parent, "r-nothing")
    refuses(scene.record("6" * 64), "holds no eval/t2-plan-2.json", scene.snapshot(), scene, "--supersede-record before plan 2 is committed")


def main():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
        parent = pathlib.Path(folder)
        plan_1 = build_template(parent / "template")
        supersede_command(parent / "template", parent, plan_1)
        committed_state(parent / "template", parent, plan_1)
        record_command(parent / "template", parent)
        build_template(parent / "superseding", already_superseding=True)
        scene = Scene(parent / "superseding", parent, "s-superseding")
        refuses(scene.supersede(), "itself a superseding plan", scene.snapshot(), scene, "--supersede when plan 2 fails check 1")
    print(f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
