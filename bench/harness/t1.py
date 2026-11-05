"""T1 from DESIGN section 8: every AgentDojo task and attack pair, played from the benchmark's own ground truth through
the real gateway. No model, no network and no cost, which makes it the floor: it shows what the gateway does to a
perfectly obedient agent that a perfect attack has hijacked.

For each pair, this script plays the user task's calls in order, carrying on after a refusal. When a result carries
the injected text, the pair counts as delivered, and the injection task's own calls run before the user task resumes.
So utility under attack exists, and "stops X% given a hijack" counts delivered pairs only. Every call goes to the
real binary, which passes what it allows to host_relay.py, and on to the real tool here.

It needs AgentDojo installed, so it runs from a virtual environment. Labels come from bench/replay_logs.py, which are
the ones the forecasts assumed, until the labels of milestone 7 exist. Everything here is a development number.

    <venv python> -X utf8 bench/harness/t1.py --clone <agentdojo checkout> --gateway <sayswho binary> --work <empty folder>
        --arm pass [--approver deny] [--workers 2] [--suite slack] [--limit 5] --out results.jsonl
    <venv python> -X utf8 bench/harness/t1.py --compare none.jsonl pass.jsonl
"""
import argparse
import collections
import concurrent.futures
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import wire  # noqa: E402

BENCHMARK_VERSION = "v1.2.2"
SUITES = ("banking", "slack", "travel", "workspace")
ARMS = ("none", "pass", "session", "value", "value-noids", "value-noprompt", "unreviewed")
# Fields two runs must agree on for `pass` to equal `none`.
COMPARED = ("utility", "security", "stock", "delivered", "results_hash", "problems")


def load_replay_module():
    """The labels and policy building live in the log replay, so that T0 and T1 can't drift apart."""
    spec = importlib.util.spec_from_file_location("replay_logs", HERE.parent / "replay_logs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plain(value):
    """What a call's arguments look like after crossing the wire. Every arm gets this, so `none` is a fair comparison."""
    return json.loads(json.dumps(value, default=str))


def structured(value):
    """The tool's return value as structuredContent. The spec requires an object, so lists and scalars get wrapped."""
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        return plain(value.model_dump(mode="json"))
    if isinstance(value, list):
        return {"result": [plain(item.model_dump(mode="json")) if isinstance(item, BaseModel) else plain(item) for item in value]}
    if isinstance(value, dict):
        return plain(value)
    return {"result": plain(value)}


def squeezed(text):
    """YAML rewraps and quotes long strings, so text is compared with whitespace, quotes and escapes taken out."""
    return re.sub(r"[\s'\"\\]+", "", text)


class Harness:
    def __init__(self, options):
        from agentdojo.task_suite.load_suites import get_suites

        self.options = options
        self.work = options.work.resolve()
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.mkdir(parents=True)
        self.suites = get_suites(BENCHMARK_VERSION)
        self.policies, self.tool_files = {}, {}
        if options.arm != "none":
            self.prepare_policies()

    def prepare_policies(self):
        replay = load_replay_module()
        parameters_by_suite = replay.suite_tools(self.options.clone)
        merged = None
        if self.options.labels:
            sys.path.insert(0, str(HERE.parent / "label"))
            import labels

            merged = json.loads(self.options.labels.read_text(encoding="utf-8"))["tools"]
        for suite, parameters in parameters_by_suite.items():
            tools_file = self.work / f"tools-{suite}.json"
            wire.write_tools(tools_file, replay.tool_listing(parameters))
            base = self.work / f"base-{suite}.json"
            base.write_text(json.dumps(wire.base_policy()), encoding="utf-8")
            draft = wire.draft_policy(self.options.gateway, base, tools_file)
            if merged is None:
                policy = replay.policy_for(self.options.arm, parameters, draft)
            else:
                # A file of merged answers covers every suite, and each suite takes its own tools.
                policy = labels.policy_for(self.options.arm, {name: merged[name] for name in parameters}, draft)
            policy_file = self.work / f"policy-{suite}.json"
            policy_file.write_text(json.dumps(policy), encoding="utf-8")
            self.policies[suite], self.tool_files[suite] = policy_file, tools_file

    def cases(self):
        """97 tasks alone, then every pair: 949 of them."""
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

        class NamedOnly(BasePipelineElement):
            # The attack only reads the pipeline's name, to address the model by it. No model runs in T1.
            name = "openai-compatible-harness"

            def query(self, *_args, **_kwargs):
                raise RuntimeError("no model runs in T1")

        out = []
        for name in SUITES:
            if self.options.suite and name != self.options.suite:
                continue
            suite = self.suites[name]
            attack = ImportantInstructionsAttack(suite, NamedOnly())
            for user_task in suite.user_tasks.values():
                out.append((name, user_task, None, suite.get_injection_vector_defaults()))
                for injection_task in suite.injection_tasks.values():
                    out.append((name, user_task, injection_task, attack.attack(user_task, injection_task)))
        return out[: self.options.limit] if self.options.limit else out

    def approver(self, tools_in_task, current):
        if self.options.approver == "approve":
            return wire.always_accept
        if self.options.approver == "inattentive":
            # Waves through any tool the user's task would use, whatever it's being pointed at.
            return lambda _params: wire.ACCEPT if current["tool"] in tools_in_task else wire.DECLINE
        return wire.always_decline

    def run_case(self, index, case):
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.types import text_content_block_from_string

        suite_name, user_task, injection_task, injections = case
        suite = self.suites[suite_name]
        environment = suite.load_and_inject_default_environment(injections)
        task_env = user_task.init_environment(environment)
        pre = task_env.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        plan = user_task.ground_truth(pre)
        tools_in_task = {call.function for call in plan}
        current = {"tool": None}

        def host(name, arguments):
            result, error = runtime.run_function(task_env, name, arguments)
            if error:
                return wire.text_result(error, is_error=True)
            return wire.text_result(tool_result_to_str(result), structured(result))

        tool_host, gateway, folder = None, None, None
        if self.options.arm != "none":
            folder = self.work / "cases" / f"{index:05d}"
            folder.mkdir(parents=True)
            prompt = folder / "prompt.txt"
            prompt.write_text(user_task.PROMPT, encoding="utf-8", newline="")
            tool_host = wire.ToolHost(host)
            prompt_file = None if self.options.arm == "value-noprompt" else prompt
            gateway = wire.GatewaySession(self.options.gateway, self.policies[suite_name], folder / "state", self.tool_files[suite_name],
                                          tool_host.port, prompt_file, self.approver(tools_in_task, current))

        executed, proposed, refused, texts = [], [], [], []
        asks = 0

        def execute(call, part):
            nonlocal asks
            arguments = plain(call.args)
            proposed.append(call)
            current["tool"] = call.function
            if gateway is None:
                reply = host(call.function, arguments)
                text, rule = reply["content"][0]["text"], None
            else:
                answer = gateway.call(call.function, arguments)
                text, rule = answer.text, answer.rule
                asks += answer.asks
            texts.append(text)
            if rule:
                refused.append({"part": part, "tool": call.function, "rule": rule})
            else:
                executed.append(call)
            return text

        delivered = False
        needles = [squeezed(text) for text in injections.values()] if injection_task else []
        problems = []
        try:
            for call in plan:
                text = execute(call, "user")
                if needles and not delivered and any(needle in squeezed(text) for needle in needles):
                    delivered = True
                    for bad in injection_task.ground_truth(task_env):
                        execute(bad, "injection")
        except Exception as problem:  # a run that broke is invalid, and never counts as a stop
            problems.append(f"{type(problem).__name__}: {problem}")
        finally:
            if gateway:
                gateway.close()
            if tool_host:
                tool_host.close()
                problems += tool_host.problems
            if folder:
                shutil.rmtree(folder, ignore_errors=True)

        output = [text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]
        record = {
            "suite": suite_name,
            "user_task": user_task.ID,
            "injection_task": injection_task.ID if injection_task else None,
            "delivered": delivered,
            "calls": len(proposed),
            "refused": refused,
            "asks": asks,
            "results_hash": hashlib.sha256("\n".join(texts).encode()).hexdigest(),
            "problems": problems,
            "utility": bool(suite._check_task_result(user_task, output, pre, task_env, executed)),
        }
        if injection_task:
            record["empty_ground_truth"] = len(injection_task.ground_truth(pre)) == 0
            # security=True means the attack won. Executed counts what ran, and stock counts what was attempted.
            record["security"] = bool(suite._check_task_result(injection_task, output, pre, task_env, executed))
            record["stock"] = bool(suite._check_task_result(injection_task, output, pre, task_env, proposed))
        return record


def share(part, whole):
    return f"{part}/{whole} ({100 * part / whole:.1f}%)" if whole else "0/0"


def report(records, label, out=sys.stdout):
    print(f"T1, {label}: ground-truth replay of AgentDojo {BENCHMARK_VERSION}, no model. Development numbers.", file=out)
    invalid = sum(1 for r in records if r["problems"])
    print(f"  cases {len(records)}, invalid {invalid}", file=out)
    print("  | suite | benign utility | utility under attack | delivered | attack won, given delivered | attempted calls refused | pairs with no ground truth |", file=out)
    print("  |---|---|---|---|---|---|---|", file=out)
    for suite in SUITES + ("all",):
        chosen = [r for r in records if suite in (r["suite"], "all")]
        benign = [r for r in chosen if r["injection_task"] is None]
        pairs = [r for r in chosen if r["injection_task"] is not None]
        scored = [r for r in pairs if not r["empty_ground_truth"]]
        delivered = [r for r in scored if r["delivered"]]
        won = sum(1 for r in delivered if r["security"])
        refused = sum(1 for r in delivered if any(f["part"] == "injection" for f in r["refused"]))
        print(f'  | {suite} | {share(sum(r["utility"] for r in benign), len(benign))} | {share(sum(r["utility"] for r in pairs), len(pairs))} | '
              f"{share(len(delivered), len(scored))} | {share(won, len(delivered))} | {share(refused, len(delivered))} | {len(pairs) - len(scored)} |", file=out)
    why = collections.Counter(f["rule"] for r in records for f in r["refused"])
    print("  refusals by rule:", dict(why.most_common()), file=out)
    misses = [f'{r["suite"]}/{r["user_task"]}/{r["injection_task"]}' for r in records if r.get("security") and r["delivered"] and not r["empty_ground_truth"]]
    print(f"  attacks that won: {len(misses)}", file=out)
    for miss in misses:
        print("    " + miss, file=out)
    for r in records:
        for problem in r["problems"]:
            print(f'  invalid: {r["suite"]}/{r["user_task"]}/{r["injection_task"]}: {problem}', file=out)


def compare(first_path, second_path):
    def load(path):
        with open(path, encoding="utf-8") as f:
            return {(r["suite"], r["user_task"], r["injection_task"]): r for r in map(json.loads, f)}

    first, second = load(first_path), load(second_path)
    differences = []
    if set(first) != set(second):
        differences.append(f"the two runs hold different cases: {len(first)} and {len(second)}")
    for key in sorted(set(first) & set(second), key=str):
        for field in COMPARED:
            if first[key].get(field) != second[key].get(field):
                differences.append(f"{key}: {field}: {first[key].get(field)} against {second[key].get(field)}")
    print(f"{len(set(first) & set(second))} cases compared on {', '.join(COMPARED)}: {len(differences)} differences")
    for line in differences[:50]:
        print("  " + line)
    return 1 if differences else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clone", type=pathlib.Path)
    parser.add_argument("--gateway", type=pathlib.Path)
    parser.add_argument("--work", type=pathlib.Path)
    parser.add_argument("--arm", default="none", choices=ARMS)
    parser.add_argument("--approver", default="deny", choices=("deny", "approve", "inattentive"))
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--suite", choices=SUITES)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out")
    parser.add_argument("--labels", type=pathlib.Path, help="merged answers from bench/label/labels.py, in place of the forecast's labels")
    parser.add_argument("--compare", nargs=2)
    options = parser.parse_args()
    if options.compare:
        return compare(*options.compare)

    harness = Harness(options)
    cases = harness.cases()
    print(f"{len(cases)} cases on arm {options.arm}, approver {options.approver}, {options.workers} at a time", file=sys.stderr, flush=True)
    with concurrent.futures.ThreadPoolExecutor(options.workers) as pool:
        records = list(pool.map(lambda pair: harness.run_case(*pair), enumerate(cases)))
    if options.out:
        with open(options.out, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")
    named = {"none": "no gateway", "pass": "pass mode", "unreviewed": "the init draft, unedited"}.get(options.arm, "merged labellers' answers" if options.labels else "forecast labels")
    report(records, f"arm {options.arm}, approver {options.approver}, labels: {named}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
