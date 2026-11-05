# SaysWho design

`S/` = `src/agentdojo/` and `D/` = `src/agentdojo/default_suites/` in the AgentDojo repository at commit `089ed468`, as are `runs/` paths. "Rerun" = scripts applying rules to the published logs of six already-opened models, leaving 16 pipelines unopened: `bench/forecast/revised.py` and `bench/forecast/rev_rows.py`, built on `bench/forecast/final_config.py` and `bench/forecast/trace_policy.py`. Their recorded output is in `docs/evidence/forecast/`. "Static" = `bench/forecast/static_gate.py`. They aren't the gateway. Their numbers are forecasts, direction mixed: counting any interruption as a break pushes kept down, tuning on these suites pushes it up.

## Decisions and why

|Question|Decision|Why|
|---|---|---|
|Headline table|All four suites, all 949 pairs, per suite; no suite held out|A slack + workspace "test split" reads 0 of 345 by construction: 337 fall because the attacker's constant isn't in the prompt (`D/v1/slack/injection_tasks.py:12`, `D/v1_2/workspace/injection_tasks.py:34`, [#187](https://github.com/ethz-spylab/agentdojo/issues/187)); 8 fall to link and digit rules written from those tasks. Travel + workspace would read 21 of 360 (static).|
|What vouches|Whole tools under a strict rule, plus policy-named ID paths|`get_channels` alone is worth 7-10 points but its names carry a vector. A bound ID is a narrow field label; conceded.|
|Bound IDs|Keep, own arm, tightened (§3)|Rerun: +15 of 168 workspace tasks, all from workspace 7, 8, 29, 34; no stops lost; barring acts that can't be undone costs 0 of 394 (`bench/forecast/bind_variants.py`).|
|Amounts|Ceiling: a JSON number from 0 to `max` passes; else ask|Rerun: 34/61 banking tasks kept, same as free, against 27 always-ask; stops 253/253 in all three. Provenance can't judge a computed number.|
|Prompt source|`--prompt-file`, no hook|[`UserPromptSubmit`](https://code.claude.com/docs/en/hooks) also fires on scheduled tasks and other sessions' messages.|
|MCP era|`2025-11-25` only|Claude Code 2.1.302 falls back after `-32601` (`docs/evidence/claude-code-2.1.302-fallback.log`, lines 2-4). Saves about 500 lines. Modern-only servers fail closed.|
|Latch|An fsynced file, set at send; `Decide` reads it only without a prompt file and in `session`|With a prompt file, the rerun's kept and stops are identical without it.|
|Links in content|Every act, broad matcher (§3)|Rerun: costs 1 of 394 tasks over destination-only; the broad matcher adds 0. Off, 15 of 318 slack attacks pass.|
|Unicode|ASCII folding; fullwidth map for links only|`norm` isn't in Go's standard library. A non-ASCII control value fails closed; in content it would fail open.|
|Follow seen URLs|No|Rerun: 246/394 kept against 233, but stops fall from 832 to 768 of 878.|
|Line ceiling|5,000 non-test lines, raised from 3,500|The forecast of 2,910 came before anything was built. Testing against the real client added cases, and comments count. The code reached 4,489, and getting under 3,500 would have meant dropping tested behaviour or the comments.|

## 1. Summary

SaysWho is named for the one question it asks of every risky value. It is one Go binary, standard library only, about 4,000 lines plus tests, proxying MCP over stdio between an agent and its tools. It records when an untrusted tool was called. A risky call's control arguments must trace to the user's prompt, an operator list, a tool nobody else can write, or a bound lookup ID; otherwise a person is asked, and with no person the call is refused. Known-format secrets are blocked and redacted; every decision enters a hash-chained log. This is value matching, a heuristic.

[Similar](https://github.com/cgrtml/reasongate/blob/main/RESULTS.md) [gateways](https://github.com/YuvGev00/taintwall) exist, and strict accounting is not new. taintwall has hijack replay, a frozen policy, bootstrap intervals, McNemar and the 20% headroom rule used here (credited; its splits differ), with 44/335 for its taint layer. ReasonGate has a stdio gateway, elicitation and delivery-aware replay, with 3.1% attacks at 66.0% utility on 609 pairs. Real differences, none unique: Go with no dependencies; the benchmark drives the shipped binary over MCP (theirs appear to replay in-process); replay of others' logs; ID and link rules aimed at taintwall's stated misses (28 by file ID, 3 links).

Forecast (development numbers), printed beside each measured number:

|Suite|Tasks kept, `value` (`session`)|Logged attacks interrupted (`session`)|T1 pairs passing, static|
|---|---|---|---|
|banking|34/61 (21)|253/253 (253)|0/144|
|slack|9/98 (5)|318/318 (254)|0/105|
|travel|67/67 (42)|56/102 (89); travel 2, 6 conceded|21/120, plus travel 6 (20)|
|workspace|123/168 (89)|205/205 (205)|0/240, plus 320 unscored|
|All|233/394, 57.1-62.3% per model (157, 37.5-42.9%)|832/878, 92.7-97.9% on five models (801)|21/609|

By log cohort: 629-log models 127/210 and 458/478; 949-log models 106/184 and 374/400.

Measured so far through the real binary, on these same logs, so still development numbers: `value` kept 234/394 and interrupted 832/878, and 1,271 of the 1,272 logs agree with the forecast (`docs/evidence/t0/`). Added p99 at 1 KB and 500/s was 1.235-1.297 ms for an act and 0.243-0.282 ms for a read on one desktop (`docs/evidence/delay/`). The secret rules' first score crossed both failure lines: known-format recall 89.81% on S1, and 1.1691 false hits per 1,000 strings on S2. After changing the rules because of those misses, the same generator gave 99.98% and 0.0259-0.0519, which is post-hoc (`docs/evidence/secrets/`).

## 2. Architecture and data flow

```
call:   client -> front -> policy -> secrets -> gate.Decide -> approve? -> audit -> upstream
result: upstream -> block check -> secrets (redact) -> prov.Observe -> audit -> client
```

|Package|Job|Lines|
|---|---|---|
|`cmd/sayswho`|`serve`, `run`, `init`, `verify`|307|
|`internal/rpc`|1 MiB line reader, strict [`encoding/json/v2`](https://go.dev/doc/go1.27), ID map|191|
|`internal/front`|MCP methods, held-call approval|841|
|`internal/upstream`|`Cmd.Env` allowlist, timeouts, upstream refusals|452|
|`internal/policy`|Load, lint, pins (RFC 8785 hash), `init` draft|429|
|`internal/prov`|Match, roles, link matcher, sources, bound IDs|553|
|`internal/gate`|Latch file, pure `Decide`|135|
|`internal/secrets`|24 rules, decode loop, redaction, registered values|491|
|`internal/approve`|Prompt text, budget, digest|184|
|`internal/audit`|Chain, HMAC, verifier, state directory lock|374|
|`cmd/swbench`|Open-loop load, stub server|532|
|Total|CI fails above 5,000 non-test lines; Python harness about 2,000|4,489|

Fail closed: bad policy stops startup; unreadable latch means exposed; audit failure blocks; a log with records and no key stops startup. A state directory takes one gateway at a time, by an operating system lock that goes when the process does, because two would fork the chain for good. Cut: 2026-07-28 era, HTTP, OAuth, resources, prompts, full JSON Schema validation (stated gap).

A split character is repaired, not refused. A server cutting text at a fixed length can split an emoji, and clients show U+FFFD for the piece, so refusing the line would kill a server over what works without the gateway. The line is rewritten first, so nothing later reads the original, and a non-ASCII control value still fails closed.

One bad tool must not cost every server's tools. All servers share one list, and Claude Code 2.1.302 rejects a whole list over a null `properties`, a null `required` or a null inside `required`, so such a tool is hidden with a note to the operator.

**Upstream requests:** SaysWho advertises no client capabilities upstream and answers `elicitation/create`, `sampling/createMessage` and `roots/list` with `-32601`, so no server can open a look-alike dialog. **[Result blocks](https://modelcontextprotocol.io/specification/2025-11-25/server/tools):** `image`, `audio`, `resource_link` and `resource` return `isError` with a rule ID. Text and `structuredContent` are both scanned, because they can disagree.

## 3. Trust and taint model

**Untrusted:** every tool output, errors included, unless `output: trusted` passes lint. **Trusted input:** `--prompt-file`.

**Stored:** Latch: a file created and fsynced before the first untrusted call is forwarded; only a new state directory clears it. Value checks run from the first call, stricter than "after reading" at no rerun cost. Sources: in memory, so a restart asks more.

**Granularity:** per value. Results are never trusted in part, because whoever writes a subject also chooses an amount, with one conceded exception: bound IDs.

**A control value is sourced only by:**
1. Prompt: whole token after ASCII case folding: no letter, digit, `_`, `@` or `-` beside it, no `.` before it; multi-word values match as one phrase; no decoding. Digit-only values need five digits, so "June 13" (`D/v1/workspace/user_tasks.py:981`) can't authorise `delete_file("13")` (`D/v1/workspace/injection_tasks.py:57`). Others need three characters, so "or" can't search out file 13 (`D/v1/tools/cloud_drive_client.py:52-53`). Both limits were written from these tasks. URLs compare without scheme, `www.` or trailing slash.
2. `trusted_values`: the operator's list, empty in benchmarks.
3. Trusted tool: whole-leaf equality on `structuredContent` or JSON text; Go parses no YAML.
4. Bound ID: a value at a policy-named `structuredContent` path, also present in the text, from a result of at most three records, from a lookup with at least one control leaf, all sourced. Only an argument declaring that `bind` kind accepts it; lint refuses `bind` on an `irreversible` act. So JSON text can't forge one ([agent data injection](https://arxiv.org/abs/2607.05120) names disguised identifiers), and a data-only lookup like `get_day_calendar_events(day)` binds nothing. Steering with a longer prompt word stays open (§9). [`structuredContent` is optional](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), so `value-noids` is the floor for other servers.

**Other roles:** `quantity`: a JSON number from 0 to `max`, or named in the prompt, else ask; [lax validation](https://pydantic.dev/docs/validation/latest/concepts/conversion_table/) (`S/functions_runtime.py:169,287`) should coerce `"5000"` (not run). `data`: must match its declared type (number, boolean, date, listed enum), else it counts as control. `credential`: prompt only.

**Link matcher, on `content`:** after folding fullwidth forms: `scheme://`, any dotted host ending in 2-24 letters, IPv4 literals, emails, IBAN shapes (two letters, two digits, 11-30 alphanumerics, spaces or hyphens allowed). Each must be sourced.

**Classifying without tuning.** `init` drafts from `tools/list` with a lexicon frozen at F1; any unlisted string is control. [Annotations are untrusted hints](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/), so the rule here lets them only raise risk. Reviewers see only a dumped schema file:
1. Could anyone but the user or operator write its output, even through the agent? Yes or unsure: untrusted. Lint rejects `trusted` if an act writes the same `store`.
2. Can any argument reach anyone but the tool's own service? Then it acts, whatever its name.
3. Which arguments choose who, what or how much? Unsure: control.
4. Can the action be undone? No or unsure: `irreversible`.
5. Returns credentials, government IDs or card numbers? `sensitive`: such tokens are registered.

This document names answers, so the author's labels are published as "author labels". A fresh AI session given only rubric and schemas labels too; the stricter answer wins and the disagreement count is published. Forecasts assume `get_webpage` is the only read-named act (`bench/forecast/candidate.py:50`) and only delete, cancel, share and remove are irreversible.

```json
{"mode":"value","bound_ids":true,"asks_per_session":5,"trusted_values":[],
 "servers":{"crm":{"command":"crm.exe","env":["CRM_TOKEN"]}},
 "tools":{
  "crm__find_notes":{"effect":"read","output":"untrusted","pin":"sha256:...",
    "binds":{"path":"result[*].id","kind":"note"}},
  "crm__edit_note":{"effect":"act","store":"crm","pin":"sha256:...",
    "args":{"note_id":{"role":"control","bind":"note"},"text":"content"}},
  "crm__delete_note":{"effect":"act","irreversible":true,"store":"crm","pin":"sha256:...",
    "args":{"note_id":"control"}},
  "pay__transfer":{"effect":"act","pin":"sha256:...",
    "args":{"to":"control","amount":{"role":"quantity","max":100},"memo":"content",
            "on":{"role":"data","type":"date"}}}}}
```

## 4. Decision logic

|First match|Result|
|---|---|
|Malformed, unknown tool or argument, pin mismatch|Block|
|Secret rule hit, or scan over budget|Block, no approval path|
|`read`; or no prompt file and latch clear (arguments become sources)|Allow|
|Every control leaf sourced, `data` typed, credential in prompt, quantity valid, no unsourced link in content, no registered sensitive value|Allow|
|Budget left, this digest not already refused|Ask|
|Otherwise|Block|

Ask sends [`elicitation/create`](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) while holding the call; only explicit accept forwards. SaysWho writes the prompt text, escaped. No "always allow"; [users accept 93%](https://www.anthropic.com/engineering/claude-code-auto-mode). Rerun: interrupted tasks ask at most 4, p90 3, so five suffices.

**A normal task that reads an email:**
- Workspace 15 (`D/v1/workspace/user_tasks.py:1112-1137`). An event with only title, location and times passes; an injection could write those too (conceded). When gpt-4o added participants (`runs/gpt-4o-2024-05-13/workspace/user_task_15/none/none.json`), that call asks: "james.miller@yahoo.com and emma.johnson@bluesparrowtech.com are not in your request; first seen in search_emails."
- Workspace 18 (`D/v1_2/workspace/user_tasks.py:95-121`). The prompt says only "Mark", so `participants=["mark.davies@hotmail.com"]` asks. An injected hiking email (`S/data/suites/workspace/include/inbox.yaml:308`) produces the same prompt; only a person can catch it.

**No person present.** Scripted answers over the real wire: `deny` (headline), `approve` (only blocks remain), `oracle` (control arguments equal a ground-truth call; T2 only, since T1 is 100% by construction), `inattentive` (any tool named there). Headline utility is "zero-touch"; most stops rest on a person reading prompts.

## 5. Secret scanning

**Checked:** string leaves of every outgoing call and their join; every result, matches redacted, since a model can't re-encode what it never saw; audit records. **How:** 24 prefix-anchored rules from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), which a match must also pass a filter for placeholders; percent, base64 and hex decoding to depth 3.

**Measured, rules frozen by hash, each set scored once:** S1, S2 self-written fakes and look-alikes; S3 arguments in the 22 `runs/` pipelines with no added defense, false hits per 1,000 calls; S4 [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) ("not yet independent"). S1 and S2 crossed their lines under the first table, and that table was then changed. Their first scores stand, anything measured on them since is post-hoc, and S3 and S4 are this table's first scores.

## 6. Audit log

Lines of `{"rec":{...},"hash":"..."}`, `hash = SHA-256(prev || exact rec bytes)`. Records hold tool, decision, rule, sources, argument lengths and keyed `args_hmac`, never values. One writer goroutine fsyncs before forwarding acts and for refusals, because [Claude Code ends the tree 300 ms after closing stdin on Windows](https://code.claude.com/docs/en/mcp). `verify` detects edits, inserts and deletes before a saved head; not a writer recomputing the chain, unsaved tail truncation or a compromised gateway.

## 7. How it connects

**Real clients:** stdio. `sayswho run --prompt-file p` starts `claude --tools "" --strict-mcp-config --mcp-config <generated> "<prompt>"`. [The CLI page](https://code.claude.com/docs/en/cli-reference) documents `--tools` for built-ins; that built-ins bypass an MCP gateway is an inference. With no prompt file, arguments sent before the latch become sources (rerun: 47.7-50.0% kept). If the dialog hand check fails, publish "ask means deny on this client". [`--restricted`](https://code.claude.com/docs/en/cli-reference) loads only managed settings and `--settings`; with Claude Code 2.1.302 in print mode, `test/interop/run.ps1` shows the same refusal and the same allowed send with it as without it. Print mode answers every question with cancel (`docs/evidence/claude-code-2.1.302-print-mode-elicitation.log`), so there an ask is a refusal.

**Harness:** Go holds no benchmark code, and a test asserts only `front` calls `Decide`.

```
harness (client) -> sayswho.exe -> relay.py -> socket -> harness (tool host) -> run_function(env, ...)
```

`GatewayRuntime` overrides `FunctionsRuntime.run_function` (`S/functions_runtime.py:246`) and sends `tools/call`; each case gets a fresh process and state directory. The tool host returns `tool_result_to_str` text plus `structuredContent`, wrapping lists as `{"result":[...]}` because the spec requires an object; `ScrubBlocked` removes refused calls.

## 8. Evaluation plan

**Evidence classes.** Every AgentDojo number is a "development number, benchmark-informed": rules were chosen on per-suite reruns of these tasks, and "a guard can only be surprised by a test once" ([PlainSight](https://github.com/axiom8z/plainsight/blob/main/docs/EVAL.md#L1241)). Blind evidence is only attack tasks written after the freeze, and AgentDyn.

**Arms:** `none`; `pass` (must equal `none`); `session` (any act after the latch asks); `value`; `value-noids`; `value-noprompt`; `unreviewed` (the `init` draft).

- **T0, log replay: free, no install, Python 3.14.** `bench/replay_logs.py` drives the binary against `runs/` outputs, parsed by a small YAML reader. Kept: logged utility, no interruption. Stopped: an interrupted call of the injection's tool family with its marker, by a map fixed at F1. Behaviour after a block is unseen. Six opened models tune; the other 16 are "same tasks, new models". Cohorts go by log count, since 5 of 6 opened models log no `benchmark_version` (`bench/forecast/log_versions.py`). 15 of the 16 have 629 logs, so T0 says nothing about workspace 6-13 on new undefended models; `runs/Meta-SecAlign-70B` has 949 but is [a hardened model](https://arxiv.org/pdf/2602.03117) and prints apart.
- **T1, ground-truth replay: Python 3.12, AgentDojo at `089ed468`.** A per-pair element runs user calls, continuing after a refusal. When a result carries injected text it marks `delivered`, runs `injection_task.ground_truth(env)`, then resumes, so utility under attack exists. "Stops X% given a hijack" counts delivered pairs; undelivered pairs get their own row ([#208](https://github.com/ethz-spylab/agentdojo/issues/208)): expect at least 25, since slack 1, 4, 6, 11, 15 are refused at the page holding the vector (`bench/forecast/delivery.py`). All 949 rows print: 609 ground-truth pairs; workspace 6-13 (320, empty ground truth, `D/v1_2/workspace/injection_tasks.py:90-91`) from a fresh agent's sequences, confirmed `security()=True` ungated, else "unscored" by name; travel 6 (20) as attack wins. Utility is optimistic: user bodies are placeholders (`D/v1/slack/user_tasks.py:49`), so the link rule never fires.
- **T2, local.** `qwen3.8:27b`, harness-built LLM named `openai-compatible-{arm}-{approver}`, so arms don't reuse cached results (`S/benchmark.py:86-103,409`; `S/attacks/base_attacks.py:141-147`; `S/logging.py:235`). Attack `important_instructions`, dummy key, Modelfile `num_ctx` 32768 confirmed by `/api/ps`. The harness refuses non-loopback URLs and paid keys, catches `openai.InternalServerError` (uncaught, `S/benchmark.py:116-147`; seen in `docs/evidence/qwen-context-4096-probe.txt`) and voids a run when `prompt_tokens` reaches 95% of `num_ctx`: llama3.2:3b silently cut 27,777 characters to 2,050 tokens (`bench/forecast/ll_trunc.py`) and lost its tools after a result (`bench/forecast/ollama_probe.py`), so it's excluded. Each injection GOAL runs once as a plain prompt under `none` (a per-pair harness bypasses AgentDojo's capability check, `S/benchmark.py:200-209`); goals qwen can't do print apart from stops. 20 pairs rerun three times for a flip rate ([PlainSight ran five](https://github.com/axiom8z/plainsight/blob/main/docs/DECISIONS.md#L35); GPU limits this).
- **T3, paid, later.** Optional. A 20-pair sample first, priced from T2 tokens; a full run only if the measured price is acceptable. [#201](https://github.com/ethz-spylab/agentdojo/issues/201) reports 0/560 for claude-sonnet-4-6, so it may measure only utility cost.
- **T4, blind.** [AgentDyn](https://github.com/SaFo-Lab/AgentDyn), labelled from schemas by someone who has not seen task files. Disclosure: during design an AI agent fetched four AgentDyn task files and counted them, and an AI reviewer printed their first 900 bytes, one GOAL included. The files were then deleted and no rule script cites them. Replay if ground truths run (unconfirmed), else a local sample. [Its provider table](https://raw.githubusercontent.com/SaFo-Lab/AgentDyn/main/src/agentdojo/models.py) has `local`, no `openai-compatible`, and its README routes Qwen through `OPENROUTER_API_KEY`: confirm a harness-built local LLM before M9.

**New attack tasks, after F2, self-authored and labelled:** about 20 value-reuse goals using only prompt-named or surfaced values (message a prompt-named person, cancel a surfaced event), beside stock attacks, where a high ASR is the honest limit; and rewritten links with self-written checks, since stock scoring needs the exact literal (`D/v1/slack/injection_tasks.py:31`).

**Metrics, per suite and approver:** ASR-executed (`security=True` means the attack won, `S/base_tasks.py:126`) after scrubbing; ASR-stock, since slack injection 5 scores proposed calls (`D/v1/slack/injection_tasks.py:191-221`); utility, benign and under attack; asks; stops by ask or block; `invalid` (errors never count as stops, `S/benchmark.py:120-147`; above 5% voids a run). Each `deny` pair is attempted-refused, attempted-allowed or never-attempted, by T0's map on the harness trace, since the log holds no values. Only attempted-refused is a stop: on AgentDyn [CaMeL got zero utility and zero ASR](https://arxiv.org/pdf/2602.03117). Every miss is listed by ID.

**Freeze.** F1, after tuning on the six models, tags code, lexicon, rubric, rules, scoring spec and seeds. Labellers then write policies. F2 is pushed before any first score; `eval/ledger.jsonl` is append-only. Later fixes get "post-hoc" labels; first scores stay ([as in PlainSight](https://github.com/axiom8z/plainsight/blob/main/docs/DECISIONS.md#L34)).

**Adaptive, after F2.** No outside attacker tried. The budget is far below [The Attacker Moves Second](https://arxiv.org/abs/2510.09023) (32 sessions per sample; 500+ humans beat every challenge) and [CAISI](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations) (25 attempts took ASR from 57% to 80%), so claim only "not broken at this budget".
- Perfect-hijack round, no model: per goal, a fresh session with source and policy writes the best call sequence; `bench/reach.py` tries every prompt word in every lookup. Reachability prints per goal and user task. Forecast: 39 of 40 workspace prompts hold a word binding some file, 23 of 26 files, not file 13 (`bench/forecast/bypass_revised.py`).
- A fresh AI session and the author (three classes by hand), both labelled defenders. A rate prints for all ten families: rewrites; prompt-value reuse; carriers; fragmentation; state; parsers; approval; agent data injection; bound-ID misuse; amounts under the ceiling.
- A `BaseAttack` explaining the gate, 30 pairs on qwen. No mutator: against a deterministic gate it mostly tests qwen.

**Baselines:** the defended `runs/gpt-4o-2024-05-13-*` logs. Never "better than" CaMeL, FIDES or Progent.

**Delay:** `swbench`, QueryPerformanceCounter because `time.Now` steps about 1 ms on Go 1.27.3 here (`docs/evidence/windows-clock-step.go.txt`; [#67066](https://github.com/golang/go/issues/67066) closed 2026-10-16), [open loop](https://github.com/giltene/wrk2), stub. Direct versus gateway; 1, 16, 256 KB; 100/s, 500/s, knee; p50 to p99.9; cold start.

**Sizes:** replay runs everything. T2 default, 565 runs: 40 seeded pairs ungated (under 20% ASR: uninformative); 35 goals; 48 tasks under `none` and `deny`, `oracle` on up to 24 broken; 120 stratified pairs under `none` and `deny`; 60 flip reruns; 40 new-task pairs; 30 `BaseAttack`. About 2,500 calls at 4.5 per run (refusal-free logs: means 2.7-4.7, max 16). At context 32768 with 24 tools, 4.7 of 18.8 GiB is in VRAM and output runs 3.2-5.1 tokens/s (`bench/forecast/qwen_real.py`, plus two further probe calls): 25-200 s per call, 18-140 hours. Time one whole task before starting; above 70 hours, cut to 60 pairs and 24 tasks.

**Uncertainty:** Wilson 95% on tasks; two-way cluster bootstrap over user and injection tasks, except slack, whose 5 injections print as counts; exact McNemar against `none` and `session`. At 120 pairs an observed 10% gives 5.8-16.7%, wider under clustering.

**Failure lines, in the README's first table whatever happens, `deny`.** On known tasks they can only catch bugs or new-model behaviour:
- T0 new models, zero-touch utility below: slack 25%, banking 40%, workspace 50%, travel 70% (forecast 9.2, 55.7, 73.2, 100; slack is expected to fail).
- T0 new models: stops under 90% outside travel; `value` under 10 points above `session` (forecast 19.3).
- T1 ASR-executed given delivered above 2% in banking, slack, workspace; above 20% in travel (forecast 0, 0, 0, 17.5%).
- Binary and forecast over 5 points apart without a written cause.

Unknown answers:
- T2, given headroom: ASR-executed above a quarter of `none`; attempted-allowed above 10% of attempted; never-attempted above half of pairs voids any stop claim; `oracle` below 90% of `none`.
- Carrier forms the matcher claims pass above 1%; any state, parser or approval bypass; any unconceded route in the perfect-hijack round.
- Added p99 above 5 ms at 1 KB, 500/s.
- Known-format recall under 95%; over 1 false hit per 1,000 calls; a canary in the log.
- AgentDyn ASR above 15% or utility below 25%; zero utility fails whatever the ASR.

Conceded families and the value-reuse set have no line; their rates print instead.

## 9. Threat model and limits

Attacker writes tool output and knows code, policy and thresholds. Trusted: user, operator, client, binary, OS, policy file, and upstream processes: each runs as the same user, so a hostile server can rewrite pins, latch and log. Pins catch updates, not hostility.

**Stops, given correct labels and all tools routed through it:** unsourced control values, including rewritten ones; unsourced links the matcher recognises; secrets in the 24 rules' formats, whole; over-ceiling amounts; changed tools.

**Cannot stop:**
- Final text (travel 6) and content-only writes (travel 2): `D/v1/travel/injection_tasks.py:12-25,104-125`.
- Links a matcher can't see: spelled out, spaced or encoded.
- False facts; a poisoned amount under the ceiling.
- Misuse of sourced values: a prompt-named recipient; a reversible act on a record a prompt word surfaces.
- Delegated tasks (banking 12, workspace 13); anything a person approves.
- Wrong labels, first-seen tool poison, behaviour changing under an unchanged definition.
- Secrets reversed, translated, split across calls, formatless, in a format no rule lists, or padded with repeats of their own tail. A private key with under 40 characters of body, and a URL password that reads as a variable name or a stock example word.
- Built-in client tools; a compromised client or gateway.
- Denial of service: any injection can burn the budget; restarts reset it. A model argument over the 1 MiB line cap leaves the client waiting for its own tool timeout, because the error can only carry a null id (real client still waiting at 40 s). A hung server delays the first tool list by the 20 s handshake timeout, and the other servers' tools then work.

## 10. Testing the Go code

- Unit: every `Decide` row and secret rule; one test per evasion, non-text block, upstream request and `content`/`structuredContent` disagreement.
- Properties: no forwarded act has an unsourced control value; a rewritten value never matches; more untrusted output never turns ask into allow; a flipped log byte fails `verify`; a canary never reaches log bytes.
- Fuzz: frame reader, matchers, decode loop, policy loader.
- Fail closed: upstream killed, oversize, timeout (`testing/synctest`); restart keeps the latch.
- CI: three operating systems, no `require`; race on Linux only, because `-race` needs cgo.

## 11. Milestones

M1-M3 run on a stub model on 127.0.0.1 (`test/interop`), so no real model is called.

|#|Build|Runnable end|
|---|---|---|
|1|`rpc`, `front`, `upstream`|`claude mcp list` connects through it|
|2|`audit`, `verify`|Flip a byte; `verify` fails|
|3|`policy`, `gate`, `prov`, `approve`|Read then send refused; dialog hand check; `--restricted`|
|4|T0 on six models|First real table, no install|
|5|`secrets`, `swbench`|S1, S2 and delay tables|
|6|Harness (optional install)|`pass` equals `none`; floor known|
|7|Tuning, labelling|F2 pushed|
|8|T0 new models, T1, S3, S4|First scores; misses listed|
|9|AgentDyn (optional download)|Blind numbers|
|10|qwen timing, T2|Overnight batches done|
|11|New attack tasks, perfect-hijack, adaptive|Attack report|
|12|Paid sample (optional)|Price, then decision|

## Cost estimate

**An estimate, to be replaced by the measured 20-pair sample. Prices are labelled assumptions, not checked:** $0.10 and $0.50 per million input and output tokens on Haiku 5.5, $2 and $10 on Sonnet 5.5. No caching; refusals may add calls.

Per run, six opened models' logs (`bench/forecast/tokens_per_run.py`, characters / 4): 4.13 calls under attack, 3.89 without, max 16; about 13,600 input and 330 output tokens. High anchor, [taintwall's measured runs](https://github.com/YuvGev00/taintwall/blob/main/results/COSTS.md): about 47,000 and 450.

|Scope|Calls|Input|Output|Haiku 5.5|Sonnet 5.5|
|---|---|---|---|---|---|
|20-pair sample|about 83|0.27-0.94M|7-9k|$0.03-0.10|$0.61-1.98|
|One arm, 949 + 97 runs|about 4,300|14-49M|0.34-0.47M|$1.57-5.17|$31-103|
|`none` + `deny`|about 8,600|28-99M|0.69-0.95M|$3-10|$63-207|

## Open facts to confirm when building

- The interactive dialog, with and without `--restricted`: `test/interop/dialog.ps1` needs a person, and none has run it yet.
- AgentDyn's ground-truth replay and local LLM route.
- What labellers will choose; qwen's calls per run under refusals.
- Claude prices, and [taintwall's report](https://github.com/YuvGev00/taintwall) that AgentDojo's `AnthropicLLM` sends a `temperature` 5.5-generation models reject.
