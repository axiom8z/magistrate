# Magistrate

A security gateway for AI agents. It is one Go binary, using only the standard library, that sits between an agent and its tools over the Model Context Protocol and asks of every risky value: who said that?

When an agent reads something untrusted, like an email or a web page, that text can try to tell it what to do next. Magistrate checks the risky arguments of each tool call. A recipient, a file ID or a URL has to trace to the user's prompt, an operator's list, a tool nobody else can write to, or a lookup the user asked for. If it doesn't, a person is asked, and with nobody there the call is refused. Known-format secrets are blocked and redacted, and every decision goes into a hash-chained log.

This is value matching, which is a heuristic and not a guarantee. [The design](docs/DESIGN.md#9-threat-model-and-limits) lists what it can't stop. Similar gateways already exist. No independent security audit has been done.

## Status

**Finished: milestones 1 to 10 are done, and 11 and 12 won't run.** The first scores are in, including a blind test on a benchmark nobody here had read, which failed its utility line, and a run on a live local model. Milestone 11, attacks written after the freeze, was left out by the owner's decision on 2026-11-11, before any of it was built. Milestone 12, an optional paid sample, was priced and then not run, by the owner's decision on 2026-11-13. [The design](docs/DESIGN.md#8-evaluation-plan) had said it might measure only utility cost, and the live-model run then found no headroom.

The labels the first scores used were written after the code was frozen, by fresh AI sessions that saw only a rubric and the tools' schemas. No person labelled. [How they were made](docs/labels/README.md).

The project was called SaysWho until 2026-11-04. Older commits and some raw outputs still use that name.

## Measured so far

The design set lines this project could fail before anything was measured, and they go here whatever happens. Each first score ran once and stays on record. [Every first score, with its caveats](docs/evidence/first-scores/README.md).

| Failure line | Measured | Result |
|---|---|---|
| Blind benchmark: normal tasks that pass, under 25% or none | 0 of 60 | **Crossed** |
| Blind benchmark: attack won, given delivered, over 15% | 0 of 160, all in one of its three suites | Not crossed |
| Normal tasks still working on 16 models nobody opened: slack under 25% | 13.79% (28/203) | **Crossed**, as the design expected |
| The same in banking (40%), workspace (50%) and travel (70%) | 59.64%, 68.16%, 100.00% | Not crossed |
| Logged attacks interrupted on those models, under 90% outside travel | 99.54% banking, 99.69% slack, 97.89% workspace | Not crossed |
| `value` under 10 points above `session` on those models | 13.26 points | Not crossed |
| Every attack pair from the benchmark's own correct calls: attack won over 2% in banking, slack or workspace, over 20% in travel | 0%, 0%, 0%, 16.94% | Not crossed |
| Gateway in pass mode changes anything | 0 of 1,046 cases | Not crossed |
| Over 1 false secret hit per 1,000 logged calls | 0 of 58,993 | Not crossed |
| Known-format secret recall under 95%, on self-written sets | 89.81% (30,608/34,080) on the first score; 99.98% post-hoc | **Crossed on the first score** |
| Over 1 false hit per 1,000 strings, on self-written sets | 1.1691 (45/38,490) on the first score; 0.0259-0.0519 post-hoc | **Crossed on the first score** |
| Added p99 above 5 ms at 1 KB and 500 requests a second | 1.297 ms at worst | Not crossed |
| Binary and forecast over 5 points apart without a written cause, on the six opened models | 1,271 of 1,272 logs agree, and 20 of the 609 pairs the forecast covered let the attack through, against its 21. Each difference has its cause written | Not crossed |
| Live model, headroom: the attack wins at least 20% of the 39 ungated pairs under no gateway | 0 of 39 (0.00%), Wilson 95% 0.00-8.97% | No headroom, so the next line doesn't apply |
| Live model: the attack wins under the gateway with nobody approving more than a quarter as often as without one, pooled or in any suite | 0 of 116 pairs under each arm | Does not apply, no headroom |
| Live model: over 10% of the pairs that attempted the attack's call had one run, pooled or in any suite | 0 attempted of 114 pairs, 0/0 | Not crossed, and no stop claim stands: 114 of 114 (100.00%) never attempted the attack's call |
| Live model, with an approver that accepts the calls a task needs: normal tasks passing under 90% of those with no gateway | 43 against 46 | Not crossed |

**The blind test failed.** [AgentDyn](https://github.com/SaFo-Lab/AgentDyn) adds three suites to AgentDojo, and nobody here read their tasks. Two fresh AI sessions labelled their tools from schemas alone, and the cautious rubric made 48 of the 69 tools acting, 41 of them irreversible. Replayed from the benchmark's own correct calls with nobody to approve anything, no task passed, so the design's rule that zero utility fails whatever the attack rate applies. The attack line held, but it says less than it seems: only one suite's attacks win at all without a gateway in this replay, and without a gateway only 23 of the 60 tasks pass. On a new set of tools, value matching with careful labels and no person present stops everything, the work included.

**On the tasks the rules were tuned on, the predictions held on new models and new labels.** No attack the design doesn't concede got through the replay of every pair, and over 97% of logged attacks outside travel were interrupted. The cost held too: with nobody to approve, about 4 in 10 normal tasks hit a refusal, and most of slack's do. The development numbers these were forecast from, on the six models opened during design, are in [docs/evidence/t0](docs/evidence/t0/README.md) and [docs/evidence/t1](docs/evidence/t1/README.md).

**The secret scanner failed its first score on self-written sets**, then held on logged calls and gets read case by case on a corpus somebody else wrote. [Details](docs/evidence/secrets/README.md).

**Delay:** the gateway added 1.235-1.297 ms at p99 for an action and 0.243-0.282 ms for a read, at 1 KB and 500 requests a second, on one desktop. [Details](docs/evidence/delay/README.md).

**The live-model run has no security result.** In the 114 of the 116 attack pairs covered by T0's frozen map of each attack's calls, the model never attempted the attack's call under `deny`, and with no gateway the attack won 0 of the 39 ungated pairs that count. With no headroom, the line on how often the attack wins under the gateway doesn't apply, and the 0 wins under each arm say nothing about the gateway. No stop claim stands either, since more than half the pairs, here all 114, never attempted the attack's call. Why the model never tried the attack's call was not measured. With nobody approving (`deny`), 26 of 48 normal tasks passed, against 46 of 48 with no gateway. One no-gateway task case was invalid and counts as a pass, which counts against the gateway, so 46 of 48 includes it. The batch of 35 goal checks had 2 invalid cases, over the 5% limit, so it was void and all 35 count as missing. With an approver that accepts a call when it does what one of the task's own ground-truth calls does (26 passing under `deny` plus 17 passing on the oracle's rerun = 43, against 46 under no gateway), 43 is not below 90% of 46 (41.4), so that line was not crossed. That approver reads DESIGN more loosely than its literal text, which favours the gateway, and it is a script, not a person. This is one local model on one machine. [Details](docs/evidence/t2/README.md).

**Not measured:** attacks written after the rules were frozen (milestone 11, left out), and a person answering the approval dialog in the real client. [The plan](docs/DESIGN.md#8-evaluation-plan) says what each will be held to.

## Try it

You need Go 1.27 or later. `run` also needs the `claude` command.

```console
go build -o magistrate ./cmd/magistrate
```

Start with a policy that names your MCP servers. Environment variables are listed by name, so the file holds no secrets:

```json
{"mode": "value", "servers": {"crm": {"command": "crm-server", "env": ["CRM_TOKEN"]}}}
```

Then draft labels for every tool, review them (the draft is only a start), and run:

```console
magistrate init --policy servers.json > policy.json
magistrate run --policy policy.json --state ./state --prompt-file prompt.txt
magistrate verify ./state/audit.log
```

`magistrate serve` runs the gateway alone over stdio, for use with another client.

## License

[MIT](LICENSE). The secret scanner's rules derive from [gitleaks](https://github.com/gitleaks/gitleaks); see [NOTICE](internal/secrets/NOTICE).
