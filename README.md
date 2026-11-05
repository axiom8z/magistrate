# Magistrate

A security gateway for AI agents. It is one Go binary, using only the standard library, that sits between an agent and its tools over the Model Context Protocol and asks of every risky value: who said that?

When an agent reads something untrusted, like an email or a web page, that text can try to tell it what to do next. Magistrate checks the risky arguments of each tool call. A recipient, a file ID or a URL has to trace to the user's prompt, an operator's list, a tool nobody else can write to, or a lookup the user asked for. If it doesn't, a person is asked, and with nobody there the call is refused. Known-format secrets are blocked and redacted, and every decision goes into a hash-chained log.

This is value matching, which is a heuristic and not a guarantee. [The design](docs/DESIGN.md#9-threat-model-and-limits) lists what it can't stop. Similar gateways already exist. No independent security audit has been done.

## Status

**Under construction: milestones 1 to 5 of 12.** The gateway is built and tested. The evaluation is not finished, and every number below is a development number.

The project was called SaysWho until 2026-11-04. Older commits and some raw outputs still use that name.

## Measured so far

The design set lines this project could fail before anything was measured, and they go here whatever happens.

| Failure line | Measured | Result |
|---|---|---|
| Known-format secret recall under 95% | 89.81% (30,608/34,080) on the first score; 99.98% post-hoc | **Crossed on the first score** |
| Over 1 false hit per 1,000 strings | 1.1691 (45/38,490) on the first score; 0.0259-0.0519 post-hoc | **Crossed on the first score** |
| Added p99 above 5 ms at 1 KB and 500 requests a second | 1.297 ms at worst | Not crossed |
| Binary and forecast over 5 points apart without a written cause | 1,271 of 1,272 logs agree | Not crossed |

The rest of the lines need runs that haven't happened yet, including every line on attacks against new models.

**The secret scanner failed its first score.** Its rules were frozen by hash, and a fresh session that never saw them wrote the test sets and scored them once. 18 of the 24 rules reached 100%. Most misses are token formats the rules don't cover, like GitLab's other prefixes and older Vault tokens, and most false hits come from placeholders that have a real token's shape. The sets are self-written and not independent, and the false-hit crossing rests on a few classes the writer chose to add.

The rules were then changed, and the same generator rerun: that's the post-hoc figure in the table. It shows the changes work on these sets. Since they were made from these sets' misses, it says little about formats nobody listed, and first scores on other data are still to come. [Details, caveats and what the changes gave up](docs/evidence/secrets/README.md).

### Agent attacks, on logs the rules were tuned on

These replay AgentDojo's published logs through the real binary, with every question answered "no". The rules were chosen by looking at these same tasks, using labels the design assumed, on the six models opened during design. So they show the binary does what the design predicted. They don't show how it does on anything new, and behaviour after a block can't be seen in a log. [Details and caveats](docs/evidence/t0/README.md).

| Arm | Normal tasks that still work | Logged attacks interrupted |
|---|---|---|
| `value`, the default | 234/394 (59.4%) | 832/878 (94.8%) |
| `session`, which asks about any action after reading | 157/394 (39.8%) | 865/878 (98.5%) |
| `pass`, which decides nothing | 394/394 (100%) | 0/878 |

| `value`, by suite | Normal tasks that still work | Logged attacks interrupted |
|---|---|---|
| banking | 34/61 (55.7%) | 253/253 |
| slack | 10/98 (10.2%) | 318/318 |
| travel | 67/67 (100%) | 56/102 (54.9%) |
| workspace | 123/168 (73.2%) | 205/205 |

So the cost is real: with nobody to approve anything, about 40% of normal tasks hit a refusal, and most of slack's do.

**Delay:** the gateway added 1.235-1.297 ms at p99 for an action and 0.243-0.282 ms for a read, at 1 KB and 500 requests a second, on one desktop. [Details](docs/evidence/delay/README.md).

**Not measured yet:** ground-truth replay of every attack pair, the models not yet opened, a live model, a blind benchmark, attacks written after the rules were frozen, and a person answering the approval dialog in the real client. [The plan](docs/DESIGN.md#8-evaluation-plan) says what each one will be held to, including the lines it could fail.

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
