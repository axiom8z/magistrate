# How the labels were made

The gateway needs a label for every tool: who can write what it returns, whether it acts, which arguments choose a target, whether it can be undone, and whether it returns secrets. These labels came after the F1 freeze, so the code, rules and rubric were fixed before anyone labelled.

**No person labelled.** The author chose to have two fresh AI sessions label instead, so these are AI sessions' labels, not the author's.

| File | What it holds |
|---|---|
| `RUBRIC.md` | What every labeller read, frozen at F1 |
| `schemas.json` | AgentDojo's 69 tools as a model sees them, and nothing else |
| `answers-1.json`, `answers-2.json` | Each AgentDojo labeller's answers, unedited |
| `merged.json` | The two merged, with every disagreement listed |
| `agentdyn-schemas.json` | AgentDyn's tools from its three new suites |
| `agentdyn-answers-3.json`, `agentdyn-answers-4.json` | Each AgentDyn labeller's answers, unedited |
| `agentdyn-merged.json` | Those two merged |

## The method

- **Each labeller saw three files**, in a folder of its own: the rubric, the schema file, and a checker that tests the answer file's shape and never its answers. Each was told not to open anything else, on the computer or online. Each said afterwards that it hadn't.
- **No labeller saw a task, a log, a forecast or another labeller's answers.** Two things reached them anyway, and are disclosed here. They know AgentDojo's tools from training, and the rubric names AgentDojo. And each session started with the context Claude Code attaches by itself: an index of the user's notes and a list of recent commit titles, which held no labels or tool details.
- **The stricter answer wins.** `bench/label/labels.py merge` combines two labellers' answers question by question, and lists every disagreement. "Unsure" always lands on the strict side. An acting tool's argument that neither labeller gave a role becomes `control`.
- **A store name only means something inside one labeller's file.** So two spellings aren't a disagreement. If either labeller's own names say an act writes what a tool returns, that tool's output isn't trusted.
- **AgentDyn's tools were labelled the same way**, by two further fresh sessions that had seen none of AgentDyn's tasks. Three names there mean different tools in different suites, so each of those is labelled per suite, as `name@suite`.

An earlier session labelled from an earlier rubric, as a pilot. Its report showed where the wording was unclear, the rubric was changed before F1, and its answers were thrown away unread.

## What came out

**AgentDojo.** The two sessions disagreed on 6 answers: 4 on whether outsiders can write a tool's output, 1 on whether an action can be undone, and 1 on whether a tool returns secrets. Each disagreement went to the stricter side. Every acting tool's argument had a role from at least one of them, so nothing had to be filled in. They answered "unsure" 20 and 26 times.

The merged labels are stricter than the ones the forecasts assumed:

| | Forecast labels | Merged labels |
|---|---|---|
| Tools that act | 25 | 26 |
| Acting tools that can't be undone | 5 | 24 |
| Tools whose output is trusted | 4 | 2 |
| Tools labelled sensitive | 1 | 5 |

Both sessions labelled `get_unread_emails` as acting, because it marks emails as read, and `get_webpage` too, because it sends the URL to whoever runs the site. Most acting tools came out as impossible to undo, because their schemas don't say, and "unsure" counts as no. An ID found by a lookup can't be used on an action that can't be undone, so these labels will cost normal tasks, and the first score will show how much. Both sessions named the same wording as hard to apply: who counts as an outsider when a business sets a value, and what an acting tool returns when its schema doesn't say. Their reports are summarized here, and the rubric stayed as it was frozen.
