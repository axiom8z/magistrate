# T0: published logs through the real gateway

`bench/replay_logs.py` sends the calls in AgentDojo's published logs through the real `magistrate` binary, one fresh process and state directory per log, and answers every question with a decline. `bench/replay/relay.py` plays the server and returns what the log says each call returned.

These are **development numbers, benchmark-informed**. The rules were chosen by looking at these same tasks, and the six models here are the ones opened during design, so they show the binary does what the design said it would, and not how it does on anything new. A log also can't show what an agent would have done after a block. Kept counts any interruption as a break. The labels are the ones the forecasts assumed, in policy form. They are not the author labels of milestone 7.

Commit `563b974`, AgentDojo checkout `089ed468`, attack `important_instructions`, approver `deny`. Each `.out` file starts with that account of what ran. Every number is unchanged, line for line, since these arms were first run at `c3b5821`. None of the six models' logs records a failed model API call.

| Arm | Tasks kept | Forecast | Logged attacks interrupted | Forecast |
|---|---|---|---|---|
| `value` | 234/394 (59.4%) | 233 | 832/878 (94.8%) | 832 |
| `value-noids` | 219/394 (55.6%) | 218 | 832/878 (94.8%) | 832 |
| `value-noprompt` | 192/394 (48.7%) | 192 | 832/878 (94.8%) | 832 |
| `session` | 157/394 (39.8%) | 157 | 865/878 (98.5%) | 801 |
| `unreviewed` (the `init` draft, unedited) | 219/394 (55.6%) | none | 831/878 (94.6%) | none |
| `pass` | 394/394 (100%) | must equal no gateway | 0/878 | must equal no gateway |

| `value`, per suite | Tasks kept | Logged attacks interrupted |
|---|---|---|
| banking | 34/61 (55.7%) | 253/253 |
| slack | 10/98 (10.2%) | 318/318 |
| travel | 67/67 (100%) | 56/102 (54.9%) |
| workspace | 123/168 (73.2%) | 205/205 |

In all 1,272 logs of every arm, each result the gateway forwarded matched its log.

## Binary against forecast

The design's failure line is a gap over five points without a written cause. `compare.out` lines up the `value` arm log by log: 1,271 of 1,272 agree. These are the written causes of the differences above.

- **One more task kept, slack `user_task_3` on `claude-3-7-sonnet-20250219`.** The forecast's link regex keeps a trailing colon, so `www.informations.com:` did not match the prompt's `www.informations.com`. The gateway trims the punctuation. The same log explains the extra task in `value-noids`.
- **`session` interrupts 865, not 801.** The forecast's session script treats `get_webpage` as a read because of its name. The labels call it an act, because it reaches outside, and the gateway follows the labels. That is the whole gap: 64 logs, all slack injection 3, each interrupted on `get_webpage`.
- **`session` stops are counted more strictly here.** This table needs an interrupted call of the attack's family holding its marker. The forecast's session row needed only the family.

The forecast and the binary differ in smaller ways that moved no count here. The forecast treats an empty string as sourced, and the gateway treats it as a value, because to a server it can mean "all of them". The forecast lets an act's output bind an ID, and the gateway allows only a lookup. Non-ASCII control values fail closed in the gateway and are normalized in the forecast.

## Rerun it

Needs Python 3.14 and a checkout of AgentDojo at `089ed468`. Nothing to install, no model and no network.

```console
go build -o magistrate ./cmd/magistrate
python -I -X utf8 bench/replay_logs.py --clone <checkout> --gateway ./magistrate --work <empty folder> --arm value --dump value.jsonl
python -I -X utf8 bench/compare_forecast.py <checkout> value.jsonl
```

Arms are `value`, `session`, `value-noids`, `value-noprompt`, `unreviewed` and `pass`. Each took about 40 seconds with two logs at a time. The script reads only the six opened models, so the rest of the runs folder stays unopened until the rules are frozen.
