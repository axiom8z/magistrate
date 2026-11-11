# Timing runs before the plan

DESIGN section 8 asks for one whole task to be timed on the local model before the full run. These are those runs. They were made before [the milestone 10 entry](../../../../eval/SCORING.md) and its draw existed, so they aren't first scores, and nothing records them.

- The first run of workspace `user_task_15` on a gated arm was cut short by the gateway's old 120-second limit for a whole case, and came out invalid. Its results weren't kept. That's why T2 now sets a limit of its own (`7dacd9f`).
- The second, [workspace-user_task_15.jsonl](workspace-user_task_15.jsonl), ran the same case in 172.9 seconds over 4 model calls. The gateway refused one `create_calendar_event` call, and the task still passed. About 43 seconds a model call put the planned runs at about 30 hours.

[qwen-context-4096-probe.txt](../../qwen-context-4096-probe.txt) is an earlier probe of the model's context, which sent it parts of banking `user_task_0`.
