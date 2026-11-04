# Forecast scripts

These scripts produced the forecasts in `docs/DESIGN.md`. **They are not the gateway.** They apply candidate
rules, written in Python, to data read from a checkout of [AgentDojo](https://github.com/ethz-spylab/agentdojo)
at commit `089ed468`. They import nothing from that checkout and run none of its code.

The rules were chosen by looking at these same suites, so every number here is a development number. Counting
any interruption as a break pushes "kept" down; tuning on these suites pushes it up. Behaviour after a block
can't be seen in a log.

Only six models' logs are read: `gpt-4o-2024-05-13`, `gpt-4o-mini-2024-07-18`, `claude-3-5-sonnet-20241022`,
`gemini-2.0-flash-001`, `meta-llama_Llama-3.3-70B-Instruct`, `claude-3-7-sonnet-20250219`. The other 16
undefended pipelines stay unopened until the rules are frozen.

Recorded output is in `docs/evidence/forecast/`. Run from outside the checkout. `$B` is this folder and `$C` is
the checkout. `revised.py` prints the design's forecast table.

| Script | Command | Recorded output |
|---|---|---|
| `revised.py` | `python -I -X utf8 $B/revised.py $B $C/runs $B` | `revised.out` |
| `rev_rows.py` | `python -I -X utf8 $B/rev_rows.py $B $C/runs $B` | `rev_rows.out` |
| `bind_variants.py` | `python -I -X utf8 $B/bind_variants.py $B $C/runs $B` | `bind_variants.out` |
| `conceded.py` | `python -I -X utf8 $B/conceded.py $B $C/runs $B` | `conceded.out` |
| `bypass_revised.py` | `python -I -X utf8 $B/bypass_revised.py $B $C $B` | `bypass_revised.out` |
| `static_gate.py` | `python -I -X utf8 $B/static_gate.py $C` | `static_gate.out` |
| `delivery.py` | `python -I -X utf8 $B/delivery.py $C $B` | `delivery.out` |
| `tokens_per_run.py` | `python -I -X utf8 $B/tokens_per_run.py $C` | `tokens.out` |
| `log_versions.py` | `python -I -X utf8 $B/log_versions.py $C/runs` | `versions.out` |
| `final_config.py` | `python -I -X utf8 $B/final_config.py $B $C/runs` | `final_config.out` |
| `candidate.py` | `python -I -X utf8 $B/candidate.py $B $C/runs` | `candidate.out` |

`trace_policy.py` is the library the others build on. `ablate.py` and `channels_only.py` were design-time checks
of single labels. `ollama_probe.py`, `ll_trunc.py` and `qwen_real.py` talk only to a local Ollama on 127.0.0.1.
