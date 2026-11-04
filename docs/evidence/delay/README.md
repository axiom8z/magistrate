# Delay the gateway adds

`cmd/swbench` measures an instant stub server directly and through the full gateway in `value` mode, with the secret scanner on, a prompt file and a pinned policy. The load is open loop: request i is due at t0 + i/rate whatever became of earlier ones, and latency runs from the due time, so a stall is charged to every request it held up. Each cell ran five interleaved rounds of 20 seconds, and the first tenth of each round is dropped as warm-up. Ranges are lowest to highest across rounds.

`act.txt` labels the tool an act, the slow path, because the decision is fsynced before the call is forwarded. `read.txt` labels it a read, which pays for no fsync and is what most calls in a session are.

Measured on one Windows 10 desktop, a Ryzen 7 3700X with 32 GB and an NVMe SSD, with the usual desktop programs open. These numbers describe that machine. The non-test Go code is the same as in commit `c3b5821`.

**The design's failure line, added p99 above 5 ms at 1 KB and 500/s, was not crossed:** added p99 was 1.235-1.297 ms for an act and 0.243-0.282 ms for a read.

| Added by the gateway, ms | Act p50 | Act p99 | Act p99.9 | Read p50 | Read p99 | Read p99.9 |
|---|---|---|---|---|---|---|
| 1 KB, 100/s | 0.888-0.918 | 1.240-1.299 | 1.318-1.433 | 0.171-0.191 | 0.318-0.464 | 8.988-10.603 |
| 1 KB, 500/s | 0.867-0.875 | 1.235-1.297 | 1.730-4.692 | 0.143-0.153 | 0.243-0.282 | 8.820-9.050 |
| 16 KB, 100/s | 1.217-1.248 | 1.578-1.714 | 1.734-3.276 | 0.492-0.509 | 0.799-0.844 | 9.661-10.751 |
| 16 KB, 500/s | 1.162-1.179 | 1.552-1.603 | 3.014-4.522 | 0.445-0.481 | 0.756-0.828 | 8.984-10.152 |
| 256 KB, 100/s | 5.958-6.004 | 6.580-6.639 | 7.207-8.005 | 5.222-5.293 | 6.048-6.724 | 10.402-15.668 |
| 256 KB, 500/s | 6.393-6.426 | 7.872-8.403 | 12.607-13.292 | 5.546-5.652 | 7.511-9.964 | 15.432-22.622 |

| Highest rate with p99 at most 10 ms and nothing failed, 3-second probes | Direct | Act | Read |
|---|---|---|---|
| 1 KB | 64,000/s | 1,062/s | 15,000/s |
| 16 KB | 64,000/s | 1,125/s | 3,750/s |
| 256 KB | 24,000/s (act run), 20,000/s (read run) | 687/s | 531/s |

Cold start to the first `tools/list` reply was 3.3-4.1 ms directly and 10.6-23.4 ms through the gateway, which also starts the stub.

Nothing failed in any round. A handful of sends ran over a millisecond late: 2 across all act rounds and 5 across all read rounds.

## What these do not explain

- **A read's p99.9 is about 9 ms in every small cell, and an act's is not.** That means at least a couple of stalls of about that length in each 20-second round. A guess is Windows flushing the log's unsynced pages in the background, which an act's fsync leaves nothing for. That is untested.
- **The act knee of about 1,100/s looks like the fsync.** That too is an inference from the read path being far higher, not something measured directly.
- **The cold start looks bimodal,** at about 11 ms or about 22 ms, and the cause is unknown.
- **The stub answers at once,** so this is what the gateway adds to the fastest possible tool. A real tool takes far longer than any of these.

## Rerun it

```console
go build -o sayswho ./cmd/sayswho
go build -o swbench ./cmd/swbench
swbench run -- sayswho serve --policy <policy> --state {state} --prompt-file <prompt>
```

The policy starts `swbench stub` as its one server, and `sayswho init` drafts it, with the payload tool as an act. `{state}` becomes a new empty folder for each start. A full run takes about 25 minutes.
