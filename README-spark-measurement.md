# Qwen3.6 / DGX Spark / Codex dual-ended measurement

Run in WSL2:

```bash
cd /home/codex_qwen
python3 run_humaneval_codex.py --range 1 1 --provider spark --capture-server
```

Default output stays in `/home/codex_qwen/results_codex_humaneval/<timestamp>/HumanEval__0/`.
Use `--timeout 600` for a bounded ten-minute Agent task. Model readiness has its own
1200-second deadline and the only necessary generation probe has a 180-second timeout.
`--limit`, `--range`, `--list-tasks`, `--resume-dir` remain supported. With no task
selection the script refuses to run; all 164 tasks require explicit `--all`.
Example resume: append `--resume-dir results_codex_humaneval/<timestamp>` with the
same selection/provider/capture options. A completed, size-valid dual capture is skipped.
There is no automatic task or model restart. `--stop-model` explicitly stops our
model/watchdog on exit; otherwise both stay running, even after an Agent error.

## Preparation and isolation

The existing Spark start/stop scripts and safety limits are reused unchanged.
A running unhealthy model is never restarted automatically. A stopped owned model
can be started once. Warmup occurs before capture, only when no successful generation
proof matches the current container ID. Existing `validation.json` proof or the
controller's `model-readiness.json` is accepted alongside current health/safety checks.

`config/spark/` contains the validated 8K Codex configuration and explicit model
catalog. The catalog is copied into the per-task runtime and read-only mounted by
the formal `isolated()` implementation. No temporary adapter, monkey patch, global
Codex configuration, auth.json copy, or Windows runtime path is used.

Native Codex and its same-release code-mode helper are discovered from the installed
entry point (including shell wrapper chains), without sourcing authentication loaders.
For Spark the transport is unauthenticated local HTTP over an SSH tunnel; HTTP/SSE
compatibility remains unchanged. TLS interception is not inserted into this path.

Project SSH config is `config/ssh_config`; check it with:

```bash
ssh -F config/ssh_config spk true
```

Private credentials and known hosts live only in `.private/`, permissions 0700/0600;
they are never included in deliverables. The existing user-owned key was provisioned
once into native WSL storage. On another machine, provision your own authorized key
and known_hosts at the configured native paths; do not disable host-key checking.
The runner owns and closes its own tunnel. It uses loopback port 18000 when free,
otherwise a free loopback port reflected in the isolated provider config. An existing
foreign tunnel is not stopped or adopted. An experiment file lock prevents concurrent
invocations. Runtime/control files stay outside formal task directories.

## Capture protocol

Each invocation has a unique run_id; task_id is HumanEval's actual ID, with a sanitized
remote directory component. Server READY precedes local READY and both precede Codex.
HTTP health markers bracket the Agent interval; they are explicitly labeled control
traffic and do not perform inference. Agent end is recorded before capture shutdown.
The original local any-interface capture, scorer, timeline, spool, interruption cleanup,
and plugin diagnostics are preserved. Server files are downloaded into the SAME task
directory, size checked, and decoded offline.

Remote controller (under `/home/huanglabspk/WaiTung/scripts/`):

```bash
python3 spark_capture.py start --run-id RUN --task-id HumanEval__0 --max-seconds 780
python3 spark_capture.py status --run-id RUN --task-id HumanEval__0
python3 spark_capture.py stop --run-id RUN --task-id HumanEval__0
python3 spark_capture.py collect --run-id RUN --task-id HumanEval__0
```

Remote sessions are stored below `WaiTung/logs/agent-capture/RUN/TASK/`. The detached
worker survives SSH session exit. Status refreshes a 45-second lease; controller death
or extended SSH loss stops capture. A hard duration and 1GiB capture-file cap bound
orphan lifetime/storage. Status is checked during Agent execution; two SSH-status
failures abort the Agent, and finally attempts stop/download. There is no unbounded
retry. Hard termination can leave a remote stopped capture to recover manually with
`collect`; retained session paths in result metadata make this explicit.

The physical route toward the actual SSH peer and current Docker network are discovered.
Multi-interface PCAPNG captures physical SSH, host lo:8000, the actual container bridge,
and bridge veths filtered to the model's container IP:8000. Interface names remain in
the PCAPNG. Only bridge observations drive HTTP byte accounting and the HTTP/SSE
timeline. Matching payload packets across interfaces are marked in server_timeline;
interface packet counts are observation counts, NOT unique traffic volume. Loopback
and docker-proxy connections may have different TCP sequence numbers and remain
distinct observation layers. Never sum them as total application bandwidth.

## Timestamps and interpretation

`codex_timeline.jsonl` timestamps indicate receipt of CLI output events, NOT first
network bytes. `server_timeline.jsonl` comes from captured packet timestamps and
TCP/HTTP reassembly at the selected bridge. It records HTTP request/response boundaries,
status, reconstructed byte lengths, SSE event sizes and packet-observation times,
capture errors and interruptions. TCP overlap/retransmission bytes are not counted
twice; gaps or incomplete HTTP messages cause an incomplete flag. Sum byte counts from
end events only; start events repeat attributes for convenient inspection.

These are packet-observed HTTP/SSE boundaries, not timestamps inside vLLM's API parser
or inference engine. Prefill, Decode, engine queue and kernel TCP-send timestamps are
explicitly unavailable. No streaming proxy buffers or changes Responses output.

Clock estimates are taken before and after each task using several SSH round trips.
The minimum-RTT midpoint estimate, all raw samples, clock sources, estimated offset,
drift and conservative uncertainty are stored. This is an error-bounded estimate,
NOT PTP/NTP-level synchronization. Current WSL and Spark clocks differ by seconds;
do not compare raw UTC values without the recorded offset/error interval.

`result.json` combines readiness/container identity/limits, versions, isolated config,
run/task IDs, lifecycle events, both capture statistics, file hashes, markers, clock
estimates, coverage and Agent/scorer results. Server coverage is checked with the
clock bound and both bracketing markers; local coverage is checked independently.
Capture quality failure is a task error, never silently promoted to success.

Local `any` PCAP includes loopback HTTP, encrypted SSH and possibly unrelated host
traffic. Physical SSH records include control channels as well as the dedicated
tunnel; the tunnel PID/socket observation and control markers are retained for
classification. The HTTP bridge view is the unambiguous application analysis view.

## Validation evidence

`tests/test_capture_lifecycle.py` performs a real READY/status/stop/collect/hash/coverage
test with health markers only: no model load, generation or Agent. Its evidence is
under `deployment/capture-selftest-*`. Original formal script backups are under
`deployment/before-dual-capture-*`. Startup failures produce truthful partial results;
capture diagnostics and debug files stay outside formal task directories or in
`result.json`, leaving the requested seven task-level files on successful dual runs.

Per user preference, future server transfers/resume use file size and PCAP parsing/coverage, without SHA256 validation. Existing historical hashes remain descriptive records. Native plugin cache identity mechanisms are unchanged.
