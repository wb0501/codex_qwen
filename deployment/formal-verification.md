# Formal dual-ended measurement verification

Command (WSL2):
```bash
cd /home/codex_qwen
python3 run_humaneval_codex.py --range 1 1 --provider spark --capture-server --timeout 600
```

One actual HumanEval/0 Agent executed, passed full task verification, exit 0, no timeout.
39 tool calls; Agent bracketing interval 597.982s.
Local packets: 56450, dropped 0.
Server observations: 155812, dropped 0, interfaces {'enP7s7': 82152, 'lo': 24202, 'docker0': 24729, 'veth11971ea': 24729}.
Both captures cover the complete Agent interval; begin/end HTTP markers observed.
Server HTTP requests/responses 62/62; Responses requests 59; SSE events 12394.
No TCP/HTTP reconstruction gaps. Server PCAP/timeline SHA256 verified after download.
Clock remote-minus-local estimate -17.166222s,
uncertainty bound 186.954ms; SSH midpoint estimates, not precise synchronization.
CLI timeline timestamps are local receipt of CLI output; HTTP/SSE timeline timestamps are packet observations.
Engine queue, prefill, decode and kernel-send timestamps remain unavailable.
Multi-interface packet counts are separate observations, not additive unique traffic volume.
Local any-interface capture can contain unrelated traffic; no automatic attribution by domain.

Qwen3.6-35B-A3B BF16 / vLLM 0.24.0 / Codex CLI 0.169.0.
Reused the same running model container, no model load or warmup repeated.
After task: health 200, model/watchdog running, MemAvailable 29.14GiB,
memory PSI avg10 0, no cgroup OOM, container swap disabled, 95GiB limit unchanged.
Default leaves model/watchdog running. --stop-model is explicit opt-in.

One recoverable model-generated function argument parse error occurred; subsequent calls and task succeeded.
Plugin resource cache publication was unavailable (native revision absent); no cache was fabricated.
Syntax/config/CLI selection, synthetic parser tests, real capture lifecycle tests passed.
Resume checked: SKIP completed HumanEval/0, no second Agent.

Result: /home/codex_qwen/results_codex_humaneval/20261123-213432-103782/HumanEval__0
Remote original capture: /home/huanglabspk/WaiTung/logs/agent-capture/20261123-213432-103782-1795440872104363832/HumanEval__0
Before-change harness backup retained in deployment/before-dual-capture-20261123T212308.
No private keys/authentication, .private, runtime controls, dataset, or model weights are in delivery.

Final amendment: Per user request, subsequent transfers/resume do not perform SHA256 verification; size/PCAP parsing/time coverage checks remain. Syntax and completed-task resume passed after this change. Cleanup manifests list removed intermediates; historical archives and formal data are retained.
