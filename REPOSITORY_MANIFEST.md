# REPOSITORY_MANIFEST — codex_qwen

公共测量框架：Agent 网络流量的双端采集、解析、事件关联与分析。

- Repository: `codex_qwen`
- Local path: `/home/codex_qwen`
- Baseline commit: 见提交信息与 `git log --oneline -1`
- Python: 3.13 / 3.14（本机基线 3.14.4）
- Measurement protocol: `agent-traffic-v3.0`

## 纳入版本管理的文件

| 文件 | 用途 | 依赖 |
|---|---|---|
| `spark_measurement.py` | SSH 采集协调、远端 worker 生命周期、结果回收 | `scripts/telemetry_merge.py`, `scripts/experiment_config.py`; 通过 `ssh spk` 调用服务端 `scripts/spark_capture.py` |
| `run_humaneval_codex.py` | HumanEval workload adapter（历史工作负载） | `scripts/experiment_config.py` |
| `scripts/parse_server_capture.py` | 服务端 PCAP 解析、HTTP/SSE 重建、跨层关联 | `tshark` |
| `scripts/telemetry_merge.py` | V3 telemetry 分段合并与摘要 | — |
| `scripts/pcap_evidence.py` | PCAP 证据抽取辅助 | `tshark` |
| `scripts/experiment_config.py` | 实验配置、context profile、部署参数校验 | — |
| `scripts/convert_legacy_results.py` | 历史结果格式迁移 | — |
| `scripts/server/spark_capture.py` | **vendored** 服务端 Prometheus/TCP 采样（权威副本在 server 仓库） | — |
| `scripts/server/agent_traffic_v3.py` | **vendored** V3 telemetry writer（权威副本在 server 仓库） | — |
| `tests/test_v3.py`, `tests/test_unified.py`, `tests/test_server_parser.py`, `tests/test_capture_lifecycle.py` | 离线单元与回归测试 | 需要 `vllm_overlay/` 与基线 vLLM（见下） |
| `tests/parse_server_capture.py` | 解析器测试辅助实现 | — |
| `fixtures/vllm_0_24_0_metrics.txt` | vLLM 0.24.0 `/metrics` 文本夹具（642 行，来自 DGX Spark 只读采样） | — |
| `config/spark/config.toml`, `config/spark/model_catalog.json` | 推理服务 Provider 与模型 catalog 模板（无密钥） | — |
| `README-spark-measurement.md`, `README.md`, `deployment/formal-verification.md` | 技术文档 | — |

## 依赖关系

```text
codex_qwen_GAIA     启动 Codex、调度任务、发起双端采集
              |  ssh spk + JSON 协议
              v
codex_qwen  本仓库：PCAP/HTTP/SSE/TCP/Prometheus 解析与关联
              |  导入 V3 telemetry 格式
              v
waitung-inference-server-measurement  vLLM 插桩、spark_capture worker、watchdog
```

- 本仓库 `scripts/server/*.py` 是 server 仓库对应文件的原样副本（SHA256 见下），用于离线测试。
- `tests/test_v3.py` / `tests/test_unified.py` 中的 overlay 校验用例需要
  `vllm_overlay/`（补丁与插桩文件，权威在 server 仓库）和 `vllm_baseline/`
  （未插桩的 vLLM 0.24.0 源码，不纳入版本管理）。
  在本仓库独立检出时这两个目录不存在，相关 4 个用例按预期跳过/报缺失，其余用例正常。

## Vendored 服务端模块校验

```text
d9cf3509957af3a49674c8323307a0790516aff177dcd344b1db17c74424a3bf  scripts/server/agent_traffic_v3.py
785f4fb0a546c375cb5ab3ba8a68a567b9f844868d22036b1fed84c1bce85372  scripts/server/spark_capture.py
```

## 明确排除

```text
DATASET/                    数据集
results_codex_humaneval/    实验产物（约 12 GB）
*.log                       运行日志
deployment/before-*/        部署快照备份
deployment/*.json           运行状态文件
deployment/deployment_verified/  嵌入的部署快照（含运行结果与 telemetry 采集）
config/ssh_config, .private/, .runtime/   认证与运行时
.venv/, __pycache__/, .cache/             环境与缓存
```

## 环境

```text
vLLM（服务端） : 0.24.0（overlay 由 server 仓库维护）
Codex CLI       : 0.169.0
Python          : 3.14.4（本机 WSL）
采集工具        : tshark / dumpcap
```
