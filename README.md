# codex_qwen

公共测量框架：Agent 网络流量的双端采集、解析、事件关联与分析。

本仓库是 **Agent Traffic Measurement** 研究项目的测量底座，本身不绑定任何
单一 Benchmark。工作负载（GAIA、HumanEval 或未来新增的 Benchmark）由
`codex_qwen_GAIA` 仓库驱动，通过 SSH 调用本仓库的模型侧采集契约。

## 职责

- 双端 PCAPNG 采集协调（本机 + 推理服务器）
- HTTP / SSE 请求-响应重建与配对
- V3 跨层 telemetry 合并（API Server / Scheduler / Engine / SSE Encoder）
- TCP 与 Prometheus 指标采样
- Agent Timeline 与网络事件的确定性关联
- 结果统计、覆盖率与数据质量校验

## 目录

```text
spark_measurement.py            SSH 采集协调、远端 worker 生命周期、结果回收
scripts/parse_server_capture.py 服务端 PCAP 解析（HTTP/SSE 重建、跨层关联）
scripts/telemetry_merge.py      V3 telemetry 分段合并
scripts/pcap_evidence.py        PCAP 证据抽取辅助
scripts/experiment_config.py    实验配置与 context profile 定义
scripts/convert_legacy_results.py 历史结果格式迁移
run_humaneval_codex.py          HumanEval workload adapter（历史工作负载）
config/spark/                   Codex Provider 与 model catalog 模板
tests/                          离线单元与回归测试
deployment/                     技术文档与部署基线
```

## 环境要求

- Python 3.13 / 3.14（本机 WSL 3.14.4）
- `tshark` / `dumpcap` / `openpyxl` / `pandas` / `pyarrow`
- 对推理服务器（DGX Spark）的 SSH 访问别名 `spk`

## 快速开始

```bash
python -m pip install -r requirements.txt   # 如有
python -m unittest discover -s tests -p 'test_*.py'
```

采集与解析的具体入口见 `REPOSITORY_MANIFEST.md`。

## 数据策略

数据集、实验产物、PCAP、telemetry 运行数据、私钥与运行时状态
全部由 `.gitignore` 排除，不进入版本管理。
## 独立关系（2026-11-26 修订，取代上方旧依赖图）

codex_qwen 与 codex_qwen_GAIA 是两个独立 workload：

- codex_qwen：HumanEval + 可复用测量框架
- codex_qwen_GAIA：GAIA + 自带测量副本

两者均通过 ssh spk 调用 waitung-inference-server-measurement 的 spark_capture.py，
不互相 import；服务端也不 import 任何一个客户端仓库。
