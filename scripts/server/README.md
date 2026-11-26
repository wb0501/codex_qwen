# Server-side measurement modules (vendored reference copies)

These files are canonical in **waitung-inference-server-measurement**
(`/home/huanglabspk/WaiTung/scripts/` on the DGX Spark). They are copied here
because the offline measurement tests import them:

- `spark_capture.py`    -> Prometheus / TCP sampling and capture worker state
- `agent_traffic_v3.py` -> V3 telemetry writer used by the vLLM overlay

Vendored copies must match the server repository commit recorded in
`REPOSITORY_MANIFEST.md`. Update them (`scp spk:...`, see below) whenever the
server-side module changes, and record the server commit SHA.

```bash
scp -q spk:/home/huanglabspk/WaiTung/scripts/spark_capture.py scripts/server/
scp -q spk:/home/huanglabspk/WaiTung/scripts/agent_traffic_v3.py scripts/server/
```
