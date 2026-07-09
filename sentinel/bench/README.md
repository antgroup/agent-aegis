# Sentinel Benchmarks

This directory contains offline and live benchmark tooling for sentinel.

## AgentHazard Phase 0

Phase 0 is intentionally offline: it loads `AgentHazard/data/dataset.json`,
validates the schema, performs deterministic stratified sampling, and writes a
dry-run report. It does not start Docker, eBPF, LLM judges, or sidecars.

After `npm run build`:

```bash
node sentinel/bench/agenthazard/run.js \
  --dataset ../AgentHazard/data/dataset.json \
  --sample-per-category 3 \
  --dry-run \
  --out results/agenthazard-p0
```

Outputs:

- `summary.json`
- `sample.json`
- `report.md`
