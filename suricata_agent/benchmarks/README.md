# Benchmark boundary

`suricata_agent.benchmarks.runner` owns application-level benchmark orchestration
and keeps the stable production contract in one place. The root
`benchmark_runner.py` module remains a compatibility import for existing scripts.
Dataset manifests and experiment outputs stay under the repository-level
`benchmarks/` directory.
