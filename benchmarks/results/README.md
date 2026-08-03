# Benchmark results

Runtime outputs are written here by `benchmarks/benchmark.py` and ignored by
the parent Git repository. `summary.json`, `summary.csv`, and `results.csv` are
the aggregate machine-readable reports.

Generation code receives only each case's `input.json`. The evaluator loads
`oracle.json` and PCAP labels only after a rule has been delivered.
