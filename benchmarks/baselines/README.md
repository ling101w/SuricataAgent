# Frozen benchmark baselines

Each baseline directory is immutable after its `freeze-manifest.json` is created.
Run `python -B benchmarks/freeze_v0_baseline.py --verify` to check the v0 source
results, copied Direct rules, dataset manifest, and aggregate artifacts against
their recorded SHA-256 hashes.
