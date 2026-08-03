# Hidden Test v1 Preregistration

This document is frozen before constructing or running the 30-CVE hidden test. The
12-CVE Benchmark v0 is a development set and will not be used for further prompt or
architecture changes in this experiment.

## Systems

The primary experiment runs each hidden case once with the same configured model:

- A, `direct_llm`: one direct Suricata-rule generation call;
- E, `direct_repair`: the exact A rule plus validation and at most two direct repairs;
- G, `semantic_intent_repair`: two-call semantic-intent generation plus validation,
  diagnosis before every repair, and at most two minimal repairs.

F is materialized only as G's paired initial source and is not a primary reported
system. B/C are excluded because the frozen dev ablation already established their
generation-time expressiveness bottleneck.

## Fixed configuration

- Model identifier: `gpt-5.5`
- Temperature: `0.1`
- Top-p: provider default
- Seed: unsupported/not supplied by the configured API
- Maximum total attempts for E/G: `3`
- Visible repair samples: `original`, `positive-01`, `negative-01`
- Held-out samples: `positive-02`, `negative-02`
- Cases: 30 CVEs not present in Benchmark v0
- Samples per case: one original, two equivalent positives, two near-miss negatives
- Primary run count: one independent run per system/case

The architecture commit, tag, prompt hashes, provider endpoint, Suricata version and
configuration hash, dataset manifest hash, and evaluator source hash are recorded in
the sealed run manifest before execution.

## Metrics and comparisons

Primary metrics:

1. held-out variant recall (`positive-02`);
2. held-out false-positive rate (`negative-02`).

Secondary metrics:

- verified rule rate;
- syntax pass rate;
- original detection rate;
- all-variant recall and all-negative false-positive rate;
- average repair attempts, model calls, and latency.

The report publishes raw A, E, and G values and percentage-point deltas for A to E,
E to G, and A to G. No metric may be substituted after results are visible.

The preregistered architecture-confirmation threshold is:

```text
G held-out variant recall - A held-out variant recall >= +10 percentage points
and
G held-out false-positive rate - A held-out false-positive rate <= +5 percentage points
```

Passing this threshold is evidence for promoting G over A on hidden test v1. Failing
it does not authorize a rerun or prompt change on the same hidden set.

## Execution discipline

- Generate and evaluate all cases before publishing any per-case result.
- Do not inspect hidden oracle files, held-out HTTP payloads, reference rules, or
  partial aggregate results from the generation/repair process.
- A and E are paired: E must use A's exact initial rule.
- G must not receive `positive-02` or `negative-02` in any model prompt.
- A failed API call or infrastructure failure is reported as such. It is not silently
  regenerated unless the preregistered runner-level retry policy performs the retry.
- The completed primary run is immutable and receives a SHA-256 freeze manifest.
- Any future repeated A/G runs are labeled confirmatory and cannot replace this run.
