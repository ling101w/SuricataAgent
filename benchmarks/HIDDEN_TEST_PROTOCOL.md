# Hidden Test Protocol

Benchmark v0's 12 CVEs are the development set. They may be used to implement and
debug F/G, but their results are not evidence of final generalization.

The final test set contains 30 different CVEs and remains sealed until the generation
architecture, prompts, model, temperature, maximum repair count, and evaluator are
frozen. Case authors may inspect and label it; system authors must not inspect its
oracle files, PCAP contents, reference rules, per-case results, or model outputs before
the single final run.

## Freeze gate

Before unsealing the test set, record:

- source commit or source-tree SHA-256 manifest;
- exact model identifier, endpoint provider, temperature, and prompt hashes;
- F/G system definitions and maximum total attempts;
- Suricata version and configuration hash;
- aggregate metric implementation and evaluator tests;
- the 30-case manifest hash.

## Sealed layout

```text
benchmarks/hidden-test-v1/
|-- manifest.public.json
|-- sealed-cases/
|   `-- CVE-.../
|       |-- input.json
|       |-- oracle.json
|       |-- pcaps/
|       `-- reference.rules       # optional
`-- results/                       # empty before the final run
```

`input.json` is model-visible. `oracle.json`, PCAP labels, held-out request contents,
and `reference.rules` are evaluator-only. The system receives no per-case feedback
beyond the explicitly visible repair samples.

## Final run

Run A, E, and G with the same frozen model input and model configuration. F is
materialized only as G's paired initial source. Do not
change prompts or code after seeing any hidden result and then report the rerun as the
same experiment. A changed system requires a new hidden test set or a clearly labeled
exploratory result.

The exact systems, model configuration, metrics, and decision threshold for hidden
test v1 are fixed in `HIDDEN_TEST_PREREGISTRATION.md`.

Publish aggregate metrics only after all cases finish:

- syntax pass rate;
- original detection rate;
- visible and held-out variant recall;
- visible and held-out false-positive rate;
- verified rule rate;
- average repair attempts and latency.

The primary architecture decision uses held-out variant recall and held-out
false-positive rate. If F/G do not improve held-out recall over A/E without increasing
held-out false positives, stop prompt tuning and evaluate retrieval as the next
ablation.
