# suricata-verify benchmark source

The official OISF `suricata-verify` repository is checked out at
`benchmarks/suricata-verify/`. It is intentionally ignored by the parent Git
repository because the checkout contains about 350 MiB of PCAP and regression
data. Its exact upstream commit is recorded in
`suricata-verify-manifest.json`.

The generated manifest selects tests that have all of the following:

- a resolvable PCAP or PCAPNG input;
- resolvable Suricata rules with HTTP detection semantics;
- structured `test.yaml` checks for expected EVE alert counts.

Rebuild the index after updating the checkout:

```powershell
python -B .\benchmarks\build_suricata_verify_manifest.py
```

Recreate the source checkout from scratch:

```powershell
git clone --depth 1 https://github.com/OISF/suricata-verify.git .\benchmarks\suricata-verify
python -B .\benchmarks\build_suricata_verify_manifest.py
```

This source is a Suricata engine and rule-behavior regression corpus, not a
CVE-organized exploit corpus. The original first 12 CVEs do not have dedicated
suricata-verify PCAP test directories. Also, `test.rules` is oracle material:
do not include it in the LLM input when measuring rule generation, or the
benchmark will leak the expected answer.

The upstream runner expects `jq` and a built Suricata source tree. The data can
still be consumed through the generated manifest by a project-specific runner.

Run the project's default 12-case HTTP smoke group with the local Suricata:

```powershell
python -B .\suricata_verify_benchmark.py
```

The runner writes exact per-SID oracle comparisons to `report.json` and a flat
case summary to `report.csv` under a timestamped `benchmark-artifacts` directory.
