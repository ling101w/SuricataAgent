# Repository architecture

The repository has three supported lifecycles:

| Area | Stable import | Responsibility |
| --- | --- | --- |
| Production | `production.py` or `suricata_agent.pipeline.direct.graph` | E-direct generate, execute, repair, verify |
| Integrations | `suricata_agent.integrations` | Versioned adapters for external callers |
| Benchmarks | `suricata_agent.benchmarks` | Reusable benchmark runners |
| Legacy | `suricata_agent.legacy.detection_plan_pipeline` | Frozen B/C detection-plan and compiler workflow |
| Experiment assets | `benchmarks/` | Datasets, manifests, frozen runs, and reports |

`production.py` remains the canonical application contract. Web, benchmark, and
bridge integrations should import `run_generation`, `WorkflowConfig`, and
`PIPELINE_ID` from that facade. New reusable implementations belong under the
`suricata_agent/` package. Root modules such as `main.py`, `direct_workflow.py`,
`generation_bridge.py`, `diagnosis.py`, `final_judge.py`, `generate_pcap.py`,
`generate_rules.py`, `pcap_tcp_analysis.py`, `poc_http_extractor.py`,
`rule_compiler.py`, `traffic_cases.py`, and `suricata_verify_benchmark.py` are
compatibility shims that forward to package implementations.

The following root modules intentionally remain implementation owners for now:

- `semantic_generation.py`: frozen benchmark scripts hash and reference this path;
  move only together with an experiment manifest/version update.
- `rule_library.py`: combines analysis, Suricata replay, persistence and CLI;
  split its responsibilities before moving it into the package.
- `web_app.py`: owns the repository-level `web/` static resource directory;
  migrate only after packaging static resources or injecting an explicit resource root.

Package modules must not import these root compatibility shims. Root shims exist
only for old scripts and downstream imports.

The direct workflow modules are intentionally narrow at their public boundary:

- `pipeline/direct/state.py`: state, model protocol, and runtime config exports.
- `pipeline/direct/prompts.py`: frozen prompt and evidence-rendering exports.
- `pipeline/direct/artifacts.py`: artifact and result-helper exports.
- `pipeline/direct/graph.py`: public graph facade.
- `pipeline/direct/nodes.py`: node migration seam.
- `pipeline/direct/implementation.py`: frozen implementation kept intact during
  the first migration phase.

Keeping the implementation intact preserves the benchmark and artifact contracts.
The next phase can move node bodies behind these module boundaries without another
public API change.
