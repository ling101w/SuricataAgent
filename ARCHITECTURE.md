# Repository architecture

The repository has three supported lifecycles:

| Area | Stable import | Responsibility |
| --- | --- | --- |
| Production | `production.py` or `suricata_agent.pipeline.direct.graph` | E-direct generate, execute, repair, verify |
| Legacy | `suricata_agent.legacy.detection_plan_pipeline` | Frozen B/C detection-plan and compiler workflow |
| Experiments | `benchmarks/` | Reproducibility runners and reports |

`production.py` remains the canonical application contract. Web, benchmark, and
bridge integrations should import `run_generation`, `WorkflowConfig`, and
`PIPELINE_ID` from that facade. The package path is the migration target for new
code. The root `main.py` and `direct_workflow.py` modules remain compatibility
shims until downstream imports have been migrated.

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
