# Benchmark v0 IR expressiveness audit

This audit compares the 12 frozen Direct LLM rules with the current generation-time
`DetectionPlan` / `DetectionFeature` schema and deterministic compiler.

- Post-generation Rule IR parse: 91.7%
- Generation schema accepts at least one role: 58.3%
- Compiler accepts at least one role: 50.0%
- Detection-semantics lossless: 25.0%
- Text/optimizer lossless: 0.0%

| Case | Direct | IR status | Semantic options lost | Compiler roles |
|---|---:|---|---|---|
| CVE-2014-3704 | syntax | optimizer_loss_only | - | alternative_evidence |
| CVE-2016-4437 | invalid | unsupported | - | - |
| CVE-2017-12629 | verified | unsupported | startswith | - |
| CVE-2018-7600 | syntax | lossy | startswith | precision, robust, alternative_evidence |
| CVE-2021-26084 | syntax | lossy | distance:0, within:200, within:512 | precision, robust, alternative_evidence |
| CVE-2021-40438 | invalid | unsupported | - | - |
| CVE-2021-41773 | verified | optimizer_loss_only | - | alternative_evidence |
| CVE-2021-43798 | verified | lossy | startswith | precision, robust, alternative_evidence |
| CVE-2022-22965 | syntax | unsupported | - | - |
| CVE-2023-38646 | verified | unsupported | startswith | - |
| CVE-2024-36401 | syntax | unsupported | - | - |
| CVE-2025-29927 | syntax | optimizer_loss_only | - | alternative_evidence |

`optimizer_loss_only` means detection behavior can be reproduced but compiler output
drops an option such as `fast_pattern`. `lossy` means a match constraint such as
`startswith`, `distance`, or `within` is lost. `unsupported` means the schema/compiler
cannot emit the feature set at all under its current policy.
