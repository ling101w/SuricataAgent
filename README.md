# Suricata 规则生成工作流

这个项目把 LLM 限定在“理解漏洞并提取检测特征”这一层。模型只返回三个固定角色的
结构化 JSON 候选，不直接编写 Suricata 规则；Python 负责严格解析、质量检查、
确定性编译、样本矩阵回放、候选评分和产物归档。

## 最终架构

```text
运行环境预检
  -> 构造正向变体 / 近似负样本矩阵
  -> LLM 提取 Precision / Robust / Alternative Evidence 三个候选 JSON
  -> Python 严格解析、lint 并确定性编译
  -> Suricata 语法检查和逐样本 PCAP 回放
  -> Evidence Fingerprint + Rule IR + Coverage Graph
  -> 按 detection_scope 分层，再在同层候选中评分
       | case_specific 通过 -> 固定主规则 SID -> 保存产物
       | success_indicator 通过 -> 分配补充 SID -> 单独保存
       | 失败 -> 确定性诊断 -> 携具体失败样本重试
```

模型输出必须按 `precision`、`robust`、`alternative_evidence` 的固定顺序提供三个
候选。下面示例展示角色和证据组合的差异：

```json
{
  "candidates": [
    {
      "role": "precision",
      "direction": "request",
      "detection_scope": "case_specific",
      "protocol": "http",
      "method": "GET",
      "features": [
        {
          "buffer": "http.uri.raw",
          "content": "/evo-apigw/evo-cirs/material/viewPDF"
        },
        {
          "buffer": "http.uri.raw",
          "content": "pdfUrl=file:///etc/passwd",
          "nocase": true
        }
      ],
      "dynamic_fields": ["Host", "Content-Length"],
      "reason": "接口、参数和完整利用值共同限定当前漏洞"
    },
    {
      "role": "robust",
      "direction": "request",
      "detection_scope": "case_specific",
      "protocol": "http",
      "method": null,
      "features": [
        {
          "buffer": "http.uri.raw",
          "content": "/evo-apigw/evo-cirs/material/viewPDF"
        },
        {"buffer": "http.uri.raw", "content": "file", "nocase": true},
        {"buffer": "http.uri.raw", "content": "passwd", "nocase": true}
      ],
      "dynamic_fields": ["Host", "Content-Length"],
      "reason": "保留最小接口身份，减少参数名和分隔符表示绑定"
    },
    {
      "role": "alternative_evidence",
      "direction": "response",
      "detection_scope": "success_indicator",
      "protocol": "http",
      "method": null,
      "features": [
        {"buffer": "file_data", "content": "root:x:0:0:"}
      ],
      "dynamic_fields": ["Content-Length"],
      "reason": "使用文件读取成功后的独立响应证据，仅作为补充指标"
    }
  ]
}
```

模型不能输出 `action`、`msg`、`flow`、`classtype`、`sid`、`rev` 或完整规则。
编译器统一完成以下工作：

- 根据 request/response 分配 `to_server` 或 `to_client`。
- 分配 `msg`、`classtype`、`sid` 和 `rev`。
- 写入 `metadata:detection_scope <scope>`，使后续 IR、验证和覆盖分析使用同一语义。
- 为引号、反斜杠、分号、竖线和不可打印字节生成安全的十六进制 `content`。
- 检查 HTTP sticky buffer、方向和 PCRE 前置锚点。
- 强制三个候选角色唯一且顺序固定，并拒绝仅靠 `nocase`、method、reason 或
  `dynamic_fields` 制造的重复证据集合；Precision 和 Robust 都必须保留 endpoint 身份与
  exploit 语义，Robust 只能减少参数名和具体 payload 绑定，不能退化成跨接口 IOC。
- 固定 scope 契约：Precision、Robust 和 request Alternative 为 `case_specific`；response
  Alternative 为 `success_indicator`，模型不能自行改变层级以影响选择优先级。
- 拒绝只含 URI 路径和参数名、固定 Host/Content-Length/Cookie、过短 content、
  request/response buffer 混用等高误报候选。

因此，模型质量影响“选择哪些检测特征”，不会再影响规则分号、转义、SID 或 sticky
buffer 的基本语法。候选角色、数量、buffer 方向、动态字段和 exploit marker 统一定义在
`rule_knowledge.py`，Prompt、编译器、诊断器和样本派生器不再各自维护副本。

## 样本矩阵

每个样本都使用独立 TCP 流生成单独 PCAP。基础正向集包括原始攻击、Host 变化、
Header 顺序变化和 TCP 分段；当请求结构适用时，还会派生额外参数、参数顺序、URL
编码、路径大小写和等价斜杠等攻击变体。

请求正文会按 `Content-Type` 解析后再变异：

- `application/json`：字段顺序、Unicode 引用、无关字段、受控大小写和命令尾空白。
- `application/x-www-form-urlencoded`：参数顺序、等价 URL 编码和无关参数。
- `multipart/form-data`：boundary、唯一字段顺序、无关 part 和目标字段表示变化。
- `application/xml`、`text/xml` 与 `+xml`：属性顺序、字符引用和无语义 XML 注释。
- 其他文本正文：仅在共享 exploit marker 明确命中时生成保守的换行变体。

安全改写正文时会重新计算 `Content-Length`。如果响应能够被保守识别为 `/etc/passwd`
泄漏证据，还会派生 root-only、登录 shell 变化、账户行重排、增加无关账户和 TCP 分段等
正向响应变体，以及错误页、单片段诱饵和文档示例等近似负响应。当前自动响应语义识别只
覆盖能够可靠确认的 passwd 场景；其他响应会记录结构化 skip reason，不会猜测性改写。

近似负样本尽量靠近原始漏洞流量，包括：

- 相同接口和参数名，但值为空、普通文件名或合法相对路径。
- 不同接口携带相同攻击字符串。
- 不同接口携带相同攻击请求证据并保留原始攻击响应，用于验证事务身份约束。
- 相同接口中使用正常参数值，仅在 User-Agent 放入攻击字符串。
- 相同 body 字段置空或替换为普通值；攻击值只出现在 description、无关 part 或 XML
  注释中。
- 用户通过 CLI 或 Web 额外提供的负样本 PCAP。

每个 `TrafficSample` 通过 `validates` 声明它实际能够证明的目标：

| `validates` | 验证目标 | 适用规则 |
| --- | --- | --- |
| `generic` | 原始事务或用户提供的通用样本 | 当前规则集中的全部 SID |
| `request_detection` | 请求变体与请求侧近似负样本 | `direction=request` |
| `response_detection` | 成功响应变体与响应侧诱饵 | `direction=response` |
| `transaction_specificity` | 相同证据换到其他 endpoint 后不得冒充当前漏洞 | `detection_scope=case_specific` |

因此，请求侧负样本可以使用普通响应；事务特异性负样本则会保留原始攻击响应。验证器会
按方向和 scope 计算每个样本的 `expected_any_sids`。样本对当前候选不适用时仍保留回放
事实，但标记 `applicable=false`，不计入该候选的通过门槛、recall 或 FP；Coverage Graph
也只统计样本契约内的 SID 命中。

并非每种漏洞都会生成所有变体；派生器只生成能够从当前 HTTP 请求确定得到的等价
样本。遇到 chunked、压缩正文、重复 Content-Type/Content-Length、未知字符集、
XML DTD/ENTITY 或无法安全解析的结构化正文时会跳过自动改写。跳过原因不会静默丢失，
而是以稳定的 `code`、`content_type`、`detail` 写入 `traffic-mutations.json` 和最终报告。
验证报告在 `sample_results` 中保留每个 PCAP 的预期、实际命中 SID 和通过状态，不再把
所有负样本结果合并成一个不可定位的列表。

## Rule IR 与 Coverage Graph

`rule_ir.py` 把生成规则或历史 `.rules` 解析为统一中间表示，保留 SID、方向、method、
sticky buffer、content/PCRE、nocase、否定匹配、管理字段和 endpoint/parameter/exploit
证据分类；旧式 `http_uri` content modifier 和 PCRE `U/I/P/H` 等 HTTP buffer modifier
也会映射到现代 sticky buffer。`evidence_fingerprint.py` 对 raw/normalized buffer、大小写、
URI 编码、斜杠表示和等价字面量 PCRE 做稳定归一化，并同时提供可展示 JSON 和
`efp:v1:<sha256>` ID。Coverage Graph 另用包含 method、protocol、nocase、否定极性和
PCRE modifier 的 `lfp:v1:<sha256>`，不会把证据相似误报成检测逻辑相同。

Coverage Graph 直接使用 Suricata 已产生的 `sample_results[].matched_sids`，不会增加回放：

- `text_duplicate`：排除 SID/msg/rev 等管理字段后，检测文本相同。
- `logic_duplicate`：完整规则逻辑指纹与 TP/FP 覆盖相同。
- `coverage_duplicate`：检测逻辑不同，但当前 benchmark 覆盖相同。
- `dominates`：A 的正样本覆盖是 B 的超集，负样本误报是子集；覆盖相同时再比较复杂度。

推荐集合按“最大化攻击覆盖、最小化 FP、最小化规则数、最小化 PCRE/复杂度”的顺序
优化。候选不超过 16 条时使用精确搜索，更大规则库使用确定性 greedy + 冗余剔除。
这个结论只对输入样本矩阵负责，不会把未测试到的真实流量说成已证明。Coverage 输入
必须证明当前全部 SID 都参与了回放；空结果、错配 SID 或无法证明完整性的旧报告会被
拒绝，不能静默生成空的 `recommended.rules`。

分析已有规则库：

```powershell
python rule_library.py .\rules\history.rules `
  --sample-results .\validation-report.json `
  --output-dir .\rule-library-analysis
```

会输出 `rule-ir.json`、`coverage-graph.json`、`library-summary.json` 和
`recommended.rules`。不提供 `--sample-results` 时只生成 IR，并明确拒绝给出删除建议。
`--sample-results` 必须来自同一批 `.rules` 的批量回放，不能拿单条生成规则的报告替代。
也可以让工具直接回放工作流已经生成的 PCAP 矩阵：

```powershell
python rule_library.py .\rules\history.rules `
  --traffic-matrix .\artifacts\traffic-matrix.json `
  --output-dir .\rule-library-analysis
```

此时会额外保存 `library-validation.json`；默认从 traffic matrix 同级的 `samples/`
寻找 PCAP，也可用 `--sample-root` 覆盖。

有 Coverage Graph 后，工具会同时生成不依赖模型的 `strategy-clusters.json`。需要最后
再让模型命名和归纳时显式增加 `--summarize-strategies`，产物改为
`detection-strategies.json`：

```powershell
python rule_library.py .\rules\history.rules `
  --sample-results .\validation-report.json `
  --summarize-strategies `
  --output-dir .\rule-library-analysis
```

模型只能填写固定的 `family`、`core_strategy`、`representation_variants` 和
`do_not_bind`；规则、SID、覆盖关系与推荐集合均不在模型输出 schema 中。没有推荐规则
的淘汰簇不会进入 catalog，组合证据中的历史 endpoint 和参数绑定也会在建簇、检索和
生成 Prompt 三层剥离。

## 候选选择与重试

三个角色候选会分别得到自己的规则、样本结果和复杂度。Precision 保留 endpoint 与
利用语义；Robust 减少接口绑定并覆盖表示变化；Alternative Evidence 优先选择强响应
证据，否则必须提供 A/B 未使用过的请求利用特征。为减少重复启动 Suricata，
实现可以批量回放后按 SID 拆分结果；某条规则造成批量语法失败时会单独加载，以隔离
坏候选。每个候选仍按自己的结果评分：

```text
score = 正向覆盖率 × 100
        - 误报负样本数 × 50
        - PCRE 数量 × 5
```

`dynamic_fields` 只记录模型识别出的不稳定字段，帮助审计和修复候选；它不参与最终
规则，也不会降低候选分数或同分时的复杂度排序。

优先从完全通过的候选中选择最高分；没有候选通过时选择最高分失败候选进入诊断。
同分时依次选择估算复杂度更低、序号更早的候选。

候选评测时临时使用 `sid_start + candidate_index - 1` 区分告警。选出最终候选后会
重新编译，并把最终规则和验证结果统一映射回 `sid_start`。因此候选顺序不会改变交付
规则的正式 SID。Coverage Graph 会同时记录 `selected_evaluation_sid`、
`selected_final_sid` 和完整 SID 映射，图中的选中节点与交付 Rule IR 使用同一正式 SID。

验证失败后，确定性诊断模块会分析规则、候选计划和逐样本结果，区分 PCRE 解析、
转义、方向、sticky buffer、raw/normalized URI、过度具体、缺少利用值和误报弱特征等
问题。下一轮 LLM 收到的是诊断、失败样本请求摘录和候选分数，仍然只能修复结构化
特征 JSON。默认最多尝试 3 次，环境错误和不可重试错误不会无意义地请求模型。

## 环境

```powershell
python -m pip install -r requirements.txt
$env:DEEPSEEK_API_KEY = "你的密钥"
```

也可以在项目目录创建 `.env`。它会在启动时读取，但不会覆盖进程中已经设置的环境
变量：

```dotenv
DEEPSEEK_API_KEY=你的密钥
DEEPSEEK_MODEL=gpt-5.5
DEEPSEEK_BASE_URL=https://api.example.com/v1
# 可选：规则库分析生成的 Detection Strategy 目录
DETECTION_STRATEGY_CATALOG=C:\path\to\detection-strategies.json
```

项目优先发现 `suricata/suricata.exe` 和 `suricata/suricata.yaml`。使用其他安装位置时
设置：

```powershell
$env:SURICATA_BIN = "C:\path\to\suricata.exe"
$env:SURICATA_CONFIG = "C:\path\to\suricata.yaml"
```

Windows 现在由 Python `subprocess.run()` 直接启动 Suricata，执行语法检查和 PCAP
回放；程序会设置配置目录作为工作目录、补充便携版和 Npcap DLL 的 `PATH`，并串行化
本机 Suricata 进程。无需 bridge 脚本或额外的常驻 PowerShell 进程。

如果怀疑 IDE、自动化工具或进程沙箱改变了 Windows 子进程行为，请在普通 PowerShell
窗口中直接运行：

```powershell
& .\diagnose_suricata_launch.ps1 -Runs 5 -TimeoutSeconds 10
```

脚本分别测试 PowerShell 直启和与 Web 后端一致的 Python 子进程启动，完整日志写入
`.runtime/launch-diagnostics/<时间>/summary.json`：

- `NATIVE_OK`：两种方式均稳定，本机不需要 bridge。
- `PYTHON_CHILD_UNSTABLE`：PowerShell 稳定、Python 不稳定，才需要 sibling bridge。
- `SURICATA_RUNTIME_UNSTABLE`：PowerShell 基线也失败，应先检查 Suricata、Npcap、配置
  和终端安全软件。

## CLI 输入

创建 `case.json`：

```json
{
  "case_id": "demo-001",
  "base": "漏洞名称、版本和影响范围",
  "poc": "漏洞利用步骤及关键参数",
  "http_request_path": "request.raw",
  "http_response_path": "response.raw",
  "negative_pcap_paths": ["benign-near-miss.pcap"]
}
```

推荐通过 `http_request_path` 和 `http_response_path` 按 bytes 读取，避免改变畸形报文、
重复头、分块编码或二进制正文。也可以直接提供 `http_request` 和 `http_response`
字符串。相对路径以 `case.json` 所在目录为基准。

运行：

```powershell
python main.py case.json --output-dir artifacts --sid-start 6000000 --max-attempts 3
```

还可使用 `--suricata-bin` 和 `--suricata-config` 覆盖运行环境。CLI 最后输出 JSON
摘要；工作流通过时退出码为 `0`，失败时为 `1`。

## Web 启动

```powershell
python web_app.py
```

默认访问 `http://127.0.0.1:8000`。需要修改监听地址或端口时设置 `WEB_HOST` 和
`WEB_PORT`。Web 支持文本或 Base64 原始 HTTP 输入、最多 4 个用户负样本、后台任务、
逐样本矩阵、候选分数、每轮诊断与规则，以及 PCAP、规则和报告下载。

Web 默认只监听本机。PoC 和 HTTP 证据会发送到 `DEEPSEEK_BASE_URL` 指向的模型服务，
不要提交不应离开本机的凭据或敏感流量。

## 产物

输出目录的主要结构如下：

```text
artifacts/
├── traffic.pcap                  # 原始正向样本的兼容入口
├── samples/                      # 每个正向变体和近似负样本的独立 PCAP
├── traffic-matrix.json           # 样本标签、来源、原因和路径
├── traffic-mutations.json        # 未执行 body mutation 的结构化原因
├── generated.rules               # 通过验证且 SID 已固定的最终规则
├── generated.rule-ir.json         # 最终规则的统一中间表示
├── coverage-graph.json            # 候选覆盖关系、推荐 SID 和删除理由
├── failed-candidate.rules        # 达到重试上限时的最后候选
├── failed-candidate.rule-ir.json  # 失败候选存在时对应的 IR
├── validation-report.json        # 最终状态、逐样本结果和全部尝试
└── attempts/
    ├── 001/
    │   ├── detection-plan.json
    │   ├── candidate-01.rules
    │   ├── candidate-01-validation.json
    │   ├── candidate-01-result.json
    │   ├── candidate.rules       # 当轮选中并固定 SID 后的规则
    │   ├── validation.json
    │   ├── diagnosis.json        # 当轮失败时生成
    │   └── attempt.json
    └── 002/
        └── ...
```

模型超时或 schema 错误也会在对应 `attempts/NNN/` 中保存
`generation-error.json` 和原始 `model-response.txt`，不会再用后一轮状态覆盖前一轮证据。

## 测试

默认测试不会调用模型，并跳过真实 Suricata 集成用例：

```powershell
python -m pytest -q --basetemp .pytest-run
```

内置 12 个小型 benchmark，覆盖 traversal、command injection、SQLi、SSRF、JSON RCE、
XML 和 multipart。日常 mutation 回归不调用模型或 Suricata：

```powershell
python benchmark_runner.py --mode mutation-only --output-dir .\benchmark-artifacts
```

完整模式会读取 `.env`、调用模型并使用本机 Suricata，汇总 positive recall、negative FP
rate、candidate pass rate、retry count 和 rule complexity：

```powershell
python benchmark_runner.py --mode full --output-dir .\benchmark-artifacts
```

runner 或预检异常的案例仍会按 manifest 派生出的正样本数计入 recall 分母；无法回放的
负样本单独计入 `negative_samples_unevaluated`，不会伪装成零误报。

完整 benchmark 会产生模型调用成本。真实交付前仍应使用与部署环境一致的 Suricata
版本、配置和业务样本复验。
