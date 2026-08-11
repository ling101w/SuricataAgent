"use strict";

const elements = {
  generatorWorkspace: document.getElementById("generatorWorkspace"),
  ruleopsWorkspace: document.getElementById("ruleopsWorkspace"),
  pcapWorkspace: document.getElementById("pcapWorkspace"),
  form: document.getElementById("generationForm"),
  caseId: document.getElementById("caseId"),
  sidStart: document.getElementById("sidStart"),
  base: document.getElementById("base"),
  poc: document.getElementById("poc"),
  maxAttempts: document.getElementById("maxAttempts"),
  httpRequest: document.getElementById("httpRequest"),
  httpResponse: document.getElementById("httpResponse"),
  httpEvidenceEditor: document.getElementById("httpEvidenceEditor"),
  pythonPocEditor: document.getElementById("pythonPocEditor"),
  pythonPoc: document.getElementById("pythonPoc"),
  pythonPocFile: document.getElementById("pythonPocFile"),
  pythonPocSource: document.getElementById("pythonPocSource"),
  importPythonPoc: document.getElementById("importPythonPoc"),
  extractPythonPoc: document.getElementById("extractPythonPoc"),
  extractedHttpRequest: document.getElementById("extractedHttpRequest"),
  extractionStatus: document.getElementById("extractionStatus"),
  extractionMeta: document.getElementById("extractionMeta"),
  requestFile: document.getElementById("requestFile"),
  responseFile: document.getElementById("responseFile"),
  requestSource: document.getElementById("requestSource"),
  responseSource: document.getElementById("responseSource"),
  requestBytes: document.getElementById("requestBytes"),
  responseBytes: document.getElementById("responseBytes"),
  negativeFiles: document.getElementById("negativePcapFiles"),
  negativeList: document.getElementById("negativePcapList"),
  addNegative: document.getElementById("addNegativePcap"),
  resetForm: document.getElementById("resetForm"),
  runButton: document.getElementById("runButton"),
  refreshRuntime: document.getElementById("refreshRuntime"),
  runtimeBanner: document.getElementById("runtimeBanner"),
  suricataStatus: document.getElementById("suricataStatus"),
  modelStatus: document.getElementById("modelStatus"),
  recentRuns: document.getElementById("recentRuns"),
  inputState: document.getElementById("inputState"),
  emptyState: document.getElementById("emptyState"),
  resultContent: document.getElementById("resultContent"),
  resultStatus: document.getElementById("resultStatus"),
  progressTrack: document.getElementById("progressTrack"),
  summaryStage: document.getElementById("summaryStage"),
  summaryAttempt: document.getElementById("summaryAttempt"),
  summaryExpected: document.getElementById("summaryExpected"),
  summaryMatched: document.getElementById("summaryMatched"),
  ruleMeta: document.getElementById("ruleMeta"),
  ruleOutput: document.getElementById("ruleOutput"),
  copyRules: document.getElementById("copyRules"),
  downloadRules: document.getElementById("downloadRules"),
  validationStages: document.getElementById("validationStages"),
  validationMetrics: document.getElementById("validationMetrics"),
  sidSection: document.getElementById("sidSection"),
  validationMessages: document.getElementById("validationMessages"),
  commandDetails: document.getElementById("commandDetails"),
  commandOutput: document.getElementById("commandOutput"),
  matrixOverview: document.getElementById("matrixOverview"),
  mutationSkips: document.getElementById("mutationSkips"),
  sampleMatrix: document.getElementById("sampleMatrix"),
  attemptList: document.getElementById("attemptList"),
  eventList: document.getElementById("eventList"),
  artifactBar: document.getElementById("artifactBar"),
  artifactCount: document.getElementById("artifactCount"),
  artifactActions: document.getElementById("artifactActions"),
  failureBanner: document.getElementById("failureBanner"),
  failureCode: document.getElementById("failureCode"),
  failureMessage: document.getElementById("failureMessage"),
  explanationHero: document.getElementById("explanationHero"),
  explanationVerdict: document.getElementById("explanationVerdict"),
  explanationHeadline: document.getElementById("explanationHeadline"),
  explanationSummary: document.getElementById("explanationSummary"),
  explanationScore: document.getElementById("explanationScore"),
  explanationChecks: document.getElementById("explanationChecks"),
  failedSamplesSection: document.getElementById("failedSamplesSection"),
  failedSampleList: document.getElementById("failedSampleList"),
  limitationList: document.getElementById("limitationList"),
  irOverview: document.getElementById("irOverview"),
  irOutput: document.getElementById("irOutput"),
  extractionResultOverview: document.getElementById("extractionResultOverview"),
  extractionCandidateList: document.getElementById("extractionCandidateList"),
  extractionOutput: document.getElementById("extractionOutput"),
  ruleopsSearch: document.getElementById("ruleopsSearch"),
  ruleopsStats: document.getElementById("ruleopsStats"),
  ruleListCount: document.getElementById("ruleListCount"),
  ruleopsRuleList: document.getElementById("ruleopsRuleList"),
  coverageGraphView: document.getElementById("coverageGraphView"),
  duplicateGroups: document.getElementById("duplicateGroups"),
  pcapAnalysisStatus: document.getElementById("pcapAnalysisStatus"),
  pcapDropzone: document.getElementById("pcapDropzone"),
  pcapFileInput: document.getElementById("pcapFileInput"),
  selectPcapFile: document.getElementById("selectPcapFile"),
  clearPcapFile: document.getElementById("clearPcapFile"),
  pcapFileName: document.getElementById("pcapFileName"),
  pcapFileMeta: document.getElementById("pcapFileMeta"),
  analyzePcap: document.getElementById("analyzePcap"),
  analyzePcapLabel: document.getElementById("analyzePcapLabel"),
  exportPcapAnalysis: document.getElementById("exportPcapAnalysis"),
  pcapResultEmpty: document.getElementById("pcapResultEmpty"),
  pcapAnalysisResult: document.getElementById("pcapAnalysisResult"),
  pcapConnectionCount: document.getElementById("pcapConnectionCount"),
  pcapSummaryGrid: document.getElementById("pcapSummaryGrid"),
  pcapStreamCount: document.getElementById("pcapStreamCount"),
  pcapStreamList: document.getElementById("pcapStreamList"),
  toast: document.getElementById("toast"),
};

const appState = {
  runtime: null,
  currentRun: null,
  previousRunStatus: null,
  pollTimer: null,
  toastTimer: null,
  rawFiles: {
    request: null,
    response: null,
  },
  evidenceMode: "http",
  pythonPocFile: null,
  pocExtraction: null,
  negativeFiles: [],
  workspace: "generator",
  ruleops: null,
  selectedRuleopsRecord: null,
  ruleopsSearchTimer: null,
  pcapFile: null,
  pcapAnalysis: null,
};

const statusLabels = {
  queued: "等待调度",
  running: "正在运行",
  passed: "验证通过",
  failed: "未通过验证",
};

const eventStatusLabels = {
  done: "已完成",
  failed: "失败",
  retrying: "准备重试",
  running: "运行中",
};

const artifactLabels = {
  pcap: "PCAP",
  rules: "规则",
  supplemental_rules: "补充规则",
  report: "报告",
  pcap_analysis: "PCAP TCP 分析",
  mutations: "变体诊断",
  rule_ir: "Rule IR",
  supplemental_rule_ir: "补充 Rule IR",
  final_judgment: "Final Judge",
  coverage_graph: "Coverage Graph",
  python_poc: "Python PoC",
  poc_extraction: "PoC 提取报告",
  extracted_request: "提取请求",
  http_candidates: "HTTP 候选",
  extraction_report: "提取报告",
};

const candidateScopeLabels = {
  case_specific: "漏洞特异主规则",
  exploit_family: "利用家族规则",
  success_indicator: "攻击成功补充指标",
};

const supplementalCandidateScopes = new Set([
  "exploit_family",
  "success_indicator",
]);

function refreshIcons() {
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    window.lucide.createIcons({ attrs: { "aria-hidden": "true" } });
  }
}

function formatBytes(size) {
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / 1024 / 1024).toFixed(1)} MiB`;
}

function utf8Size(value) {
  return new TextEncoder().encode(value).byteLength;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function formatDuration(value) {
  if (value === null || value === undefined || value === "") return "—";
  const milliseconds = Number(value);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toFixed(2)} s`;
}

function formatPercent(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${Math.round(number * 100)}%`;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((item) => displayValue(item)).filter(Boolean).join("\n");
  }
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function finiteNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function appendEmptyState(container, message) {
  const empty = document.createElement("div");
  empty.className = "panel-empty";
  empty.textContent = message;
  container.append(empty);
}

function detailText(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => item.msg || item.message || JSON.stringify(item))
      .join("；");
  }
  if (detail && typeof detail === "object") {
    return detail.message || detail.msg || JSON.stringify(detail);
  }
  return "请求失败";
}

async function apiFetch(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    throw new Error(detailText(body?.detail ?? body));
  }
  return body;
}

function showToast(message, isError = false) {
  clearTimeout(appState.toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("is-error", isError);
  elements.toast.classList.add("is-visible");
  appState.toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 3200);
}

function setRuntimeItem(element, state, label) {
  element.classList.remove("is-ready", "is-error", "is-checking");
  element.classList.add(`is-${state}`);
  element.querySelector("span:last-child").textContent = label;
  element.title = label;
  element.setAttribute("aria-label", label);
}

function isRunActive() {
  return ["queued", "running"].includes(appState.currentRun?.status);
}

function updateRunButton() {
  const environmentReady = Boolean(
    appState.runtime?.suricata?.ok && appState.runtime?.model?.configured,
  );
  elements.runButton.disabled = !environmentReady || isRunActive();
  const label = elements.runButton.querySelector("span");
  label.textContent = isRunActive() ? "正在运行" : "生成并验证";
}

async function loadRuntime() {
  setRuntimeItem(elements.suricataStatus, "checking", "Suricata 检查中");
  setRuntimeItem(elements.modelStatus, "checking", "模型检查中");
  elements.refreshRuntime.disabled = true;
  try {
    appState.runtime = await apiFetch("/api/runtime");
    const { suricata, model } = appState.runtime;
    setRuntimeItem(
      elements.suricataStatus,
      suricata.ok ? "ready" : "error",
      suricata.ok ? "Suricata 就绪" : "Suricata 异常",
    );
    setRuntimeItem(
      elements.modelStatus,
      model.configured ? "ready" : "error",
      model.configured ? model.name : "模型未配置",
    );

    const problems = [];
    if (!suricata.ok) {
      problems.push(suricata.message || "Suricata 运行环境不可用");
    }
    if (!model.configured) {
      problems.push("请设置 LLM_API_KEY、LLM_BASE_URL 和 LLM_MODEL，设置后重启 Web 服务");
    }
    elements.runtimeBanner.hidden = problems.length === 0;
    elements.runtimeBanner.textContent = problems.join("；");
  } catch (error) {
    appState.runtime = null;
    setRuntimeItem(elements.suricataStatus, "error", "环境接口异常");
    setRuntimeItem(elements.modelStatus, "error", "环境接口异常");
    elements.runtimeBanner.hidden = false;
    elements.runtimeBanner.textContent = error.message;
  } finally {
    elements.refreshRuntime.disabled = false;
    updateRunButton();
    refreshIcons();
  }
}

function switchInputTab(name) {
  document.querySelectorAll("[data-input-tab]").forEach((button) => {
    const active = button.dataset.inputTab === name;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
  ["request", "response"].forEach((kind) => {
    const panel = document.getElementById(`${kind}Panel`);
    const active = kind === name;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
}

function switchEvidenceMode(mode) {
  appState.evidenceMode = mode === "python_poc" ? "python_poc" : "http";
  const pythonMode = appState.evidenceMode === "python_poc";
  elements.httpEvidenceEditor.hidden = pythonMode;
  elements.pythonPocEditor.hidden = !pythonMode;
  elements.httpRequest.required = !pythonMode;
  elements.pythonPoc.required = pythonMode;
  elements.poc.required = !pythonMode;
  document.querySelectorAll("[data-evidence-mode]").forEach((button) => {
    const active = button.dataset.evidenceMode === appState.evidenceMode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
}

function switchResultTab(name) {
  document.querySelectorAll("[data-result-tab]").forEach((button) => {
    const active = button.dataset.resultTab === name;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll("[data-result-panel]").forEach((panel) => {
    const active = panel.dataset.resultPanel === name;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
}

function switchWorkspace(name) {
  const workspace = ["generator", "ruleops", "pcap"].includes(name)
    ? name
    : "generator";
  appState.workspace = workspace;
  elements.generatorWorkspace.hidden = workspace !== "generator";
  elements.ruleopsWorkspace.hidden = workspace !== "ruleops";
  elements.pcapWorkspace.hidden = workspace !== "pcap";
  document.querySelectorAll("[data-workspace]").forEach((button) => {
    const active = button.dataset.workspace === appState.workspace;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  });
  if (workspace === "ruleops") loadRuleOps(elements.ruleopsSearch.value.trim());
}

function renderExplanation(explanation) {
  const value = explanation || {};
  const verdict = value.verdict || "pending";
  const labels = {
    verified: "VERIFIED",
    rejected: "REJECTED",
    not_verified: "NOT VERIFIED",
    pending: "PENDING",
  };
  elements.explanationHero.className = `explanation-hero is-${verdict}`;
  elements.explanationVerdict.textContent = labels[verdict] || String(verdict).toUpperCase();
  elements.explanationHeadline.textContent = value.headline || "尚未形成交付结论";
  elements.explanationSummary.textContent =
    value.summary || "完整 Verify 结束后，这里会给出可追溯的结果解释。";
  elements.explanationScore.textContent = verdict === "verified" ? "PASS" : verdict === "rejected" ? "FAIL" : "—";

  elements.explanationChecks.replaceChildren();
  const checks = Array.isArray(value.checks) ? value.checks : [];
  if (!checks.length) {
    appendEmptyState(elements.explanationChecks, "等待 runtime evidence");
  } else {
    checks.forEach((check) => {
      const row = document.createElement("div");
      row.className = `explanation-check is-${check.passed ? "passed" : "failed"}`;
      const icon = document.createElement("i");
      icon.dataset.lucide = check.passed ? "check" : "x";
      const label = document.createElement("span");
      label.textContent = check.label || "Check";
      const detail = document.createElement("strong");
      detail.textContent = check.detail || (check.passed ? "通过" : "失败");
      row.append(icon, label, detail);
      elements.explanationChecks.append(row);
    });
  }

  const failed = Array.isArray(value.failed_samples) ? value.failed_samples : [];
  elements.failedSamplesSection.hidden = failed.length === 0;
  elements.failedSampleList.replaceChildren();
  failed.forEach((sample) => {
    const row = document.createElement("div");
    row.className = "failed-sample-row";
    const identity = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = sample.name || "unknown sample";
    const reason = document.createElement("span");
    reason.textContent = sample.reason || "未提供样本说明";
    identity.append(name, reason);
    const observed = document.createElement("code");
    const sids = Array.isArray(sample.matched_sids) ? sample.matched_sids : [];
    observed.textContent = sample.expected === "alert"
      ? sids.length ? `命中 ${sids.join(", ")}` : "未告警"
      : sids.length ? `误报 ${sids.join(", ")}` : "无告警";
    row.append(identity, observed);
    elements.failedSampleList.append(row);
  });

  elements.limitationList.replaceChildren();
  const limitations = Array.isArray(value.limitations) ? value.limitations : [];
  limitations.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    elements.limitationList.append(li);
  });
  if (!limitations.length) {
    const li = document.createElement("li");
    li.textContent = "等待最终验证边界。";
    elements.limitationList.append(li);
  }
  refreshIcons();
}

function renderRuleIR(ruleIr) {
  elements.irOverview.replaceChildren();
  const code = elements.irOutput.querySelector("code");
  if (!ruleIr) {
    code.textContent = "Verify 后解析 Final Rule…";
    appendEmptyState(elements.irOverview, "IR 不参与生成、Repair 或 Verify 门槛");
    return;
  }
  appendMetric(elements.irOverview, "SID", String(ruleIr.sid ?? "—"));
  appendMetric(elements.irOverview, "方向", ruleIr.direction || "—");
  appendMetric(elements.irOverview, "Scope", ruleIr.detection_scope || "—");
  appendMetric(elements.irOverview, "特征", String((ruleIr.features || []).length));
  const evidence = ruleIr.evidence || {};
  appendMetric(
    elements.irOverview,
    "证据原子",
    String(Object.values(evidence).flatMap((items) => Array.isArray(items) ? items : []).length),
  );
  code.textContent = JSON.stringify(ruleIr, null, 2);
}

function renderPocExtraction(extraction, inputMode = "http") {
  elements.extractionResultOverview.replaceChildren();
  elements.extractionCandidateList.replaceChildren();
  const code = elements.extractionOutput.querySelector("code");
  if (!extraction) {
    appendEmptyState(
      elements.extractionResultOverview,
      inputMode === "python_poc" ? "等待 prepare 阶段静态提取" : "当前任务使用 Raw HTTP 输入",
    );
    code.textContent = inputMode === "python_poc"
      ? "Python PoC 尚未形成可回放请求…"
      : "HTTP 输入不需要 PoC 提取…";
    return;
  }
  const selected = extraction.selected || {};
  appendMetric(elements.extractionResultOverview, "Adapter", extraction.adapter || "—");
  appendMetric(elements.extractionResultOverview, "候选", String(extraction.candidate_count ?? 0));
  appendMetric(
    elements.extractionResultOverview,
    "Confidence",
    selected.confidence == null ? "—" : String(selected.confidence),
    extraction.accepted ? "is-good" : "is-warning",
  );
  appendMetric(
    elements.extractionResultOverview,
    "请求来源",
    extraction.selected_request_overridden ? "人工补全" : "静态提取",
  );
  (extraction.candidates || []).forEach((candidate, index) => {
    const row = document.createElement("div");
    row.className = `extraction-candidate${index === extraction.selected_index ? " is-selected" : ""}`;
    const identity = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${candidate.method || "HTTP"} ${candidate.path || "/"}`;
    const source = document.createElement("span");
    source.textContent = `${candidate.client || "unknown"} · line ${candidate.source_line || "—"}`;
    identity.append(title, source);
    const confidence = document.createElement("code");
    confidence.textContent = `confidence ${candidate.confidence ?? "—"}`;
    row.append(identity, confidence);
    elements.extractionCandidateList.append(row);
  });
  code.textContent = selected.raw_request || "没有可展示的 Raw HTTP";
}

function statBlock(label, value) {
  const item = document.createElement("div");
  item.className = "ruleops-stat";
  const title = document.createElement("span");
  title.textContent = label;
  const number = document.createElement("strong");
  number.textContent = String(value ?? 0);
  item.append(title, number);
  return item;
}

function renderCoverageSnapshot(record, snapshots) {
  elements.coverageGraphView.replaceChildren();
  if (!record) {
    appendEmptyState(elements.coverageGraphView, "选择一条规则查看同 case Coverage Graph");
    return;
  }
  const snapshot = snapshots?.[record.case_id];
  if (!snapshot) {
    appendEmptyState(elements.coverageGraphView, "该 case 尚无 joint replay coverage evidence");
    return;
  }
  const summary = document.createElement("div");
  summary.className = "coverage-evidence-strip";
  [
    ["证据", snapshot.evidence === "joint_runtime_replay" ? "Joint replay" : snapshot.evidence],
    ["规则", snapshot.rule_count],
    ["样本", snapshot.sample_count],
    ["推荐", (snapshot.recommended_record_ids || []).length],
  ].forEach(([label, value]) => summary.append(statBlock(label, value)));
  elements.coverageGraphView.append(summary);

  const graph = snapshot.graph || {};
  const sidMap = snapshot.evaluation_sid_map || {};
  const nodes = document.createElement("div");
  nodes.className = "coverage-node-list";
  (graph.nodes || []).forEach((node) => {
    const mapped = sidMap[String(node.sid)] || {};
    const row = document.createElement("div");
    row.className = `coverage-node${(graph.recommended_sids || []).includes(node.sid) ? " is-recommended" : ""}`;
    const title = document.createElement("strong");
    title.textContent = mapped.record_id || `evaluation SID ${node.sid}`;
    const detail = document.createElement("span");
    detail.textContent = `SID ${mapped.deployment_sid ?? "—"} · TP ${node.positive_hits?.length || 0} · FP ${node.negative_hits?.length || 0}`;
    row.append(title, detail);
    nodes.append(row);
  });
  elements.coverageGraphView.append(nodes);

  const relations = document.createElement("div");
  relations.className = "coverage-relation-list";
  (graph.relations || []).forEach((relation) => {
    const row = document.createElement("div");
    const source = sidMap[String(relation.source_sid)]?.record_id || relation.source_sid;
    const target = sidMap[String(relation.target_sid)]?.record_id || relation.target_sid;
    row.textContent = `${source} → ${target}`;
    const kind = document.createElement("code");
    kind.textContent = relation.kind;
    row.append(kind);
    relations.append(row);
  });
  if (!(graph.relations || []).length) appendEmptyState(relations, "没有可证明的重复或支配关系");
  elements.coverageGraphView.append(relations);
}

function renderRuleOps(data) {
  appState.ruleops = data;
  const stats = data?.stats || {};
  elements.ruleopsStats.replaceChildren(
    statBlock("Verified rules", stats.verified),
    statBlock("Cases", stats.cases),
    statBlock("去重命中", stats.duplicate_observations),
    statBlock("Coverage sets", stats.coverage_snapshots),
  );
  const records = Array.isArray(data?.records) ? data.records : [];
  if (
    appState.selectedRuleopsRecord &&
    !records.some((record) => record.record_id === appState.selectedRuleopsRecord.record_id)
  ) {
    appState.selectedRuleopsRecord = null;
  }
  if (!appState.selectedRuleopsRecord && records.length) {
    appState.selectedRuleopsRecord = records[0];
  }
  elements.ruleListCount.textContent = `${records.length} 条`;
  elements.ruleopsRuleList.replaceChildren();
  if (!records.length) appendEmptyState(elements.ruleopsRuleList, "没有匹配的 verified rule");
  records.forEach((record) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `ruleops-rule-row${appState.selectedRuleopsRecord?.record_id === record.record_id ? " is-selected" : ""}`;
    const top = document.createElement("div");
    const caseId = document.createElement("strong");
    const caseIds = Array.isArray(record.case_ids) && record.case_ids.length
      ? record.case_ids
      : [record.case_id];
    caseId.textContent = caseIds.length > 2
      ? `${caseIds.slice(0, 2).join(" · ")} · +${caseIds.length - 2}`
      : caseIds.join(" · ");
    const sid = document.createElement("code");
    sid.textContent = `SID ${record.sid}`;
    top.append(caseId, sid);
    const evidence = document.createElement("span");
    const endpoint = record.evidence?.endpoint || [];
    const exploit = record.evidence?.exploit || [];
    evidence.textContent = [...endpoint, ...exploit].slice(0, 3).join(" · ") || "未分类证据";
    const footer = document.createElement("small");
    footer.textContent = `${record.direction || "request"} · ${record.detection_scope || "case_specific"} · ${record.logic_fingerprint?.slice(0, 16) || "no fingerprint"}`;
    button.append(top, evidence, footer);
    button.addEventListener("click", () => {
      appState.selectedRuleopsRecord = record;
      renderRuleOps(appState.ruleops);
      renderCoverageSnapshot(record, appState.ruleops.coverage_snapshots);
    });
    elements.ruleopsRuleList.append(button);
  });
  renderCoverageSnapshot(appState.selectedRuleopsRecord, data?.coverage_snapshots || {});

  elements.duplicateGroups.replaceChildren();
  const groups = Array.isArray(data?.duplicate_groups) ? data.duplicate_groups : [];
  if (groups.length) {
    const heading = document.createElement("div");
    heading.className = "section-heading";
    const title = document.createElement("strong");
    title.textContent = "Evidence overlap";
    const count = document.createElement("span");
    count.textContent = `${groups.length} 组`;
    heading.append(title, count);
    elements.duplicateGroups.append(heading);
    groups.forEach((group) => {
      const row = document.createElement("div");
      row.className = "duplicate-group-row";
      row.textContent = group.case_ids.join(" · ");
      const code = document.createElement("code");
      code.textContent = group.evidence_fingerprint.slice(0, 22);
      row.append(code);
      elements.duplicateGroups.append(row);
    });
  }
  refreshIcons();
}

async function loadRuleOps(query = "") {
  try {
    const suffix = query ? `?q=${encodeURIComponent(query)}` : "";
    renderRuleOps(await apiFetch(`/api/ruleops${suffix}`));
  } catch (error) {
    showToast(error.message, true);
  }
}

function sourceElements(kind) {
  if (kind === "request") {
    return {
      textarea: elements.httpRequest,
      input: elements.requestFile,
      source: elements.requestSource,
      bytes: elements.requestBytes,
    };
  }
  return {
    textarea: elements.httpResponse,
    input: elements.responseFile,
    source: elements.responseSource,
    bytes: elements.responseBytes,
  };
}

function updateByteCount(kind) {
  const controls = sourceElements(kind);
  const file = appState.rawFiles[kind];
  controls.bytes.textContent = formatBytes(
    file ? file.size : utf8Size(controls.textarea.value),
  );
}

async function importRawFile(kind, file) {
  const limit = appState.runtime?.limits?.http_bytes || 4 * 1024 * 1024;
  if (file.size > limit) {
    showToast(`文件超过 ${formatBytes(limit)} 限制`, true);
    return;
  }
  const controls = sourceElements(kind);
  const bytes = await file.arrayBuffer();
  appState.rawFiles[kind] = file;
  controls.textarea.value = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  controls.source.textContent = `${file.name} · 原始字节`;
  controls.input.value = "";
  updateByteCount(kind);
  showToast(`已导入 ${file.name}`);
}

function markRawInputEdited(kind) {
  if (appState.rawFiles[kind]) {
    appState.rawFiles[kind] = null;
    sourceElements(kind).source.textContent = "文本输入 · 自动补全 CRLF";
  }
  updateByteCount(kind);
}

function renderNegativeFiles() {
  elements.negativeList.replaceChildren();
  appState.negativeFiles.forEach((file, index) => {
    const row = document.createElement("div");
    row.className = "file-item";

    const name = document.createElement("span");
    name.className = "file-item-name";
    name.textContent = file.name;

    const size = document.createElement("span");
    size.className = "file-item-size";
    size.textContent = formatBytes(file.size);

    const remove = document.createElement("button");
    remove.className = "remove-file";
    remove.type = "button";
    remove.title = "移除文件";
    remove.setAttribute("aria-label", `移除 ${file.name}`);
    remove.dataset.removeFile = String(index);
    remove.innerHTML = '<i data-lucide="x" data-fallback="×"></i>';

    row.append(name, size, remove);
    elements.negativeList.append(row);
  });
  refreshIcons();
}

function addNegativeFiles(fileList) {
  const maxCount = appState.runtime?.limits?.negative_pcap_count || 4;
  const maxSize = appState.runtime?.limits?.negative_pcap_bytes || 16 * 1024 * 1024;
  for (const file of fileList) {
    if (appState.negativeFiles.length >= maxCount) {
      showToast(`最多添加 ${maxCount} 个反向 PCAP`, true);
      break;
    }
    if (file.size > maxSize) {
      showToast(`${file.name} 超过 ${formatBytes(maxSize)} 限制`, true);
      continue;
    }
    appState.negativeFiles.push(file);
  }
  elements.negativeFiles.value = "";
  renderNegativeFiles();
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return window.btoa(binary);
}

function clearPcapResult() {
  appState.pcapAnalysis = null;
  elements.pcapResultEmpty.hidden = false;
  elements.pcapAnalysisResult.hidden = true;
  elements.exportPcapAnalysis.hidden = true;
  elements.pcapSummaryGrid.replaceChildren();
  elements.pcapStreamList.replaceChildren();
}

function setPcapFile(file) {
  const limit = appState.runtime?.limits?.pcap_analysis_bytes || 16 * 1024 * 1024;
  if (!file) return;
  if (!/\.(?:pcap|pcapng)$/i.test(file.name)) {
    showToast("请选择 .pcap 或 .pcapng 文件", true);
    return;
  }
  if (file.size > limit) {
    showToast(`${file.name} 超过 ${formatBytes(limit)} 限制`, true);
    return;
  }
  appState.pcapFile = file;
  elements.pcapFileInput.value = "";
  elements.pcapFileName.textContent = file.name;
  elements.pcapFileMeta.textContent = `${formatBytes(file.size)} · ${
    file.name.toLowerCase().endsWith(".pcapng") ? "PCAPNG" : "PCAP"
  }`;
  elements.pcapDropzone.classList.add("has-file");
  elements.analyzePcap.disabled = false;
  elements.clearPcapFile.disabled = false;
  elements.pcapAnalysisStatus.textContent = "文件就绪";
  clearPcapResult();
}

function resetPcapAnalyzer() {
  appState.pcapFile = null;
  elements.pcapFileInput.value = "";
  elements.pcapFileName.textContent = "未选择文件";
  elements.pcapFileMeta.textContent = "PCAP / PCAPNG";
  elements.pcapDropzone.classList.remove("has-file", "is-dragging");
  elements.analyzePcap.disabled = true;
  elements.clearPcapFile.disabled = true;
  elements.pcapAnalysisStatus.textContent = "等待文件";
  clearPcapResult();
}

function formatCaptureDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1) return `${Math.round(value * 1000)} ms`;
  return `${value.toFixed(value < 10 ? 3 : 1)} s`;
}

function pcapCloseLabel(stream) {
  if (stream.bidirectional_fin) return "双向 FIN";
  if (stream.seen_rst) return "RST";
  const labels = {
    one_sided_fin: "单向 FIN",
    not_observed: "未观察到关闭",
  };
  return labels[stream.close_type] || stream.close_type || "—";
}

function renderPcapAnalysis(result) {
  appState.pcapAnalysis = result;
  const summary = result.summary || {};
  const streams = Array.isArray(result.streams) ? result.streams : [];
  elements.pcapResultEmpty.hidden = true;
  elements.pcapAnalysisResult.hidden = false;
  elements.exportPcapAnalysis.hidden = false;
  elements.pcapConnectionCount.textContent = String(result.connection_count ?? 0);
  elements.pcapAnalysisStatus.textContent = "分析完成";
  elements.pcapSummaryGrid.replaceChildren();
  [
    ["完整握手", summary.complete_handshakes],
    ["不完整 / 中途", summary.incomplete_or_midstream],
    ["TCP 包", summary.tcp_packets],
    ["双向 FIN", summary.bidirectional_fin_streams],
    ["RST", summary.reset_streams],
    ["抓包时长", formatCaptureDuration(summary.capture_duration_seconds)],
  ].forEach(([label, value]) => appendMetric(
    elements.pcapSummaryGrid,
    label,
    String(value ?? 0),
  ));

  elements.pcapStreamCount.textContent = `${streams.length} 条`;
  elements.pcapStreamList.replaceChildren();
  if (!streams.length) {
    const empty = document.createElement("div");
    empty.className = "pcap-stream-empty";
    empty.textContent = "未发现 TCP 连接";
    elements.pcapStreamList.append(empty);
    refreshIcons();
    return;
  }

  const header = document.createElement("div");
  header.className = "pcap-stream-row pcap-stream-row--header";
  ["ID", "端点", "包", "载荷", "握手", "关闭"].forEach((label) => {
    const cell = document.createElement("span");
    cell.textContent = label;
    header.append(cell);
  });
  elements.pcapStreamList.append(header);

  streams.forEach((stream) => {
    const row = document.createElement("div");
    row.className = "pcap-stream-row";
    const id = document.createElement("code");
    id.textContent = `#${stream.stream_id}`;
    const endpoints = document.createElement("div");
    endpoints.className = "pcap-stream-endpoints";
    const client = document.createElement("strong");
    client.textContent = stream.client || "unknown";
    const server = document.createElement("span");
    server.textContent = `→ ${stream.server || "unknown"}`;
    endpoints.append(client, server);
    const packets = document.createElement("span");
    packets.dataset.label = "包";
    packets.textContent = String(stream.packets ?? 0);
    const payload = document.createElement("span");
    payload.dataset.label = "载荷";
    payload.textContent = formatBytes(stream.payload_bytes || 0);
    const handshake = document.createElement("span");
    handshake.dataset.label = "握手";
    handshake.className = `pcap-stream-state ${
      stream.handshake_complete ? "is-complete" : "is-incomplete"
    }`;
    handshake.textContent = stream.handshake_complete ? "完整" : "不完整";
    const close = document.createElement("span");
    close.dataset.label = "关闭";
    close.textContent = pcapCloseLabel(stream);
    row.append(id, endpoints, packets, payload, handshake, close);
    elements.pcapStreamList.append(row);
  });
  refreshIcons();
}

async function analyzeSelectedPcap() {
  const file = appState.pcapFile;
  if (!file) return;
  elements.analyzePcap.disabled = true;
  elements.clearPcapFile.disabled = true;
  elements.analyzePcapLabel.textContent = "正在分析";
  elements.pcapAnalysisStatus.textContent = "正在分析";
  try {
    const result = await apiFetch("/api/pcap/analyze", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        content_base64: arrayBufferToBase64(await file.arrayBuffer()),
      }),
    });
    renderPcapAnalysis(result);
    showToast(`发现 ${result.connection_count} 个 TCP 连接`);
  } catch (error) {
    clearPcapResult();
    elements.pcapAnalysisStatus.textContent = "分析失败";
    showToast(error.message, true);
  } finally {
    elements.analyzePcap.disabled = false;
    elements.clearPcapFile.disabled = false;
    elements.analyzePcapLabel.textContent = "分析 TCP 连接";
  }
}

function exportPcapAnalysis() {
  if (!appState.pcapAnalysis) return;
  const blob = new Blob(
    [JSON.stringify(appState.pcapAnalysis, null, 2)],
    { type: "application/json" },
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const sourceName = appState.pcapAnalysis.file?.name || "capture.pcap";
  link.href = url;
  link.download = `${sourceName.replace(/\.(?:pcap|pcapng)$/i, "")}-tcp-analysis.json`;
  link.click();
  URL.revokeObjectURL(url);
}

async function encodedHttpInput(kind) {
  const controls = sourceElements(kind);
  const file = appState.rawFiles[kind];
  if (!file) {
    return {
      encoding: "utf8",
      content: controls.textarea.value,
    };
  }
  return {
    encoding: "base64",
    content: arrayBufferToBase64(await file.arrayBuffer()),
    filename: file.name,
  };
}

async function encodedPythonPoc() {
  if (!appState.pythonPocFile) {
    return {
      encoding: "utf8",
      content: elements.pythonPoc.value,
      filename: "poc.py",
    };
  }
  return {
    encoding: "base64",
    content: arrayBufferToBase64(await appState.pythonPocFile.arrayBuffer()),
    filename: appState.pythonPocFile.name,
  };
}

function clearPocExtraction() {
  appState.pocExtraction = null;
  elements.extractionStatus.textContent = "尚未提取";
  elements.extractionMeta.textContent = "AST static analysis";
  elements.extractedHttpRequest.value = "";
}

async function importPythonPoc(file) {
  const limit = appState.runtime?.limits?.python_poc_bytes || 1024 * 1024;
  if (file.size > limit) {
    showToast(`Python PoC 超过 ${formatBytes(limit)} 限制`, true);
    return;
  }
  appState.pythonPocFile = file;
  elements.pythonPoc.value = new TextDecoder("utf-8", { fatal: false }).decode(
    await file.arrayBuffer(),
  );
  elements.pythonPocSource.textContent = `${file.name} · 仅静态解析`;
  elements.pythonPocFile.value = "";
  clearPocExtraction();
}

async function extractPythonHttp() {
  if (!elements.pythonPoc.value.trim()) {
    showToast("Python PoC 不能为空", true);
    return;
  }
  elements.extractPythonPoc.disabled = true;
  elements.extractionStatus.textContent = "正在提取";
  try {
    const extraction = await apiFetch("/api/poc/extract", {
      method: "POST",
      body: JSON.stringify({ python_poc: await encodedPythonPoc() }),
    });
    appState.pocExtraction = extraction;
    elements.extractedHttpRequest.value = extraction.selected?.raw_request || "";
    elements.extractionStatus.textContent = extraction.accepted ? "提取完成" : "需要人工补全";
    elements.extractionMeta.textContent = `${extraction.candidate_count} 个候选 · confidence ${extraction.selected?.confidence ?? "—"}`;
  } catch (error) {
    clearPocExtraction();
    elements.extractionStatus.textContent = "提取失败";
    showToast(error.message, true);
  } finally {
    elements.extractPythonPoc.disabled = false;
  }
}

async function encodedNegativeFiles() {
  return Promise.all(
    appState.negativeFiles.map(async (file) => ({
      filename: file.name,
      content_base64: arrayBufferToBase64(await file.arrayBuffer()),
    })),
  );
}

function initialRunView(maxAttempts) {
  return {
    job_id: "pending",
    case_id: elements.caseId.value,
    input_mode: appState.evidenceMode,
    status: "queued",
    stage: "preflight",
    stage_label: "环境预检",
    attempt: 0,
    max_attempts: maxAttempts,
    failure: null,
    rules: null,
    validation: null,
    sample_matrix: [],
    pcap_analysis: null,
    mutation_skips: [],
    final_judgment: null,
    rule_ir: null,
    explanation: null,
    ruleops: null,
    poc_extraction: null,
    pipeline: "E-direct-repair-v1",
    attempts: [],
    progress: [
      { id: "preflight", status: "running", runs: 0 },
      { id: "prepare", status: "pending", runs: 0 },
      { id: "generate", status: "pending", runs: 0 },
      { id: "execute", status: "pending", runs: 0 },
      { id: "repair", status: "pending", runs: 0 },
      { id: "verify", status: "pending", runs: 0 },
      { id: "parse_ir", status: "pending", runs: 0 },
      { id: "ruleops", status: "pending", runs: 0 },
      { id: "persist", status: "pending", runs: 0 },
    ],
    events: [],
    artifacts: [],
  };
}

async function submitRun(event) {
  event.preventDefault();
  if (!elements.form.reportValidity()) return;
  if (!appState.runtime?.suricata?.ok || !appState.runtime?.model?.configured) {
    showToast("运行环境尚未就绪", true);
    return;
  }

  const maxAttempts = Number(elements.maxAttempts.value);
  appState.previousRunStatus = appState.currentRun?.status || null;
  appState.currentRun = initialRunView(maxAttempts);
  renderRun(appState.currentRun);
  updateRunButton();

  try {
    const [httpRequest, httpResponse, pythonPoc, negativePcaps] = await Promise.all([
      appState.evidenceMode === "python_poc"
        ? Promise.resolve({
            encoding: "utf8",
            content: elements.extractedHttpRequest.value,
          })
        : encodedHttpInput("request"),
      encodedHttpInput("response"),
      appState.evidenceMode === "python_poc"
        ? encodedPythonPoc()
        : Promise.resolve(null),
      encodedNegativeFiles(),
    ]);
    const payload = {
      case_id: elements.caseId.value.trim(),
      base: elements.base.value,
      poc: elements.poc.value,
      input_mode: appState.evidenceMode,
      http_request: httpRequest,
      http_response: httpResponse,
      python_poc: pythonPoc,
      negative_pcaps: negativePcaps,
      options: {
        sid_start: Number(elements.sidStart.value),
        max_attempts: maxAttempts,
      },
    };
    const created = await apiFetch("/api/runs", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    window.sessionStorage.setItem("suricata-rule-lab-run", created.job_id);
    startPolling(created.job_id);
  } catch (error) {
    appState.currentRun = {
      ...appState.currentRun,
      status: "failed",
      stage: "done",
      failure: { code: "REQUEST_ERROR", message: error.message },
    };
    renderRun(appState.currentRun);
    showToast(error.message, true);
  }
}

function statusClass(status) {
  return ["queued", "running", "passed", "failed"].includes(status)
    ? `status-${status}`
    : "status-idle";
}

function renderProgress(progress = []) {
  const byStage = new Map(progress.map((item) => [item.id, item]));
  elements.progressTrack.querySelectorAll("li").forEach((step) => {
    const item = byStage.get(step.dataset.stage);
    step.classList.remove(
      "is-pending",
      "is-running",
      "is-done",
      "is-failed",
      "is-retrying",
    );
    step.classList.add(`is-${item?.status || "pending"}`);
    const label = step.querySelector(".step-label");
    const baseLabel = item?.label || label.textContent.replace(/ · \d+$/, "");
    label.textContent = item?.runs > 1 ? `${baseLabel} · ${item.runs}` : baseLabel;
  });
}

function joinSids(values) {
  return Array.isArray(values) && values.length ? values.join(", ") : "—";
}

function renderRules(job) {
  const rules = job.rules || "";
  elements.ruleOutput.querySelector("code").textContent = rules || "等待候选编译…";
  elements.copyRules.disabled = !rules;
  const rulesArtifact = (job.artifacts || []).find((item) => item.kind === "rules");
  if (rulesArtifact) {
    elements.downloadRules.href = rulesArtifact.download_url;
    elements.downloadRules.classList.remove("is-disabled");
  } else {
    elements.downloadRules.removeAttribute("href");
    elements.downloadRules.classList.add("is-disabled");
  }

  if (job.status === "passed") {
    elements.ruleMeta.textContent = `已验证规则 · 第 ${job.attempt} 次尝试`;
  } else if (job.status === "failed" && rules) {
    elements.ruleMeta.textContent = `未通过的最后候选 · 第 ${job.attempt} 次尝试`;
  } else if (rules) {
    elements.ruleMeta.textContent = `候选规则 · 第 ${job.attempt} 次尝试`;
  } else {
    elements.ruleMeta.textContent = "等待候选规则";
  }
}

function validationStageState(validation, stage) {
  if (!validation) return "pending";
  if (validation.failed_stage === stage) return "failed";
  if ((validation.completed_stages || []).includes(stage)) return "done";
  return "pending";
}

function validationStageDetail(validation, stage) {
  if (!validation) return "尚未执行";
  const details = {
    static: "项目规则策略",
    syntax:
      validation.syntax_ok === true
        ? "规则加载成功"
        : validation.syntax_ok === false
          ? "规则加载失败"
          : "尚未执行",
    positive:
      validation.positive_match_ok === true
        ? "正向流量命中"
        : validation.positive_match_ok === false
          ? "正向流量未按预期命中"
          : "尚未执行",
    negative:
      validation.negative_match_ok === true
        ? "反向流量无误报"
        : validation.negative_match_ok === false
          ? "反向流量产生告警"
          : "未提供或尚未执行",
  };
  return details[stage];
}

function appendMetric(container, label, value, className = "") {
  const item = document.createElement("div");
  item.className = `result-metric${className ? ` ${className}` : ""}`;
  const title = document.createElement("span");
  title.textContent = label;
  const content = document.createElement("strong");
  content.textContent = value;
  item.append(title, content);
  container.append(item);
}

function renderValidation(validation) {
  const stages = [
    ["static", "静态策略"],
    ["syntax", "语法加载"],
    ["positive", "正向回放"],
    ["negative", "反向回放"],
  ];
  elements.validationStages.replaceChildren();
  stages.forEach(([id, label]) => {
    const state = validationStageState(validation, id);
    const row = document.createElement("div");
    row.className = "validation-row";

    const name = document.createElement("span");
    name.className = "validation-name";
    name.textContent = label;

    const detail = document.createElement("span");
    detail.className = "validation-detail";
    detail.textContent = validationStageDetail(validation, id);

    const badge = document.createElement("span");
    badge.className = `validation-badge is-${state}`;
    badge.textContent =
      state === "done" ? "通过" : state === "failed" ? "失败" : "等待";
    row.append(name, detail, badge);
    elements.validationStages.append(row);
  });

  const sampleResults = validation?.sample_results || [];
  const passedSamples = sampleResults.filter((item) => item.passed === true).length;
  const qualityWarnings = validation?.quality_warnings || [];
  const falsePositiveCount = finiteNumber(validation?.false_positive_count);
  elements.validationMetrics.replaceChildren();
  appendMetric(
    elements.validationMetrics,
    "样本通过",
    sampleResults.length ? `${passedSamples} / ${sampleResults.length}` : "—",
  );
  appendMetric(
    elements.validationMetrics,
    "正向覆盖率",
    formatPercent(validation?.positive_coverage),
    validation?.positive_coverage === 1 ? "is-good" : "",
  );
  appendMetric(
    elements.validationMetrics,
    "误报样本",
    falsePositiveCount === null ? "—" : String(falsePositiveCount),
    falsePositiveCount === null ? "" : falsePositiveCount === 0 ? "is-good" : "is-warning",
  );
  appendMetric(
    elements.validationMetrics,
    "质量告警",
    String(qualityWarnings.length),
    qualityWarnings.length ? "is-warning" : "is-good",
  );

  const sidValues = [
    ["预期 SID", validation?.expected_sids],
    ["正向命中", validation?.positive_matched_sids],
    ["反向命中", validation?.negative_matched_sids],
  ];
  elements.sidSection.replaceChildren();
  sidValues.forEach(([label, values]) => {
    const item = document.createElement("div");
    item.className = "sid-item";
    const title = document.createElement("span");
    title.textContent = label;
    const code = document.createElement("code");
    code.textContent = joinSids(values);
    item.append(title, code);
    elements.sidSection.append(item);
  });

  elements.validationMessages.replaceChildren();
  const messages = [
    ...(validation?.errors || []).map((message) => ({ message, error: true })),
    ...(validation?.warnings || []).map((message) => ({ message, error: false })),
    ...qualityWarnings.map((message) => ({ message, error: false, quality: true })),
  ];
  const seenMessages = new Set();
  messages.forEach(({ message, error, quality }) => {
    const text = displayValue(message);
    if (!text || seenMessages.has(text)) return;
    seenMessages.add(text);
    const item = document.createElement("div");
    item.className = `validation-message${error ? " is-error" : ""}${
      quality ? " is-quality" : ""
    }`;
    item.textContent = text;
    elements.validationMessages.append(item);
  });

  const commandOutput = validation?.command_output || "";
  elements.commandDetails.hidden = !commandOutput;
  elements.commandOutput.textContent = commandOutput;
}

function expectedLabel(expected) {
  if (expected === "alert" || expected === true) return "应告警";
  if (expected === "no_alert" || expected === false) return "应静默";
  return displayValue(expected) || "待定";
}

function sourceLabel(source) {
  const labels = {
    original: "原始流量",
    generated: "自动构造",
    derived: "自动构造",
    auto: "自动构造",
    uploaded: "用户上传",
    user: "用户上传",
  };
  return labels[source] || displayValue(source) || "未标注来源";
}

function mergeSampleResults(job) {
  const samples = Array.isArray(job.sample_matrix) ? job.sample_matrix : [];
  const results = Array.isArray(job.validation?.sample_results)
    ? job.validation.sample_results
    : [];
  const resultsByName = new Map(results.map((item) => [item.name, item]));
  const merged = samples.map((sample) => ({
    ...sample,
    ...(resultsByName.get(sample.name) || {}),
  }));
  const sampleNames = new Set(samples.map((item) => item.name));
  results.forEach((result) => {
    if (!sampleNames.has(result.name)) merged.push(result);
  });
  return merged;
}

function renderSampleMatrix(job) {
  const samples = mergeSampleResults(job);
  const validation = job.validation || {};
  const pcapSummary = job.pcap_analysis?.summary || {};
  const falsePositiveCount = finiteNumber(validation.false_positive_count);
  const positiveCount = samples.filter((item) => item.expected === "alert").length;
  const negativeCount = samples.filter((item) => item.expected === "no_alert").length;
  const passedCount = samples.filter((item) => item.passed === true).length;

  elements.matrixOverview.replaceChildren();
  appendMetric(elements.matrixOverview, "全部样本", String(samples.length));
  appendMetric(elements.matrixOverview, "正向", String(positiveCount));
  appendMetric(elements.matrixOverview, "反向", String(negativeCount));
  appendMetric(
    elements.matrixOverview,
    "验证通过",
    samples.length ? `${passedCount} / ${samples.length}` : "—",
    samples.length && passedCount === samples.length ? "is-good" : "",
  );
  appendMetric(
    elements.matrixOverview,
    "正向覆盖",
    formatPercent(validation.positive_coverage),
    validation.positive_coverage === 1 ? "is-good" : "",
  );
  appendMetric(
    elements.matrixOverview,
    "误报",
    falsePositiveCount === null ? "—" : String(falsePositiveCount),
    falsePositiveCount === null ? "" : falsePositiveCount === 0 ? "is-good" : "is-warning",
  );
  appendMetric(
    elements.matrixOverview,
    "PCAP 数量",
    String(pcapSummary.pcap_count ?? samples.length),
  );
  appendMetric(
    elements.matrixOverview,
    "TCP 连接",
    String(pcapSummary.tcp_connections ?? 0),
  );
  appendMetric(
    elements.matrixOverview,
    "多连接 PCAP",
    String(pcapSummary.multi_connection_pcaps ?? 0),
    Number(pcapSummary.multi_connection_pcaps || 0) > 0 ? "is-warning" : "",
  );
  appendMetric(
    elements.matrixOverview,
    "分析失败",
    String(pcapSummary.failed_pcaps ?? 0),
    Number(pcapSummary.failed_pcaps || 0) > 0 ? "is-warning" : "is-good",
  );

  const mutationSkips = Array.isArray(job.mutation_skips) ? job.mutation_skips : [];
  elements.mutationSkips.replaceChildren();
  elements.mutationSkips.hidden = mutationSkips.length === 0;
  if (mutationSkips.length) {
    const title = document.createElement("strong");
    title.textContent = `${mutationSkips.length} 项正文变体未生成`;
    elements.mutationSkips.append(title);
    mutationSkips.forEach((skip) => {
      const row = document.createElement("div");
      const code = document.createElement("code");
      code.textContent = skip.code || "MUTATION_SKIPPED";
      const detail = document.createElement("span");
      detail.textContent = `${skip.content_type || "unknown"} · ${
        skip.detail || "未提供原因"
      }`;
      row.append(code, detail);
      elements.mutationSkips.append(row);
    });
  }

  elements.sampleMatrix.replaceChildren();
  if (!samples.length) {
    appendEmptyState(elements.sampleMatrix, "样本矩阵尚未生成");
    return;
  }

  const header = document.createElement("div");
  header.className = "matrix-row matrix-row--header";
  ["样本", "预期", "TCP 连接", "实际", "结果"].forEach((label) => {
    const cell = document.createElement("span");
    cell.textContent = label;
    header.append(cell);
  });
  elements.sampleMatrix.append(header);

  samples.forEach((sample, index) => {
    const row = document.createElement("div");
    row.className = `matrix-row${
      sample.passed === true
        ? " is-passed"
        : sample.passed === false
          ? " is-failed"
          : ""
    }`;

    const identity = document.createElement("div");
    identity.className = "sample-identity";
    const name = document.createElement("strong");
    name.textContent = sample.name || `样本 ${index + 1}`;
    const meta = document.createElement("span");
    meta.className = "sample-source";
    const splitLabel = sample.split === "repair" ? "Repair 可见" : sample.split === "verify_only" ? "Verify only" : "";
    meta.textContent = [sourceLabel(sample.source), splitLabel].filter(Boolean).join(" · ");
    const requestLine = document.createElement("code");
    requestLine.className = "sample-request-line";
    requestLine.textContent = sample.request_line || "无请求行";
    requestLine.title = requestLine.textContent;
    identity.append(name, meta, requestLine);
    if (sample.reason) {
      const reason = document.createElement("span");
      reason.className = "sample-reason";
      reason.textContent = displayValue(sample.reason);
      reason.title = reason.textContent;
      identity.append(reason);
    }

    const expected = document.createElement("span");
    expected.className = `matrix-badge ${
      sample.expected === "alert"
        ? "is-alert"
        : sample.expected === "no_alert"
          ? "is-silent"
          : "is-pending"
    }`;
    expected.textContent = expectedLabel(sample.expected);

    const tcp = document.createElement("div");
    tcp.className = `sample-tcp${sample.tcp?.analysis_ok === false ? " is-error" : ""}`;
    const connectionCount = sample.tcp?.connection_count;
    const tcpCount = document.createElement("strong");
    tcpCount.textContent =
      Number.isFinite(Number(connectionCount)) && connectionCount !== null
        ? `${connectionCount} 个`
        : "分析失败";
    const tcpDetail = document.createElement("span");
    if (connectionCount === null || connectionCount === undefined) {
      tcpDetail.textContent = sample.tcp?.error || "暂无统计";
      tcp.title = tcpDetail.textContent;
    } else {
      tcpDetail.textContent = `握手 ${sample.tcp.complete_handshakes || 0} · FIN ${
        sample.tcp.bidirectional_fin_streams || 0
      } · RST ${sample.tcp.reset_streams || 0}`;
    }
    tcp.append(tcpCount, tcpDetail);

    const actual = document.createElement("span");
    actual.className = "sample-actual";
    const matchedSids = Array.isArray(sample.matched_sids) ? sample.matched_sids : [];
    actual.textContent = matchedSids.length
      ? `命中 SID ${matchedSids.join(", ")}`
      : sample.passed === undefined || sample.passed === null
        ? "等待回放"
        : "未命中";

    const passed = document.createElement("span");
    passed.className = `matrix-badge ${
      sample.passed === true
        ? "is-pass"
        : sample.passed === false
          ? "is-fail"
          : "is-pending"
    }`;
    passed.textContent =
      sample.passed === true ? "通过" : sample.passed === false ? "失败" : "等待";

    row.append(identity, expected, tcp, actual, passed);
    elements.sampleMatrix.append(row);
  });
}

function candidateIndex(candidate) {
  if (!candidate || typeof candidate !== "object") return null;
  return candidate.candidate_index ?? candidate.index ?? null;
}

function candidateIsSupplemental(candidate) {
  if (!candidate || typeof candidate !== "object") return false;
  return candidate.selection_tier === "supplemental" ||
    supplementalCandidateScopes.has(candidate.detection_scope);
}

function candidateIsSelected(candidate, selectedCandidate) {
  if (candidateIsSupplemental(candidate)) return false;
  if (
    selectedCandidate &&
    typeof selectedCandidate === "object" &&
    candidateIsSupplemental(selectedCandidate)
  ) {
    return false;
  }
  const selected =
    selectedCandidate && typeof selectedCandidate === "object"
      ? candidateIndex(selectedCandidate)
      : selectedCandidate;
  const index = candidateIndex(candidate);
  return index !== null && index !== undefined &&
    selected !== null && selected !== undefined &&
    String(index) === String(selected);
}

function candidateScore(score) {
  const number = finiteNumber(score);
  if (number === null) return "—";
  return Number.isInteger(number) ? String(number) : number.toFixed(1);
}

function candidateRoleLabel(candidate) {
  const role = candidate.role ?? candidate.plan?.role;
  return {
    precision: "Precision",
    robust: "Robust",
    alternative_evidence: "Alternative Evidence",
  }[role] ?? "";
}

function candidateEvidenceSummary(candidate) {
  const evidence = candidate.rule_ir?.evidence;
  if (!evidence || typeof evidence !== "object") return "—";
  return ["endpoint", "parameter", "exploit", "success"]
    .filter((key) => Array.isArray(evidence[key]) && evidence[key].length)
    .join(" + ") || "—";
}

function candidateEvidenceValues(candidate, key) {
  const values = candidate.rule_ir?.evidence?.[key];
  if (!Array.isArray(values) || !values.length) return "无";
  return values.map((value) => String(value)).join("\n");
}

function candidateScopeLabel(scope) {
  return candidateScopeLabels[scope] || scope || "—";
}

function candidateNovelEvidence(candidate) {
  const values = Array.isArray(candidate.novel_evidence)
    ? candidate.novel_evidence
    : [];
  if (!values.length) return "无独有证据";
  return values
    .map((item) => {
      const value = String(item.value || "").replace(/^(?:literal|regex):/, "");
      return `${item.buffer || "unknown"} = ${value}`;
    })
    .join("\n");
}

function appendCandidateEvidenceRow(container, labelText, valueText, className = "") {
  const term = document.createElement("dt");
  term.textContent = labelText;
  const value = document.createElement("dd");
  value.textContent = valueText || "—";
  if (className) value.className = className;
  if (valueText) value.title = valueText;
  container.append(term, value);
}

function candidateSidSummary(candidate, selected) {
  const values = [];
  const supplemental = candidateIsSupplemental(candidate);
  if (candidate.delivered && candidate.final_sid != null) {
    values.push(
      `${supplemental ? "补充交付" : "主规则交付"} ${candidate.final_sid}`,
    );
  } else if (selected && candidate.final_sid != null) {
    values.push(`本轮编译 ${candidate.final_sid}`);
  }
  if (candidate.evaluation_sid != null) {
    values.push(`评测 ${candidate.evaluation_sid}`);
  }
  return values.join(" · ") || "—";
}

function renderCandidate(candidate, selectedCandidate, fallbackIndex) {
  const selected = candidateIsSelected(candidate, selectedCandidate);
  const supplemental = candidateIsSupplemental(candidate);
  const wrapper = document.createElement("article");
  wrapper.className = `candidate-item${selected ? " is-selected" : ""}${
    candidate.passed === true ? " is-passed" : candidate.passed === false ? " is-failed" : ""
  }`;

  const header = document.createElement("div");
  header.className = "candidate-header";
  const title = document.createElement("strong");
  const role = candidateRoleLabel(candidate);
  title.textContent = `候选 ${candidate.candidate_index ?? fallbackIndex + 1}${
    role ? ` · ${role}` : ""
  }`;
  const badges = document.createElement("div");
  badges.className = "candidate-badges";
  const scopeBadge = document.createElement("span");
  scopeBadge.className = `candidate-badge ${
    supplemental ? "is-supplemental" : "is-scope"
  }`;
  scopeBadge.textContent = candidateScopeLabel(candidate.detection_scope);
  badges.append(scopeBadge);
  if (selected) {
    const selectedBadge = document.createElement("span");
    selectedBadge.className = "candidate-badge is-selected";
    selectedBadge.textContent = candidate.delivered
      ? "最终主规则"
      : "本轮主候选";
    badges.append(selectedBadge);
  }
  if (supplemental && candidate.delivered) {
    const deliveredBadge = document.createElement("span");
    deliveredBadge.className = "candidate-badge is-delivered";
    deliveredBadge.textContent = "补充规则已交付";
    badges.append(deliveredBadge);
  }
  const score = document.createElement("span");
  score.className = "candidate-badge is-score";
  score.textContent = `参考值 ${candidateScore(candidate.score)}`;
  badges.append(score);
  if (candidate.passed !== undefined && candidate.passed !== null) {
    const passed = document.createElement("span");
    passed.className = `candidate-badge ${candidate.passed ? "is-pass" : "is-fail"}`;
    passed.textContent = candidate.passed
      ? "样本验证通过"
      : candidate.compile_error
        ? "质量检查未通过"
        : candidate.validation
          ? "样本门槛未通过"
          : "未参与验证";
    badges.append(passed);
  }
  header.append(title, badges);
  wrapper.append(header);

  if (candidate.reason) {
    const reason = document.createElement("p");
    reason.className = "candidate-reason";
    reason.textContent = displayValue(candidate.reason);
    wrapper.append(reason);
  }

  const evidence = document.createElement("dl");
  evidence.className = "candidate-evidence";
  appendCandidateEvidenceRow(
    evidence,
    "证据链",
    candidateEvidenceSummary(candidate),
  );
  appendCandidateEvidenceRow(
    evidence,
    "检测层级",
    candidateScopeLabel(candidate.detection_scope),
  );
  appendCandidateEvidenceRow(
    evidence,
    "漏洞身份",
    candidateEvidenceValues(candidate, "endpoint"),
    "is-multiline",
  );
  appendCandidateEvidenceRow(
    evidence,
    "参数上下文",
    candidateEvidenceValues(candidate, "parameter"),
    "is-multiline",
  );
  appendCandidateEvidenceRow(
    evidence,
    "利用证据",
    candidateEvidenceValues(candidate, "exploit"),
    "is-multiline",
  );
  appendCandidateEvidenceRow(
    evidence,
    "成功证据",
    candidateEvidenceValues(candidate, "success"),
    "is-multiline",
  );
  appendCandidateEvidenceRow(
    evidence,
    "独有证据",
    candidateNovelEvidence(candidate),
    "is-multiline",
  );
  appendCandidateEvidenceRow(
    evidence,
    "倾向",
    candidate.expected_tradeoff || "—",
  );
  appendCandidateEvidenceRow(
    evidence,
    "SID",
    candidateSidSummary(candidate, selected),
  );
  appendCandidateEvidenceRow(
    evidence,
    "Fingerprint",
    candidate.evidence_fingerprint_id || "—",
    "is-fingerprint",
  );
  wrapper.append(evidence);

  const validation = candidate.validation || {};
  const falsePositiveCount = finiteNumber(validation.false_positive_count);
  const facts = document.createElement("div");
  facts.className = "candidate-facts";
  const complexity = document.createElement("span");
  complexity.innerText = `复杂度\n${displayValue(candidate.complexity) || "—"}`;
  const coverage = document.createElement("span");
  coverage.innerText = `正向覆盖\n${formatPercent(validation.positive_coverage)}`;
  const falsePositives = document.createElement("span");
  falsePositives.innerText = `误报样本\n${
    falsePositiveCount === null ? "—" : falsePositiveCount
  }`;
  facts.append(complexity, coverage, falsePositives);
  wrapper.append(facts);

  if (candidate.compile_error) {
    const compileError = document.createElement("div");
    compileError.className = "candidate-error";
    compileError.textContent = displayValue(candidate.compile_error);
    wrapper.append(compileError);
  }

  const displaysSupplementalDelivery = supplemental &&
    candidate.delivered && candidate.supplemental_final_rule;
  const displaysPrimaryDelivery = selected &&
    candidate.delivered && candidate.final_rule;
  const displayedRule = displaysSupplementalDelivery
    ? candidate.supplemental_final_rule
    : displaysPrimaryDelivery
      ? candidate.final_rule
      : candidate.rule;
  if (displayedRule) {
    const ruleLabel = document.createElement("div");
    ruleLabel.className = "candidate-rule-label";
    ruleLabel.textContent = displaysSupplementalDelivery
      ? `补充交付规则 · SID ${candidate.final_sid ?? "—"}`
      : displaysPrimaryDelivery
        ? `主规则交付 · SID ${candidate.final_sid ?? "—"}`
        : `评测规则 · SID ${candidate.evaluation_sid ?? "—"}`;
    const rule = document.createElement("pre");
    rule.className = "candidate-rule";
    const code = document.createElement("code");
    code.textContent = displayedRule;
    rule.append(code);
    wrapper.append(ruleLabel, rule);
  }

  const validationMessages = [
    ...(validation.errors || []),
    ...(validation.quality_warnings || []),
  ].map((item) => displayValue(item)).filter(Boolean);
  if (validationMessages.length) {
    const details = document.createElement("details");
    details.className = "candidate-validation";
    const summary = document.createElement("summary");
    summary.textContent = `验证详情 · ${validationMessages.length} 条`;
    const output = document.createElement("pre");
    output.textContent = validationMessages.join("\n");
    details.append(summary, output);
    wrapper.append(details);
  }

  return wrapper;
}

function renderAttempts(attempts = []) {
  elements.attemptList.replaceChildren();
  if (!Array.isArray(attempts) || !attempts.length) {
    appendEmptyState(elements.attemptList, "尚无规则生成尝试");
    return;
  }

  attempts.forEach((attempt, index) => {
    const candidates = Array.isArray(attempt.candidates) ? attempt.candidates : [];
    const selectedPrimaryCandidate = candidates.find((candidate) =>
      candidateIsSelected(candidate, attempt.selected_candidate),
    );
    const details = document.createElement("details");
    details.className = "attempt-item";
    details.open = index === attempts.length - 1;

    const summary = document.createElement("summary");
    const identity = document.createElement("span");
    identity.className = "attempt-identity";
    const number = document.createElement("strong");
    number.textContent = `第 ${attempt.attempt ?? index + 1} 次尝试`;
    const outcome = document.createElement("span");
    outcome.className = `attempt-outcome${attempt.generation_error || attempt.error ? " is-failed" : ""}`;
    outcome.textContent = attempt.error
      ? "执行失败"
      : attempt.kind === "generate"
        ? "Direct generation"
        : attempt.kind === "repair"
          ? "Execution-guided repair"
      : attempt.generation_error
      ? "生成失败"
      : selectedPrimaryCandidate
        ? `选中候选 ${candidateIndex(selectedPrimaryCandidate) ?? "—"}`
        : attempt.selected_candidate !== null && attempt.selected_candidate !== undefined
          ? "未选出漏洞特异主规则"
        : "未选出规则";
    identity.append(number, outcome);

    const timing = document.createElement("span");
    timing.className = "attempt-timing";
    timing.textContent = `生成 ${formatDuration(attempt.generation_ms)} · 验证 ${formatDuration(
      attempt.validation_ms,
    )}`;
    summary.append(identity, timing);
    details.append(summary);

    const body = document.createElement("div");
    body.className = "attempt-body";
    if (attempt.generation_error) {
      const generationError = document.createElement("div");
      generationError.className = "candidate-error";
      generationError.textContent = displayValue(attempt.generation_error);
      body.append(generationError);
    }

    if (attempt.kind && attempt.selected_rule) {
      const directRule = document.createElement("pre");
      directRule.className = "candidate-rule";
      const code = document.createElement("code");
      code.textContent = attempt.selected_rule;
      directRule.append(code);
      body.append(directRule);
    }
    if (attempt.kind === "repair" && attempt.feedback) {
      const feedback = document.createElement("details");
      feedback.className = "candidate-validation";
      const summary = document.createElement("summary");
      summary.textContent = "查看本轮 runtime feedback";
      const output = document.createElement("pre");
      output.textContent = JSON.stringify(attempt.feedback, null, 2);
      feedback.append(summary, output);
      body.append(feedback);
    }

    const diagnosisText = displayValue(attempt.diagnosis);
    if (diagnosisText) {
      const diagnosis = document.createElement("section");
      diagnosis.className = "attempt-diagnosis";
      const title = document.createElement("strong");
      title.textContent = "失败诊断与修复建议";
      const content = document.createElement("pre");
      content.textContent = diagnosisText;
      diagnosis.append(title, content);
      body.append(diagnosis);
    }

    const strategyContext = Array.isArray(attempt.strategy_context)
      ? attempt.strategy_context
      : [];
    if (strategyContext.length) {
      const strategySummary = document.createElement("div");
      strategySummary.className = "strategy-context-summary";
      const labels = strategyContext.map((item) =>
        item.summary?.family ||
        (Array.isArray(item.family_labels) ? item.family_labels.join(" + ") : "") ||
        (Array.isArray(item.exploit_families) ? item.exploit_families.join(" + ") : "") ||
        item.cluster_id,
      );
      strategySummary.textContent = `检索历史策略 · ${labels.join(" · ")}`;
      body.append(strategySummary);
    }
    const judgment = attempt.final_judgment;
    if (judgment) {
      const graphSummary = document.createElement("div");
      graphSummary.className = "coverage-summary";
      const graphHeader = document.createElement("div");
      graphHeader.className = "coverage-summary-header";
      graphHeader.textContent = `Final Judge · 候选 ${judgment.selected_candidate ?? "—"}`;
      graphSummary.append(graphHeader);
      const reason = document.createElement("p");
      reason.className = "coverage-scope-note";
      reason.textContent = judgment.reason || "未提供判断理由";
      graphSummary.append(reason);
      const risks = Array.isArray(judgment.overfitting_risks)
        ? judgment.overfitting_risks
        : [];
      if (risks.length) {
        const riskText = document.createElement("p");
        riskText.className = "coverage-scope-note";
        riskText.textContent = `过拟合风险 · ${risks.join(" · ")}`;
        graphSummary.append(riskText);
      }
      body.append(graphSummary);
    }
    const candidateList = document.createElement("div");
    candidateList.className = "candidate-list";
    candidates.forEach((candidate, candidateIndex) => {
      candidateList.append(
        renderCandidate(candidate, attempt.selected_candidate, candidateIndex),
      );
    });
    if (!candidates.length && !attempt.generation_error && !attempt.kind) {
      appendEmptyState(candidateList, "本次尝试没有可验证候选");
    }
    body.append(candidateList);

    const ruleDiff = displayValue(attempt.rule_diff);
    if (ruleDiff) {
      const diff = document.createElement("details");
      diff.className = "rule-diff";
      const diffSummary = document.createElement("summary");
      diffSummary.textContent = "查看与上次规则的差异";
      const output = document.createElement("pre");
      output.textContent = ruleDiff;
      diff.append(diffSummary, output);
      body.append(diff);
    }

    details.append(body);
    elements.attemptList.append(details);
  });
}

function renderEvents(events = []) {
  elements.eventList.replaceChildren();
  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "validation-message";
    empty.textContent = "等待第一个工作流节点完成";
    elements.eventList.append(empty);
    return;
  }
  events.forEach((event) => {
    const row = document.createElement("div");
    row.className = `event-row is-${event.status}`;

    const marker = document.createElement("span");
    marker.className = "event-marker";
    const name = document.createElement("span");
    name.className = "event-name";
    name.textContent = event.label;
    const detail = document.createElement("span");
    detail.className = "event-detail";
    detail.textContent = `${eventStatusLabels[event.status] || event.status}${
      event.attempt ? ` · 尝试 ${event.attempt}` : ""
    }`;
    const time = document.createElement("time");
    time.className = "event-time";
    time.textContent = formatTime(event.time);
    row.append(marker, name, detail, time);
    elements.eventList.append(row);
  });
}

function renderArtifacts(artifacts = []) {
  elements.artifactBar.hidden = artifacts.length === 0;
  elements.artifactCount.textContent = `${artifacts.length} 个文件`;
  elements.artifactActions.replaceChildren();
  artifacts.forEach((artifact) => {
    const link = document.createElement("a");
    link.className = "artifact-link";
    link.href = artifact.download_url;
    link.title = `${artifact.name} · ${formatBytes(artifact.size)}`;
    link.innerHTML = '<i data-lucide="download" data-fallback="↓"></i>';
    const label = document.createElement("span");
    label.textContent = artifactLabels[artifact.kind] || artifact.name;
    link.append(label);
    elements.artifactActions.append(link);
  });
  refreshIcons();
}

function renderRun(job) {
  appState.currentRun = job;
  elements.emptyState.hidden = true;
  elements.resultContent.hidden = false;

  elements.resultStatus.className = `result-status ${statusClass(job.status)}`;
  elements.resultStatus.querySelector("span:last-child").textContent =
    statusLabels[job.status] || job.status;
  elements.inputState.textContent =
    job.job_id && job.job_id !== "pending"
      ? `RUN ${job.job_id.slice(0, 8).toUpperCase()}`
      : "正在提交";

  renderProgress(job.progress);
  elements.summaryStage.textContent = job.stage_label || job.stage || "—";
  elements.summaryAttempt.textContent = `${job.attempt || 0} / ${job.max_attempts}`;
  elements.summaryExpected.textContent = joinSids(job.validation?.expected_sids);
  elements.summaryMatched.textContent = joinSids(job.validation?.positive_matched_sids);
  renderRules(job);
  renderExplanation(job.explanation);
  renderValidation(job.validation);
  renderSampleMatrix(job);
  renderAttempts(job.attempts);
  renderEvents(job.events);
  renderRuleIR(job.rule_ir);
  renderPocExtraction(job.poc_extraction, job.input_mode);
  renderArtifacts(job.artifacts);

  elements.failureBanner.hidden = !job.failure;
  if (job.failure) {
    elements.failureCode.textContent = job.failure.code || "任务失败";
    elements.failureMessage.textContent = job.failure.message || "未提供错误详情";
  }

  const justFailed = appState.previousRunStatus !== "failed" && job.status === "failed";
  if (justFailed && job.explanation) switchResultTab("explanation");
  appState.previousRunStatus = job.status;
  updateRunButton();
}

async function pollRun(jobId) {
  try {
    const job = await apiFetch(`/api/runs/${jobId}`);
    renderRun(job);
    if (["queued", "running"].includes(job.status)) {
      appState.pollTimer = window.setTimeout(() => pollRun(jobId), 900);
    } else {
      await loadRecentRuns(jobId);
      await loadRuleOps();
      showToast(job.status === "passed" ? "规则已通过验证" : "规则未通过验证", job.status !== "passed");
    }
  } catch (error) {
    updateRunButton();
    showToast(error.message, true);
  }
}

function startPolling(jobId) {
  clearTimeout(appState.pollTimer);
  appState.pollTimer = null;
  pollRun(jobId);
}

async function loadRecentRuns(selectedId = null) {
  try {
    const data = await apiFetch("/api/runs");
    const selected = selectedId || appState.currentRun?.job_id || "";
    elements.recentRuns.replaceChildren();
    if (!data.runs.length) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "暂无任务";
      elements.recentRuns.append(empty);
      return;
    }
    data.runs.forEach((run) => {
      const option = document.createElement("option");
      option.value = run.job_id;
      option.textContent = `${run.case_id} · ${statusLabels[run.status] || run.status}`;
      option.selected = run.job_id === selected;
      elements.recentRuns.append(option);
    });
  } catch (error) {
    showToast(error.message, true);
  }
}

async function loadRun(jobId) {
  clearTimeout(appState.pollTimer);
  try {
    const job = await apiFetch(`/api/runs/${jobId}`);
    renderRun(job);
    window.sessionStorage.setItem("suricata-rule-lab-run", jobId);
    if (["queued", "running"].includes(job.status)) startPolling(jobId);
  } catch (error) {
    window.sessionStorage.removeItem("suricata-rule-lab-run");
    showToast(error.message, true);
  }
}

async function copyRules() {
  const rules = appState.currentRun?.rules;
  if (!rules) return;
  try {
    await navigator.clipboard.writeText(rules);
    showToast("规则已复制");
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = rules;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    showToast("规则已复制");
  }
}

function resetInputs() {
  elements.form.reset();
  elements.caseId.value = "demo-001";
  elements.sidStart.value = "123";
  elements.maxAttempts.value = "3";
  appState.rawFiles.request = null;
  appState.rawFiles.response = null;
  appState.pythonPocFile = null;
  appState.negativeFiles = [];
  elements.requestSource.textContent = "文本输入 · 自动补全 CRLF";
  elements.responseSource.textContent = "文本输入 · 自动补全 CRLF";
  elements.pythonPocSource.textContent = "文本输入 · 仅静态解析";
  clearPocExtraction();
  updateByteCount("request");
  updateByteCount("response");
  renderNegativeFiles();
  switchInputTab("request");
  switchEvidenceMode("http");
}

function bindEvents() {
  document.querySelectorAll("[data-workspace]").forEach((button) => {
    button.addEventListener("click", () => switchWorkspace(button.dataset.workspace));
  });
  elements.selectPcapFile.addEventListener("click", () => elements.pcapFileInput.click());
  elements.pcapFileInput.addEventListener("change", (event) => {
    if (event.target.files[0]) setPcapFile(event.target.files[0]);
  });
  elements.clearPcapFile.addEventListener("click", resetPcapAnalyzer);
  elements.analyzePcap.addEventListener("click", analyzeSelectedPcap);
  elements.exportPcapAnalysis.addEventListener("click", exportPcapAnalysis);
  ["dragenter", "dragover"].forEach((eventName) => {
    elements.pcapDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.pcapDropzone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    elements.pcapDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.pcapDropzone.classList.remove("is-dragging");
    });
  });
  elements.pcapDropzone.addEventListener("drop", (event) => {
    if (event.dataTransfer.files[0]) setPcapFile(event.dataTransfer.files[0]);
  });
  document.querySelectorAll("[data-input-tab]").forEach((button) => {
    button.addEventListener("click", () => switchInputTab(button.dataset.inputTab));
  });
  document.querySelectorAll("[data-evidence-mode]").forEach((button) => {
    button.addEventListener("click", () => switchEvidenceMode(button.dataset.evidenceMode));
  });
  document.querySelectorAll("[data-result-tab]").forEach((button) => {
    button.addEventListener("click", () => switchResultTab(button.dataset.resultTab));
  });
  document.querySelectorAll("[data-import]").forEach((button) => {
    button.addEventListener("click", () => sourceElements(button.dataset.import).input.click());
  });

  elements.requestFile.addEventListener("change", (event) => {
    if (event.target.files[0]) importRawFile("request", event.target.files[0]);
  });
  elements.responseFile.addEventListener("change", (event) => {
    if (event.target.files[0]) importRawFile("response", event.target.files[0]);
  });
  elements.importPythonPoc.addEventListener("click", () => elements.pythonPocFile.click());
  elements.pythonPocFile.addEventListener("change", (event) => {
    if (event.target.files[0]) importPythonPoc(event.target.files[0]);
  });
  elements.extractPythonPoc.addEventListener("click", extractPythonHttp);
  elements.pythonPoc.addEventListener("input", () => {
    if (appState.pythonPocFile) {
      appState.pythonPocFile = null;
      elements.pythonPocSource.textContent = "文本输入 · 仅静态解析";
    }
    clearPocExtraction();
  });
  elements.extractedHttpRequest.addEventListener("input", () => {
    if (appState.pocExtraction) {
      elements.extractionStatus.textContent = "已人工调整";
      elements.extractionMeta.textContent = "Raw HTTP override";
    }
  });
  elements.httpRequest.addEventListener("input", () => markRawInputEdited("request"));
  elements.httpResponse.addEventListener("input", () => markRawInputEdited("response"));
  elements.addNegative.addEventListener("click", () => elements.negativeFiles.click());
  elements.negativeFiles.addEventListener("change", (event) => addNegativeFiles(event.target.files));
  elements.negativeList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-file]");
    if (!button) return;
    appState.negativeFiles.splice(Number(button.dataset.removeFile), 1);
    renderNegativeFiles();
  });
  elements.form.addEventListener("submit", submitRun);
  elements.resetForm.addEventListener("click", resetInputs);
  elements.refreshRuntime.addEventListener("click", loadRuntime);
  elements.copyRules.addEventListener("click", copyRules);
  elements.recentRuns.addEventListener("change", (event) => {
    if (event.target.value) loadRun(event.target.value);
  });
  elements.ruleopsSearch.addEventListener("input", () => {
    clearTimeout(appState.ruleopsSearchTimer);
    appState.ruleopsSearchTimer = window.setTimeout(
      () => loadRuleOps(elements.ruleopsSearch.value.trim()),
      250,
    );
  });
}

async function initialize() {
  refreshIcons();
  bindEvents();
  updateByteCount("request");
  updateByteCount("response");
  await Promise.all([loadRuntime(), loadRecentRuns(), loadRuleOps()]);
  const storedRun = window.sessionStorage.getItem("suricata-rule-lab-run");
  if (storedRun) await loadRun(storedRun);
}

initialize();
