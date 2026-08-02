"use strict";

const elements = {
  form: document.getElementById("generationForm"),
  caseId: document.getElementById("caseId"),
  sidStart: document.getElementById("sidStart"),
  base: document.getElementById("base"),
  poc: document.getElementById("poc"),
  maxAttempts: document.getElementById("maxAttempts"),
  httpRequest: document.getElementById("httpRequest"),
  httpResponse: document.getElementById("httpResponse"),
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
  negativeFiles: [],
};

const statusLabels = {
  queued: "等待调度",
  running: "正在运行",
  passed: "验证通过",
  failed: "运行失败",
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
  mutations: "变体诊断",
  rule_ir: "Rule IR",
  supplemental_rule_ir: "补充 Rule IR",
  coverage: "Coverage Graph",
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
      problems.push("未设置 DEEPSEEK_API_KEY，设置后请重启 Web 服务");
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
    status: "queued",
    stage: "preflight",
    stage_label: "环境预检",
    attempt: 0,
    max_attempts: maxAttempts,
    failure: null,
    rules: null,
    validation: null,
    sample_matrix: [],
    mutation_skips: [],
    coverage_graph: null,
    rule_ir: null,
    attempts: [],
    progress: [
      { id: "preflight", status: "running", runs: 0 },
      { id: "build_samples", status: "pending", runs: 0 },
      { id: "extract_features", status: "pending", runs: 0 },
      { id: "evaluate_candidates", status: "pending", runs: 0 },
      { id: "diagnose_failure", status: "pending", runs: 0 },
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
    const [httpRequest, httpResponse, negativePcaps] = await Promise.all([
      encodedHttpInput("request"),
      encodedHttpInput("response"),
      encodedNegativeFiles(),
    ]);
    const payload = {
      case_id: elements.caseId.value.trim(),
      base: elements.base.value,
      poc: elements.poc.value,
      http_request: httpRequest,
      http_response: httpResponse,
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
  ["样本", "预期", "实际", "结果"].forEach((label) => {
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
    meta.textContent = sourceLabel(sample.source);
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

    row.append(identity, expected, actual, passed);
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
  if (
    candidate.coverage_sid != null &&
    candidate.coverage_sid !== candidate.evaluation_sid
  ) {
    values.push(`图 ${candidate.coverage_sid}`);
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
  score.textContent = `评分 ${candidateScore(candidate.score)}`;
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
    outcome.className = `attempt-outcome${attempt.generation_error ? " is-failed" : ""}`;
    outcome.textContent = attempt.generation_error
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
    const graph = attempt.coverage_graph;
    if (graph) {
      const graphSummary = document.createElement("div");
      graphSummary.className = "coverage-summary";
      if (graph.error_code) {
        graphSummary.classList.add("is-error");
        graphSummary.textContent = `Coverage Graph 失败 · ${graph.error_code} · ${graph.error || "未提供原因"}`;
      } else {
        const relationValues = Array.isArray(graph.relations) ? graph.relations : [];
        const duplicateCount = relationValues.filter((item) =>
          ["text_duplicate", "logic_duplicate", "coverage_duplicate"].includes(item.kind),
        ).length;
        const dominanceCount = relationValues.filter(
          (item) => item.kind === "dominates",
        ).length;
        const recommended = Array.isArray(graph.recommended_sids)
          ? graph.recommended_sids.join(", ") || "无"
          : "—";
        const recommendedByScope = graph.recommended_by_scope || {};
        const hasScopedRecommendations = recommendedByScope &&
          typeof recommendedByScope === "object" &&
          Object.keys(candidateScopeLabels).some((scope) =>
            Array.isArray(recommendedByScope[scope]),
          );
        const sidNamespace = graph.sid_namespace === "delivery_mapped"
          ? "交付映射 SID"
          : graph.sid_namespace === "delivery"
            ? "交付 SID"
            : "评测 SID";

        const graphHeader = document.createElement("div");
        graphHeader.className = "coverage-summary-header";
        graphHeader.textContent = `Coverage Graph · ${sidNamespace} · 重复 ${duplicateCount} · 经验覆盖 ${dominanceCount}`;
        graphSummary.append(graphHeader);

        const scopeGroups = document.createElement("div");
        scopeGroups.className = "coverage-scope-groups";
        if (hasScopedRecommendations) {
          Object.entries(candidateScopeLabels).forEach(([scope, label]) => {
            const values = Array.isArray(recommendedByScope[scope])
              ? recommendedByScope[scope]
              : [];
            const row = document.createElement("div");
            row.className = "coverage-scope-row";
            const scopeLabel = document.createElement("span");
            scopeLabel.textContent = label;
            const sids = document.createElement("code");
            sids.textContent = values.length ? `SID ${values.join(", ")}` : "无";
            row.append(scopeLabel, sids);
            scopeGroups.append(row);
          });
        } else {
          const row = document.createElement("div");
          row.className = "coverage-scope-row";
          const scopeLabel = document.createElement("span");
          scopeLabel.textContent = "推荐规则";
          const sids = document.createElement("code");
          sids.textContent = ["—", "无"].includes(recommended)
            ? recommended
            : `SID ${recommended}`;
          row.append(scopeLabel, sids);
          scopeGroups.append(row);
        }
        graphSummary.append(scopeGroups);

        const comparisonNote = document.createElement("p");
        comparisonNote.className = "coverage-scope-note";
        comparisonNote.textContent = "关系仅在同方向 + 同检测层级内比较";
        graphSummary.append(comparisonNote);
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
    if (!candidates.length && !attempt.generation_error) {
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
  renderValidation(job.validation);
  renderSampleMatrix(job);
  renderAttempts(job.attempts);
  renderEvents(job.events);
  renderArtifacts(job.artifacts);

  elements.failureBanner.hidden = !job.failure;
  if (job.failure) {
    elements.failureCode.textContent = job.failure.code || "任务失败";
    elements.failureMessage.textContent = job.failure.message || "未提供错误详情";
  }

  const justFailed = appState.previousRunStatus !== "failed" && job.status === "failed";
  if (justFailed && job.validation) switchResultTab("validation");
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
      showToast(job.status === "passed" ? "规则已通过验证" : "任务运行失败", job.status !== "passed");
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
  appState.negativeFiles = [];
  elements.requestSource.textContent = "文本输入 · 自动补全 CRLF";
  elements.responseSource.textContent = "文本输入 · 自动补全 CRLF";
  updateByteCount("request");
  updateByteCount("response");
  renderNegativeFiles();
  switchInputTab("request");
}

function bindEvents() {
  document.querySelectorAll("[data-input-tab]").forEach((button) => {
    button.addEventListener("click", () => switchInputTab(button.dataset.inputTab));
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
}

async function initialize() {
  refreshIcons();
  bindEvents();
  updateByteCount("request");
  updateByteCount("response");
  await Promise.all([loadRuntime(), loadRecentRuns()]);
  const storedRun = window.sessionStorage.getItem("suricata-rule-lab-run");
  if (storedRun) await loadRun(storedRun);
}

initialize();
