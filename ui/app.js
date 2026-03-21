const byId = (id) => document.getElementById(id);

const els = {
  apiKey: byId("apiKey"),
  clientId: byId("clientId"),
  demoContent: byId("demoContent"),
  fileInput: byId("fileInput"),
  fileMeta: byId("fileMeta"),
  refreshDashboard: byId("refreshDashboard"),
  startNewSession: byId("startNewSession"),
  stepUploadOriginal: byId("stepUploadOriginal"),
  stepTriggerPow: byId("stepTriggerPow"),
  stepSolveAndRetry: byId("stepSolveAndRetry"),
  healthValue: byId("healthValue"),
  healthMeta: byId("healthMeta"),
  encryptionValue: byId("encryptionValue"),
  encryptionMeta: byId("encryptionMeta"),
  storageValue: byId("storageValue"),
  storageMeta: byId("storageMeta"),
  activeFilesValue: byId("activeFilesValue"),
  uniqueChunksValue: byId("uniqueChunksValue"),
  dedupSavedValue: byId("dedupSavedValue"),
  dedupSavedMeta: byId("dedupSavedMeta"),
  powValue: byId("powValue"),
  powMeta: byId("powMeta"),
  monitoringValue: byId("monitoringValue"),
  monitoringMeta: byId("monitoringMeta"),
  step1Output: byId("step1Output"),
  step2Output: byId("step2Output"),
  step3Output: byId("step3Output"),
  challengeOutput: byId("challengeOutput"),
  metricsOutput: byId("metricsOutput"),
  statusOutput: byId("statusOutput"),
  eventOutput: byId("eventOutput"),
};

const state = {
  selectedFile: null,
  lastChallenges: [],
  lastProofs: null,
  sessionId: "",
};

function pretty(payload) {
  if (payload === undefined || payload === null) {
    return "No data";
  }
  if (typeof payload === "string") {
    return payload;
  }
  try {
    return JSON.stringify(payload, null, 2);
  } catch (error) {
    return String(payload);
  }
}

function prependLog(label, payload) {
  const stamp = new Date().toLocaleTimeString();
  const block = `[${stamp}] ${label}\n${pretty(payload)}\n\n`;
  els.eventOutput.textContent = block + els.eventOutput.textContent;
}

function apiKey() {
  return (els.apiKey.value || "").trim();
}

function clientId() {
  return (els.clientId.value || "").trim();
}

function makeSessionId() {
  return `reviewer-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function defaultDemoContent(sessionId) {
  return [
    "Secure dedup reviewer demo payload",
    `session: ${sessionId}`,
    `generated_at: ${new Date().toISOString()}`,
  ].join("\n");
}

function usingAutoPayload() {
  return !state.selectedFile;
}

function resetOutputs() {
  els.step1Output.textContent = "Ready.";
  els.step2Output.textContent = "No duplicate attempt yet.";
  els.step3Output.textContent = "No solve attempt yet.";
  els.challengeOutput.textContent = "No challenge returned yet.";
}

function startNewSession({ refresh = true } = {}) {
  state.sessionId = makeSessionId();
  state.lastChallenges = [];
  state.lastProofs = null;
  els.clientId.value = state.sessionId;
  if (!state.selectedFile) {
    els.demoContent.value = defaultDemoContent(state.sessionId);
  }
  resetOutputs();
  prependLog("New reviewer session", {
    client_id: state.sessionId,
  });
  if (refresh) {
    refreshDashboard();
  }
}

function defaultHeaders(withClientId = true) {
  const headers = {};
  if (apiKey()) {
    headers["X-API-Key"] = apiKey();
  }
  if (withClientId) {
    headers["X-Client-ID"] = clientId();
  }
  return headers;
}

async function readBody(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function fetchJson(path, options = {}) {
  try {
    const response = await fetch(path, options);
    const body = await readBody(response);
    return {
      ok: response.ok,
      status: response.status,
      body,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      body: {
        error: "Network error",
        detail: String(error),
      },
    };
  }
}

async function fetchJsonWithTimeout(path, options = {}, timeoutMs = 4000) {
  if (typeof AbortController === "undefined") {
    return fetchJson(path, options);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchJson(path, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function clearCurrentPolicy() {
  if (!clientId()) {
    return { ok: false, status: 0, body: { error: "Missing client id" } };
  }

  return fetchJson("/demo/clear-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...defaultHeaders(false),
    },
    body: JSON.stringify({ client_id: clientId() }),
  });
}

function effectiveDemoFile() {
  if (state.selectedFile) {
    return {
      payload: state.selectedFile,
      name: state.selectedFile.name,
      size: state.selectedFile.size,
    };
  }

  const content = (els.demoContent.value || "").trim() || "secure dedup demo payload";
  const payload = new Blob([content], { type: "text/plain" });
  return {
    payload,
    name: "demo-step-upload.txt",
    size: payload.size,
  };
}

async function uploadWithProofs(powProofs = null, { autoRecoverPolicy = true } = {}) {
  const demoFile = effectiveDemoFile();
  const runUpload = async () => {
    const form = new FormData();
    form.append("file", demoFile.payload, demoFile.name);

    if (powProofs) {
      form.append("pow_proofs_json", JSON.stringify(powProofs));
    }

    return fetchJson("/upload", {
      method: "POST",
      headers: defaultHeaders(true),
      body: form,
    });
  };

  let result = await runUpload();
  if (autoRecoverPolicy && (result.status === 403 || result.status === 429)) {
    prependLog("Policy recovery", "Clearing active demo policy and retrying once.");
    await clearCurrentPolicy();
    result = await runUpload();
  }

  prependLog("Upload request", {
    file_name: demoFile.name,
    file_size: demoFile.size,
    status: result.status,
    body: result.body,
  });
  return result;
}

function challengeSummary(challenges) {
  if (!Array.isArray(challenges) || !challenges.length) {
    return "No challenge returned yet.";
  }

  const first = challenges[0];
  const difficulty = first.adaptive_profile?.difficulty_level || "normal";
  return pretty({
    challenge_count: challenges.length,
    first_chunk_hash: first.chunk_hash,
    first_challenge_id: first.challenge_id,
    difficulty_level: difficulty,
    offset: first.offset,
    length: first.length,
    expires_at: first.expires_at,
  });
}

function applyMetrics(summary, config = {}) {
  const storage = summary?.storage || {};
  const pow = summary?.pow || {};
  const encryption = summary?.encryption || {};
  const activity = summary?.activity || {};
  const fingerprint = config?.fingerprint || {};

  els.activeFilesValue.textContent = String(storage.active_files ?? 0);
  els.uniqueChunksValue.textContent = String(storage.unique_chunks ?? 0);
  els.dedupSavedValue.textContent = String(storage.dedup_saved_chunks ?? 0);
  els.dedupSavedMeta.textContent = `${storage.dedup_saved_percent ?? 0}% logical chunks saved by dedup`;
  els.powValue.textContent = `${pow.proofs_verified ?? 0} / ${pow.proofs_rejected ?? 0}`;
  els.powMeta.textContent = `${pow.challenges_issued ?? 0} challenges issued`;
  els.monitoringValue.textContent = String(activity.clients_seen ?? 0);
  els.monitoringMeta.textContent = `${activity.requests_seen ?? 0} requests observed`;
  els.encryptionValue.textContent = encryption.enabled ? "Enabled" : "Disabled";
  const fingerprintLabel = fingerprint.mode === "secret_hmac"
    ? "secret-HMAC dedup token"
    : "public SHA-256 dedup token";
  els.encryptionMeta.textContent = encryption.enabled
    ? `${encryption.mode || "AES-GCM"} | ${fingerprintLabel} | segment ${encryption.segment_size || "n/a"}`
    : "Set CHUNK_ENCRYPTION_KEY to enable encrypted storage";
}

async function refreshDashboard() {
  const [health, config, metrics] = await Promise.all([
    fetchJson("/health"),
    fetchJson("/demo/config"),
    fetchJson("/metrics"),
  ]);
  const status = await fetchJsonWithTimeout("/demo/status?limit=10", {}, 4000);

  if (health.ok && health.body.status === "ok") {
    els.healthValue.textContent = "Healthy";
    els.healthMeta.textContent = "Service responding";
  } else {
    els.healthValue.textContent = "Error";
    els.healthMeta.textContent = `Health check failed (${health.status || "network"})`;
  }

  if (config.ok) {
    const storage = config.body.storage || {};
    els.storageValue.textContent = storage.backend || "Unknown";
    if (storage.backend === "localstack") {
      els.storageMeta.textContent = storage.bucket
        ? `LocalStack S3 bucket: ${storage.bucket}`
        : "LocalStack S3";
    } else if (storage.backend === "s3") {
      els.storageMeta.textContent = storage.bucket ? `S3 bucket: ${storage.bucket}` : "AWS S3";
    } else if (storage.backend === "filesystem") {
      els.storageMeta.textContent = storage.configured_backend === "localstack"
        ? "Waiting for LocalStack, filesystem fallback active"
        : "Filesystem fallback";
    } else {
      els.storageMeta.textContent = storage.bucket || "Storage status loaded";
    }
  } else {
    els.storageValue.textContent = "Error";
    els.storageMeta.textContent = "Failed to load storage config";
  }

  if (metrics.ok) {
    applyMetrics(metrics.body.summary || {}, config.body || {});
    els.metricsOutput.textContent = pretty(metrics.body.summary || metrics.body);
  } else {
    els.metricsOutput.textContent = pretty(metrics.body);
  }

  if (status.ok) {
    els.statusOutput.textContent = pretty(status.body || status);
  } else {
    els.statusOutput.textContent = pretty({
      message: "Live status feed unavailable",
      hint: "Use /docs for a reliable demo flow, or retry dashboard refresh.",
      detail: status.body || status,
    });
  }
}

async function runOriginalUploadStep() {
  state.lastChallenges = [];
  state.lastProofs = null;
  els.challengeOutput.textContent = "No challenge returned yet.";

  let result = await uploadWithProofs(null);
  if (result.status === 409 && usingAutoPayload()) {
    prependLog("Fresh payload recovery", "Generated content already existed, starting a fresh reviewer session and retrying.");
    startNewSession({ refresh: false });
    result = await uploadWithProofs(null);
  }
  els.step1Output.textContent = pretty(result.body);
  if (result.ok) {
    prependLog("Step 1 complete", "Original upload stored successfully.");
  } else {
    prependLog("Step 1 failed", result.body);
  }
  await refreshDashboard();
}

async function runDuplicateUploadStep() {
  const result = await uploadWithProofs(null);
  els.step2Output.textContent = pretty(result.body);

  const challenges = result.body?.detail?.required_challenges || [];
  state.lastChallenges = Array.isArray(challenges) ? challenges : [];
  els.challengeOutput.textContent = challengeSummary(state.lastChallenges);

  if (result.status === 409 && state.lastChallenges.length) {
    prependLog("Step 2 complete", {
      message: "Duplicate upload correctly triggered PoW.",
      challenge_count: state.lastChallenges.length,
    });
  } else {
    prependLog("Step 2 result", result.body);
  }
  await refreshDashboard();
}

async function runSolveAndRetry() {
  if (!state.lastChallenges.length) {
    await runDuplicateUploadStep();
  }

  if (!state.lastChallenges.length) {
    els.step3Output.textContent = "No pending challenge is available to solve.";
    prependLog("Step 3 blocked", "Duplicate upload did not return a challenge.");
    return;
  }

  const solve = await fetchJson("/demo/solve_pow", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...defaultHeaders(false),
    },
    body: JSON.stringify({ challenges: state.lastChallenges }),
  });

  if (!solve.ok || !solve.body?.pow_proofs) {
    els.step3Output.textContent = pretty(solve.body);
    prependLog("Step 3 solve failed", solve.body);
    await refreshDashboard();
    return;
  }

  state.lastProofs = solve.body.pow_proofs;
  const retry = await uploadWithProofs(state.lastProofs);
  els.step3Output.textContent = pretty({
    solve: solve.body,
    retry: retry.body,
  });

  if (retry.ok) {
    prependLog("Step 3 complete", "PoW solved and duplicate upload retried successfully.");
    state.lastChallenges = [];
    els.challengeOutput.textContent = "Latest challenge solved successfully.";
  } else {
    prependLog("Step 3 retry failed", retry.body);
  }

  await refreshDashboard();
}

els.fileInput?.addEventListener("change", (event) => {
  state.selectedFile = event.target.files[0] || null;
  if (state.selectedFile) {
    els.fileMeta.textContent = `Selected file: ${state.selectedFile.name} (${state.selectedFile.size} bytes)`;
    prependLog("File selected", {
      name: state.selectedFile.name,
      size: state.selectedFile.size,
      type: state.selectedFile.type,
    });
  } else {
    els.fileMeta.textContent = "No file selected. The text above will be turned into a demo file.";
  }
});

els.refreshDashboard?.addEventListener("click", refreshDashboard);
els.startNewSession?.addEventListener("click", () => startNewSession());
els.stepUploadOriginal?.addEventListener("click", runOriginalUploadStep);
els.stepTriggerPow?.addEventListener("click", runDuplicateUploadStep);
els.stepSolveAndRetry?.addEventListener("click", runSolveAndRetry);

startNewSession({ refresh: false });
refreshDashboard();
