const byId = (id) => document.getElementById(id);

const els = {
  apiKey: byId("apiKey"),
  clientId: byId("clientId"),
  policyClientId: byId("policyClientId"),
  demoContent: byId("demoContent"),
  fileInput: byId("fileInput"),
  fileMeta: byId("fileMeta"),
  runFullDemo: byId("runFullDemo"),
  runBaselineStep: byId("runBaselineStep"),
  runDuplicateStep: byId("runDuplicateStep"),
  runSolveRetryStep: byId("runSolveRetryStep"),
  runAttackStep: byId("runAttackStep"),
  uploadOnce: byId("uploadOnce"),
  uploadDuplicate: byId("uploadDuplicate"),
  solvePow: byId("solvePow"),
  retryUpload: byId("retryUpload"),
  inspectChunk: byId("inspectChunk"),
  forceRateLimit: byId("forceRateLimit"),
  forceBlock: byId("forceBlock"),
  clearPolicy: byId("clearPolicy"),
  refreshOverview: byId("refreshOverview"),
  refreshMetrics: byId("refreshMetrics"),
  healthChip: byId("healthChip"),
  encryptionChip: byId("encryptionChip"),
  storageChip: byId("storageChip"),
  policyChip: byId("policyChip"),
  detectionChip: byId("detectionChip"),
  activityChip: byId("activityChip"),
  healthMeta: byId("healthMeta"),
  encryptionMeta: byId("encryptionMeta"),
  storageMeta: byId("storageMeta"),
  policyMeta: byId("policyMeta"),
  detectionMeta: byId("detectionMeta"),
  activityMeta: byId("activityMeta"),
  scenarioLog: byId("scenarioLog"),
  uploadLog: byId("uploadLog"),
  powLog: byId("powLog"),
  policyLog: byId("policyLog"),
  encryptionLog: byId("encryptionLog"),
  statusLog: byId("statusLog"),
  metricsLog: byId("metricsLog"),
  eventLog: byId("eventLog"),
};

const state = {
  selectedFile: null,
  lastChallenges: [],
  lastProofs: null,
  lastChunk: null,
};

function setChip(el, text, level) {
  el.textContent = text;
  el.classList.remove("good", "warn", "bad");
  if (level) {
    el.classList.add(level);
  }
}

function pretty(payload) {
  if (payload === undefined) return "No data";
  if (typeof payload === "string") return payload;
  try {
    return JSON.stringify(payload, null, 2);
  } catch (err) {
    return String(payload);
  }
}

function appendScenario(message) {
  const stamp = new Date().toLocaleTimeString();
  els.scenarioLog.textContent = `[${stamp}] ${message}\n` + els.scenarioLog.textContent;
}

function logEvent(label, payload) {
  const stamp = new Date().toLocaleTimeString();
  const entry = `[${stamp}] ${label}\n${pretty(payload)}\n\n`;
  els.eventLog.textContent = entry + els.eventLog.textContent;
}

function apiKey() {
  return (els.apiKey.value || "").trim();
}

function clientId() {
  return (els.clientId.value || "").trim();
}

function policyClientId() {
  return (els.policyClientId.value || "").trim() || clientId();
}

function defaultHeaders(withClientId = true) {
  const headers = {
    "X-API-Key": apiKey(),
  };
  if (withClientId) {
    headers["X-Client-ID"] = clientId();
  }
  return headers;
}

async function readBody(res) {
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }
  return res.text();
}

async function fetchJson(path, options = {}) {
  try {
    const res = await fetch(path, options);
    const body = await readBody(res);
    return { ok: res.ok, status: res.status, body };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      body: { error: "Network error", detail: String(err) },
    };
  }
}

function effectiveDemoFile() {
  if (state.selectedFile) {
    return {
      payload: state.selectedFile,
      name: state.selectedFile.name,
      size: state.selectedFile.size,
    };
  }

  const rawText = (els.demoContent.value || "").trim();
  const content = rawText || `secure dedup demo ${new Date().toISOString()}`;
  const blob = new Blob([content], { type: "text/plain" });
  return {
    payload: blob,
    name: "demo-auto.txt",
    size: blob.size,
  };
}

function buildInvalidProofs() {
  const bad = {};
  for (const challenge of state.lastChallenges) {
    bad[challenge.chunk_hash] = {
      challenge_id: challenge.challenge_id,
      proof: "deadbeef",
    };
  }
  return bad;
}

async function refreshPolicySnapshot() {
  const id = policyClientId();
  if (!id) {
    setChip(els.policyChip, "Missing ID", "warn");
    els.policyMeta.textContent = "Set Policy Client ID";
    return null;
  }

  const result = await fetchJson(`/demo/policy/${encodeURIComponent(id)}`, {
    headers: {
      "X-API-Key": apiKey(),
    },
  });

  if (result.ok) {
    const active = result.body.active_policy;
    if (active && active.action && active.action !== "ALLOW") {
      const level = active.action === "BLOCK" ? "bad" : "warn";
      setChip(els.policyChip, active.action, level);
      els.policyMeta.textContent = `Cooldown ${Math.round(active.remaining_sec || 0)}s`;
    } else {
      setChip(els.policyChip, "ALLOW", "good");
      els.policyMeta.textContent = "No active policy action";
    }
    els.policyLog.textContent = pretty(result.body);
  } else {
    setChip(els.policyChip, "Error", "bad");
    els.policyMeta.textContent = "Policy endpoint failed";
    els.policyLog.textContent = pretty(result.body);
  }

  return result;
}

async function refreshOverview() {
  const policyPromise = refreshPolicySnapshot();
  const [health, config, status, policy] = await Promise.all([
    fetchJson("/health"),
    fetchJson("/demo/config"),
    fetchJson("/demo/status?limit=20"),
    policyPromise,
  ]);

  if (health.ok && health.body.status === "ok") {
    setChip(els.healthChip, "Healthy", "good");
    els.healthMeta.textContent = "Service responding on /health";
  } else {
    setChip(els.healthChip, "Unhealthy", "bad");
    els.healthMeta.textContent = `Health check failed (${health.status || "network"})`;
  }

  if (config.ok) {
    const encryption = config.body.encryption || {};
    if (encryption.enabled) {
      setChip(els.encryptionChip, "Enabled", "good");
      els.encryptionMeta.textContent = `Key ${encryption.key_bytes || 0} bytes`;
    } else {
      setChip(els.encryptionChip, "Disabled", "warn");
      els.encryptionMeta.textContent = "Set CHUNK_ENCRYPTION_KEY for encrypted chunks";
    }

    const storage = config.body.storage || {};
    setChip(els.storageChip, storage.backend || "Unknown", storage.backend ? "good" : "warn");
    els.storageMeta.textContent = storage.local_dir ? `Dir: ${storage.local_dir}` : "No storage details";

    const detection = (config.body.detection || {}).mode || "unknown";
    setChip(els.detectionChip, detection, detection === "supervised" ? "good" : "warn");
    els.detectionMeta.textContent = `Threshold ${(config.body.detection || {}).unsupervised_threshold ?? "n/a"}`;
  } else {
    setChip(els.encryptionChip, "Error", "bad");
    setChip(els.storageChip, "Error", "bad");
    setChip(els.detectionChip, "Error", "bad");
    els.encryptionMeta.textContent = "Failed to load /demo/config";
    els.storageMeta.textContent = "Failed to load /demo/config";
    els.detectionMeta.textContent = "Failed to load /demo/config";
  }

  if (status.ok) {
    const summary = status.body.summary || {};
    const activeClients = summary.active_clients || 0;
    const bufferedEvents = summary.total_buffered_events || 0;
    setChip(els.activityChip, `${activeClients} clients`, activeClients > 0 ? "good" : "warn");
    els.activityMeta.textContent = `${bufferedEvents} buffered events`;
    els.statusLog.textContent = pretty(status.body);
  } else {
    setChip(els.activityChip, "Error", "bad");
    els.activityMeta.textContent = "Failed to load /demo/status";
    els.statusLog.textContent = pretty(status.body);
  }

  if (policy) {
    logEvent("Overview refreshed", {
      health,
      config,
      status,
      policy,
    });
  }
}

async function refreshMetrics() {
  const metrics = await fetchJson("/metrics");
  els.metricsLog.textContent = pretty(metrics.body);
  logEvent("Metrics refreshed", metrics.body || metrics);
}

async function uploadFile(mode = "none") {
  const demoFile = effectiveDemoFile();
  const form = new FormData();
  form.append("file", demoFile.payload, demoFile.name);

  if (mode === "good" && state.lastProofs) {
    form.append("pow_proofs_json", JSON.stringify(state.lastProofs));
  }

  if (mode === "bad" && state.lastChallenges.length) {
    form.append("pow_proofs_json", JSON.stringify(buildInvalidProofs()));
  }

  const result = await fetchJson("/upload", {
    method: "POST",
    headers: defaultHeaders(true),
    body: form,
  });

  els.uploadLog.textContent = pretty(result.body);
  logEvent(`Upload (${mode})`, result.body || result);

  if (result.ok) {
    state.lastChallenges = [];
    state.lastProofs = null;
    const recipe = result.body.file_recipe || [];
    state.lastChunk = recipe.length ? recipe[0] : null;
    appendScenario(`Upload successful (${demoFile.name}, ${demoFile.size} bytes)`);
    return result;
  }

  const detail = result.body && result.body.detail;
  if (result.status === 409 && detail && detail.required_challenges) {
    state.lastChallenges = detail.required_challenges;
    els.powLog.textContent = pretty(detail.required_challenges);
    appendScenario(`PoW required: ${detail.required_challenges.length} challenge(s) returned`);
  } else {
    appendScenario(`Upload failed with status ${result.status}`);
  }

  return result;
}

async function solvePowChallenges() {
  if (!state.lastChallenges.length) {
    appendScenario("No pending PoW challenges to solve.");
    return { ok: false, status: 0, body: { error: "No challenges available" } };
  }

  const result = await fetchJson("/demo/solve_pow", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey(),
    },
    body: JSON.stringify({ challenges: state.lastChallenges }),
  });

  els.powLog.textContent = pretty(result.body);
  logEvent("PoW solve", result.body || result);

  if (result.ok && result.body.pow_proofs) {
    state.lastProofs = result.body.pow_proofs;
    appendScenario("PoW proofs generated successfully.");
  } else {
    appendScenario(`PoW solve failed (${result.status}).`);
  }

  return result;
}

async function retryWithProofs() {
  if (!state.lastProofs) {
    appendScenario("No proofs available. Run PoW solve first.");
    return;
  }
  await uploadFile("good");
}

async function inspectLastChunk() {
  if (!state.lastChunk) {
    appendScenario("No chunk to inspect yet. Upload a file first.");
    return;
  }

  const result = await fetchJson(`/demo/chunk/${encodeURIComponent(state.lastChunk)}`, {
    headers: {
      "X-API-Key": apiKey(),
    },
  });

  els.encryptionLog.textContent = pretty(result.body);
  logEvent("Chunk inspect", result.body || result);
}

async function forcePolicy(action) {
  const id = policyClientId();
  if (!id) {
    appendScenario("Policy client id missing.");
    return;
  }

  const result = await fetchJson("/demo/force-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey(),
    },
    body: JSON.stringify({ client_id: id, action }),
  });

  els.policyLog.textContent = pretty(result.body);
  logEvent(`Force policy ${action}`, result.body || result);
  await refreshPolicySnapshot();
}

async function clearPolicy() {
  const id = policyClientId();
  if (!id) {
    appendScenario("Policy client id missing.");
    return;
  }

  const result = await fetchJson("/demo/clear-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey(),
    },
    body: JSON.stringify({ client_id: id }),
  });

  els.policyLog.textContent = pretty(result.body);
  logEvent("Clear policy", result.body || result);
  await refreshPolicySnapshot();
}

async function runBaselineStep() {
  appendScenario("Step 1: Baseline upload started.");
  await uploadFile("none");
  await refreshOverview();
}

async function runDuplicateStep() {
  appendScenario("Step 2: Duplicate upload started (expecting PoW challenge).");
  await uploadFile("none");
  await refreshOverview();
}

async function runSolveRetryStep() {
  appendScenario("Step 3: Solve PoW and retry upload.");
  if (!state.lastChallenges.length) {
    appendScenario("No pending challenge found. Triggering duplicate upload first.");
    await uploadFile("none");
  }
  if (!state.lastChallenges.length) {
    appendScenario("Still no challenge returned; cannot run solve+retry.");
    return;
  }

  const solved = await solvePowChallenges();
  if (solved.ok) {
    await retryWithProofs();
  }
  await refreshOverview();
  await refreshMetrics();
}

async function runAttackStep() {
  appendScenario("Step 4: Bad proof attack simulation started.");
  if (!state.lastChallenges.length) {
    appendScenario("No pending challenge. Triggering duplicate upload first.");
    await uploadFile("none");
  }

  if (!state.lastChallenges.length) {
    appendScenario("No challenge available for attack simulation.");
    return;
  }

  const attack = await uploadFile("bad");
  if (!attack.ok) {
    appendScenario(`Attack request blocked/rejected as expected (status ${attack.status}).`);
  }
  await refreshOverview();
}

async function runFullDemo() {
  els.scenarioLog.textContent = "Running full demo story...\n";
  appendScenario("Full story: baseline -> duplicate challenge -> solve+retry -> optional bad-proof attack.");
  await runBaselineStep();
  await runDuplicateStep();
  await runSolveRetryStep();
  await runAttackStep();
  appendScenario("Full demo story completed.");
}

els.fileInput.addEventListener("change", (event) => {
  state.selectedFile = event.target.files[0] || null;
  if (state.selectedFile) {
    els.fileMeta.textContent = `Selected: ${state.selectedFile.name} (${state.selectedFile.size} bytes)`;
    logEvent("File selected", {
      name: state.selectedFile.name,
      size: state.selectedFile.size,
      type: state.selectedFile.type,
    });
  } else {
    els.fileMeta.textContent = "No file selected. Auto-generated demo payload will be used.";
  }
});

els.runFullDemo.addEventListener("click", runFullDemo);
els.runBaselineStep.addEventListener("click", runBaselineStep);
els.runDuplicateStep.addEventListener("click", runDuplicateStep);
els.runSolveRetryStep.addEventListener("click", runSolveRetryStep);
els.runAttackStep.addEventListener("click", runAttackStep);
els.uploadOnce.addEventListener("click", () => uploadFile("none"));
els.uploadDuplicate.addEventListener("click", () => uploadFile("none"));
els.solvePow.addEventListener("click", solvePowChallenges);
els.retryUpload.addEventListener("click", retryWithProofs);
els.inspectChunk.addEventListener("click", inspectLastChunk);
els.forceRateLimit.addEventListener("click", () => forcePolicy("RATE_LIMIT"));
els.forceBlock.addEventListener("click", () => forcePolicy("BLOCK"));
els.clearPolicy.addEventListener("click", clearPolicy);
els.refreshOverview.addEventListener("click", refreshOverview);
els.refreshMetrics.addEventListener("click", refreshMetrics);

refreshOverview();
refreshMetrics();
