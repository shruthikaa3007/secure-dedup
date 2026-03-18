const byId = (id) => document.getElementById(id);

const els = {
  apiKey: byId("apiKey"),
  clientId: byId("clientId"),
  policyClientId: byId("policyClientId"),
  fileInput: byId("fileInput"),
  uploadOnce: byId("uploadOnce"),
  uploadDuplicate: byId("uploadDuplicate"),
  retryUpload: byId("retryUpload"),
  solvePow: byId("solvePow"),
  refreshStatus: byId("refreshStatus"),
  refreshStatusAlt: byId("refreshStatusAlt"),
  refreshMetrics: byId("refreshMetrics"),
  inspectChunk: byId("inspectChunk"),
  forceRateLimit: byId("forceRateLimit"),
  forceBlock: byId("forceBlock"),
  clearPolicy: byId("clearPolicy"),
  healthChip: byId("healthChip"),
  encryptionChip: byId("encryptionChip"),
  policyChip: byId("policyChip"),
  storageChip: byId("storageChip"),
  healthMeta: byId("healthMeta"),
  encryptionMeta: byId("encryptionMeta"),
  policyMeta: byId("policyMeta"),
  storageMeta: byId("storageMeta"),
  uploadLog: byId("uploadLog"),
  powLog: byId("powLog"),
  policyLog: byId("policyLog"),
  metricsLog: byId("metricsLog"),
  encryptionLog: byId("encryptionLog"),
  eventLog: byId("eventLog"),
};

const state = {
  file: null,
  lastChallenges: [],
  lastProofs: null,
  lastUpload: null,
  lastChunk: null,
};

function chip(el, text, level) {
  el.textContent = text;
  el.classList.remove("good", "warn", "bad");
  if (level) {
    el.classList.add(level);
  }
}

function pretty(payload) {
  if (payload === undefined) return "No data.";
  if (typeof payload === "string") return payload;
  try {
    return JSON.stringify(payload, null, 2);
  } catch (err) {
    return String(payload);
  }
}

function logEvent(label, payload) {
  const stamp = new Date().toLocaleTimeString();
  const entry = `[${stamp}] ${label}\n${pretty(payload)}\n\n`;
  els.eventLog.textContent = entry + els.eventLog.textContent;
}

function headers() {
  return {
    "X-API-Key": els.apiKey.value.trim(),
    "X-Client-ID": els.clientId.value.trim(),
  };
}

async function readBody(res) {
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return res.json();
  }
  return res.text();
}

async function fetchJson(path, options = {}) {
  const res = await fetch(path, options);
  const body = await readBody(res);
  return { ok: res.ok, status: res.status, body };
}

async function refreshStatus() {
  const health = await fetchJson("/health");
  if (health.ok && health.body.status === "ok") {
    chip(els.healthChip, "Healthy", "good");
    els.healthMeta.textContent = "API responding";
  } else {
    chip(els.healthChip, "Down", "bad");
    els.healthMeta.textContent = "No response from /health";
  }

  const status = await fetchJson("/demo/status");
  if (status.ok) {
    const enc = status.body.encryption || {};
    if (enc.enabled) {
      chip(els.encryptionChip, "Enabled", "good");
      els.encryptionMeta.textContent = `Key ${enc.key_bytes || 0} bytes, segment ${enc.segment_size || "n/a"}`;
    } else {
      chip(els.encryptionChip, "Disabled", "warn");
      els.encryptionMeta.textContent = "Set CHUNK_ENCRYPTION_KEY to enable";
    }

    const storage = status.body.storage || {};
    chip(els.storageChip, storage.backend || "Unknown", "good");
    els.storageMeta.textContent = storage.backend ? `Backend: ${storage.backend}` : "No storage info";
  } else {
    chip(els.encryptionChip, "Unknown", "warn");
    chip(els.storageChip, "Unknown", "warn");
  }

  await refreshPolicy();
  logEvent("Status refreshed", status.body || status);
}

async function refreshMetrics() {
  const metrics = await fetchJson("/metrics");
  if (metrics.ok) {
    els.metricsLog.textContent = pretty(metrics.body);
  } else {
    els.metricsLog.textContent = pretty(metrics.body);
  }
  logEvent("Metrics", metrics.body || metrics);
}

async function refreshPolicy() {
  const clientId = els.policyClientId.value.trim() || els.clientId.value.trim();
  if (!clientId) {
    chip(els.policyChip, "Missing ID", "warn");
    els.policyMeta.textContent = "Set a policy client id";
    return;
  }

  const res = await fetchJson(`/demo/policy/${encodeURIComponent(clientId)}`, {
    headers: { "X-API-Key": els.apiKey.value.trim() },
  });

  if (res.ok) {
    const active = res.body.active_policy;
    if (active && active.action && active.action !== "ALLOW") {
      chip(els.policyChip, active.action, active.action === "BLOCK" ? "bad" : "warn");
      els.policyMeta.textContent = `Cooldown ${Math.round(active.remaining_sec || 0)}s`;
    } else {
      chip(els.policyChip, "ALLOW", "good");
      els.policyMeta.textContent = "No active policy";
    }
    els.policyLog.textContent = pretty(res.body);
  } else {
    chip(els.policyChip, "Unknown", "warn");
    els.policyMeta.textContent = "Policy snapshot failed";
    els.policyLog.textContent = pretty(res.body);
  }
  logEvent("Policy snapshot", res.body || res);
}

async function doUpload(withProofs) {
  if (!state.file) {
    logEvent("Upload", "Select a file first.");
    return;
  }

  const form = new FormData();
  form.append("file", state.file);
  if (withProofs && state.lastProofs) {
    form.append("pow_proofs_json", JSON.stringify(state.lastProofs));
  }

  const res = await fetch("/upload", {
    method: "POST",
    headers: headers(),
    body: form,
  });

  const body = await readBody(res);
  if (!res.ok) {
    els.uploadLog.textContent = pretty(body);
    logEvent("Upload failed", body);

    if (res.status === 409 && body.detail && body.detail.required_challenges) {
      state.lastChallenges = body.detail.required_challenges;
      els.powLog.textContent = pretty(state.lastChallenges);
      logEvent("PoW challenges", state.lastChallenges);
    }
    return;
  }

  state.lastUpload = body;
  state.lastChallenges = [];
  state.lastProofs = null;
  els.uploadLog.textContent = pretty(body);
  els.powLog.textContent = "No challenges yet.";
  logEvent("Upload success", body);

  if (body.file_recipe && body.file_recipe.length > 0) {
    state.lastChunk = body.file_recipe[0];
  }

  await refreshPolicy();
}

async function solvePow() {
  if (!state.lastChallenges || state.lastChallenges.length === 0) {
    logEvent("PoW", "No challenges available to solve.");
    return;
  }

  const res = await fetchJson("/demo/solve_pow", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": els.apiKey.value.trim(),
    },
    body: JSON.stringify({ challenges: state.lastChallenges }),
  });

  if (res.ok) {
    state.lastProofs = res.body.pow_proofs || null;
    els.powLog.textContent = pretty(res.body);
  } else {
    els.powLog.textContent = pretty(res.body);
  }
  logEvent("PoW solver", res.body || res);
}

async function retryUploadWithProofs() {
  if (!state.lastProofs) {
    logEvent("Upload", "No proofs available. Solve PoW first.");
    return;
  }
  await doUpload(true);
}

async function inspectChunk() {
  const chunk = state.lastChunk;
  if (!chunk) {
    logEvent("Inspect", "No chunk available. Upload a file first.");
    return;
  }
  const res = await fetchJson(`/demo/chunk/${encodeURIComponent(chunk)}`, {
    headers: { "X-API-Key": els.apiKey.value.trim() },
  });
  els.encryptionLog.textContent = pretty(res.body);
  logEvent("Chunk inspect", res.body || res);
}

async function forcePolicy(action) {
  const clientId = els.policyClientId.value.trim() || els.clientId.value.trim();
  if (!clientId) {
    logEvent("Policy", "Set a policy client id.");
    return;
  }
  const res = await fetchJson("/demo/force-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": els.apiKey.value.trim(),
    },
    body: JSON.stringify({ client_id: clientId, action }),
  });
  els.policyLog.textContent = pretty(res.body);
  logEvent(`Force policy ${action}`, res.body || res);
  await refreshPolicy();
}

async function clearPolicy() {
  const clientId = els.policyClientId.value.trim() || els.clientId.value.trim();
  const res = await fetchJson("/demo/clear-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": els.apiKey.value.trim(),
    },
    body: JSON.stringify({ client_id: clientId }),
  });
  els.policyLog.textContent = pretty(res.body);
  logEvent("Clear policy", res.body || res);
  await refreshPolicy();
}

els.fileInput.addEventListener("change", (event) => {
  state.file = event.target.files[0] || null;
  if (state.file) {
    logEvent("File selected", { name: state.file.name, size: state.file.size });
  }
});

els.uploadOnce.addEventListener("click", () => doUpload(false));
els.uploadDuplicate.addEventListener("click", () => doUpload(false));
els.solvePow.addEventListener("click", solvePow);
els.retryUpload.addEventListener("click", retryUploadWithProofs);
els.refreshStatus.addEventListener("click", refreshStatus);
els.refreshStatusAlt.addEventListener("click", refreshStatus);
els.refreshMetrics.addEventListener("click", refreshMetrics);
els.inspectChunk.addEventListener("click", inspectChunk);
els.forceRateLimit.addEventListener("click", () => forcePolicy("RATE_LIMIT"));
els.forceBlock.addEventListener("click", () => forcePolicy("BLOCK"));
els.clearPolicy.addEventListener("click", clearPolicy);

refreshStatus();
