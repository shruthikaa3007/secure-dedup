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
  runScenarioSuite: byId("runScenarioSuite"),
  downloadScenarioJson: byId("downloadScenarioJson"),
  downloadScenarioCsv: byId("downloadScenarioCsv"),
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
  suiteLog: byId("suiteLog"),
  suiteReportLog: byId("suiteReportLog"),
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
  lastSuiteReport: null,
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

function nowIso() {
  return new Date().toISOString();
}

function ensure(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function metricDelta(before, after) {
  const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  const delta = {};
  for (const key of keys) {
    delta[key] = Number(after?.[key] || 0) - Number(before?.[key] || 0);
  }
  return delta;
}

async function metricsSnapshot() {
  const res = await fetchJson("/metrics");
  return res.ok ? (res.body.metrics || {}) : {};
}

function downloadTextFile(filename, content, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
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

function createTextFile(name, text) {
  return {
    payload: new Blob([text], { type: "text/plain" }),
    name,
  };
}

async function uploadForClient(clientIdValue, fileObj, { powProofs = null, fileId = null } = {}) {
  const form = new FormData();
  form.append("file", fileObj.payload, fileObj.name);
  if (powProofs) {
    form.append("pow_proofs_json", JSON.stringify(powProofs));
  }
  if (fileId) {
    form.append("file_id", fileId);
  }

  return fetchJson("/upload", {
    method: "POST",
    headers: {
      "X-API-Key": apiKey(),
      "X-Client-ID": clientIdValue,
    },
    body: form,
  });
}

async function clearPolicyForClient(clientIdValue) {
  return fetchJson("/demo/clear-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey(),
    },
    body: JSON.stringify({ client_id: clientIdValue }),
  });
}

async function forcePolicyForClient(clientIdValue, action) {
  return fetchJson("/demo/force-policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey(),
    },
    body: JSON.stringify({ client_id: clientIdValue, action }),
  });
}

async function uploadWithPolicyRecovery(clientIdValue, fileObj, options = {}) {
  let result = await uploadForClient(clientIdValue, fileObj, options);
  if (result.status === 429) {
    await clearPolicyForClient(clientIdValue);
    result = await uploadForClient(clientIdValue, fileObj, options);
  }
  return result;
}

function suiteLog(message) {
  const stamp = new Date().toLocaleTimeString();
  els.suiteLog.textContent = `[${stamp}] ${message}\n` + els.suiteLog.textContent;
}

function csvEscape(value) {
  const raw = String(value ?? "");
  return `"${raw.replace(/"/g, '""')}"`;
}

function buildSuiteCsv(report) {
  const metricKeys = Array.from(
    new Set((report.results || []).flatMap((item) => Object.keys(item.metrics_delta || {}))),
  ).sort();
  const header = ["scenario", "status", "duration_ms", "detail", ...metricKeys.map((key) => `delta_${key}`)];
  const rows = [header.map(csvEscape).join(",")];

  for (const item of report.results || []) {
    const row = [item.name, item.status, item.duration_ms, item.detail || ""];
    for (const key of metricKeys) {
      row.push((item.metrics_delta || {})[key] ?? 0);
    }
    rows.push(row.map(csvEscape).join(","));
  }
  return rows.join("\n") + "\n";
}

async function runScenarioCase(suite, name, fn) {
  const before = await metricsSnapshot();
  const started = performance.now();
  let status = "PASS";
  let detail = "";
  let data = null;

  try {
    data = await fn();
  } catch (err) {
    status = "FAIL";
    detail = String(err?.message || err);
  }

  const after = await metricsSnapshot();
  const durationMs = Math.round(performance.now() - started);
  const result = {
    name,
    status,
    duration_ms: durationMs,
    detail,
    data,
    metrics_before: before,
    metrics_after: after,
    metrics_delta: metricDelta(before, after),
  };
  suite.results.push(result);
  suiteLog(`${status} ${name} (${durationMs} ms)${detail ? ` - ${detail}` : ""}`);
  return result;
}

async function runScenarioSuite() {
  els.suiteLog.textContent = "Running scenario suite...\n";
  els.suiteReportLog.textContent = "Generating report...\n";

  const ts = Date.now();
  const mainClient = `${clientId() || "demo"}-suite-main-${ts}`;
  const secondClient = `${clientId() || "demo"}-suite-second-${ts}`;
  const thirdClient = `${clientId() || "demo"}-suite-third-${ts}`;
  const baseFile = effectiveDemoFile();

  const ctx = {
    mainClient,
    secondClient,
    thirdClient,
    baseFile,
    mainChunkHash: null,
    mainChallenges: [],
    secondaryFileId: null,
  };

  const suite = {
    generated_at: nowIso(),
    api_key_present: Boolean(apiKey()),
    clients: {
      main: mainClient,
      second: secondClient,
      third: thirdClient,
    },
    results: [],
  };

  await runScenarioCase(suite, "Scenario 1 - Baseline Upload", async () => {
    const res = await uploadWithPolicyRecovery(ctx.mainClient, ctx.baseFile);
    ensure(res.ok, `Baseline upload failed (${res.status})`);
    const recipe = res.body.file_recipe || [];
    ensure(recipe.length > 0, "Baseline upload returned empty file_recipe");
    ctx.mainChunkHash = recipe[0];
    return {
      file_id: res.body.file?.file_id || null,
      total_chunks: res.body.total_chunks || 0,
      chunk_hash: ctx.mainChunkHash,
    };
  });

  await runScenarioCase(suite, "Scenario 2 - Duplicate Requires PoW", async () => {
    let res = await uploadForClient(ctx.mainClient, ctx.baseFile);
    if (res.status === 429) {
      await clearPolicyForClient(ctx.mainClient);
      res = await uploadForClient(ctx.mainClient, ctx.baseFile);
    }
    ensure(res.status === 409, `Expected 409 duplicate challenge, got ${res.status}`);
    const challenges = res.body?.detail?.required_challenges || [];
    ensure(challenges.length > 0, "No required_challenges returned");
    ctx.mainChallenges = challenges;
    return { challenge_count: challenges.length };
  });

  await runScenarioCase(suite, "Scenario 3 - PoW Solve And Retry", async () => {
    ensure(ctx.mainChallenges.length > 0, "Missing PoW challenges from previous scenario");
    const challengePayload = ctx.mainChallenges.map((c) => ({
      chunk_hash: c.chunk_hash,
      challenge_id: c.challenge_id,
      nonce_hex: c.nonce_hex,
      offset: c.offset,
      length: c.length,
    }));
    const solve = await fetchJson("/demo/solve_pow", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
      },
      body: JSON.stringify({ challenges: challengePayload }),
    });
    ensure(solve.ok, `PoW solve endpoint failed (${solve.status})`);
    const proofs = solve.body.pow_proofs || {};
    ensure(Object.keys(proofs).length > 0, "PoW solve returned empty proofs");
    const retry = await uploadWithPolicyRecovery(ctx.mainClient, ctx.baseFile, { powProofs: proofs });
    ensure(retry.ok, `Retry upload failed (${retry.status})`);
    return { proof_count: Object.keys(proofs).length, retry_total_chunks: retry.body.total_chunks || 0 };
  });

  await runScenarioCase(suite, "Scenario 4 - Policy Enforcement And Recovery", async () => {
    const rlForce = await forcePolicyForClient(ctx.mainClient, "RATE_LIMIT");
    ensure(rlForce.ok, `Force RATE_LIMIT failed (${rlForce.status})`);
    const rlAttempt = await uploadForClient(
      ctx.mainClient,
      createTextFile(`rate_limit_${ts}.txt`, `rate-limit-${nowIso()}`),
    );
    ensure(rlAttempt.status === 429, `Expected 429 after RATE_LIMIT, got ${rlAttempt.status}`);

    await clearPolicyForClient(ctx.mainClient);
    const rlRecover = await uploadWithPolicyRecovery(
      ctx.mainClient,
      createTextFile(`rate_limit_recover_${ts}.txt`, `rate-limit-recover-${nowIso()}`),
    );
    ensure(rlRecover.ok, `Recovery after RATE_LIMIT failed (${rlRecover.status})`);

    const blockForce = await forcePolicyForClient(ctx.mainClient, "BLOCK");
    ensure(blockForce.ok, `Force BLOCK failed (${blockForce.status})`);
    const blockAttempt = await uploadForClient(
      ctx.mainClient,
      createTextFile(`block_${ts}.txt`, `block-${nowIso()}`),
    );
    ensure(blockAttempt.status === 403, `Expected 403 after BLOCK, got ${blockAttempt.status}`);

    await clearPolicyForClient(ctx.mainClient);
    const blockRecover = await uploadWithPolicyRecovery(
      ctx.mainClient,
      createTextFile(`block_recover_${ts}.txt`, `block-recover-${nowIso()}`),
    );
    ensure(blockRecover.ok, `Recovery after BLOCK failed (${blockRecover.status})`);
    return { rate_limit_blocked: true, block_blocked: true };
  });

  await runScenarioCase(suite, "Scenario 5 - File Version Update And Delete", async () => {
    const first = await uploadWithPolicyRecovery(
      ctx.secondClient,
      createTextFile(`version_v1_${ts}.txt`, `version-v1-${nowIso()}`),
    );
    ensure(first.ok, `First version upload failed (${first.status})`);
    const fileId = first.body?.file?.file_id;
    ensure(fileId, "No file_id returned for versioning scenario");
    ctx.secondaryFileId = fileId;

    const second = await uploadWithPolicyRecovery(
      ctx.secondClient,
      createTextFile(`version_v2_${ts}.txt`, `version-v2-${nowIso()}`),
      { fileId },
    );
    ensure(second.ok, `Second version upload failed (${second.status})`);
    ensure(second.body?.file?.version === 2, "Expected version=2 after update");

    const fetched = await fetchJson(`/files/${encodeURIComponent(fileId)}`, {
      headers: {
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.secondClient,
      },
    });
    ensure(fetched.ok, `Fetch file by id failed (${fetched.status})`);

    const deleted = await fetchJson(`/files/${encodeURIComponent(fileId)}`, {
      method: "DELETE",
      headers: {
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.secondClient,
      },
    });
    ensure(deleted.ok, `Delete file failed (${deleted.status})`);
    return { file_id: fileId, version_after_update: second.body.file.version };
  });

  await runScenarioCase(suite, "Scenario 6 - Ownership Transfer And Audit", async () => {
    ensure(ctx.mainChunkHash, "Main chunk hash not available");
    const before = await fetchJson(`/ownership/${encodeURIComponent(ctx.mainChunkHash)}`, {
      headers: {
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.mainClient,
      },
    });
    ensure(before.ok, `Ownership fetch failed (${before.status})`);

    const transfer = await fetchJson("/ownership/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.mainClient,
      },
      body: JSON.stringify({
        chunk_hash: ctx.mainChunkHash,
        to_client_id: ctx.thirdClient,
      }),
    });
    ensure(transfer.ok, `Ownership transfer failed (${transfer.status})`);

    const challenge = await fetchJson("/audit/challenge", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.thirdClient,
      },
      body: JSON.stringify({
        chunk_hash: ctx.mainChunkHash,
        length: 16,
      }),
    });
    ensure(challenge.ok, `Audit challenge failed (${challenge.status})`);
    const ch = challenge.body.challenge || {};

    const solveAudit = await fetchJson("/demo/solve_audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
      },
      body: JSON.stringify({
        challenge: {
          chunk_hash: ch.chunk_hash,
          challenge_id: ch.challenge_id,
          nonce_hex: ch.nonce_hex,
          offset: ch.offset,
          length: ch.length,
        },
      }),
    });
    ensure(solveAudit.ok, `Solve audit proof failed (${solveAudit.status})`);

    const verify = await fetchJson("/audit/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey(),
      },
      body: JSON.stringify({
        challenge_id: ch.challenge_id,
        proof: solveAudit.body.proof,
      }),
    });
    ensure(verify.ok && verify.body?.verified === true, `Audit verify failed (${verify.status})`);

    const quick = await fetchJson(`/audit/quick/${encodeURIComponent(ctx.mainChunkHash)}`, {
      headers: {
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.thirdClient,
      },
    });
    ensure(quick.ok, `Quick audit failed (${quick.status})`);
    return { audit_verified: true, owner_count_after_transfer: transfer.body?.ownership?.owner_count || 0 };
  });

  await runScenarioCase(suite, "Scenario 7 - Encryption Status And UI Hooks", async () => {
    const enc = await fetchJson("/demo/encryption", {
      headers: {
        "X-API-Key": apiKey(),
        "X-Client-ID": ctx.mainClient,
      },
    });
    ensure(enc.ok, `Encryption status endpoint failed (${enc.status})`);
    ensure(typeof enc.body?.encryption_enabled === "boolean", "Missing encryption_enabled in response");
    return { encryption_enabled: enc.body.encryption_enabled, demo_mode: true };
  });

  await runScenarioCase(suite, "Scenario 8 - Status And Metrics Summary", async () => {
    const status = await fetchJson("/demo/status?limit=30");
    const metrics = await fetchJson("/metrics");
    ensure(status.ok, `Status endpoint failed (${status.status})`);
    ensure(metrics.ok, `Metrics endpoint failed (${metrics.status})`);
    return {
      active_clients: status.body?.summary?.active_clients || 0,
      total_buffered_events: status.body?.summary?.total_buffered_events || 0,
      metrics_keys: Object.keys(metrics.body?.metrics || {}).sort(),
    };
  });

  const passed = suite.results.filter((r) => r.status === "PASS").length;
  suite.summary = {
    total: suite.results.length,
    passed,
    failed: suite.results.length - passed,
  };

  state.lastSuiteReport = suite;
  els.suiteReportLog.textContent = pretty(suite);
  suiteLog(`Scenario suite complete: ${suite.summary.passed}/${suite.summary.total} passed.`);
  logEvent("Scenario suite report", suite);
  await refreshOverview();
  await refreshMetrics();
}

function suiteTimestampForFile(report) {
  const iso = (report && report.generated_at) || nowIso();
  return iso.replace(/[-:]/g, "").replace(/\..+$/, "").replace("T", "_");
}

function downloadScenarioReportJson() {
  if (!state.lastSuiteReport) {
    suiteLog("No report available. Run the scenario suite first.");
    return;
  }
  const stamp = suiteTimestampForFile(state.lastSuiteReport);
  downloadTextFile(
    `scenario_suite_report_${stamp}.json`,
    `${JSON.stringify(state.lastSuiteReport, null, 2)}\n`,
    "application/json",
  );
}

function downloadScenarioMetricsCsv() {
  if (!state.lastSuiteReport) {
    suiteLog("No report available. Run the scenario suite first.");
    return;
  }
  const stamp = suiteTimestampForFile(state.lastSuiteReport);
  downloadTextFile(
    `scenario_suite_metrics_${stamp}.csv`,
    buildSuiteCsv(state.lastSuiteReport),
    "text/csv",
  );
}

async function handleRunScenarioSuite() {
  if (!apiKey()) {
    suiteLog("API key is required to run the scenario suite.");
    return;
  }

  els.runScenarioSuite.disabled = true;
  try {
    await runScenarioSuite();
  } finally {
    els.runScenarioSuite.disabled = false;
  }
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
els.runScenarioSuite.addEventListener("click", handleRunScenarioSuite);
els.downloadScenarioJson.addEventListener("click", downloadScenarioReportJson);
els.downloadScenarioCsv.addEventListener("click", downloadScenarioMetricsCsv);
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
