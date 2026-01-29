// ================= CONFIG =================
const API_BASE = "https://majorproject-production-a975.up.railway.app";

// ================= STATE =================
let autoMode = false;
let lastItemId = null;
let activeScanItemId = null;
let listenersAttached = false;
let itemChangedHooked = false;

// ================= INIT =================
Office.onReady(() => {
  if (listenersAttached) return;
  listenersAttached = true;

  const scanBtn = document.getElementById("scanBtn");
  const reportBtn = document.getElementById("reportBtn");
  const quarantineBtn = document.getElementById("quarantineBtn");
  const autoToggle = document.getElementById("autoToggle");

  if (scanBtn) scanBtn.addEventListener("click", scanCurrentEmail);
  if (reportBtn) reportBtn.addEventListener("click", reportCurrentEmail);
  if (quarantineBtn) quarantineBtn.addEventListener("click", quarantineCurrentEmail);

  if (autoToggle) {
    autoToggle.addEventListener("change", (e) => {
      autoMode = e.target.checked;
      setStatus(autoMode ? "Auto mode enabled." : "Auto mode disabled.");

      hookItemChanged();

      if (autoMode) {
        resetUIForNewEmail();
        scanCurrentEmail();
      }
    });
  }

  hookItemChanged();
  setStatus("Ready.");
});

// ================= UI HELPERS =================
function setStatus(msg) {
  document.getElementById("status").textContent = msg;
}

function resetUIForNewEmail() {
  setVerdictUI("—");
  setScoreUI("aiScore", null);
  setScoreUI("sublimeScore", null);
  setReasonsUI([], []);
  setQuarantineVisibility(null);
  disableReport(true);
  setStatus("New email selected. Ready to scan.");
}

function setVerdictUI(verdictText) {
  const el = document.getElementById("verdict");
  el.textContent = verdictText ?? "—";
  el.classList.remove("green", "orange", "red", "neutral");
  el.classList.add(colorClassForVerdict(verdictText));
}

function setScoreUI(id, score) {
  const el = document.getElementById(id);
  if (score === null || score === undefined || Number.isNaN(score)) {
    el.textContent = "—";
    el.classList.remove("green", "orange", "red");
    el.classList.add("neutral");
    return;
  }
  const v = Math.max(0, Math.min(100, Number(score)));
  el.textContent = `${v.toFixed(0)}%`;
  el.classList.remove("green", "orange", "red", "neutral");
  el.classList.add(colorClassForScore(v));
}

function setReasonsUI(reasons, indicators) {
  const ul = document.getElementById("reasons");
  ul.innerHTML = "";

  const allItems = [];
  if (indicators?.length) indicators.forEach(i => allItems.push({ text: i, type: "indicator" }));
  if (reasons?.length) reasons.forEach(r => r?.trim() && allItems.push({ text: r, type: "reason" }));

  if (!allItems.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No analysis details available.";
    ul.appendChild(li);
    return;
  }

  allItems.forEach(item => {
    const li = document.createElement("li");
    li.textContent = item.text;
    if (item.type === "indicator") li.style.color = "#ff9800";
    ul.appendChild(li);
  });
}

function colorClassForScore(score) {
  if (score >= 70) return "red";
  if (score >= 40) return "orange";
  return "green";
}

function colorClassForVerdict(v) {
  const s = (v || "").toLowerCase();
  if (s.includes("phish")) return "red";
  if (s.includes("susp")) return "orange";
  if (s.includes("safe") || s.includes("legit")) return "green";
  return "neutral";
}

function setQuarantineVisibility(verdict) {
  const section = document.getElementById("quarantineSection");
  const btn = document.getElementById("quarantineBtn");
  const v = (verdict || "").toUpperCase();

  if (v === "SUSPICIOUS" || v === "PHISHING") {
    section.classList.remove("hidden");
    btn.disabled = false;
    btn.innerHTML = "🛡️ Move to Quarantine";
  } else {
    section.classList.add("hidden");
  }
}

function disableReport(disabled) {
  document.getElementById("reportBtn").disabled = !!disabled;
}

// ================= ITEM CHANGE HANDLING =================
function hookItemChanged() {
  if (itemChangedHooked) return;
  itemChangedHooked = true;

  const mailbox = Office.context.mailbox;
  if (!mailbox?.addHandlerAsync) return;

  mailbox.addHandlerAsync(Office.EventType.ItemChanged, onItemChanged);
}

function onItemChanged() {
  const item = Office.context.mailbox.item;
  const itemId = item?.itemId || null;

  if (!itemId || itemId === lastItemId) return;

  lastItemId = itemId;
  activeScanItemId = null;

  resetUIForNewEmail();

  if (autoMode) {
    scanCurrentEmail();
  }
}

// ================= SCANNING =================
async function scanCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item || !item.itemId) return;

  const scanItemId = item.itemId;
  activeScanItemId = scanItemId;

  disableReport(true);
  setStatus("Extracting email...");

  try {
    const eml = await getEmlFromItem(item);
    const attachments = await getAttachmentsMetadata(item);

    setStatus("Analyzing...");

    const res = await fetch(`${API_BASE}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eml, attachments })
    });

    if (!res.ok) throw new Error(`Analyze failed (${res.status})`);
    const data = await res.json();

    // 🚨 Email changed mid-scan → discard
    if (activeScanItemId !== scanItemId) return;

    setVerdictUI(data.verdict);
    setScoreUI("aiScore", data.ai_score);
    setScoreUI("sublimeScore", data.sublime_score);
    setReasonsUI(data.reasons || [], data.indicators || []);
    setQuarantineVisibility(data.verdict);

    disableReport(false);
    setStatus("Scan complete.");
  } catch (err) {
    console.error(err);
    if (activeScanItemId !== scanItemId) return;
    setStatus(`Error: ${err.message}`);
    resetUIForNewEmail();
  }
}

// ================= REPORT =================
async function reportCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item) return;

  disableReport(true);
  setStatus("Reporting...");

  try {
    const eml = await getEmlFromItem(item);
    const attachments = await getAttachmentsMetadata(item);

    const res = await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eml, attachments })
    });

    if (!res.ok) throw new Error(`Report failed (${res.status})`);
    setStatus("Reported successfully.");
  } catch (err) {
    console.error(err);
    setStatus(`Report error: ${err.message}`);
  } finally {
    disableReport(false);
  }
}

// ================= EML =================
async function getEmlFromItem(item) {
  const pseudo = await buildPseudoEml(item);
  return `__BASE64_EML__:${btoa(unescape(encodeURIComponent(pseudo)))}`;
}

async function buildPseudoEml(item) {
  let headers = "";
  try {
    if (item.getAllInternetHeadersAsync) {
      headers = await getAsyncProm(item, item.getAllInternetHeadersAsync, {});
    }
  } catch {}

  const bodyText = await getAsyncProm(item, item.body.getAsync, { coercionType: Office.CoercionType.Text }).catch(() => "");
  const bodyHtml = await getAsyncProm(item, item.body.getAsync, { coercionType: Office.CoercionType.Html }).catch(() => "");

  const subject = item.subject || "";
  const from = item.from?.emailAddress || "";
  const to = (item.to || []).map(x => x.emailAddress).join(", ");
  const boundary = "----=_NextPart_" + Date.now().toString(36);

  let eml = `From: ${from}
To: ${to}
Subject: ${subject}
${headers || ""}
MIME-Version: 1.0`;

  if (bodyHtml) {
    eml += `
Content-Type: multipart/alternative; boundary="${boundary}"

--${boundary}
Content-Type: text/plain; charset="utf-8"

${bodyText}

--${boundary}
Content-Type: text/html; charset="utf-8"

${bodyHtml}

--${boundary}--`;
  } else {
    eml += `
Content-Type: text/plain; charset="utf-8"

${bodyText}`;
  }

  return eml;
}

// ================= ATTACHMENTS =================
async function getAttachmentsMetadata(item) {
  return (item.attachments || []).map(a => ({
    name: a.name || "unknown",
    size: a.size || 0,
    contentType: a.contentType || "application/octet-stream",
    isInline: a.isInline || false
  }));
}

// ================= PROMISIFY =================
function getAsyncProm(item, method, opts) {
  return new Promise((resolve, reject) => {
    method.call(item, opts, res => {
      res.status === Office.AsyncResultStatus.Succeeded
        ? resolve(res.value)
        : reject(res.error);
    });
  });
}
