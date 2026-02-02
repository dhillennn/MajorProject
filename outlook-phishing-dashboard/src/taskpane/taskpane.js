// ================= CONFIG =================
const API_BASE = "https://majorproject-production-a975.up.railway.app";
const POLL_INTERVAL = 500; // Check every 500ms for item changes

// ================= STATE =================
let autoMode = false;
let lastItemId = null;
let activeScanItemId = null;
let listenersAttached = false;
let itemChangedHooked = false;
let pollTimer = null;

// ================= INIT =================
Office.onReady(() => {
  if (listenersAttached) return;
  listenersAttached = true;

  const scanBtn = document.getElementById("scanBtn");
  const reportBtn = document.getElementById("reportBtn");
  const quarantineBtn = document.getElementById("quarantineBtn");
  const autoToggle = document.getElementById("autoToggle");

  // Remove any existing listeners first
  if (scanBtn) {
    const newScanBtn = scanBtn.cloneNode(true);
    scanBtn.parentNode.replaceChild(newScanBtn, scanBtn);
    newScanBtn.addEventListener("click", scanCurrentEmail);
  }

  if (reportBtn) {
    const newReportBtn = reportBtn.cloneNode(true);
    reportBtn.parentNode.replaceChild(newReportBtn, reportBtn);
    newReportBtn.addEventListener("click", reportCurrentEmail);
  }

  if (quarantineBtn) {
    const newQuarantineBtn = quarantineBtn.cloneNode(true);
    quarantineBtn.parentNode.replaceChild(newQuarantineBtn, quarantineBtn);
    newQuarantineBtn.addEventListener("click", quarantineCurrentEmail);
  }

  if (autoToggle) {
    const newAutoToggle = autoToggle.cloneNode(true);
    autoToggle.parentNode.replaceChild(newAutoToggle, autoToggle);
    newAutoToggle.addEventListener("change", (e) => {
      autoMode = e.target.checked;
      setStatus(autoMode ? "Auto mode enabled." : "Auto mode disabled.");

      if (autoMode) {
        hookItemChanged();
        resetUIForNewEmail();
        scanCurrentEmail();
        startPolling();
      } else {
        stopPolling();
      }
    });
  }

  // Hook ItemChanged so Office.context.mailbox.item updates properly when selecting emails
  hookItemChanged();
  // Don't start polling by default - only when auto mode is enabled
  setStatus("Ready.");
});

// ================= POLLING FOR PREVIEW CHANGES =================
function startPolling() {
  if (pollTimer) return;
  
  pollTimer = setInterval(() => {
    checkForItemChange();
  }, POLL_INTERVAL);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function checkForItemChange() {
  const item = Office.context.mailbox.item;
  const itemId = item?.itemId || item?.conversationId || null;

  // Skip if no valid ID
  if (!itemId) return;
  
  // Create signature for comparison
  const subject = item.subject || "";
  const from = item.from?.emailAddress || "";
  const emailSignature = `${itemId}_${subject}_${from}`;
  
  // Skip if same item
  if (emailSignature === lastItemId) return;
  
  // Skip if scan is actively processing the previous item
  if (activeScanItemId === lastItemId) {
    console.log("Scan in progress for previous item");
    return;
  }

  // New item detected
  console.log("ItemChanged detected - new email selected");
  lastItemId = emailSignature;
  activeScanItemId = null;
  
  // Always reset UI when email changes
  resetUIForNewEmail();

  // Only auto-scan if in auto mode
  if (autoMode) {
    scanCurrentEmail();
  }
}

// ================= UI HELPERS =================
function setStatus(msg) {
  const el = document.getElementById("status");
  if (el) el.textContent = msg;
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
  if (!el) return;
  el.textContent = verdictText ?? "—";
  el.classList.remove("green", "orange", "red", "neutral");
  el.classList.add(colorClassForVerdict(verdictText));
}

function setScoreUI(id, score) {
  const el = document.getElementById(id);
  if (!el) return;
  if (score === null || score === undefined || Number.isNaN(score)) {
    el.textContent = "—";
    el.classList.remove("green", "orange", "red");
    el.classList.add("neutral");
    return;
  }
  const v = Math.max(0, Math.min(100, Number(score)));
  el.textContent = `${v.toFixed(0)}%`;

  // Get current verdict text
  const verdictText = document.getElementById("verdict")?.textContent;

  el.classList.remove("green", "orange", "red", "neutral");
  el.classList.add(colorClassForConfidence(v, verdictText));
}

function setReasonsUI(reasons, indicators) {
  const ul = document.getElementById("reasons");
  if (!ul) return;
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

function colorClassForConfidence(score, verdict) {
  const v = (verdict || "").toLowerCase();

  // Low confidence is always warning
  if (score < 40) return "orange";

  // Medium confidence is caution
  if (score < 70) return "orange";

  // High confidence → follow verdict
  if (v.includes("phish")) return "red";
  if (v.includes("susp")) return "orange";
  if (v.includes("safe") || v.includes("legit")) return "green";

  return "neutral";
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
  if (!section || !btn) return;
  
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
  const btn = document.getElementById("reportBtn");
  if (btn) btn.disabled = !!disabled;
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
  checkForItemChange();
}

// ================= SCANNING =================
async function scanCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item) {
    console.log("No item found");
    setStatus("No email selected.");
    return;
  }

  // Use multiple identifiers to detect email changes
  const scanItemId = item.itemId || item.conversationId || item.internetMessageId || Date.now().toString();
  const subject = item.subject || "";
  const from = item.from?.emailAddress || "";
  
  // Create a unique identifier combining multiple properties
  const emailSignature = `${scanItemId}_${subject}_${from}`;
  
  console.log("Scan requested for:", scanItemId);
  console.log("Subject:", subject);
  console.log("From:", from);
  console.log("Email signature:", emailSignature);
  console.log("Last scanned:", lastItemId);
  console.log("Currently scanning:", activeScanItemId);
  
  // Prevent duplicate scans of the SAME email
  if (activeScanItemId === emailSignature) {
    console.log("Scan already in progress for this email");
    return;
  }
  
  // Update tracking
  lastItemId = emailSignature;
  activeScanItemId = emailSignature;
  
  console.log("Starting scan for:", emailSignature);

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
    if (activeScanItemId !== emailSignature) {
      console.log("Email changed during scan, discarding results");
      return;
    }

    setVerdictUI(data.verdict);
    setScoreUI("aiScore", data.ai_score);
    setScoreUI("sublimeScore", data.sublime_score);
    setReasonsUI(data.reasons || [], data.indicators || []);
    setQuarantineVisibility(data.verdict);

    disableReport(false);
    activeScanItemId = null; // Clear so same email can be rescanned if needed
    setStatus("Scan complete.");
  } catch (err) {
    console.error(err);
    if (activeScanItemId !== emailSignature) {
      console.log("Email changed during scan, discarding error");
      return;
    }
    activeScanItemId = null; // Clear on error
    setStatus(`Error: ${err.message}`);
    resetUIForNewEmail();
  }
}

// ================= REPORT =================
async function reportCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item) return;

  const reportBtn = document.getElementById("reportBtn");
  if (!reportBtn) return;

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

// ================= QUARANTINE =================
async function quarantineCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item) {
    setStatus("No email item found.");
    return;
  }

  const btn = document.getElementById("quarantineBtn");
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-icon">⏳</span> Moving...';
  setStatus("Moving to quarantine...");

  try {
    const itemId = item.itemId;
    if (!itemId) {
      throw new Error("Cannot get email ID");
    }

    await moveToQuarantineEWS(itemId);

    btn.classList.add("success");
    btn.innerHTML = '<span class="btn-icon">✓</span> Quarantined';
    setStatus("Email moved to Quarantine folder.");

    try {
      const eml = await getEmlFromItem(item);
      await fetch(`${API_BASE}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ eml, quarantined: true })
      });
    } catch (reportErr) {
      console.warn("Auto-report after quarantine failed:", reportErr);
    }

  } catch (err) {
    console.error("Quarantine error:", err);
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">🛡️</span> Move to Quarantine';
    setStatus(`Quarantine failed: ${err.message}`);
  }
}

function moveToQuarantineEWS(itemId) {
  return new Promise((resolve, reject) => {
    const ewsId = convertToEwsId(itemId);

    const soapRequest = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013"/>
  </soap:Header>
  <soap:Body>
    <m:MoveItem>
      <m:ToFolderId>
        <t:DistinguishedFolderId Id="junkemail"/>
      </m:ToFolderId>
      <m:ItemIds>
        <t:ItemId Id="${ewsId}"/>
      </m:ItemIds>
    </m:MoveItem>
  </soap:Body>
</soap:Envelope>`;

    Office.context.mailbox.makeEwsRequestAsync(soapRequest, (result) => {
      if (result.status === Office.AsyncResultStatus.Failed) {
        tryAlternativeMove(itemId).then(resolve).catch(reject);
        return;
      }

      const response = result.value;
      if (response.includes("ResponseClass=\"Success\"")) {
        resolve();
      } else if (response.includes("ErrorMoveCopyFailed") || response.includes("ErrorItemNotFound")) {
        reject(new Error("Email may have already been moved or deleted"));
      } else {
        tryAlternativeMove(itemId).then(resolve).catch(reject);
      }
    });
  });
}

function convertToEwsId(itemId) {
  if (itemId.startsWith("AAM")) return itemId;
  return itemId;
}

async function tryAlternativeMove(itemId) {
  return new Promise((resolve, reject) => {
    const item = Office.context.mailbox.item;
    if (Office.context.mailbox.restUrl) {
      moveViaRest(itemId)
        .then(resolve)
        .catch(() => reject(new Error("Could not move email. Please manually move to Junk folder.")));
    } else {
      reject(new Error("Move not supported. Please manually move to Junk folder."));
    }
  });
}

async function moveViaRest(itemId) {
  const restUrl = Office.context.mailbox.restUrl;
  const accessToken = await getAccessToken();

  const response = await fetch(`${restUrl}/v2.0/me/messages/${itemId}/move`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ DestinationId: "JunkEmail" })
  });

  if (!response.ok) {
    throw new Error(`REST move failed: ${response.status}`);
  }
}

function getAccessToken() {
  return new Promise((resolve, reject) => {
    Office.context.mailbox.getCallbackTokenAsync({ isRest: true }, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value);
      } else {
        reject(new Error("Could not get access token"));
      }
    });
  });
}

// ================= EML =================
async function getEmlFromItem(item) {
  try {
    const pseudo = await buildPseudoEml(item);
    const base64 = btoa(unescape(encodeURIComponent(pseudo)));
    return `__BASE64_EML__:${base64}`;
  } catch (err) {
    console.error("Failed to build EML:", err);
    throw new Error("Could not extract email content");
  }
}

async function buildPseudoEml(item) {
  let headers = "";
  try {
    if (typeof item.getAllInternetHeadersAsync === "function") {
      headers = await getAsyncProm(item, item.getAllInternetHeadersAsync, {});
    }
  } catch {}

  let bodyText = "";
  try {
    bodyText = await getAsyncProm(item, item.body.getAsync, { coercionType: Office.CoercionType.Text });
  } catch {}

  let bodyHtml = "";
  try {
    bodyHtml = await getAsyncProm(item, item.body.getAsync, { coercionType: Office.CoercionType.Html });
  } catch {}

  const subject = item.subject || "";
  const from = item.from?.emailAddress || item.from?.displayName || "";
  const to = (item.to || []).map(x => x.emailAddress || x.displayName).join(", ");
  const boundary = "----=_NextPart_" + Date.now().toString(36);

  let eml = `From: ${from}
To: ${to}
Subject: ${subject}
${headers ? headers.trim() : ""}
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

  // Remove Outlook's "Attachments:" summary that breaks RFC822 format
  // This is sometimes appended by getAllInternetHeadersAsync() in Outlook
  if (eml.includes("\nAttachments:\n")) {
    eml = eml.split("\nAttachments:\n")[0];
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