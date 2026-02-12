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
  if (id === "sublimeScore") {
  el.classList.add(colorClassForSublime(v));} 
  else {
  el.classList.add(colorClassForConfidence(v, verdictText));}
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

function colorClassForSublime(score) {
  // Sublime: LOWER = better

  if (score < 40) return "green";     // Safe
  if (score < 70) return "orange";    // Suspicious
  return "red";                       // High risk
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
    const vt_attachments = await getVirusTotalAttachmentHashes(item);

    setStatus("Analyzing...");

    const res = await fetch(`${API_BASE}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eml, attachments, vt_attachments })
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
    // CHANGE 1: Use TextEncoder for Unicode-safe base64 encoding.
    // The previous btoa(unescape(encodeURIComponent(...))) approach silently corrupts
    // or truncates strings containing Unicode characters (curly quotes, em-dashes,
    // non-breaking spaces, etc.) that are common in HTML email bodies from Outlook.
    // TextEncoder converts the full string to a proper UTF-8 byte array first,
    // ensuring the MIME boundaries in the HTML part are never corrupted.
    const encoder = new TextEncoder();
    const bytes = encoder.encode(pseudo);
    let binary = "";
    bytes.forEach(b => binary += String.fromCharCode(b));
    const base64 = btoa(binary);
    return `__BASE64_EML__:${base64}`;
  } catch (err) {
    console.error("Failed to build EML:", err);
    throw new Error("Could not extract email content");
  }
}

// ================= BODY EXTRACTION WITH PROPER ERROR HANDLING =================
async function getBodyWithRetry(item, coercionType, retries = 3, delay = 300) {
  let lastError = null;
  
  for (let i = 0; i < retries; i++) {
    try {
      const body = await new Promise((resolve, reject) => {
        item.body.getAsync(coercionType, (result) => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            resolve(result.value || "");
          } else {
            reject(new Error(result.error?.message || "Body extraction failed"));
          }
        });
      });
      
      // Return body even if empty (empty is valid)
      return body;
    } catch (err) {
      lastError = err;
      console.warn(`Body extraction attempt ${i + 1} failed:`, err);
      if (i < retries - 1) {
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }
  
  console.error("All body extraction attempts failed:", lastError);
  return ""; // Return empty string as fallback
}

async function buildPseudoEml(item) {
  // Get transport headers
  let transportHeaders = "";
  try {
    if (typeof item.getAllInternetHeadersAsync === "function") {
      transportHeaders = await getAsyncProm(item, item.getAllInternetHeadersAsync, {});
    }
  } catch (err) {
    console.warn("Could not get transport headers:", err);
  }

  // Get email body in BOTH formats
  const bodyText = await getBodyWithRetry(item, Office.CoercionType.Text);
  const bodyHtml = await getBodyWithRetry(item, Office.CoercionType.Html);

  // Get basic headers
  const subject = item.subject || "(No Subject)";
  const from = item.from?.emailAddress || item.from?.displayName || "unknown@unknown.com";
  const to = (item.to || []).map(x => x.emailAddress || x.displayName).join(", ") || "undisclosed-recipients";
  const date = item.dateTimeCreated
  ? new Date(item.dateTimeCreated).toUTCString()
  : "Thu, 01 Jan 1970 00:00:00 GMT";

  const messageId = item.internetMessageId || `<static-fallback@outlook.com>`;

  // Get attachment metadata (for VirusTotal check)
  const attachments = await getAttachmentsMetadata(item);

  // FILTER transport headers to remove problematic encoded headers
  const forbiddenHeaders = [
    'from', 'to', 'subject', 'date', 'message-id',
    'mime-version', 'content-type', 'content-transfer-encoding',
    'x-microsoft-antispam',  // Problematic for Sublime (but Sublime won't see these anyway)
    'dkim-signature',
    'arc-'
  ];
  // CHANGE 3: The forbidden header names above are stored WITHOUT trailing colons.
  // The filter extracts headerName as line.split(':')[0].toLowerCase() which also has
  // no colon, so headerName.startsWith(h) now correctly matches and blocks duplicate
  // MIME-Version / Content-Type headers from transport headers bleeding into the EML.
  // Previously the colon mismatch ('mime-version' vs 'mime-version:') meant these
  // headers were never filtered, causing Python's email parser to find a duplicate
  // Content-Type header and collapse the multipart structure to plain text.
  
  let cleanHeaders = '';
  if (transportHeaders && transportHeaders.trim()) {
    const headerLines = transportHeaders.split('\n');
    let skipSection = false;
    
    cleanHeaders = headerLines
      .filter(line => {
        const lower = line.toLowerCase().trim();
        
        const isNewHeader = line.length > 0 && 
                           line.includes(':') && 
                           !line.startsWith(' ') && 
                           !line.startsWith('\t');
        
        if (isNewHeader) {
          const headerName = line.split(':')[0].toLowerCase();
          
          // Skip forbidden headers
          if (forbiddenHeaders.some(h => headerName.startsWith(h))) {
            skipSection = true;
            return false;
          }
          
          // Skip headers with RFC 2047 encoding
          if (line.includes('=?') && line.includes('?=')) {
            skipSection = true;
            return false;
          }
          
          skipSection = false;
        }
        
        if (skipSection) return false;
        
        // Skip RFC 2047 encoded continuations
        if (line.includes('=?') && line.includes('?=')) {
          return false;
        }
        
        // Skip empty lines or base64-looking lines
        if (!line.trim() || /^[A-Za-z0-9+/=]{60,}$/.test(line)) {
          return false;
        }
        
        return true;
      })
      .join('\n');
    
    if (cleanHeaders.includes("\nAttachments:\n")) {
      cleanHeaders = cleanHeaders.split("\nAttachments:\n")[0];
    }
  }

  // Build RFC822 with BOTH text and HTML
  const stableId =
  item.internetMessageId ||
  item.itemId ||
  item.conversationId ||
  `${item.subject || ""}_${item.from?.emailAddress || ""}`;

  const boundary = "----=_NextPart_" + btoa(unescape(encodeURIComponent(stableId))).replace(/[^A-Za-z0-9]/g, "").slice(0, 24);

  
  let eml = `From: ${from}
To: ${to}
Subject: ${subject}
Date: ${date}
Message-ID: ${messageId}
`;

  // Add filtered headers
  if (cleanHeaders.trim()) {
    eml += cleanHeaders.trim() + '\n';
  }

  // Add MIME structure with BOTH text and HTML
  if (bodyHtml && bodyHtml.trim()) {
    // Multipart email with both text and HTML
    eml += `MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="${boundary}"

`;

    // Text part
    // CHANGE 2a: Use 8bit instead of 7bit for the plain text part.
    // 7bit declares all content is ASCII with lines <=998 chars, which is often false
    // for Outlook emails. 8bit tells Python's email parser to treat the payload as
    // raw bytes that may contain high bytes, which matches how we decode it on the
    // server side with .decode("utf-8", errors="replace").
    eml += `--${boundary}
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

${bodyText || ""}

`;

    // HTML part
    // CHANGE 2b: Use 8bit instead of 7bit for the HTML part.
    // This is the critical fix for the missing HTML body: HTML from Outlook routinely
    // contains Unicode characters and long lines that violate the 7bit constraint.
    // With 7bit declared, Python's email library may misread the payload boundaries,
    // causing get_payload(decode=True) to return nothing or truncated content.
    eml += `--${boundary}
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 8bit

${bodyHtml}

--${boundary}--
`;

  } else {
    // Plain text only
    eml += `MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

${bodyText || ""}
`;
  }

  return eml;
}

// Updated attachment metadata function
async function getAttachmentsMetadata(item) {
  if (!item.attachments || item.attachments.length === 0) {
    return [];
  }

  // Get attachment details
  const attachments = [];
  
  for (const attachment of item.attachments) {
    try {
      // For Outlook attachments, we can get metadata but not content
      // The backend will need to use the SHA256 hash we compute
      const metadata = {
        name: attachment.name || "unknown",
        size: attachment.size || 0,
        contentType: attachment.contentType || "application/octet-stream",
        isInline: attachment.isInline || false,
        id: attachment.id || null
      };

      // Note: We can't easily get the attachment content from Outlook Web Add-in
      // The backend will need to handle this differently
      // Options:
      // 1. Backend extracts attachments from the raw EML
      // 2. We send attachment IDs and backend fetches via Graph API
      // 3. We fetch attachment content here (requires getAttachmentContentAsync)
      
      attachments.push(metadata);
    } catch (err) {
      console.warn(`Failed to get attachment metadata for ${attachment.name}:`, err);
    }
  }

  return attachments;
}

// --- VT attachment hashing helpers (additive) ---

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes.buffer;
}

async function sha256Hex(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Compute SHA256 hashes for attachments for VirusTotal lookup.
 * - Does NOT change your existing "attachments" payload
 * - Returns a separate array for "vt_attachments"
 */
async function getVirusTotalAttachmentHashes(item, options = {}) {
  const MAX_ATTACHMENTS = options.maxAttachments ?? 3;
  const MAX_SIZE_BYTES = options.maxSizeBytes ?? (5 * 1024 * 1024); // 5MB
  const SKIP_INLINE = options.skipInline ?? true;

  if (!item?.attachments || item.attachments.length === 0) return [];

  // Some Outlook clients may not support getAttachmentContentAsync reliably
  if (typeof item.getAttachmentContentAsync !== "function") {
    console.warn("getAttachmentContentAsync not available on this client; skipping vt_attachments.");
    return [];
  }

  const vt = [];
  const candidates = item.attachments
    .filter(a => (SKIP_INLINE ? !a.isInline : true))
    .slice(0, MAX_ATTACHMENTS);

  for (const att of candidates) {
    try {
      const filename = att.name || "unknown";
      const size = att.size || 0;
      const contentType = att.contentType || "application/octet-stream";
      const id = att.id || null;

      if (!id) continue;
      if (size > MAX_SIZE_BYTES) {
        console.warn(`Skipping VT hash (too large): ${filename} (${size} bytes)`);
        continue;
      }

      const content = await new Promise((resolve) => {
        item.getAttachmentContentAsync(id, (res) => {
          if (res.status === Office.AsyncResultStatus.Succeeded) resolve(res.value);
          else resolve(null);
        });
      });

      if (!content) continue;

      // We only support Base64 attachments for hashing here
      if (content.format !== Office.MailboxEnums.AttachmentContentFormat.Base64) {
        console.warn(`Skipping unsupported attachment format for ${filename}:`, content.format);
        continue;
      }

      const buffer = base64ToArrayBuffer(content.content);
      const sha256 = await sha256Hex(buffer);

      vt.push({ filename, size, contentType, sha256 });
    } catch (e) {
      console.warn("Failed to hash attachment for VT:", att?.name, e);
    }
  }

  return vt;
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

/* =====================================================================
   TEMP DEBUG EML BUILDER (DELETE AFTER TESTING)
   This section adds a debug button that shows the COMPLETE EML
   that will be sent to Sublime API.
===================================================================== */

Office.onReady(() => {
  const debugBtn = document.getElementById("debugExtractBtn");
  if (!debugBtn) return;

  debugBtn.addEventListener("click", debugShowEML);
});

async function debugShowEML() {
  const item = Office.context.mailbox.item;
  const outputBox = document.getElementById("debugOutput");
  const outputText = document.getElementById("debugText");

  if (!item) {
    outputText.textContent = "No email selected.";
    outputBox.classList.remove("hidden");
    return;
  }

  outputText.textContent = "Building EML...\n";
  outputBox.classList.remove("hidden");

  try {
    // 🔨 Build the EXACT EML that will be sent
    const eml = await buildPseudoEml(item);

    // 🧪 Display the complete EML structure
    outputText.textContent =
`===== COMPLETE EML STRUCTURE =====
Total Length: ${eml.length} characters

${eml}

===== END OF EML =====

📋 Copy this output to verify:
- Blank line exists after headers?
- MIME boundaries match?
- Content-Transfer-Encoding correct?
- No duplicate headers?`;

  } catch (err) {
    outputText.textContent = "EML build failed:\n" + err.message + "\n\n" + err.stack;
    console.error("Debug EML error:", err);
  }
}

/* ================= END TEMP DEBUG EML BUILDER ================= */