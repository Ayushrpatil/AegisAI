import "./styles.css";
import { scanSolidity } from "./scanner.js";
import { fixedSample, vulnerableSample } from "./samples.js";

const app = document.querySelector("#app");
app.innerHTML = `
  <header class="topbar">
    <a class="brand" href="#"><span class="brand-mark">A</span><span>AegisAI</span></a>
    <nav class="topnav" aria-label="Primary navigation">
      <a href="#scanner">Scanner</a>
      <a href="#findings">Findings</a>
      <a href="#method">Method</a>
    </nav>
    <span class="prototype-pill"><i></i> Local analysis ready</span>
  </header>
  <main>
    <section class="hero">
      <div class="hero-title">
        <p class="eyebrow">Explainable smart-contract security</p>
        <h1>Find the weakness.<br><em>Understand the fix.</em></h1>
      </div>
      <div class="hero-aside">
        <p class="hero-copy">Scan Solidity for eleven high-value vulnerability patterns. Every result includes source evidence, an attack path, and constrained remediation guidance.</p>
        <div class="hero-proof" aria-label="Scanner capabilities">
          <div><strong>11</strong><span>focused detectors</span></div>
          <div><strong>0.4–0.8</strong><span>Solidity support</span></div>
          <div><strong>98.5%</strong><span>dataset recall</span></div>
        </div>
      </div>
    </section>
    <section class="scanner-shell" id="scanner">
      <div class="editor-panel">
        <div class="panel-heading">
          <div class="panel-title"><span class="step-number">01</span><div><p class="eyebrow">Input</p><h2>Solidity contract</h2></div></div>
          <div class="sample-actions">
            <label class="upload-button" for="source-file">Upload .sol files</label>
            <input id="source-file" class="sr-only" type="file" multiple accept=".sol,.txt,text/plain" />
            <button class="text-button" id="load-vulnerable">Vulnerable sample</button>
            <button class="text-button" id="load-fixed">Fixed sample</button>
          </div>
        </div>
        <div class="editor-chrome"><span><i></i> Source workspace</span><span>Local only</span></div>
        <label class="sr-only" for="source">Solidity source code</label>
        <textarea id="source" spellcheck="false"></textarea>
        <div class="editor-footer">
          <span id="source-stats">0 lines</span>
          <button class="scan-button" id="scan">Run security scan <span>→</span></button>
        </div>
      </div>
      <aside class="summary-panel" aria-live="polite">
        <div class="summary-heading"><span class="step-number">02</span><div><p class="eyebrow">Scan status</p><h2 id="status-title">Ready to analyze</h2><p id="status-copy">Upload or paste one Solidity source file.</p></div></div>
        <div class="engine-status"><span>Analysis engine</span><strong id="engine-name">Waiting</strong></div>
        <div class="score-wrap">
          <div class="score-ring" id="score-ring"><strong id="score">—</strong><span>risk score</span></div>
          <p>Prioritized from deterministic evidence, not probabilistic guesses.</p>
        </div>
        <dl class="summary-grid">
          <div><dt>High</dt><dd id="high-count">—</dd></div>
          <div><dt>Medium</dt><dd id="medium-count">—</dd></div>
          <div><dt>Scan time</dt><dd id="scan-time">—</dd></div>
        </dl>
        <div class="report-actions">
          <button class="download-button" id="download" disabled>Download JSON report</button>
          <button class="download-button" id="download-html" disabled>Download HTML report</button>
        </div>
      </aside>
    </section>
    <section class="results-section" id="findings">
      <div class="results-heading">
        <div><p class="eyebrow">03 · Evidence-linked report</p><h2>Security findings</h2></div>
        <p>Guidance explains deterministic findings; it does not prove safety.</p>
      </div>
      <div id="results" class="results-list">
        <div class="empty-state"><span>01</span><h3>No scan run yet</h3><p>Your prioritized findings will appear here.</p></div>
      </div>
    </section>
    <section class="trust-section" id="method">
      <div class="section-kicker"><p class="eyebrow">How AegisAI reasons</p><span>Transparent by design</span></div>
      <div class="trust-grid">
        <article><span>01</span><h3>Deterministic detection</h3><p>Rules own the security signal and always cite the triggering source lines.</p></article>
        <article><span>02</span><h3>Constrained explanation</h3><p>Reviewed templates translate evidence into plain-language attack paths and fixes.</p></article>
        <article><span>03</span><h3>Explicit limitations</h3><p>AegisAI is an educational triage tool, not a substitute for a professional audit.</p></article>
      </div>
    </section>
  </main>
  <footer><span>AegisAI v0.1</span><span>Local-first · No source code is uploaded</span></footer>
`;

const source = document.querySelector("#source");
const results = document.querySelector("#results");
const downloadButton = document.querySelector("#download");
const htmlDownloadButton = document.querySelector("#download-html");
const fileInput = document.querySelector("#source-file");
let lastReport = null;
let sourceName = "Pasted source";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function updateSourceStats() {
  const lines = source.value ? source.value.split(/\r?\n/).length : 0;
  document.querySelector("#source-stats").textContent =
    `${sourceName} · ${lines} line${lines === 1 ? "" : "s"}`;
}

function loadSample(sample) {
  sourceName = sample === vulnerableSample ? "VulnerableVault.sol" : "SaferVault.sol";
  source.value = sample;
  updateSourceStats();
  source.focus();
}

async function loadSourceFiles(fileList) {
  const files = [...(fileList || [])];
  if (!files.length) return;
  if (files.some((file) => !["sol", "txt"].includes(file.name.split(".").pop()?.toLowerCase()))) {
    document.querySelector("#status-title").textContent = "Unsupported file";
    document.querySelector("#status-copy").textContent = "Choose a Solidity .sol file or plain-text .txt file.";
    fileInput.value = "";
    return;
  }
  if (files.some((file) => file.size > 1024 * 1024) || files.reduce((sum, file) => sum + file.size, 0) > 2 * 1024 * 1024) {
    document.querySelector("#status-title").textContent = "File is too large";
    document.querySelector("#status-copy").textContent = "The local prototype accepts files up to 1 MB.";
    fileInput.value = "";
    return;
  }
  const contents = await Promise.all(files.map((file) => file.text()));
  sourceName = files.length === 1 ? files[0].name : `${files.length} Solidity files`;
  source.value = contents.map((content, index) => `// ===== ${files[index].name} =====\n${content}`).join("\n\n");
  updateSourceStats();
  document.querySelector("#status-title").textContent = files.length === 1 ? "Contract loaded" : "Project files loaded";
  document.querySelector("#status-copy").textContent = `${files.map((file) => file.name).join(", ")} ready for analysis.`;
}

function renderFinding(item, index) {
  const evidence = item.evidence.map((line) => `
    <div class="evidence-line"><span>${line.number}</span><code>${escapeHtml(line.text)}</code></div>
  `).join("");
  return `
    <article class="finding-card">
      <div class="finding-index">${String(index + 1).padStart(2, "0")}</div>
      <div class="finding-body">
        <div class="finding-title">
          <div><span class="severity ${item.severity}">${item.severity}</span><span class="rule-id">${item.ruleId}</span><h3>${escapeHtml(item.title)}</h3></div>
          <span class="confidence">${Math.round(item.confidence * 100)}% confidence</span>
        </div>
        <div class="evidence-block"><p>Source evidence</p>${evidence}</div>
        <div class="finding-explanation">
          <div><h4>Why it matters</h4><p>${escapeHtml(item.explanation)}</p></div>
          <div><h4>Likely attack path</h4><p>${escapeHtml(item.attackPath)}</p></div>
        </div>
        <div class="remediation">
          <div><span>Template-guided remediation</span><p>${escapeHtml(item.remediation)}</p></div>
          <pre><code>${escapeHtml(item.fixedExample)}</code></pre>
        </div>
      </div>
    </article>`;
}

async function runScan() {
  if (!source.value.trim()) {
    document.querySelector("#status-title").textContent = "Source required";
    document.querySelector("#status-copy").textContent = "Paste Solidity code before running a scan.";
    source.focus();
    return;
  }
  const scanButton = document.querySelector("#scan");
  scanButton.disabled = true;
  scanButton.firstChild.textContent = "Compiling and scanning ";
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: source.value, filename: sourceName })
    });
    if (!response.ok) throw new Error(`Analyzer API returned ${response.status}`);
    lastReport = await response.json();
  } catch {
    lastReport = {
      sourceName,
      engine: "Browser rule fallback",
      compiler: { available: false, diagnostics: [] },
      ...scanSolidity(source.value)
    };
  } finally {
    scanButton.disabled = false;
    scanButton.firstChild.textContent = "Run security scan ";
  }
  const score = Math.min(100, lastReport.counts.high * 32 + lastReport.counts.medium * 18);
  document.querySelector("#score").textContent = score;
  document.querySelector("#score-ring").style.setProperty("--score", `${score * 3.6}deg`);
  document.querySelector("#high-count").textContent = lastReport.counts.high;
  document.querySelector("#medium-count").textContent = lastReport.counts.medium;
  document.querySelector("#scan-time").textContent = `${lastReport.durationMs} ms`;
  document.querySelector("#engine-name").textContent = lastReport.engine || lastReport.scanner;
  document.querySelector("#status-title").textContent = lastReport.findings.length
    ? `${lastReport.findings.length} finding${lastReport.findings.length === 1 ? "" : "s"} detected`
    : "No supported patterns found";
  const compilerErrors = lastReport.compiler?.diagnostics?.filter((item) => item.severity === "error") || [];
  document.querySelector("#status-copy").textContent = compilerErrors.length
    ? `${compilerErrors.length} Solidity compiler error${compilerErrors.length === 1 ? "" : "s"} found. Review the report before security findings.`
    : lastReport.findings.length
      ? "The contract compiled. Review high-severity evidence before deployment."
      : "The contract compiled and passed this narrow scan. Unsupported vulnerability classes may still exist.";
  downloadButton.disabled = false;
  htmlDownloadButton.disabled = false;
  const diagnostics = (lastReport.compiler?.diagnostics || []).map((item) => `
    <article class="compiler-diagnostic ${item.severity}">
      <span>${escapeHtml(item.severity)}</span>
      <div><h3>Solidity compiler</h3><p>${escapeHtml(item.formattedMessage || item.message)}</p></div>
    </article>
  `).join("");
  const findingMarkup = lastReport.findings.length
    ? lastReport.findings.map(renderFinding).join("")
    : `<div class="empty-state safe"><span>✓</span><h3>No supported patterns detected</h3><p>This is not proof that the contract is secure. Continue with testing and professional review.</p></div>`;
  results.innerHTML = diagnostics + findingMarkup;
}

source.addEventListener("input", updateSourceStats);
source.addEventListener("input", () => {
  if (!source.value) sourceName = "Pasted source";
});
fileInput.addEventListener("change", () => loadSourceFiles(fileInput.files));
document.querySelector("#load-vulnerable").addEventListener("click", () => loadSample(vulnerableSample));
document.querySelector("#load-fixed").addEventListener("click", () => loadSample(fixedSample));
document.querySelector("#scan").addEventListener("click", runScan);
downloadButton.addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `aegisai-report-${Date.now()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});

htmlDownloadButton.addEventListener("click", () => {
  if (!lastReport) return;
  const sections = lastReport.findings.map((item) => `
    <section><h2>${escapeHtml(item.severity.toUpperCase())}: ${escapeHtml(item.title)}</h2>
    <p><strong>Rule:</strong> ${escapeHtml(item.ruleId)} · ${Math.round(item.confidence * 100)}% confidence</p>
    <h3>Evidence</h3><pre>${item.evidence.map((line) => `${line.number}: ${escapeHtml(line.text)}`).join("\n")}</pre>
    <h3>Why it matters</h3><p>${escapeHtml(item.explanation)}</p>
    <h3>Attack path</h3><p>${escapeHtml(item.attackPath)}</p>
    <h3>Remediation</h3><p>${escapeHtml(item.remediation)}</p>
    <pre>${escapeHtml(item.fixedExample)}</pre></section>`).join("");
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>AegisAI report</title>
    <style>body{font:16px/1.5 system-ui;max-width:900px;margin:40px auto;padding:0 24px;color:#10251e}section{border-top:1px solid #9aaba4;padding:24px 0}pre{white-space:pre-wrap;background:#eef2ec;padding:16px}small{color:#60756d}@media print{body{margin:0}}</style>
    </head><body><h1>AegisAI Security Report</h1>
    <p><strong>Source:</strong> ${escapeHtml(lastReport.sourceName || sourceName)}</p>
    <p><strong>Engine:</strong> ${escapeHtml(lastReport.engine || lastReport.scanner)}</p>
    <p><strong>Summary:</strong> ${lastReport.counts.high} high, ${lastReport.counts.medium} medium findings.</p>
    ${sections || "<p>No supported patterns were detected. This does not prove safety.</p>"}
    <small>Educational triage report; not a substitute for a professional audit.</small></body></html>`;
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `aegisai-report-${Date.now()}.html`;
  anchor.click();
  URL.revokeObjectURL(url);
});

updateSourceStats();
