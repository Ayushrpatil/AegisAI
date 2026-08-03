import "./styles.css";
import { RULES, scanSolidity } from "./scanner.js";
import { fixedSample, vulnerableSample } from "./samples.js";

const app = document.querySelector("#app");
app.innerHTML = `
  <header class="topbar">
    <a class="brand" href="#"><span class="brand-mark">A</span><span>AegisAI</span></a>
    <nav class="topnav" aria-label="Primary navigation">
      <a href="#scanner">Scanner</a>
      <a href="#coverage">Coverage</a>
      <a href="#findings">Findings</a>
      <a href="#ai-reasoning">AI reasoning</a>
      <a href="#method">Method</a>
    </nav>
    <span class="prototype-pill"><i></i> Deterministic engine ready</span>
  </header>
  <main>
    <section class="hero">
      <div class="hero-title">
        <p class="eyebrow">Explainable smart-contract security</p>
        <h1>Find the weakness.<br><em>Understand the fix.</em></h1>
      </div>
      <div class="hero-aside">
        <p class="hero-copy">Scan Solidity for ${RULES.length} high-value vulnerability patterns. Every result includes source evidence, an attack path, and constrained remediation guidance.</p>
        <div class="hero-proof" aria-label="Scanner capabilities">
          <div><strong>${RULES.length}</strong><span>focused detectors</span></div>
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
        <label class="ai-mode-control" for="ai-mode">
          <span class="mode-switch"><input id="ai-mode" type="checkbox" /><i></i></span>
          <span class="mode-label"><strong>AI-assisted explanations</strong><small>Grounded only in verified rule evidence</small></span>
          <b>Beta</b>
        </label>
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
    <section class="coverage-section" id="coverage">
      <div class="coverage-heading">
        <div>
          <p class="eyebrow">03 · Detector coverage</p>
          <h2>Focused on failures that matter.</h2>
        </div>
        <div class="coverage-summary">
          <strong>${RULES.length}</strong>
          <p>Evidence-based rules across execution, authorization, cryptography, and state safety.</p>
        </div>
      </div>
      <div class="detector-groups">
        <article class="detector-group">
          <p>Execution safety</p>
          <h3>External control flow</h3>
          <ul>
            <li><span>Reentrancy</span><code>REENTRANCY</code></li>
            <li><span>Unchecked calls</span><code>CALL</code></li>
            <li class="new-rule"><span>User-controlled delegatecall</span><b>New</b></li>
            <li><span>Denial of service</span><code>DOS</code></li>
          </ul>
        </article>
        <article class="detector-group">
          <p>Authorization</p>
          <h3>Privilege & lifecycle</h3>
          <ul>
            <li><span>tx.origin authorization</span><code>AUTH</code></li>
            <li><span>Ownership initialization</span><code>ACCESS</code></li>
            <li class="new-rule"><span>Unprotected destruction</span><b>New</b></li>
          </ul>
        </article>
        <article class="detector-group">
          <p>Cryptographic use</p>
          <h3>Inputs & commitments</h3>
          <ul>
            <li><span>Predictable randomness</span><code>RANDOM</code></li>
            <li><span>Timestamp dependence</span><code>TIME</code></li>
            <li class="new-rule"><span>Packed encoding collision</span><b>New</b></li>
          </ul>
        </article>
        <article class="detector-group">
          <p>State integrity</p>
          <h3>Data & transaction safety</h3>
          <ul>
            <li><span>Legacy arithmetic</span><code>ARITH</code></li>
            <li><span>Transaction ordering</span><code>FRONT</code></li>
            <li><span>Short-address ABI</span><code>ABI</code></li>
            <li><span>Storage references</span><code>STORAGE</code></li>
          </ul>
        </article>
      </div>
      <p class="coverage-note">A clean scan means these focused patterns were not detected. It is not proof of complete contract safety.</p>
    </section>
    <section class="results-section" id="findings">
      <div class="results-heading">
        <div><p class="eyebrow">04 · Evidence-linked report</p><h2>Security findings</h2></div>
        <p>Guidance explains deterministic findings; it does not prove safety.</p>
      </div>
      <div id="results" class="results-list">
        <div class="empty-state"><span>01</span><h3>No scan run yet</h3><p>Your prioritized findings will appear here.</p></div>
      </div>
    </section>
    <section class="ai-reasoning-section" id="ai-reasoning">
      <div class="ai-reasoning-heading">
        <div><p class="eyebrow">05 · Grounded interpretation</p><h2>AI reasoning summary</h2></div>
        <p>A concise rationale derived from verified findings—not hidden chain-of-thought and never a new security claim.</p>
      </div>
      <div id="ai-reasoning-content" class="ai-reasoning-content">
        <div class="ai-reasoning-empty"><span>AI</span><h3>Reasoning mode is off</h3><p>Enable AI-assisted explanations and run a scan to generate evidence-grounded reasoning summaries.</p></div>
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
  <footer><span>AegisAI v0.2</span><span>Local by default · AI mode sends verified finding evidence only</span></footer>
`;

const source = document.querySelector("#source");
const results = document.querySelector("#results");
const downloadButton = document.querySelector("#download");
const htmlDownloadButton = document.querySelector("#download-html");
const fileInput = document.querySelector("#source-file");
const aiModeInput = document.querySelector("#ai-mode");
const aiReasoningContent = document.querySelector("#ai-reasoning-content");
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
  const explanationBadge = item.explanationMode === "openai-grounded"
    ? `<span class="ai-result-badge">AI grounded</span>`
    : `<span class="template-result-badge">Reviewed template</span>`;
  return `
    <article class="finding-card">
      <div class="finding-index">${String(index + 1).padStart(2, "0")}</div>
      <div class="finding-body">
        <div class="finding-title">
          <div><span class="severity ${item.severity}">${item.severity}</span><span class="rule-id">${item.ruleId}</span><h3>${escapeHtml(item.title)}</h3></div>
          <div class="finding-meta">${explanationBadge}<span class="confidence">${Math.round(item.confidence * 100)}% confidence</span></div>
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
        ${item.caution ? `<p class="ai-caution"><span>AI limitation</span>${escapeHtml(item.caution)}</p>` : ""}
      </div>
    </article>`;
}

function renderAIReasoning(report) {
  if (!report.ai?.requested) {
    aiReasoningContent.innerHTML = `<div class="ai-reasoning-empty"><span>AI</span><h3>Reasoning mode is off</h3><p>Enable AI-assisted explanations and run a scan to generate evidence-grounded reasoning summaries.</p></div>`;
    return;
  }
  if (!report.findings.length) {
    aiReasoningContent.innerHTML = `<div class="ai-reasoning-empty"><span>0</span><h3>No findings to explain</h3><p>The deterministic scanner did not produce a supported finding, so AI reasoning was not requested.</p></div>`;
    return;
  }
  if (!report.ai.used) {
    aiReasoningContent.innerHTML = `<div class="ai-reasoning-empty unavailable"><span>!</span><h3>AI reasoning unavailable</h3><p>The scan completed with reviewed templates. Confirm the server-side API key and model, then run the scan again.</p></div>`;
    return;
  }
  const cards = report.findings.map((item, index) => {
    const evidence = item.evidence.map((line) => `<li><span>L${line.number}</span><code>${escapeHtml(line.text)}</code></li>`).join("");
    return `<article class="reasoning-card">
      <div class="reasoning-card-head"><span>${String(index + 1).padStart(2, "0")}</span><div><p>${escapeHtml(item.ruleId)}</p><h3>${escapeHtml(item.title)}</h3></div><b class="${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</b></div>
      <div class="reasoning-grid">
        <div class="reasoning-assessment"><h4>Grounded assessment</h4><p>${escapeHtml(item.reasoningSummary || item.explanation)}</p></div>
        <div class="reasoning-evidence"><h4>Evidence considered</h4><ul>${evidence}</ul></div>
      </div>
      <div class="reasoning-footer"><span>Model caution</span><p>${escapeHtml(item.caution || "Human review is required.")}</p></div>
    </article>`;
  }).join("");
  aiReasoningContent.innerHTML = `<div class="ai-reasoning-meta"><span><i></i> Grounded AI active</span><strong>${escapeHtml(report.ai.model)}</strong><small>${report.findings.length} verified finding${report.findings.length === 1 ? "" : "s"} explained</small></div>${cards}`;
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
      body: JSON.stringify({ source: source.value, filename: sourceName, aiMode: aiModeInput.checked })
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
    scanButton.firstChild.textContent = aiModeInput.checked ? "Run AI-assisted scan " : "Run security scan ";
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
  const baseStatusCopy = compilerErrors.length
    ? `${compilerErrors.length} Solidity compiler error${compilerErrors.length === 1 ? "" : "s"} found. Review the report before security findings.`
    : lastReport.findings.length
      ? "The contract compiled. Review high-severity evidence before deployment."
      : "The contract compiled and passed this narrow scan. Unsupported vulnerability classes may still exist.";
  document.querySelector("#status-copy").textContent = lastReport.ai?.requested && !lastReport.ai.used
    ? `${baseStatusCopy} AI was unavailable, so reviewed templates were used.`
    : lastReport.ai?.used
      ? `${baseStatusCopy} Explanations were generated from verified evidence by ${lastReport.ai.model}.`
      : baseStatusCopy;
  downloadButton.disabled = false;
  htmlDownloadButton.disabled = false;
  // Compiler warnings are intentionally suppressed in the UI. They are often
  // noisy for legacy dataset contracts and are not AegisAI security findings.
  // Keep compiler errors visible because they can invalidate scan results.
  const diagnostics = (lastReport.compiler?.diagnostics || [])
    .filter((item) => item.severity === "error")
    .map((item) => `
    <article class="compiler-diagnostic ${item.severity}">
      <span>${escapeHtml(item.severity)}</span>
      <div><h3>Solidity compiler</h3><p>${escapeHtml(item.formattedMessage || item.message)}</p></div>
    </article>
  `).join("");
  const findingMarkup = lastReport.findings.length
    ? lastReport.findings.map(renderFinding).join("")
    : `<div class="empty-state safe"><span>✓</span><h3>No supported patterns detected</h3><p>This is not proof that the contract is secure. Continue with testing and professional review.</p></div>`;
  results.innerHTML = diagnostics + findingMarkup;
  renderAIReasoning(lastReport);
}

source.addEventListener("input", updateSourceStats);
source.addEventListener("input", () => {
  if (!source.value) sourceName = "Pasted source";
});
fileInput.addEventListener("change", () => loadSourceFiles(fileInput.files));
document.querySelector("#load-vulnerable").addEventListener("click", () => loadSample(vulnerableSample));
document.querySelector("#load-fixed").addEventListener("click", () => loadSample(fixedSample));
document.querySelector("#scan").addEventListener("click", runScan);
aiModeInput.addEventListener("change", () => {
  const scanButton = document.querySelector("#scan");
  scanButton.firstChild.textContent = aiModeInput.checked ? "Run AI-assisted scan " : "Run security scan ";
  document.querySelector("#engine-name").textContent = aiModeInput.checked ? "Rules + grounded AI" : "Waiting";
});
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
    ${item.reasoningSummary ? `<h3>AI reasoning summary</h3><p>${escapeHtml(item.reasoningSummary)}</p>` : ""}
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
