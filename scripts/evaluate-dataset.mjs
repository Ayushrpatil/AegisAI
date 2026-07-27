import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSolidity } from "../src/scanner.js";

const root = dirname(fileURLToPath(import.meta.url));
const projectRoot = dirname(root);
const datasetRoot = join(projectRoot, "Contracts", "dataset");
const reportRoot = join(projectRoot, "reports");
const categoryRule = {
  arithmetic: "AEGIS-ARITH-001",
  bad_randomness: "AEGIS-RANDOM-001",
  denial_of_service: "AEGIS-DOS-001",
  front_running: "AEGIS-FRONT-001",
  other: "AEGIS-STORAGE-001",
  short_addresses: "AEGIS-ABI-001",
  time_manipulation: "AEGIS-TIME-001",
  reentrancy: "AEGIS-REENTRANCY-001",
  unchecked_low_level_calls: "AEGIS-CALL-001"
};

function codeWithoutComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

function expectedRuleFor(category, source) {
  if (category === "access_control") {
    const code = codeWithoutComments(source);
    if (/\btx\.origin\b/.test(code)) return "AEGIS-AUTH-001";
    const contractName = code.match(/\bcontract\s+([A-Za-z_]\w*)/)?.[1] || "";
    const functionPattern = /\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\b(?:public|external)\b[^{;]*\{([\s\S]*?)\}/g;
    for (const match of code.matchAll(functionPattern)) {
      if (
        match[1] !== contractName &&
        /\b(?:owner|admin|creator)\s*=\s*msg\.sender\b/i.test(match[2]) &&
        !/\b(?:owner|admin|creator)\s*==\s*address\s*\(\s*0\s*\)/i.test(match[2])
      ) {
        return "AEGIS-ACCESS-002";
      }
    }
  }
  return categoryRule[category] || null;
}

async function solidityFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return solidityFiles(path);
    return entry.isFile() && entry.name.endsWith(".sol") ? [path] : [];
  }));
  return nested.flat();
}

function annotatedLines(source, category) {
  const label = category.toUpperCase();
  return source.split(/\r?\n/).flatMap((line, index) =>
    line.includes("<yes>") && line.includes("<report>") && line.toUpperCase().includes(label)
      ? [index + 1]
      : []
  );
}

const files = await solidityFiles(datasetRoot);
const rows = [];
for (const path of files) {
  const source = await readFile(path, "utf8");
  const category = relative(datasetRoot, path).split(/[\\/]/)[0];
  const report = scanSolidity(source);
  const expectedRule = expectedRuleFor(category, source);
  const matching = expectedRule
    ? report.findings.filter((finding) => finding.ruleId === expectedRule)
    : [];
  const labels = annotatedLines(source, category);
  const evidenceLines = matching.flatMap((finding) => finding.evidence.map((line) => line.number));
  const evidenceHit = labels.length
    ? labels.some((label) => evidenceLines.some((line) => Math.abs(line - label) <= 2))
    : null;
  rows.push({
    file: relative(datasetRoot, path).replaceAll("\\", "/"),
    category,
    supportedCategory: Boolean(expectedRule),
    expectedRule,
    detected: matching.length > 0,
    findingCount: report.findings.length,
    findingRules: [...new Set(report.findings.map((finding) => finding.ruleId))],
    annotatedLines: labels,
    evidenceHit
  });
}

const categories = [...new Set(rows.map((row) => row.category))].sort().map((category) => {
  const categoryRows = rows.filter((row) => row.category === category);
  const targetRows = categoryRows.filter((row) => row.supportedCategory);
  const detected = targetRows.filter((row) => row.detected).length;
  const annotationComparable = categoryRows.filter((row) => row.evidenceHit !== null);
  return {
    category,
    scope: category === "access_control" ? "tx.origin + unprotected ownership initialization" : categoryRule[category] ? "full category" : "not supported",
    files: categoryRows.length,
    targetFiles: targetRows.length,
    detected,
    detectionRate: targetRows.length ? Number((detected / targetRows.length).toFixed(4)) : null,
    annotatedFiles: annotationComparable.length,
    evidenceHits: annotationComparable.filter((row) => row.evidenceHit).length
  };
});

const supportedRows = rows.filter((row) => row.supportedCategory);
const unsupportedRows = rows.filter((row) => !row.supportedCategory);
const summary = {
  generatedAt: new Date().toISOString(),
  totalFiles: rows.length,
  supportedCategoryFiles: supportedRows.length,
  supportedCategoryDetected: supportedRows.filter((row) => row.detected).length,
  supportedCategoryRecall: Number(
    (supportedRows.filter((row) => row.detected).length / supportedRows.length).toFixed(4)
  ),
  unsupportedCategoryFiles: unsupportedRows.length,
  unsupportedFilesWithFindings: unsupportedRows.filter((row) => row.findingCount > 0).length,
  note: "Access-control coverage is intentionally limited to tx.origin and unprotected ownership initialization; category-level recall is not a claim of general access-control coverage."
};

await mkdir(reportRoot, { recursive: true });
await writeFile(
  join(reportRoot, "dataset-evaluation.json"),
  JSON.stringify({ summary, categories, files: rows }, null, 2)
);
const table = categories.map((item) =>
  `| ${item.category} | ${item.scope} | ${item.files} | ${item.targetFiles} | ${item.detected} | ${item.detectionRate === null ? "—" : `${(item.detectionRate * 100).toFixed(1)}%`} |`
).join("\n");
await writeFile(
  join(reportRoot, "dataset-evaluation.md"),
  `# AegisAI Dataset Evaluation\n\nGenerated: ${summary.generatedAt}\n\n` +
  `- Total contracts: ${summary.totalFiles}\n` +
  `- Contracts in supported categories: ${summary.supportedCategoryFiles}\n` +
  `- Supported-category detections: ${summary.supportedCategoryDetected}\n` +
  `- Supported-category category-level recall: ${(summary.supportedCategoryRecall * 100).toFixed(1)}%\n` +
  `- Unsupported-category files with findings: ${summary.unsupportedFilesWithFindings}/${summary.unsupportedCategoryFiles}\n\n` +
  `> ${summary.note}\n\n` +
  `| Category | Claimed scope | Dataset files | Evaluation targets | Detected | Detection rate |\n| --- | --- | ---: | ---: | ---: | ---: |\n${table}\n`
);

console.log(JSON.stringify(summary, null, 2));
