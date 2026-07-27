import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const target = process.argv[2];
const outputPath = process.argv[3] || "reports/slither-report.json";

async function assertCompatibleSolc(targetPath) {
  const source = await readFile(targetPath, "utf8");
  const pragma = source.match(/pragma\s+solidity\s+([^;]+);/i)?.[1]?.trim();
  if (!pragma) return;
  const requiredFamily = pragma.match(/\b(0\.[4-8])\./)?.[1];
  if (!requiredFamily) return;
  const { stdout } = await execFileAsync("solc", ["--version"], { windowsHide: true });
  const activeVersion = stdout.match(/Version:\s*(\d+\.\d+\.\d+)/i)?.[1];
  if (!activeVersion?.startsWith(`${requiredFamily}.`)) {
    const recommended =
      requiredFamily === "0.4" ? "0.4.26" :
      requiredFamily === "0.5" ? "0.5.17" :
      requiredFamily === "0.6" ? "0.6.12" :
      requiredFamily === "0.7" ? "0.7.6" : "0.8.36";
    throw new Error(
      `Compiler mismatch: ${basename(targetPath)} requires ${pragma}, but solc ${activeVersion || "unknown"} is active.\n` +
      `Run:\n  solc-select install ${recommended}\n  solc-select use ${recommended}\nThen rerun this command.`
    );
  }
}

if (!target) {
  console.error("Usage: npm run scan:slither -- <contract-or-project-path> [output.json]");
  process.exitCode = 1;
} else {
  const absoluteTarget = resolve(target);
  try {
    await readFile(absoluteTarget);
  } catch {
    throw new Error(`Target does not exist: ${absoluteTarget}`);
  }
  await assertCompatibleSolc(absoluteTarget);
  const workspace = await mkdtemp(join(tmpdir(), "aegisai-slither-"));
  const rawReport = join(workspace, "slither.json");
  try {
    await execFileAsync("slither", [absoluteTarget, "--json", rawReport], {
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024
    });
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new Error("Slither is not installed. Install it with pipx install slither-analyzer.");
    }
    // Slither may return a non-zero code while still producing a useful JSON report.
    try {
      await readFile(rawReport);
    } catch {
      throw new Error(`Slither failed: ${error.stderr || error.message}`);
    }
  }

  const raw = JSON.parse(await readFile(rawReport, "utf8"));
  const detectors = raw.results?.detectors || [];
  const normalized = {
    schemaVersion: "1.0",
    scanner: "Slither adapter",
    sourceName: basename(absoluteTarget),
    generatedAt: new Date().toISOString(),
    findings: detectors.map((item) => ({
      ruleId: `SLITHER-${String(item.check || "UNKNOWN").toUpperCase()}`,
      title: item.check || "Slither finding",
      severity: item.impact?.toLowerCase() || "informational",
      confidence: item.confidence?.toLowerCase() || "unknown",
      explanation: item.description?.trim() || "",
      evidence: (item.elements || []).flatMap((element) =>
        (element.source_mapping?.lines || []).map((line) => ({
          file: element.source_mapping?.filename_relative || element.source_mapping?.filename_short,
          number: line
        }))
      ),
      provenance: "slither"
    }))
  };
  await writeFile(resolve(outputPath), JSON.stringify(normalized, null, 2));
  console.log(`Saved ${normalized.findings.length} normalized Slither findings to ${resolve(outputPath)}`);
  await rm(workspace, { recursive: true, force: true });
}
