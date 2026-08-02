import solc from "solc";
import solc04 from "solc-0-4";
import solc05 from "solc-0-5";
import solc06 from "solc-0-6";
import solc07 from "solc-0-7";
import { scanSolidity } from "../src/scanner.js";
import { explainFindingsWithOpenAI } from "./explanation-adapter.js";

function selectCompiler(source) {
  const pragma = String(source || "").match(/pragma\s+solidity\s+([^;]+);/i)?.[1]?.trim() || null;
  return {
    compiler:
      (pragma && /\b0\.4(?:\.|\b)/.test(pragma) ? solc04 : null) ||
      (pragma && /\b0\.5(?:\.|\b)/.test(pragma) ? solc05 : null) ||
      (pragma && /\b0\.6(?:\.|\b)/.test(pragma) ? solc06 : null) ||
      (pragma && /\b0\.7(?:\.|\b)/.test(pragma) ? solc07 : null) ||
      solc,
    pragma
  };
}

function normalizeExactLegacyPragma(source, pragma) {
  const exactVersion = pragma?.match(/^=?\s*(0\.4\.\d+)$/)?.[1] || null;
  if (!exactVersion) return { compilerSource: source, normalized: false };
  return {
    compilerSource: source.replace(
      /pragma\s+solidity\s+[^;]+;/i,
      `pragma solidity >=${exactVersion} <0.5.0;`
    ),
    normalized: true
  };
}

function compileStandard(compiler, input) {
  const serializedInput = JSON.stringify(input);
  if (typeof compiler.compileStandardWrapper === "function") {
    return compiler.compileStandardWrapper(serializedInput);
  }
  return compiler.compile(serializedInput);
}

export function analyzeContract(source, filename = "Contract.sol") {
  const startedAt = performance.now();
  const sourceText = String(source || "");
  const safeFilename = String(filename || "Contract.sol").replace(/[^a-zA-Z0-9_.-]/g, "_");
  const { compiler, pragma } = selectCompiler(sourceText);
  const { compilerSource, normalized } = normalizeExactLegacyPragma(sourceText, pragma);
  const input = {
    language: "Solidity",
    sources: { [safeFilename]: { content: compilerSource } },
    settings: {
      outputSelection: { "*": { "*": ["abi"], "": ["ast"] } }
    }
  };
  const output = JSON.parse(compileStandard(compiler, input));
  const diagnostics = (output.errors || []).map((item) => ({
    severity: item.severity,
    type: item.type,
    errorCode: item.errorCode || null,
    message: item.message,
    formattedMessage: item.formattedMessage,
    sourceLocation: item.sourceLocation || null
  }));
  const ruleReport = scanSolidity(sourceText);
  return {
    ...ruleReport,
    sourceName: safeFilename,
    engine: `solc ${compiler.version()} + AegisAI rules`,
    durationMs: Number((performance.now() - startedAt).toFixed(2)),
    compiler: {
      available: true,
      version: compiler.version(),
      requestedPragma: pragma,
      pragmaNormalized: normalized,
      compiled: !diagnostics.some((item) => item.severity === "error"),
      diagnostics
    }
  };
}

export async function analyzeContractWithOptions(source, filename = "Contract.sol", options = {}) {
  const report = analyzeContract(source, filename);
  const aiRequested = options.aiMode === true;
  if (!aiRequested || !report.findings.length) {
    return {
      ...report,
      ai: {
        requested: aiRequested,
        configured: Boolean(options.apiKey || process.env.OPENAI_API_KEY),
        used: false,
        model: options.model || process.env.OPENAI_MODEL || "gpt-5.6-luna",
        fallbackCount: 0
      }
    };
  }

  try {
    const generated = await explainFindingsWithOpenAI(report.findings, options);
    const findings = report.findings.map((finding, index) => ({
      ...finding,
      ...generated.explanations[index],
      deterministicEvidence: true,
      explanationMode: generated.explanations[index]?.mode || "reviewed-template"
    }));
    const used = findings.some((finding) => finding.explanationMode === "openai-grounded");
    return {
      ...report,
      findings,
      engine: used ? `${report.engine} + grounded OpenAI explanations` : report.engine,
      ai: {
        requested: true,
        configured: generated.configured,
        used,
        model: generated.model,
        fallbackCount: generated.fallbackCount,
        error: generated.error || null
      }
    };
  } catch (error) {
    return {
      ...report,
      findings: report.findings.map((finding) => ({
        ...finding,
        deterministicEvidence: true,
        explanationMode: "reviewed-template"
      })),
      ai: {
        requested: true,
        configured: Boolean(options.apiKey || process.env.OPENAI_API_KEY),
        used: false,
        model: options.model || process.env.OPENAI_MODEL || "gpt-5.6-luna",
        fallbackCount: report.findings.length,
        error: error.message
      }
    };
  }
}
