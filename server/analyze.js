import solc from "solc";
import solc04 from "solc-0-4";
import solc05 from "solc-0-5";
import solc06 from "solc-0-6";
import solc07 from "solc-0-7";
import { scanSolidity } from "../src/scanner.js";

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
