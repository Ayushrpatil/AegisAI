import test from "node:test";
import assert from "node:assert/strict";
import { explainFinding, explainFindingsWithOpenAI } from "../server/explanation-adapter.js";

test("uses reviewed evidence-grounded templates when no endpoint is configured", async () => {
  const finding = {
    ruleId: "AEGIS-TEST-001",
    explanation: "Verified explanation",
    attackPath: "Verified path",
    remediation: "Verified remediation",
    evidence: [{ number: 7, text: "unsafe();" }]
  };
  const result = await explainFinding(finding, { endpoint: "" });
  assert.equal(result.mode, "reviewed-template");
  assert.equal(result.provenance, finding.ruleId);
  assert.equal(result.explanation, finding.explanation);
});

test("falls back to reviewed templates when AI mode has no API key", async () => {
  const finding = {
    ruleId: "AEGIS-TEST-002",
    explanation: "Verified explanation",
    attackPath: "Verified path",
    remediation: "Verified remediation",
    evidence: [{ number: 8, text: "unsafe();" }]
  };
  const result = await explainFindingsWithOpenAI([finding], { apiKey: "" });
  assert.equal(result.configured, false);
  assert.equal(result.fallbackCount, 1);
  assert.equal(result.explanations[0].mode, "reviewed-template");
  assert.equal(result.explanations[0].provenance, finding.ruleId);
});

test("accepts structured grounded OpenAI explanations without changing provenance", async () => {
  const finding = {
    ruleId: "AEGIS-TEST-003",
    title: "Verified finding",
    severity: "high",
    confidence: 0.9,
    explanation: "Verified explanation",
    attackPath: "Verified path",
    remediation: "Verified remediation",
    evidence: [{ number: 9, text: "unsafe();" }]
  };
  const fetchImpl = async (_url, request) => {
    const body = JSON.parse(request.body);
    assert.equal(body.store, false);
    assert.equal(body.text.format.type, "json_schema");
    return {
      ok: true,
      json: async () => ({
        output: [{
          content: [{
            type: "output_text",
            text: JSON.stringify({ explanations: [{
              findingIndex: 0,
              ruleId: finding.ruleId,
              explanation: "Grounded explanation",
              attackPath: "Grounded attack path",
              remediation: "Grounded remediation",
              reasoningSummary: "The cited call occurs before the verified state update, which directly matches the supplied rule.",
              caution: "Human review is required."
            }] })
          }]
        }]
      })
    };
  };
  const result = await explainFindingsWithOpenAI([finding], {
    apiKey: "test-key",
    model: "test-model",
    fetchImpl
  });
  assert.equal(result.configured, true);
  assert.equal(result.fallbackCount, 0);
  assert.equal(result.explanations[0].mode, "openai-grounded");
  assert.equal(result.explanations[0].provenance, finding.ruleId);
  assert.equal(result.explanations[0].model, "test-model");
  assert.match(result.explanations[0].reasoningSummary, /cited call/);
});

test("batches large finding sets without losing grounded explanations", async () => {
  const findings = Array.from({ length: 5 }, (_, index) => ({
    ruleId: `AEGIS-BATCH-${index}`,
    title: `Verified finding ${index}`,
    severity: "medium",
    confidence: 0.8,
    explanation: `Verified explanation ${index}`,
    attackPath: `Verified path ${index}`,
    remediation: `Verified remediation ${index}`,
    evidence: [{ number: index + 1, text: `unsafe${index}();` }]
  }));
  let requestCount = 0;
  const fetchImpl = async (_url, request) => {
    requestCount += 1;
    const body = JSON.parse(request.body);
    const payload = JSON.parse(body.input[1].content[0].text);
    assert.ok(payload.findings.length <= 2);
    return {
      ok: true,
      json: async () => ({
        output: [{
          content: [{
            type: "output_text",
            text: JSON.stringify({ explanations: payload.findings.map((finding) => ({
              findingIndex: finding.findingIndex,
              ruleId: finding.ruleId,
              explanation: `Grounded ${finding.ruleId}`,
              attackPath: "Grounded attack path",
              remediation: "Grounded remediation",
              reasoningSummary: "Grounded reasoning summary",
              caution: "Human review is required."
            })) })
          }]
        }]
      })
    };
  };
  const result = await explainFindingsWithOpenAI(findings, {
    apiKey: "test-key",
    model: "test-model",
    batchSize: 2,
    fetchImpl
  });
  assert.equal(requestCount, 3);
  assert.equal(result.fallbackCount, 0);
  assert.equal(result.error, null);
  assert.equal(result.explanations.length, findings.length);
  assert.ok(result.explanations.every((item) => item.mode === "openai-grounded"));
});
