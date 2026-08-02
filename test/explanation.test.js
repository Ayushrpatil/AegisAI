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
