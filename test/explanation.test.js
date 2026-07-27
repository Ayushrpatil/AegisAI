import test from "node:test";
import assert from "node:assert/strict";
import { explainFinding } from "../server/explanation-adapter.js";

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
