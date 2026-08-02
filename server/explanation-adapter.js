function templateExplanation(finding) {
  return {
    mode: "reviewed-template",
    explanation: finding.explanation,
    attackPath: finding.attackPath,
    remediation: finding.remediation,
    reasoningSummary: finding.explanation,
    caution: "This guidance explains a deterministic finding and does not prove contract safety.",
    provenance: finding.ruleId
  };
}

function outputText(response) {
  if (typeof response.output_text === "string") return response.output_text;
  return (response.output || [])
    .flatMap((item) => item.content || [])
    .filter((item) => item.type === "output_text" && typeof item.text === "string")
    .map((item) => item.text)
    .join("");
}

function explanationSchema() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      explanations: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            findingIndex: { type: "integer" },
            ruleId: { type: "string" },
            explanation: { type: "string" },
            attackPath: { type: "string" },
            remediation: { type: "string" },
            reasoningSummary: { type: "string" },
            caution: { type: "string" }
          },
          required: ["findingIndex", "ruleId", "explanation", "attackPath", "remediation", "reasoningSummary", "caution"]
        }
      }
    },
    required: ["explanations"]
  };
}

export async function explainFindingsWithOpenAI(findings, options = {}) {
  const apiKey = options.apiKey || process.env.OPENAI_API_KEY;
  const model = options.model || process.env.OPENAI_MODEL || "gpt-5.6-luna";
  if (!apiKey) {
    return {
      configured: false,
      model,
      explanations: findings.map(templateExplanation),
      fallbackCount: findings.length,
      error: "OPENAI_API_KEY is not configured."
    };
  }

  const evidencePayload = findings.map((finding, findingIndex) => ({
    findingIndex,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    evidence: finding.evidence,
    verifiedExplanation: finding.explanation,
    verifiedAttackPath: finding.attackPath,
    verifiedRemediation: finding.remediation
  }));
  const fetchImpl = options.fetchImpl || fetch;
  const response = await fetchImpl("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      store: false,
      reasoning: { effort: "low" },
      max_output_tokens: 1800,
      input: [
        {
          role: "system",
          content: [{
            type: "input_text",
            text: [
              "You are the constrained explanation layer for AegisAI, a defensive Solidity security scanner.",
              "The supplied findings are already verified by deterministic rules. Do not add, remove, merge, or change findings, severity, confidence, rule IDs, or evidence.",
              "For each finding, improve only the plain-language explanation, realistic attack path, actionable remediation, and a concise reasoning summary.",
              "The reasoning summary must explain how the cited evidence supports the existing rule in two or three sentences. It must not reveal hidden chain-of-thought.",
              "Do not claim that the contract is safe. Do not invent code, state, dependencies, or exploitability beyond the supplied evidence.",
              "The caution must briefly identify any material uncertainty and state that human review is required."
            ].join(" ")
          }]
        },
        {
          role: "user",
          content: [{
            type: "input_text",
            text: JSON.stringify({ task: "Explain these verified findings", findings: evidencePayload })
          }]
        }
      ],
      text: {
        verbosity: "low",
        format: {
          type: "json_schema",
          name: "aegisai_grounded_explanations",
          strict: true,
          schema: explanationSchema()
        }
      }
    }),
    signal: AbortSignal.timeout(options.timeoutMs || 25000)
  });
  if (!response.ok) {
    const details = await response.text().catch(() => "");
    throw new Error(`OpenAI explanation request returned ${response.status}${details ? `: ${details.slice(0, 240)}` : ""}`);
  }
  const raw = await response.json();
  const parsed = JSON.parse(outputText(raw));
  const byIndex = new Map((parsed.explanations || []).map((item) => [item.findingIndex, item]));
  let fallbackCount = 0;
  const explanations = findings.map((finding, index) => {
    const generated = byIndex.get(index);
    if (!generated || generated.ruleId !== finding.ruleId) {
      fallbackCount += 1;
      return templateExplanation(finding);
    }
    return {
      mode: "openai-grounded",
      explanation: generated.explanation,
      attackPath: generated.attackPath,
      remediation: generated.remediation,
      reasoningSummary: generated.reasoningSummary,
      caution: generated.caution,
      provenance: finding.ruleId,
      model
    };
  });
  return { configured: true, model, explanations, fallbackCount };
}

export async function explainFinding(finding, options = {}) {
  const endpoint = options.endpoint || process.env.AEGIS_EXPLANATION_ENDPOINT;
  if (!endpoint) return templateExplanation(finding);

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(options.apiKey ? { Authorization: `Bearer ${options.apiKey}` } : {})
    },
    body: JSON.stringify({
      task: "Explain only the supplied deterministic smart-contract finding.",
      constraints: [
        "Do not add vulnerabilities.",
        "Cite only supplied evidence.",
        "Preserve severity and rule ID.",
        "State uncertainty explicitly."
      ],
      finding
    }),
    signal: AbortSignal.timeout(options.timeoutMs || 10000)
  });
  if (!response.ok) throw new Error(`Explanation adapter returned ${response.status}`);
  return {
    mode: "grounded-external",
    ...(await response.json()),
    provenance: finding.ruleId
  };
}
