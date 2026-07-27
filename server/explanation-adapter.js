export async function explainFinding(finding, options = {}) {
  const endpoint = options.endpoint || process.env.AEGIS_EXPLANATION_ENDPOINT;
  if (!endpoint) {
    return {
      mode: "reviewed-template",
      explanation: finding.explanation,
      attackPath: finding.attackPath,
      remediation: finding.remediation,
      provenance: finding.ruleId
    };
  }

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
