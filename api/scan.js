import { analyzeContractWithOptions } from "../server/analyze.js";

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.status(405).json({ error: "Method not allowed" });
    return;
  }
  try {
    const { source, filename, aiMode } = request.body || {};
    if (typeof source !== "string" || !source.trim()) {
      response.status(400).json({ error: "Solidity source is required." });
      return;
    }
    response.status(200).json(await analyzeContractWithOptions(source, filename, { aiMode }));
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
}
