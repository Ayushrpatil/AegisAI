import { analyzeContract } from "../server/analyze.js";

export default function handler(request, response) {
  if (request.method !== "POST") {
    response.status(405).json({ error: "Method not allowed" });
    return;
  }
  try {
    const { source, filename } = request.body || {};
    if (typeof source !== "string" || !source.trim()) {
      response.status(400).json({ error: "Solidity source is required." });
      return;
    }
    response.status(200).json(analyzeContract(source, filename));
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
}
