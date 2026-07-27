import { createServer } from "node:http";
import { analyzeContract } from "./server/analyze.js";

const port = Number(process.env.AEGIS_API_PORT || 3001);

createServer((request, response) => {
  if (request.method === "GET" && request.url === "/api/health") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ status: "ok", engine: "solc" }));
    return;
  }
  if (request.method !== "POST" || request.url !== "/api/scan") {
    response.writeHead(404).end();
    return;
  }
  let body = "";
  request.on("data", (chunk) => {
    body += chunk;
    if (body.length > 1_100_000) request.destroy();
  });
  request.on("end", () => {
    try {
      const { source, filename } = JSON.parse(body);
      if (typeof source !== "string" || !source.trim()) throw new Error("Solidity source is required.");
      const report = analyzeContract(source, filename);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(report));
    } catch (error) {
      response.writeHead(400, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: error.message }));
    }
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`AegisAI analyzer API: http://127.0.0.1:${port}`);
});
