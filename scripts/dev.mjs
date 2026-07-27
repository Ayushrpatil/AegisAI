import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const api = spawn(process.execPath, ["server.mjs"], { stdio: "inherit" });
const viteBin = new URL("../node_modules/vite/bin/vite.js", import.meta.url);
const web = spawn(process.execPath, [fileURLToPath(viteBin)], { stdio: "inherit" });

function shutdown() {
  api.kill();
  web.kill();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
api.on("exit", (code) => {
  if (code) process.exitCode = code;
});
web.on("exit", (code) => {
  if (code) process.exitCode = code;
});
