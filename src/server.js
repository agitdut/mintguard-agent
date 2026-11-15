// MintGuard HTTP server — no frameworks, no keys.
//   GET  /health          -> { ok: true, service, version, chainId }
//   POST /audit           -> { contract, holder? } => full audit report
//   GET  /                -> usage
// Port: $PORT (default 8787). Read-only: never signs or broadcasts.

import http from "node:http";
import { auditContract, isValidAddress } from "./audit.js";

const PORT = parseInt(process.env.PORT ?? "8787", 10);
const VERSION = "1.0.0";

function send(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 64 * 1024) reject(new Error("body too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    if (req.method === "GET" && url.pathname === "/health") {
      return send(res, 200, { ok: true, service: "mintguard-agent", version: VERSION, chainId: 56 });
    }
    if (req.method === "GET" && url.pathname === "/") {
      return send(res, 200, {
        service: "mintguard-agent",
        version: VERSION,
        usage: "POST /audit { \"contract\": \"0x...\", \"holder\": \"0x...\" (optional, for transfer simulation) }",
        tracks: "TOKEN (transfer sim) / MINT / OTHER",
        verdicts: "GO >= 80 · CAUTION 50-79 · BLOCK < 50",
      });
    }
    if (req.method === "POST" && url.pathname === "/audit") {
      let body;
      try {
        body = JSON.parse(await readBody(req));
      } catch {
        return send(res, 400, { error: "invalid JSON body" });
      }
      const contract = body.contract;
      const holder = body.holder ?? null;
      if (!isValidAddress(contract)) {
        return send(res, 400, { error: `invalid contract address: ${contract}` });
      }
      if (holder !== null && !isValidAddress(holder)) {
        return send(res, 400, { error: `invalid holder address: ${holder}` });
      }
      const report = await auditContract(contract, { holder });
      return send(res, 200, report);
    }
    return send(res, 404, { error: "not found" });
  } catch (err) {
    return send(res, 500, { error: String(err.message).slice(0, 300) });
  }
});

server.listen(PORT, () => {
  console.log(`MintGuard listening on http://localhost:${PORT} (BSC 56, read-only)`);
});
