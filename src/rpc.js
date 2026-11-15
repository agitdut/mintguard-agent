// Rotating JSON-RPC client for BSC (chain 56).
// Public endpoints only, no API keys. Retries across providers and
// distinguishes a real execution revert (JSON-RPC code 3 — meaningful
// evidence) from rate limiting / transport failures (rotate to next RPC).

export const DEFAULT_RPCS = [
  "https://bsc-rpc.publicnode.com",
  "https://rpc-bsc.48.club",
  "https://bsc-dataseed.binance.org",
  "https://bsc-dataseed1.binance.org",
  "https://1rpc.io/bnb",
];

const RATE_LIMIT_CODES = new Set([-32005, -32007, -32603]);

export class RpcError extends Error {
  constructor(message, { code = null, reverted = false, revertReason = null } = {}) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.reverted = reverted;
    this.revertReason = revertReason;
  }
}

function decodeRevertReason(errorData) {
  // error.data is often "0x08c379a0..." (Error(string)) — decode the string.
  if (typeof errorData !== "string" || !errorData.startsWith("0x08c379a0")) return null;
  try {
    const hex = errorData.slice(10);
    const offset = parseInt(hex.slice(0, 64), 16);
    const len = parseInt(hex.slice(offset * 2, offset * 2 + 64), 16);
    const bytes = Buffer.from(hex.slice(offset * 2 + 64, offset * 2 + 64 + len * 2), "hex");
    return bytes.toString("utf8");
  } catch {
    return null;
  }
}

export class RotatingRpc {
  constructor(rpcUrls = DEFAULT_RPCS) {
    this.rpcUrls = rpcUrls;
  }

  async call(method, params, { timeoutMs = 15000 } = {}) {
    const errors = [];
    for (const url of this.rpcUrls) {
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const text = await res.text();
        let json;
        try {
          json = JSON.parse(text);
        } catch {
          throw new Error(`non-JSON response from ${url}: ${text.slice(0, 80)}`);
        }
        if (json.error) {
          const { code, message, data } = json.error;
          if (code === 3 || /execution reverted/i.test(String(message))) {
            throw new RpcError(`execution reverted: ${message}`, {
              code,
              reverted: true,
              revertReason: decodeRevertReason(data) ?? message,
            });
          }
          if (RATE_LIMIT_CODES.has(code) || /limit exceeded/i.test(String(message))) {
            errors.push(`${url}: rate-limited`);
            continue; // try next RPC
          }
          throw new RpcError(`${url}: ${message}`, { code });
        }
        return json.result;
      } catch (err) {
        if (err instanceof RpcError && err.reverted) throw err; // a revert is evidence, not a transport failure
        errors.push(`${url}: ${err.message.slice(0, 100)}`);
      }
    }
    throw new RpcError(`all RPCs failed for ${method}: ${errors.join(" | ")}`);
  }

  async blockNumber() {
    return parseInt(await this.call("eth_blockNumber", []), 16);
  }

  async getCode(address) {
    return this.call("eth_getCode", [address, "latest"]);
  }

  async ethCall({ to, from, data }) {
    const tx = { to };
    if (from) tx.from = from;
    if (data) tx.data = data;
    return this.call("eth_call", [tx, "latest"]);
  }

  async getStorageAt(address, slot) {
    return this.call("eth_getStorageAt", [address, slot, "latest"]);
  }

  async getLogs({ address, topics, fromBlock, toBlock }) {
    return this.call("eth_getLogs", [{ address, topics, fromBlock, toBlock }]);
  }
}
