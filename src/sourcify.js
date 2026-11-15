// Sourcify verification check (free public API, no key).
// https://sourcify.dev/server/v2/contract/{chainId}/{address}
// Returns { status: "exact_match" | "partial_match" | "unverified", ... }.
// A 404 / match:null means the contract source is NOT verified.

const SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract";

export async function checkSourcify(address, chainId = 56) {
  const url = `${SOURCIFY_BASE}/${chainId}/${address}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(20000),
    });
    if (res.status === 404) return { status: "unverified", match: null };
    if (!res.ok) return { status: "unknown", match: null, error: `HTTP ${res.status}` };
    const json = await res.json();
    const match = json.match ?? null;
    if (match === "exact_match") {
      return { status: "exact_match", match, verifiedAt: json.verifiedAt ?? null };
    }
    if (match === "partial_match") {
      return { status: "partial_match", match, verifiedAt: json.verifiedAt ?? null };
    }
    return { status: "unverified", match: null };
  } catch (err) {
    return { status: "unknown", match: null, error: String(err.message).slice(0, 120) };
  }
}
