// MintGuard audit engine — BNB Chain (56) only.
// Evidence order: on-chain state first, Sourcify second, transfer
// simulation third. Nothing here signs, broadcasts, or moves funds.
//
// Scoring (start 100, deductions are evidence, not vibes):
//   Sourcify unverified            -25   | partial match -10
//   live owner (not 0x0 / 0xdead)  -15
//   upgradeable proxy              -10
//   pause capability in bytecode    -5   | currently paused: hard cap 30
//   tax-setter in bytecode         -10
//   blacklist in bytecode          -10
//   max-tx / max-wallet setters     -5
//   trading-gate setters            -5
//   withdraw / rescue fns           -5
//   hidden-mint fn + live owner     -5   (0 when owner renounced)
//   transfer sim reverts while the holder's balanceOf > 0
//                                  -> hard BLOCK, score capped at 20
// Verdict: GO >= 80 · CAUTION 50-79 · BLOCK < 50.

import { ethers } from "ethers";
import { RotatingRpc, RpcError } from "./rpc.js";
import { checkSourcify } from "./sourcify.js";
import { scanBytecode, selectorOf } from "./selectors.js";

export const CHAIN_ID = 56;
export const DEAD = "0x000000000000000000000000000000000000dEaD";
export const ZERO = "0x0000000000000000000000000000000000000000";

const EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const TRANSFER_TOPIC = ethers.id("Transfer(address,address,uint256)");

export function scoreToVerdict(score) {
  if (score >= 80) return "GO";
  if (score >= 50) return "CAUTION";
  return "BLOCK";
}

export function isValidAddress(address) {
  return /^0x[0-9a-fA-F]{40}$/.test(address ?? "");
}

function check(id, title, status, detail, points = 0) {
  return { id, title, status, detail, points };
}

async function tryCall(rpc, { to, from, data }) {
  try {
    return { ok: true, result: await rpc.ethCall({ to, from, data }) };
  } catch (err) {
    if (err instanceof RpcError && err.reverted) {
      return { ok: false, reverted: true, reason: err.revertReason ?? err.message };
    }
    return { ok: false, error: err.message };
  }
}

// Find a holder with a positive balance to simulate a transfer from:
// 1) an explicit holder address, 2) recent Transfer logs (last 2000 blocks).
async function findHolder(rpc, token, explicitHolder) {
  if (explicitHolder) {
    const bal = await rpc.ethCall({
      to: token,
      data: selectorOf("balanceOf(address)") + explicitHolder.slice(2).padStart(64, "0"),
    });
    return { holder: explicitHolder, balance: BigInt(bal) };
  }
  try {
    const latest = await rpc.blockNumber();
    const logs = await rpc.getLogs({
      address: token,
      topics: [TRANSFER_TOPIC],
      fromBlock: "0x" + Math.max(0, latest - 2000).toString(16),
      toBlock: "latest",
    });
    const candidates = [...new Set(logs.map((l) => "0x" + l.topics[2].slice(26)))]
      .filter((a) => a.toLowerCase() !== ZERO && a.toLowerCase() !== DEAD.toLowerCase())
      .slice(0, 8);
    for (const c of candidates) {
      const bal = await rpc.ethCall({
        to: token,
        data: selectorOf("balanceOf(address)") + c.slice(2).padStart(64, "0"),
      });
      if (BigInt(bal) > 0n) return { holder: c, balance: BigInt(bal) };
    }
  } catch {
    // log discovery is best-effort on public RPCs; fall through to "unknown"
  }
  return { holder: null, balance: 0n };
}

export async function auditContract(address, { rpc = new RotatingRpc(), holder = null } = {}) {
  if (!isValidAddress(address)) {
    throw new Error(`invalid EVM address: ${address}`);
  }
  const addr = ethers.getAddress(address);
  const checks = [];
  let score = 100;
  let blockNumber = null;
  let track = "UNKNOWN";

  try {
    blockNumber = await rpc.blockNumber();
  } catch {
    blockNumber = null;
  }

  // 1. Code must exist.
  const code = await rpc.getCode(addr);
  if (!code || code === "0x") {
    return {
      address: addr, chainId: CHAIN_ID, blockNumber, track: "EOA",
      verdict: "BLOCK", score: 0,
      checks: [check("code", "Contract code exists", "fail", "Address holds no bytecode (EOA or undeployed).", -100)],
      summary: "Not a contract — nothing to audit.",
    };
  }

  // 4. Proxy / upgradeability (EIP-1967 slots). A proxy's own bytecode is
  // just a forwarder — audit the IMPLEMENTATION's code, never the proxy's.
  let scanCode = code;
  let implementation = null;
  try {
    const impl = await rpc.getStorageAt(addr, EIP1967_IMPL_SLOT);
    const implAddr = "0x" + impl.slice(26);
    if (implAddr !== ZERO) {
      const implCode = await rpc.getCode(implAddr);
      if (implCode && implCode !== "0x") {
        implementation = implAddr;
        scanCode = implCode;
        score -= 10;
        checks.push(check("proxy", "Upgradeable proxy", "warn", `EIP-1967 implementation slot points at ${implAddr} — logic can be swapped. Bytecode checks below audit the implementation.`, -10));
      } else {
        checks.push(check("proxy", "Not a proxy", "pass", "EIP-1967 implementation slot is set but points at an address with no code.", 0));
      }
    } else {
      checks.push(check("proxy", "Not a proxy", "pass", "EIP-1967 implementation slot is empty.", 0));
    }
  } catch (err) {
    checks.push(check("proxy", "Proxy check failed", "unknown", String(err.message).slice(0, 100), 0));
  }

  const { privileged, core } = scanBytecode(scanCode);
  track = core.mint && !core.transfer ? "MINT" : core.transfer ? "TOKEN" : "OTHER";
  if (implementation) {
    checks.push(check("implementation", "Auditing implementation via proxy", "info", `Proxy ${addr} delegates to ${implementation} (${(scanCode.length - 2) / 2} bytes); selectors below come from the implementation.`, 0));
  }

  // 2. Sourcify verification.
  const ver = await checkSourcify(addr, CHAIN_ID);
  if (ver.status === "exact_match") {
    checks.push(check("sourcify", "Source verified (Sourcify exact_match)", "pass", `Verified at ${ver.verifiedAt ?? "unknown"}.`, 0));
  } else if (ver.status === "partial_match") {
    score -= 10;
    checks.push(check("sourcify", "Source partially verified", "warn", "Sourcify partial_match only — metadata differs from deployed bytecode.", -10));
  } else if (ver.status === "unverified") {
    score -= 25;
    checks.push(check("sourcify", "Source NOT verified", "fail", "No Sourcify match — source cannot be read or confirmed.", -25));
  } else {
    checks.push(check("sourcify", "Verification status unknown", "unknown", `Sourcify lookup failed: ${ver.error ?? "?"}. Scored as unverified-equivalent is NOT applied.`, 0));
  }

  // 3. Owner: renounced (0x0 / 0xdead) vs live vs no owner() at all.
  const ownerCall = await tryCall(rpc, { to: addr, data: selectorOf("owner()") });
  let owner = null;
  let ownerLive = false;
  if (ownerCall.ok) {
    owner = ethers.getAddress("0x" + ownerCall.result.slice(26));
    if (owner === ZERO || owner.toLowerCase() === DEAD.toLowerCase()) {
      checks.push(check("owner", "Owner renounced", "pass", `owner() = ${owner} — no live admin.`, 0));
    } else {
      ownerLive = true;
      score -= 15;
      checks.push(check("owner", "Live owner", "warn", `owner() = ${owner} — an admin can still change the contract.`, -15));
    }
  } else if (ownerCall.reverted) {
    checks.push(check("owner", "No owner() function", "unknown", "owner() reverts — contract may not use Ownable; admin status unproven.", 0));
  } else {
    checks.push(check("owner", "Owner check failed", "unknown", `owner() call failed: ${ownerCall.error}.`, 0));
  }

  // 5. Pause.
  const pausedCall = await tryCall(rpc, { to: addr, data: selectorOf("paused()") });
  if (pausedCall.ok && BigInt(pausedCall.result) === 1n) {
    score = Math.min(score, 30);
    checks.push(check("paused", "Contract is PAUSED", "fail", "paused() = true — transfers/mints are halted right now.", -70));
  } else if (privileged.pause) {
    score -= 5;
    checks.push(check("pause", "Pause function present", "warn", "Bytecode contains pause()/unpause() — an admin can halt the contract.", -5));
  } else {
    checks.push(check("pause", "No pause function", "pass", "No paused() and no pause selector in bytecode.", 0));
  }

  // 6. Privileged-function inventory from bytecode.
  const deductions = {
    "tax-setter": [-10, "Tax/fee setter in bytecode", "An admin can change buy/sell tax after launch."],
    "blacklist": [-10, "Blacklist function in bytecode", "An admin can block addresses from trading."],
    "fee-exclusion": [-5, "Fee-exclusion setter in bytecode", "An admin can exempt chosen wallets from fees."],
    "max-tx": [-5, "Max-tx setter in bytecode", "An admin can cap transfer sizes."],
    "max-wallet": [-5, "Max-wallet setter in bytecode", "An admin can cap wallet holdings."],
    "trading-gate": [-5, "Trading-gate setter in bytecode", "An admin controls when trading opens."],
    "withdraw": [-5, "Withdraw/rescue function in bytecode", "An admin can pull funds out of the contract."],
    "upgrade": [-5, "Upgrade function in bytecode", "Logic can be replaced by an admin call."],
  };
  for (const [category, [pts, title, detail]] of Object.entries(deductions)) {
    if (privileged[category]) {
      score += pts;
      checks.push(check(`priv-${category}`, title, "warn", `${detail} Selectors: ${privileged[category].join(", ")}`, pts));
    }
  }
  if (privileged["hidden-mint"]) {
    if (ownerLive) {
      score -= 5;
      checks.push(check("priv-hidden-mint", "Mint function + live owner", "warn", `Bytecode contains a mint function and the owner is live — supply can grow. Selectors: ${privileged["hidden-mint"].join(", ")}`, -5));
    } else {
      checks.push(check("priv-hidden-mint", "Mint function present, owner renounced", "pass", "A mint selector exists but there is no live owner to call it.", 0));
    }
  }
  if (privileged["ownership-transfer"]) {
    checks.push(check("priv-ownership-transfer", "transferOwnership present", "info", "Standard Ownable function; harmless while the owner is renounced.", 0));
  }

  // 7. Transfer simulation (TOKEN track only) — the honeypot gate.
  // balanceOf(holder) > 0 AND transfer(1 wei) reverts with "exceeds balance"
  // means the displayed balance is fake: the token cannot be sold.
  if (track === "TOKEN") {
    const { holder: simHolder, balance } = await findHolder(rpc, addr, holder);
    if (!simHolder || balance === 0n) {
      checks.push(check("transfer-sim", "Transfer simulation skipped", "unknown", "No holder with a positive balance was found, so exit could not be simulated. Treat as unproven, not as safe.", 0));
    } else {
      const data =
        selectorOf("transfer(address,uint256)") +
        DEAD.slice(2).padStart(64, "0") +
        (1n).toString(16).padStart(64, "0");
      const sim = await tryCall(rpc, { from: simHolder, to: addr, data });
      if (sim.ok) {
        checks.push(check("transfer-sim", "Transfer simulation succeeded", "pass", `transfer(1 wei) from holder ${simHolder} (balance ${balance}) returned ${sim.result.slice(0, 10)}… — exit works.`, 0));
      } else if (sim.reverted) {
        score = Math.min(score, 20);
        checks.push(check("transfer-sim", "HONEYPOT: transfer reverts despite positive balance", "fail", `Holder ${simHolder} shows balanceOf ${balance}, but transfer(1 wei) reverts: ${sim.reason ?? "execution reverted"}. Displayed balance is not spendable.`, -80));
      } else {
        checks.push(check("transfer-sim", "Transfer simulation inconclusive", "unknown", `Simulation failed with a transport error, not a revert: ${sim.error}.`, 0));
      }
    }
  } else if (track === "MINT") {
    checks.push(check("transfer-sim", "Transfer simulation n/a (mint contract)", "info", "This is a mint contract, not a token — exit is judged by the mint's own rules, not by a token transfer.", 0));
  }

  score = Math.max(0, Math.min(100, score));
  const verdict = scoreToVerdict(score);
  const summary =
    verdict === "GO"
      ? "Verified source, no live admin, no blocking privileges — clears the audit."
      : verdict === "CAUTION"
        ? "Usable only with acknowledged risks — see the failed/warn checks."
        : "Do not mint, buy, or interact — blocking risk found.";

  return { address: addr, chainId: CHAIN_ID, blockNumber, track, verdict, score, checks, summary };
}
