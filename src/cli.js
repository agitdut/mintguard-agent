#!/usr/bin/env node
// MintGuard CLI: node src/cli.js <contract> [--holder <addr>] [--json]
// Read-only audit — never signs, broadcasts, or moves funds.

import { auditContract } from "./audit.js";

function usage() {
  console.log("Usage: mintguard <contract-address> [--holder <address>] [--json]");
  console.log("  Audits a BNB Chain (56) contract and prints GO / CAUTION / BLOCK.");
  console.log("  --holder  a wallet holding the token, used for the transfer simulation.");
  process.exit(2);
}

const args = process.argv.slice(2);
const contract = args.find((a) => !a.startsWith("--"));
const holderIdx = args.indexOf("--holder");
const holder = holderIdx >= 0 ? args[holderIdx + 1] : null;
const asJson = args.includes("--json");
if (!contract || (holderIdx >= 0 && !holder)) usage();

const report = await auditContract(contract, { holder });

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

console.log(`\nMintGuard audit — ${report.address} (BSC 56, block ${report.blockNumber ?? "?"})`);
console.log(`Track: ${report.track}   Score: ${report.score}/100   Verdict: ${report.verdict}`);
console.log(`Summary: ${report.summary}\n`);
for (const c of report.checks) {
  const icon = c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : c.status === "warn" ? "!" : "?";
  console.log(` [${icon}] ${c.title} (${c.points >= 0 ? "+" : ""}${c.points})`);
  console.log(`     ${c.detail}`);
}
console.log(`\nDECISION: ${report.verdict} — ${report.summary}`);
console.log("Reference only, not investment advice.\n");
