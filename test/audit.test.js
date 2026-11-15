// MintGuard tests — live on-chain evidence (BSC 56, public RPCs + Sourcify).
// These tests assert verdicts that were verified by hand before the suite
// was written; they do NOT fabricate on-chain state.
//   ACOS 0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69 — exact_match, owner=0xdead -> GO
//   NIAN 0xffd92f75d2e29adf3b41f92850fc864214a81d2f — unverified, transfer reverts
//        despite balanceOf 50,776.08 for holder 0x58a6... -> BLOCK (honeypot)
//   MOCHI 0xf0d4898c6ACB98B88d1D7BEE313a324AB30cfcD1 — transfer sim succeeds
//        from holder 0x9187... (positive control for the simulation method)

import { test } from "node:test";
import assert from "node:assert/strict";
import { auditContract, scoreToVerdict, isValidAddress } from "../src/audit.js";
import { selectorOf } from "../src/selectors.js";

const ACOS = "0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69";
const NIAN = "0xffd92f75d2e29adf3b41f92850fc864214a81d2f";
const MOCHI = "0xf0d4898c6ACB98B88d1D7BEE313a324AB30cfcD1";
const HOLDER_NIAN = "0x58a616B74483742EAc5026f9e42D2015E7c7E03a";
const HOLDER_MOCHI = "0x9187BDb11273A71ddAe7F4023064b3Ccf0aa16b0";

test("selectors are derived from signatures, not hand-copied", () => {
  assert.equal(selectorOf("transfer(address,uint256)"), "0xa9059cbb");
  assert.equal(selectorOf("balanceOf(address)"), "0x70a08231");
  assert.equal(selectorOf("owner()"), "0x8da5cb5b");
  assert.equal(selectorOf("mint()"), "0x1249c58b");
});

test("verdict thresholds", () => {
  assert.equal(scoreToVerdict(100), "GO");
  assert.equal(scoreToVerdict(80), "GO");
  assert.equal(scoreToVerdict(79), "CAUTION");
  assert.equal(scoreToVerdict(50), "CAUTION");
  assert.equal(scoreToVerdict(49), "BLOCK");
  assert.equal(scoreToVerdict(0), "BLOCK");
});

test("address validation", () => {
  assert.equal(isValidAddress(ACOS), true);
  assert.equal(isValidAddress("0x123"), false);
  assert.equal(isValidAddress("not-an-address"), false);
  assert.equal(isValidAddress(null), false);
});

test("ACOS (Agent Cosmos mint) audits GO", { timeout: 120_000 }, async () => {
  const r = await auditContract(ACOS);
  assert.equal(r.track, "MINT");
  assert.equal(r.verdict, "GO");
  assert.ok(r.score >= 80, `expected score >= 80, got ${r.score}`);
  const sourcify = r.checks.find((c) => c.id === "sourcify");
  assert.equal(sourcify.status, "pass");
  const owner = r.checks.find((c) => c.id === "owner");
  assert.equal(owner.status, "pass"); // owner() = 0xdead
});

test("NIAN (confirmed honeypot) audits BLOCK", { timeout: 120_000 }, async () => {
  const r = await auditContract(NIAN, { holder: HOLDER_NIAN });
  assert.equal(r.track, "TOKEN");
  assert.equal(r.verdict, "BLOCK");
  assert.ok(r.score < 50, `expected score < 50, got ${r.score}`);
  const sim = r.checks.find((c) => c.id === "transfer-sim");
  assert.equal(sim.status, "fail");
  assert.match(sim.title, /HONEYPOT/);
  const sourcify = r.checks.find((c) => c.id === "sourcify");
  assert.equal(sourcify.status, "fail"); // unverified
});

test("transfer simulation positive control (MOCHI)", { timeout: 120_000 }, async () => {
  const r = await auditContract(MOCHI, { holder: HOLDER_MOCHI });
  assert.equal(r.track, "TOKEN");
  const sim = r.checks.find((c) => c.id === "transfer-sim");
  assert.equal(sim.status, "pass"); // the method itself works on a sellable token
});

test("EOA address audits BLOCK, not a contract", { timeout: 120_000 }, async () => {
  const r = await auditContract(HOLDER_NIAN);
  assert.equal(r.track, "EOA");
  assert.equal(r.verdict, "BLOCK");
  assert.equal(r.score, 0);
});

test("invalid address throws", async () => {
  await assert.rejects(() => auditContract("0x123"), /invalid EVM address/);
});
