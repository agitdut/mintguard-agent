# MintGuard

**A security auditor agent for free mints on BNB Chain.** Give it a contract
address, get a `GO` / `CAUTION` / `BLOCK` verdict with on-chain evidence —
before you mint, buy, or interact.

Built for [Agent Games](https://agentgames.zkverify.io) (zkVerify) Season 01,
Wildcard track. Entry is free; the audit itself is read-only and uses only
free public infrastructure: BSC public RPCs and the Sourcify API. No API
keys, no wallet, no signing, no transactions.

## What it checks

| Check | Evidence |
|---|---|
| Contract code exists | `eth_getCode` |
| Source verified | Sourcify v2 — `exact_match` / `partial_match` / unverified |
| Owner live or renounced | `owner()` — `0x0` / `0xdead` = renounced, otherwise live admin |
| Upgradeable proxy | EIP-1967 implementation slot |
| Pause | `paused()` + pause selectors in bytecode |
| Privileged functions | Bytecode scan for mint / tax-setter / blacklist / max-tx / trading-gate / withdraw selectors (selectors derived at runtime from canonical signatures via keccak256) |
| **Transfer simulation (TOKEN track)** | `eth_call transfer(1 wei)` from a real holder — if `balanceOf > 0` but the transfer reverts, the displayed balance is fake: **honeypot** |

## Verdicts

- **GO** — score ≥ 80. Verified source, no live admin, no blocking privileges.
- **CAUTION** — score 50–79. Usable only with acknowledged risks.
- **BLOCK** — score < 50. Do not mint, buy, or interact.

Scoring starts at 100. Unverified source −25, live owner −15, upgradeable
proxy −10, tax/blacklist setters −10 each, and a failed transfer simulation
with a positive balance hard-caps the score at 20 (BLOCK).

## Run it

```bash
npm install
npm start          # HTTP server on http://localhost:8787
npm run audit -- 0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69
npm test           # live on-chain tests (BSC 56)
```

### HTTP API

```bash
# Health
curl localhost:8787/health

# Audit a contract
curl -X POST localhost:8787/audit \
  -H 'Content-Type: application/json' \
  -d '{"contract": "0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69"}'

# Audit a token with a known holder (enables the transfer simulation)
curl -X POST localhost:8787/audit \
  -H 'Content-Type: application/json' \
  -d '{"contract": "0xffd92f75d2e29adf3b41f92850fc864214a81d2f",
       "holder": "0x58a616B74483742EAc5026f9e42D2015E7c7E03a"}'
```

Response:

```json
{
  "address": "0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69",
  "chainId": 56,
  "blockNumber": 133639041,
  "track": "MINT",
  "verdict": "GO",
  "score": 100,
  "checks": [
    { "id": "sourcify", "title": "Source verified (Sourcify exact_match)", "status": "pass", "detail": "Verified at 2026-10-25T02:54:25Z.", "points": 0 },
    { "id": "owner", "title": "Owner renounced", "status": "pass", "detail": "owner() = 0x000000000000000000000000000000000000dEaD — no live admin.", "points": 0 }
  ],
  "summary": "Verified source, no live admin, no blocking privileges — clears the audit."
}
```

### CLI

```bash
node src/cli.js 0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69
node src/cli.js 0xffd92f75d2e29adf3b41f92850fc864214a81d2f --holder 0x58a616B74483742EAc5026f9e42D2015E7c7E03a
node src/cli.js 0x3Aeda314ec05BC22E3c26a543E16Df2B8cC8fe69 --json
```

## Known results (verified live)

| Contract | Track | Verdict | Why |
|---|---|---|---|
| Agent Cosmos `0x3Aeda3…8fe69` | MINT | **GO** (100) | Sourcify `exact_match`, owner = `0xdead`, no proxy, no pause |
| NIAN `0xffd92f…81d2f` | TOKEN | **BLOCK** (20) | Unverified + transfer reverts despite `balanceOf` 50,776.08 — confirmed honeypot |

## Design notes

- **Evidence order:** on-chain state first, Sourcify second, simulation third.
  A homepage counter or a project's own claims are never evidence.
- **Fail closed:** if the transfer simulation cannot run (no holder found),
  the check is reported `unknown` — never silently treated as safe.
- **Selectors from signatures:** every function selector is computed at
  runtime from its canonical signature (`ethers.id`), never hand-copied.
- **RPC rotation:** five public BSC endpoints, automatic failover on rate
  limits; a JSON-RPC execution revert (code 3) is treated as evidence,
  not as a transport failure.
- **Read-only by construction:** the code contains no signing, no
  broadcasting, and no private-key handling of any kind.

## Limitations

- Bytecode selector presence proves a function exists in code, not that it
  is live/reachable — those findings are scored moderately and labelled.
- The transfer simulation covers plain `transfer`; pair-keyed or
  size-keyed taxes and swap-only blocks need a router simulation (roadmap).
- Public RPCs rate-limit in waves; the client rotates, but a heavy audit
  run can still be slow.

## License

MIT. Reference only, not investment advice.
