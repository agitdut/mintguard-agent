// Privileged-function inventory.
// Selectors are DERIVED at runtime from canonical function signatures
// (ethers.id = keccak256, first 4 bytes) — never hand-copied.
// Presence of a selector in bytecode is evidence the function EXISTS in
// the code; it does not by itself prove the function is live/reachable,
// so findings are labelled "bytecode" and scored moderately.

import { ethers } from "ethers";

export const selectorOf = (signature) => ethers.id(signature).slice(0, 10);

// signature -> category. Keep the list to well-known admin patterns.
export const PRIVILEGED_SIGNATURES = {
  // hidden mint
  "mint(address,uint256)": "hidden-mint",
  "mint(uint256)": "hidden-mint",
  "mint(address,uint256,bytes)": "hidden-mint",
  // tax / fee setters
  "setTax(uint256)": "tax-setter",
  "setBuyTax(uint256)": "tax-setter",
  "setSellTax(uint256)": "tax-setter",
  "setTaxes(uint256,uint256)": "tax-setter",
  "updateBuyFees(uint256,uint256)": "tax-setter",
  "updateSellFees(uint256,uint256)": "tax-setter",
  "setFee(uint256)": "tax-setter",
  // blacklist / exclusion
  "setBlacklist(address,bool)": "blacklist",
  "blacklist(address)": "blacklist",
  "excludeFromFees(address,bool)": "fee-exclusion",
  "setExcluded(address,bool)": "fee-exclusion",
  // transfer limits
  "setMaxTxAmount(uint256)": "max-tx",
  "setMaxWallet(uint256)": "max-wallet",
  "setMaxTx(uint256)": "max-tx",
  // trading gates
  "setTradingEnabled(bool)": "trading-gate",
  "enableTrading()": "trading-gate",
  "setSwapEnabled(bool)": "trading-gate",
  // ownership / upgrade
  "renounceOwnership()": "renounce",
  "transferOwnership(address)": "ownership-transfer",
  "upgradeTo(address)": "upgrade",
  "upgradeToAndCall(address,bytes)": "upgrade",
  // fund withdrawal
  "withdraw()": "withdraw",
  "rescueETH()": "withdraw",
  "emergencyWithdraw()": "withdraw",
  // pause
  "pause()": "pause",
  "unpause()": "pause",
};

// Standard ERC-20 / mint entry points used for classification.
export const CORE_SIGNATURES = {
  "transfer(address,uint256)": "transfer",
  "balanceOf(address)": "balanceOf",
  "mint()": "mint",
  "freeMint()": "mint",
  "owner()": "owner",
  "paused()": "paused",
};

export function scanBytecode(code) {
  const haystack = code.toLowerCase();
  const found = {}; // category -> [selector]
  for (const [sig, category] of Object.entries(PRIVILEGED_SIGNATURES)) {
    const sel = selectorOf(sig);
    if (haystack.includes(sel.slice(2))) {
      (found[category] ??= []).push(sel);
    }
  }
  const core = {};
  for (const [sig, name] of Object.entries(CORE_SIGNATURES)) {
    // Several signatures can map to one name (mint() / freeMint()) — OR them.
    core[name] = Boolean(core[name]) || haystack.includes(selectorOf(sig).slice(2));
  }
  return { privileged: found, core };
}
