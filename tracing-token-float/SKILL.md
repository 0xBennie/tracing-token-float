---
name: tracing-token-float
description: Use when you need to establish who actually controls a token's circulating float — auditing tokenomics disclosures against on-chain reality, investigating suspected insider control, wash liquidity or fake float, tracing airdrop sybil farms, judging whether a token's market cap is backed by real exit liquidity, or answering "how much of this is the team's?" Covers EVM chains, multi-chain LayerZero OFT tokens, Safe multisigs, vesting/timelock contracts, and Uniswap-V3-style concentrated liquidity pools.
---

# Tracing Token Float

## Overview

Determine what fraction of a token's circulating supply is actually controlled by its issuer, and whether the resulting market cap is backed by any real exit liquidity.

**Core principle: every number must be independently recomputable from raw chain data, and the final attribution must close exactly onto the float — no gaps, no double counting.**

The single most common failure is not a wrong number, it's a **mixed denominator**: counting locked supply in the numerator while dividing by total supply. That produces impressive, meaningless percentages. Fix the denominator first, then attribute.

## When to Use

- Auditing a token's disclosed tokenomics against what the chain actually shows
- "Is the float real, or does the team control it through intermediaries?"
- Sizing dump risk before an unlock or listing
- Investigating airdrop farming / sybil clusters
- Checking whether quoted market cap survives contact with the order book

**Not for:** price prediction, TA, or any question that doesn't reduce to "who holds what, and can they sell it."

## Start Here

```bash
python scripts/scan.py --chain base --token 0xABC... \
       --also-audit 0xBRIDGE_ADAPTER... --holdings 100000000
```

Three numbers, minutes, no database: can they print/freeze/drain, how much the book
actually absorbs, and what the position is worth against that. Run it before committing
to the full method below — either answer can make the rest academic.

**Audit every contract that holds or moves the token, not just the token.** Bridge
adapters, vesting factories, distributors, staking pools. The token itself is the
contract everyone reads and therefore the least likely place to find anything; the
escrow nobody thinks to open is where a `sweep()` lives. `scripts/privileges.py`
extracts every selector the runtime bytecode dispatches and flags the ones granting
unilateral control — then proves each one live by showing a stranger refused with an
auth error where the owner is not.

If a mint path exists outside the bridge logic, "who controls the float" is the wrong
question — they can print. This also decides whether `totalSupply()` is an invariant the
identity gates below may rest on.

## The Chain

Work bottom-up. Each layer is worthless if the one below it didn't pass its gate.

| Layer | What you produce | Gate before moving on |
|---|---|---|
| **L0 Replay** | Local DB of every `Transfer` event; balances rebuilt from flows | Rebuilt balances sum **exactly** to `totalSupply` (wei-precise); zero negative balances; holder count matches the explorer |
| **L1 Distribution** | The genesis tree: deployer EOA → first large transfers → each allocation bucket | Every on-chain bucket reconciles against the published allocation table; discrepancies named |
| **L2 Attribution** | Each material address tagged with an ownership tier (below) | Tiers sum exactly to the float |
| **L3 Clustering** | Address clusters under one controller | Infrastructure addresses excluded (see pitfalls) or clusters collapse |
| **L4 Sybil** | Batch-controlled airdrop claimers | Collision rate compared against a stated null hypothesis |
| **L5 Control** | Who holds the keys; what the locks are actually worth | Effective lock period computed, not assumed |
| **L6 Cross-chain** | Bridge mode determined, then per-chain supply reconciled | Lock-and-mint: adapter escrow == remote `totalSupply`. Native burn/mint: per-chain supplies sum to the global total. Residual named per message |
| **L7 Market** | Depth curve, real exit liquidity | Liquidity profile reproduces pool reserves within ~10% |
| **L8 Close** | Two independent totals agree | Lineage method and balance method differ only by explainable in-flight amounts |

## Attribution Tiers

Never merge these. Report them separately and let the reader choose their own hard line.

- **A — Provable ownership.** Multisigs, official contracts, explorer-labelled addresses. On-chain fact.
- **B — Lineage-traced.** Every token arrived, within N hops, from a Tier A address and never touched a market. Strong.
- **C — Issuer-funded liquidity.** Tokens sitting inside LP positions the issuer owns. Real but not freely sellable.
- **D — Assumed.** Dormant airdrop recipients, "probably the team." **State it as an assumption and keep it out of the headline number.** Publishing D as fact is how analyses get discredited.
- **M — Market makers.** Not resolvable on-chain: a MM's inventory may be the issuer's, borrowed from the issuer, or its own. Give it its own bucket and say plainly that resolving it needs off-chain agreements. Forcing it to either side destroys the number.

**Report a range, never a point estimate.** Tier A alone is your defensible floor; A+B (+C) is the ceiling. A single decimal invites the issuer to rebut one address and dismiss the whole analysis; a range with tiered evidence survives losing any individual call.

**Two different questions — keep them on separate lines.** (1) How much of the float was never really distributed. (2) How much the issuer re-accumulated from the market after listing. They have opposite implications: the first is a disclosure problem, the second is ordinary buying. Merging them is indefensible.

## Two Methods, One Answer

Compute the float twice, independently:

1. **Lineage:** sum what the issuer actually pushed out, minus what came back.
2. **Balance:** `totalSupply` minus every issuer-held address, vesting contract, and unclaimed distributor balance.

They must agree. A residual is acceptable only when you can name it (cross-chain in flight, a stuck transfer). An unexplained gap means an address is mis-tagged — find it before publishing.

## The Number That Matters Most

Paper market cap is not exit liquidity. Build the V3 liquidity profile and simulate the sell:

- Walk `tickBitmap` → `ticks` to get every initialized tick and its `liquidityNet`
- **Self-check:** integrate the profile back into token0/token1 reserves and compare to the pool's actual ERC-20 balances. Within ~10% is expected (the gap is uncollected fees, which don't participate in swaps). A wild mismatch means your profile is wrong — usually the sign-extension trap in pitfalls.
- Simulate sells across sizes; report tokens actually fillable, proceeds, average price, and post-trade price

Then state the ratio plainly: **controlled position at mark price, versus total stablecoin reachable across every pool.** This is usually the finding that reframes everything else.

## Verification

- Tag addresses in one pass across all chains, not per-chain then summed — the same address can look inert on one chain and be a signer on another
- Snapshot at a stated block and time — and read any single pool's state within one consistent block (see pitfalls #12)
- Number every claim (`A1`, `J4`, …) so reviewers can accept or reject them one at a time
- Recompute each headline figure by a second path before it ships
- For anything consequential, run independent reviewers per layer, then have separate agents **try to refute** the disputed findings rather than confirm them
- Track retractions in the deliverable. An analysis that shows what it got wrong is more credible, not less

**REQUIRED READING before you compute anything:** [references/pitfalls.md](references/pitfalls.md) — the traps that silently corrupt results while every number still looks plausible. Several will hit you.

For concentrated-liquidity math and the depth simulator: [references/v3-depth.md](references/v3-depth.md).

Reusable tools: [scripts/scan.py](scripts/scan.py) (the three-number pass above), [scripts/privileges.py](scripts/privileges.py) (selector extraction + live-control proof), [scripts/rpc.py](scripts/rpc.py) (rotating multi-endpoint JSON-RPC with batching), [scripts/replay.py](scripts/replay.py) (event replay → SQLite + identity self-check), [scripts/lineage.py](scripts/lineage.py) (weighted provenance), [scripts/depth.py](scripts/depth.py) (V3 profile + sell simulator + reserve self-check).

## Common Mistakes

| Mistake | Consequence |
|---|---|
| Trusting an explorer's holder list | Contract-held and bridged balances are misattributed; you never see the flows |
| Mixed numerator/denominator | Headline percentage is meaningless |
| Treating pool ERC-20 balance as the issuer's LP position | Third-party LPs and JIT liquidity get attributed to the issuer |
| Weighted lineage on a high-frequency address | Its own churn dilutes provenance to noise; use net-flow or timing evidence instead |
| Reporting assumed attribution as fact | One rebuttal discredits the whole analysis |
| Quoting market cap without depth | The headline risk number is off by orders of magnitude |
