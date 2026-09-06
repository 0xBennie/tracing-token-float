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

## The Runbook

The layer table below says what each layer produces. This says what to actually type.
Every step is gated: a non-zero exit means STOP, not "note it and continue".

```bash
cd scripts

# L0  Replay, then certify. Two gates, and they are not the same gate.
python replay.py --rpc bsc --token 0xTOKEN --from-block <deploy> --db t.db --workers 4
python replay.py --db t.db --verify --rpc bsc          # exit 0 = CERTIFIED
#   exit 1 -> a range is missing or the supply identity failed. Re-run the line above;
#             it fetches only what ranges_done does not already cover.
#   exit 3 -> it REFUSED to certify (no bounds recorded, or no --rpc). Not a pass.
# Nothing below this line means anything until this exits 0.

# Privileges, before any percentage. Audit every contract that HOLDS or MOVES the
# token, never just the token — the escrow nobody opens is where a sweep() lives.
python privileges.py --chain bsc 0xTOKEN 0xADAPTER 0xVESTING 0xDISTRIBUTOR

# L7  Market, early. Thin depth makes the percentage academic.
python scan.py --chain bsc --token 0xTOKEN --also-audit 0xADAPTER --holdings <n>

# L1/L2  Fix the DENOMINATOR before attributing anything. Exclusions are what is not
#        in the float: vesting, timelock, treasury, unclaimed distributor, escrow.
python balances.py --db t.db --supply 1000000000 \
       --exclude 0xVESTING:team-vesting:vesting \
       --exclude 0xADAPTER:bridge-escrow:bridge_escrow --top 30
#   Prints the itemised subtraction and asserts it closes in wei. Every percentage it
#   prints names its denominator; --show ADDR prints one address both ways side by side.

# L5  Keys. Safes that share signers are ONE controller, not several holders.
python control.py safes --chain bsc --token 0xTOKEN --float <float> 0xSAFE1 0xSAFE2 ...
python control.py lock  --chain bsc 0xVESTING          # EFFECTIVE lock, not nominal

# L6  Cross-chain, before any percentage. Adding chains up double-counts lock-and-mint.
python control.py bridge --home eth:0xTOKEN:0xADAPTER --remote bsc:0xTOKEN monad:0xTOKEN

# L7  Whose liquidity is it? Subtract the issuer's own bid from "reachable".
python positions.py --chain bsc --pool 0xPOOL --issuer 0xLP 0xTREASURY

# L2/L8  The tier table, and the gate that makes it publishable.
python attribute.py --tiers audit.json --out run1.json
python attribute.py --tiers audit.json --diff run1.json     # what moved since
#   close() fails on any gap or double count and prints "Nothing above this line may
#   be published". The headline is a RANGE; D and M sit outside it by construction.
```

Run L0 and the privilege audit before anything else. Either one can make the rest
academic: a live mint path means they can print, and a book that absorbs $30k means
the float percentage is a rounding error on the real answer.

## The Chain

Work bottom-up. Each layer is worthless if the one below it didn't pass its gate.

| Layer | What you produce | Gate before moving on |
|---|---|---|
| **L0 Replay** | Local DB of every `Transfer` event; balances rebuilt from flows | **Coverage first:** every block range in `[deploy, snapshot]` was actually answered by a node — a range nobody served is invisible to every check below it. Then: rebuilt balances sum **exactly** to `totalSupply` (wei-precise, negatives included); zero negative balances; holder count matches the explorer |
| **L1 Distribution** | The genesis tree: deployer EOA → first large transfers → each allocation bucket | Every on-chain bucket reconciles against the published allocation table; discrepancies named |
| **L1.5 Pool birth** | Who took the initial liquidity, in the block that seeded it | The block that created each pool is read transaction by transaction |
| **L2 Attribution** | Each material address tagged with an ownership tier (below) | Tiers sum exactly to the float |
| **L3 Clustering** | Address clusters under one controller | Infrastructure addresses excluded (see pitfalls) or clusters collapse |
| **L4 Sybil** | Batch-controlled airdrop claimers | Collision rate compared against a stated null hypothesis |
| **L5 Control** | Who holds the keys; what the locks are actually worth | Effective lock period computed, not assumed |
| **L6 Cross-chain** | Bridge mode determined, then per-chain supply reconciled | Lock-and-mint: adapter escrow == remote `totalSupply`. Native burn/mint: per-chain supplies sum to the global total. Residual named per message |
| **L7 Market** | Depth curve, real *third-party* exit liquidity | `sum(liquidityNet)==0`, below-tick sum == `liquidity()`, and reserves reproduced without exceeding the balance |
| **L8 Close** | Two independent totals agree | Lineage method and balance method differ only by explainable in-flight amounts |

**L1.5 is the layer most analyses skip, and it decided this one.** Read the pool-creation
block itself, in order. In the case this skill came from, the issuer seeded roughly 11 million
tokens and **87.3% left in the same block** — nine addresses, log indices in an arithmetic
run with nothing interleaved, so the snipes were bundled directly behind the seeding
transaction. The same nine appeared together in 32 later blocks out of some 39,000 distinct
buyers. None of that is visible in balances, net flows, or holder counts; it is visible
only by reading one block. The sister chain, seeded by the same team, had **zero**
same-block outflow — so this is a per-pool fact, never an assumption.

## Attribution Tiers

Never merge these. Report them separately and let the reader choose their own hard line.

- **A — Provable ownership.** Multisigs, official contracts, explorer-labelled addresses. On-chain fact.
- **B — Lineage-traced.** Every token arrived, within N hops, from a Tier A address and never touched a market. Strong.
- **C — Issuer-funded liquidity.** Tokens sitting inside LP positions the issuer owns. Real but not freely sellable.
- **D — Assumed.** Dormant airdrop recipients, "probably the team." **State it as an assumption and keep it out of the headline number.** Publishing D as fact is how analyses get discredited.
- **M — Market makers.** A MM's inventory may be the issuer's, borrowed from it, or its own. Give it its own bucket — but **M is a starting bucket, not a verdict**. Try to empty it before you publish it.

  A one-hop test between issuer and desk returning zero does not mean independence; it means you have not looked at hop two. Shell chains are built precisely to make hop one clean. What resolves M on-chain:
  - **A test transfer before the real one.** `10.00` then `~1.4 million` from the same sender, minutes apart, at every hop. Nobody sanity-checks an address they do not control the other end of.
  - **Arrival before the pool exists.** Inventory in place N blocks *before* the pool is created is not a desk that bought in; it was positioned.
  - **Return flow to the issuer's treasury.** An independent desk does not send inventory back to the issuer's multisig. This is the single strongest signal, and it is a direction question, not a net-flow question.

  In the audit this skill came from, all three held and roughly 1.5 million tokens moved from "third-party desk" to the issuer's side — the only reclassification that changed the headline. Publishing M as unresolvable would have understated issuer control by about a point of float.

  Say "unresolvable" only after those three come back negative, and say which ones you checked.

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
- **Self-check:** integrate the profile back into token0/token1 reserves and compare to the pool's actual ERC-20 balances. The model must never EXCEED the balance (fees inflate the balance, not positions) and a shortfall beyond ~25% means the scan window truncated the book. Two structural identities catch truncation that the reserve comparison alone misses: `sum(liquidityNet) == 0` over the full tick range, and the sum below the current tick equalling `liquidity()`. Assert all four.
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

Reusable tools: [scripts/scan.py](scripts/scan.py) (the three-number pass above), [scripts/privileges.py](scripts/privileges.py) (selector extraction + live-control proof), [scripts/rpc.py](scripts/rpc.py) (rotating multi-endpoint JSON-RPC with batching), [scripts/replay.py](scripts/replay.py) (parallel event replay → SQLite, with the coverage gate and the supply identity), [scripts/balances.py](scripts/balances.py) (exact rebuild + the float denominator), [scripts/control.py](scripts/control.py) (Safe signer intersection, effective lock period, cross-chain supply), [scripts/positions.py](scripts/positions.py) (V3 liquidity attributed to its real owners), [scripts/attribute.py](scripts/attribute.py) (the tier table and the closure gate), [scripts/lineage.py](scripts/lineage.py) (weighted provenance), [scripts/depth.py](scripts/depth.py) (V3 profile + sell simulator in both directions + structural self-check).

## Common Mistakes

| Mistake | Consequence |
|---|---|
| Trusting an explorer's holder list | Contract-held and bridged balances are misattributed; you never see the flows |
| Mixed numerator/denominator | Headline percentage is meaningless |
| Treating pool ERC-20 balance as the issuer's LP position | Third-party LPs and JIT liquidity get attributed to the issuer |
| Weighted lineage on a high-frequency address | Its own churn dilutes provenance to noise; use the first-funding tx and pool-creation-block position — a net balance fails the same way |
| Classifying behaviour from net flow or buy/sell counts | Both discard time; a one-block snipe followed by six weeks of distribution reads as accumulation |
| Treating a passed screen as a verdict | The most convincing candidates fail mechanically — fee claims and exchange wallets both mimic accumulation |
| Totalling exit liquidity without attributing LP ownership | The issuer's own bid counts as depth it can sell into; report third-party reachable quote separately |
| Reporting assumed attribution as fact | One rebuttal discredits the whole analysis |
| Quoting market cap without depth | The headline risk number is off by orders of magnitude |
