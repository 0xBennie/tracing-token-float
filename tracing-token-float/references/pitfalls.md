# Pitfalls

Traps that corrupt results silently — every number still looks plausible afterwards. Read before computing.

---

## 1. Mixed denominator

The one that ruins whole analyses. Counting locked, never-circulated supply in the numerator while dividing by total supply yields percentages like "98% controlled" that collapse the moment anyone checks.

**Rule:** fix the denominator first and state it in every headline. If the claim is about float, the numerator may contain only tokens that are actually in the float. Locked allocations belong in a separate risk section with their unlock schedule, never inside the control percentage.

## 2. Float-point wei

`CAST(val AS REAL)` in SQLite silently loses precision above 2^53. Token amounts in wei blow past that at ~9 tokens. Aggregates look right to four significant figures and the supply identity misses by thousands.

- **Aggregation for display:** `CAST(val AS REAL)/1e18` is fine.
- **Any identity check** (rebuilt supply == `totalSupply`, cross-chain reconciliation, "sums to exactly N"): accumulate with Python `int` over the raw wei strings. No exceptions — this check is the entire basis for trusting the dataset.

## 3. `liquidityNet` sign extension

`ticks(int24)` returns `liquidityNet` as `int128`, but ABI encoding sign-extends it into a full 256-bit word. Decoding word[1] as a 128-bit two's-complement value turns every negative `liquidityNet` into a ~10^38 number.

```python
def s256(v):  # correct
    return v - (1 << 256) if v >= (1 << 255) else v

net = s256(int(raw_hex[64:128], 16))
```

Symptom: reconstructed pool reserves come out ~10^50 instead of ~10^6. The reserve self-check catches this immediately — which is why you run it.

## 4. Pool balance is not the issuer's LP position

A pool's ERC-20 balance mixes: the issuer's positions, third-party LPs, JIT liquidity, and uncollected fees. Three consequences:

- **"Tokens deposited − tokens now in pool = tokens sold" is not a valid identity.** It attributes everyone's liquidity to the issuer.
- The defensible realization figure is the **quote-currency actually withdrawn** by the issuer's position (`Collect`/`DecreaseLiquidity` on their `tokenId`s), not a token-count difference.
- Pool balances visibly jitter block to block where JIT vaults operate. Snapshot once and say when.

## 5. JIT liquidity is not exit liquidity

JIT market makers add liquidity inside a single transaction for flow they've already seen, then withdraw. They will not absorb a large dump. For dump-risk sizing, the **static** liquidity profile is the correct measure; including JIT overstates depth badly.

## 6. Weighted lineage dies on active addresses

Propagating provenance backward by amount share works for addresses that received and held. On an address that trades constantly, its own churn recycles through the pool and dilutes true provenance toward zero — an address seeded entirely by the issuer can show <10% issuer lineage after enough round trips.

**Use instead:** net flow between the address and known issuer addresses; first-funding transaction; whether non-market inflows exist at all; timing correlation. Say which method you used and why.

## 7. Clustering collapses without an infrastructure blocklist

Union-find over "shared counterparty" evidence merges everything into one giant cluster the moment a pool, router, bridge, CEX hot wallet, or distributor contract is included — they touch everyone.

- Exclude high-degree infrastructure before clustering
- Require strong evidence, or ≥2 independent evidence classes, to merge
- Cap cluster size and inspect anything near the cap; it usually means a leak

Evidence classes that work: bidirectional repeated transfers, ≥5 repeated one-way transfers, funded by the same non-hub address, receipt of wei-identical amounts in the same batch.

## 8. Sybil detection without a null hypothesis is noise

"2,728 duplicate amounts" means nothing alone. State the null model (amounts independent across claimers), compute the expected collision count under it, and report the ratio. Several orders of magnitude above expectation is a finding; 2× is not.

Corroborate with a second, independent signal — e.g. claim-sequence spacing far tighter than independent arrival would produce.

**EIP-7702 tell:** a delegated EOA's code is `0xef0100` + 20-byte implementation address. Many claimers delegating to the same implementation indicates one batch tool.

## 9. `claimed() == 0` does not mean "not unlocked"

Vesting contracts distinguish *vested* from *withdrawn*. A schedule can be well past its cliff with nothing pulled. Read `claimable()` / `releasable()`, not just `claimed()`.

Consequence for the float: vested-but-unwithdrawn tokens are **not** circulating and must stay out of the denominator — but they are immediately available to the issuer and belong in the risk section.

## 10. Effective lock period, not nominal

A vesting pool is only locked for as long as nobody can rewrite it. Trace the admin path:

1. Does the vesting factory/pool expose `updateSchedule`, `updateBeneficiary`, `withdrawPool`?
2. Who holds `ADMIN_ROLE`/owner?
3. If a `TimelockController`: read `getMinDelay()`, then `PROPOSER_ROLE`, `EXECUTOR_ROLE`, `CANCELLER_ROLE`.
4. **If proposer, executor and canceller are the same multisig, the effective lock is the timelock delay** — not the advertised cliff. Nobody can veto.

Intersect the owner sets of every holding multisig too. Separate multisigs sharing signers are not separation of control.

## 11. Same address, different role per chain

With LayerZero OFT, the adapter on the home chain and the token contract on the remote chain frequently share an address. Reconcile explicitly: adapter escrow == remote `totalSupply`. Any residual must be named (in-flight messages, a mis-sent transfer). Enumerate `peers()` to bound how many chains exist — don't assume.

## 12. Pool state read across blocks

`slot0()`, `liquidity()`, `tickBitmap` and `ticks` are separate calls. On a pool with JIT
market makers they can land in different blocks, giving you active liquidity from one
state and a tick set from another. The integration then walks off the end of the book,
`L` goes negative, and the self-check reports **negative reserves** — a nonsense result
that is easy to misread as a math error.

Two fixes:

- **Pin to a block** (`eth_call` with an explicit block number). Cleanest — but most
  public Base/BSC nodes are pruned and answer historical calls with
  "archive request required". Works only against an archive endpoint.
- **Drift detection.** Read the `(sqrtPrice, tick, liquidity)` triple, run the scan at
  `latest`, then re-read the triple. If it moved, redo the scan. Portable across public
  nodes, and the retry count tells you how churny the pool is.

Same discipline for balances: a pool's reserves and its liquidity profile must come from
the same state, or the reserve self-check compares two different pools.

## 13. Public RPC limits

Rotate endpoints and retry. Batch JSON-RPC arrays above ~120 items get rejected outright by most public nodes, and some free tiers cap batches far lower (drpc: 3) — detect that error and drop the endpoint from your batch rotation rather than failing the run. Cache `tickBitmap` words and `ticks` results; a naive tick walk re-fetches the same words thousands of times and will time out.

---

## Quick self-checks

| Check | Passes when |
|---|---|
| Supply identity | Rebuilt positive balances sum, in wei, exactly to `totalSupply` |
| No negatives | Zero addresses with negative rebuilt balance |
| Holder count | Matches the block explorer at the same block |
| Cross-chain | Adapter escrow == remote `totalSupply`, residual named |
| Liquidity profile | Integrated reserves within ~10% of pool ERC-20 balances |
| Attribution closure | Tiers sum exactly to float; nothing counted twice |
| Two-method agreement | Lineage total and balance total differ only by explained in-flight |
