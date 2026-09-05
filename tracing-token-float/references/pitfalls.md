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

**Use instead:** the first-funding transaction; the address's position in the block that
seeded the pool; a histogram of buy times; whether any non-market inflow exists at all.

**Not net flow.** A net balance is the one substitute that fails the same way lineage
does — it discards time. See #18: an address that sniped 87% of the initial liquidity in
one block and then distributed for six weeks shows a *positive* net flow that reads as
accumulation.

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

With LayerZero OFT, the adapter on the home chain and the token contract on the remote chain frequently share an address. Enumerate `peers()` to bound how many chains exist — don't assume the disclosed count.

**Determine the bridge mode first — the reconciliation formula depends on it.** Read the
debit/credit path: does it move tokens into an adapter (lock-and-mint) or `_burn`/`_mint`
(native)? Lock-and-mint reconciles as adapter escrow == remote `totalSupply`; native
reconciles as the per-chain supplies summing to the global total. Get this backwards and
L6 is wrong in a way that looks arithmetically fine.

Pairing the send/receive events by their message `guid` beats a balance snapshot: every
residual resolves to a specific transaction instead of an unexplained delta.

**Tag addresses across all chains in one pass.** The same address can be a labelled
multisig signer on one chain and an unremarkable holder on the other. Labelling each
chain independently and summing lets an entity hide in the chain you looked at second.

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
- **Self-check-driven retry.** Scan at `latest`, then reconstruct reserves from the
  profile and compare against the pool's ERC-20 balances; if the reconstruction fails,
  rescan. This is what the code does, and it is the only one of the two that works.

  Do **not** gate on drift in the `(sqrtPrice, tick, liquidity)` triple: on any pool with
  real flow every swap moves `sqrtPrice`, so the check never passes and the scan retries
  until it gives up. The invariant you care about is that the profile reconstructs the
  reserves — not that nothing moved.

Same discipline for balances: a pool's reserves and its liquidity profile must come from
the same state, or the reserve self-check compares two different pools.

## 13. Public RPC limits

Rotate endpoints and retry. Batch JSON-RPC arrays above ~120 items get rejected outright by most public nodes, and some free tiers cap batches far lower (drpc: 3) — detect that error and drop the endpoint from your batch rotation rather than failing the run. Cache `tickBitmap` words and `ticks` results; a naive tick walk re-fetches the same words thousands of times and will time out.

## 14. Auditing the token and stopping there

The token contract is the one everybody reads, so it is the least rewarding place to
look. The unilateral control paths live in the contracts around it — the bridge adapter
holding cross-chain collateral, the vesting factory, the airdrop distributor, the staking
pool.

A real case: a token contract with no owner, no mint, no pause, not a proxy — genuinely
clean, and the whole analysis treated the supply as fixed. Its LayerZero OFT adapter,
holding 20M tokens of collateral backing the entire remote chain, carried a
**non-standard `sweep(address)`** transferring `balanceOf(this)` in full to the owner —
a 4/6 multisig. Every token on the remote chain was unbacked on demand, with no timelock.
Nothing in the transfer graph would ever have shown this. It is only visible by reading
the adapter's runtime bytecode.

Two habits: enumerate selectors from the **bytecode**, not from a source skim (the
dangerous function is the one that isn't in the standard interface you're pattern-matching
against); and prove a privileged path is *live* rather than merely present.

**Do not test liveness by success.** A privileged function usually still reverts for the
owner under `eth_call` — a later precondition, a zero-value transfer. Compare *revert
payloads* instead: a stranger gets `OwnableUnauthorizedAccount` (`0x118cdaa7`) or
`AccessControlUnauthorizedAccount` (`0xe2517d3f`), the owner gets something else or
nothing. Different failures prove the gate exists and that the owner is past it. Always
run a garbage selector as a control, or a fallback-everything contract reads as a hit.

## 15. `getCode != "0x"` misclassifies EIP-7702 accounts

A delegated EOA carries code — `0xef0100` followed by a 20-byte implementation address —
so the naive contract test counts it as a contract. In one holder cohort this turned
71 real contracts into 219, inflating "contract-held" supply threefold.

Test the prefix: 23 bytes beginning `0xef0100` is a delegated **EOA**, not a contract.
The same tell identifies batch tooling — many claimers delegating to one implementation
is a sybil signal, not a diversity signal.

## 16. A full fill is not a good fill

Below the current price a V3 book keeps absorbing token0 all the way down — as the price
approaches zero the quantity it will take is unbounded. So a sell that "completes" proves
nothing: dumping 10M tokens into a pool holding $36k of quote fills 100%, pays $36k, and
lands at an average of a third of a cent.

Report the stop reason alongside the fill, and read the **average price**, never the fill
ratio. Three outcomes look identical in a fill column and mean completely different
things: filled at a fair price, filled at a catastrophic price, and could not fill.

The related mis-accounting: when proceeds hit the pool's quote balance, solve for the
price where cumulative output equals that balance. Truncating the total afterwards
reports the whole requested size as filled while paying a capped amount — an average
price nobody could ever have gotten.

## 17. Holder count is not dispersion

Neither a large holder count nor a small one tells you the float is dispersed. Two
distinct populations both inflate it and neither is a retail holder:

- **Wash-trading wallets** — one-shot round trips that buy from a pool and sell straight
  back, leaving a wei-level remainder. Tell: first inflow and last outflow are the same
  pool, `n_in == n_out == 1`.
- **Passive airdrop wallets** — funded once by the distributor and never moved. Tell:
  first inflow is the claim contract, `n_out == 0`.

Classify before counting, and report what the holders actually are. "Dust" is the wrong
label for the first group: their lifetime inflow can exceed total supply many times over.

## 18. Net flow is not behavior

The single worst substitution in this whole file, because the number looks like an answer.

`vol_in − vol_out` and the buy-count/sell-count ratio both discard time, and a one-shot
snipe followed by distribution is indistinguishable from patient accumulation once you do.
A real case: six wallets showed `+roughly 4.7 million` net and a 160-buy / ~17,000-sell split. Read
as aggregates that says "accumulating, and market-making". The sequence says otherwise —
**over 99% of all buying happened in the single block that seeded the pool** (nine addresses
took 87.3% of the initial liquidity, log indices in an arithmetic run with nothing
interleaved), and the ~17,000 sells were a six-week drip, one per block, median a few hundred tokens.

Before classifying any address, compute three things:

- **first-tx and max-tx share of total buying** — a snipe shows >90% in one transaction
- **a histogram of buy times**, normalised over the *observation window* (first buy → chain
  head), never over the address's own active span; the latter makes any run of consecutive
  buys score 100% coverage and passes every address
- **where the first buy sits relative to the pool-creation block**

## 19. Criteria are a sieve, not a verdict

Every address that passes your filters still has to be checked mechanically, because the
most convincing candidates are convincing for the wrong reason. Of three addresses that
passed a five-criterion accumulation screen in the case above, all three were false:

- one had **bought nothing** — its inflows were `collectFees`. Tell: both tokens leave the
  pool in the same transaction with **zero inflow**. A swap is always one in, one out;
  two-sided outflow with no input is a fee claim or a burn, never a buy.
- one was an exchange's internal wallet — three transactions, single counterparty
- one compressed every buy into 48 hours and looked distributed only because the criterion
  measured coverage against its own lifetime

Report the mechanism you verified, not the criteria that passed.

## 20. N-hop-zero-contact does not prove independence

"No transfers between them at one or two hops" is the standard independence test and it is
routinely defeated by pass-through shells. The signature to look for instead:

- a **test transfer** (1.00 / 10.00 tokens) immediately before the full amount, at each hop
- shells whose entire lifetime is 2-in / 1-out
- arrival timed against a structural event — in the case above, some 1,900 blocks before the
  pool was created
- **value flowing back** to the issuer's treasury (~1.5 million tokens here). An independent
  desk does not return inventory to the issuer's multisig.

Walk 3–5 hops with test-transfer detection before concluding independence, and treat
"funded before the pool existed" as near-decisive on its own.

## 21. Exit liquidity minus the issuer's own bid

Summing the quote currency across pools overstates what a *seller* can reach whenever the
issuer is also the liquidity provider. In the case above, **99.3% of the quote token in the
main pool sat in the issuer's own LP positions**, priced 45–82% below spot. The issuer
selling into that is moving its own money between its own pockets — net cash zero.

Attribute every LP position by `ownerOf` before totalling, then report two numbers: total
reachable quote, and **third-party** reachable quote. The second is the one that matters.
The same audit distinguishes a sell ladder from liquidity: a position whose range sits
entirely above spot holds only the token and is a limit-order ladder — 98% of the issuer's
LP was parked at 1.8–9× spot.

## 22. Derived constants must be measured, not recalled

Chain constants drift and reference values go stale. Both failures below shipped:

- **Block time**: "BSC ≈0.75 s" was recalled; the measured value across four anchor blocks
  was **0.4502 s** — a 67% error that miscomputed every "days since last activity" on that
  chain. Take two block timestamps and divide. Better: pass **head timestamps** downstream

  Re-measured 2026-09-05 over three windows each, and quoted here only so you can see the
  spread you are up against — **re-measure, do not cite this table**. BSC has already
  changed twice:

  | chain | s/block | note |
  |---|---|---|
  | BSC | 0.4500 | was 3 s, then 0.75 s, now 0.45 — any recalled value is wrong |
  | Base | 2.0000 | stable |
  | Ethereum | 12.04–12.06 | 12 s nominal; the excess is missed slots |

  Two timestamps and a subtraction cost one RPC call. A recalled constant costs a rewrite
  rather than a seconds-per-block figure, so consumers cannot re-derive it wrongly.
- **Price**: a cached registry file was quoted as spot. It was five months old and the token
  had fallen 82%. Read price from the pool's `slot0` at a stated block, or stamp the file
  time next to any cached figure.

Also: two chains have no common block height. State each chain's block **and timestamp**,
and report the offset (~2,300 s in the case above) rather than picking a midpoint that
matches neither.

---

## 23. A range nobody answered is invisible to the supply identity

The gate everyone trusts cannot see the failure that actually happens.

A pruned node does not error on a historical `eth_getLogs` it cannot serve. It returns
`{"result": []}` — byte-identical to a genuinely quiet range. The scanner records the
window as covered and moves on. 126 of 1383 ranges went this way on one BSC replay: no
error, no crash, 620 negative balances, rebuilt supply 2.82M tokens high, every
percentage wrong.

Now the part that makes it lethal. **The supply identity does not catch this.** Every
Transfer that is not a mint or a burn moves the same amount out of one balance and into
another, so it contributes exactly zero to the sum of all balances. Delete an arbitrary
number of pure peer-to-peer ranges and `sum(balances) == totalSupply` still holds to the
wei. It moves only if the hole swallowed a mint or a burn — and on a fixed-supply token
every mint happens in the deploy block, so the identity's entire detection power is spent
before the first transfer. Negative balances only appear if a wallet's *funding* transfer
fell in the hole, so a hole positioned after distribution completes produces none. **The
failure mode gets quieter as the token matures — quietest exactly when the analysis
matters most.**

Worse, if `verify()` sums only positive balances (the obvious way to write it), the
"rebuilt supply" difference it prints is algebraically equal to the negative-balance
mass. Two lines that look like two agreeing gates are one number printed twice.

What actually works, because it is provenance metadata rather than arithmetic over the
rows you kept:

- **Record successes, never failures.** A `ranges_done(lo PRIMARY KEY, hi, n, ts)` row
  written in the *same transaction* as that window's transfers. A `holes` table is
  write-only state that drifts; a missing `ranges_done` row cannot be forgotten and a
  re-run heals it.
- **Gate on the interval complement.** Merge the covered intervals, diff against
  `[from_block, to_block]`, refuse to certify if anything is missing. Exit non-zero.
- **Qualify the endpoint pool at startup** against a window known to contain logs, and
  refuse to start if nothing answers. Keep historical-log endpoints in a separate list
  from general `eth_call` endpoints — most public nodes serve one and not the other.
- **Never accept `[]` on one node's word.** Re-query; only believe it when independent
  attempts agree.
- **Store `n` per window** and flag counts landing exactly on a round number (1000,
  5000, 10000) — that is a silent result cap, not a quiet range.
- **Pin `totalSupply()` to the scan's own upper block**, not `latest`. Otherwise a burn
  after the scan can cancel a missing mint inside a hole.

## 24. A rate limit is not a range error

Both arrive as an error string with the word "limit" in it, and they demand opposite
responses: a range error means *split the window*, a rate limit means *wait and retry the
same window*. Match "limit exceeded" as a range signal and a throttled node will drive
your scanner to bisect a perfectly good 5,000-block window down to single blocks, each of
which gets throttled in turn. I did exactly this while hardening the scripts in this
skill: a 10-window scan that takes 36 seconds turned into 500 one-block windows and ran
for seven minutes before I killed it.

Match range signals specifically — "block range", "response size", "too large", "result
set", "query timeout" — and treat "rate limit", "too many requests", "429", "throttle",
"quota" as a backoff. Check them in that order, and let rate signals veto range signals
when a message contains both.

Related: never skip `raise_for_status()`. A 429 or 503 carrying a JSON body parses as a
normal reply, so the run ends blaming the data instead of the rate limit — and a
`{"result": null}` handed back to a caller expecting a list crashes somewhere unrelated.

## Quick self-checks

| Check | Passes when |
|---|---|
| Supply identity | Rebuilt positive balances sum, in wei, exactly to `totalSupply` |
| No negatives | Zero addresses with negative rebuilt balance |
| Holder count | Matches the block explorer at the same block |
| Cross-chain | Adapter escrow == remote `totalSupply`, residual named |
| Liquidity profile | `sum(liquidityNet)==0` over the full range; below-tick sum == `liquidity()`; integrated reserves at or just below the ERC-20 balances |
| Attribution closure | Tiers sum exactly to float; nothing counted twice |
| Two-method agreement | Lineage total and balance total differ only by explained in-flight |
| Behaviour classified | First-tx share, buy-time histogram and pool-creation-block position computed — never a net balance |
| Screened addresses re-verified | Every candidate that passed the filters checked mechanically; `collectFees` ruled out |
| Independence | 3–5 hops walked with test-transfer detection; no value returning to the issuer |
| Exit liquidity | LP positions attributed by `ownerOf`; third-party reachable quote reported separately |
| Constants | Block time and price measured at a stated block, not recalled or read from cache |
| Privileges | Every contract that holds or moves the token audited — adapter, vesting factory, distributor — not just the token; each live path named with its holder and threshold |
| Cross-chain labels | No address tagged as issuer on one chain and untagged on another |
