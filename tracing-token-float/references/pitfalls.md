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
A real case: six wallets showed roughly +4.7 million net and a ~160-buy / ~17,000-sell split. Read
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

## 21. "Exit liquidity" is three numbers, and subtracting the issuer's LP answers only two of them

You attribute the pool's quote by `ownerOf`, subtract the issuer's share, and publish the
remainder as what a seller can reach. The arithmetic is right and the label is wrong. An
AMM pays out of whatever liquidity sits at the tick it is crossing; it has no idea who
minted it. **Who owns the money and who is selling are different questions, and the
subtraction belongs only to the second.**

The first version of this entry was written from a case where 99.3% of the main pool's
quote sat in issuer positions parked at 1.8–9× spot — a sell ladder holding only the
token. There, subtracting was nearly free, because a ladder contributes no quote to
subtract. It generalised badly. The next case had a **two-sided position straddling
spot** holding roughly $360,000 of real USDT below the price. The same subtraction reported that
a third party could reach **about $10,000**. A 10,000-token sale at that moment actually paid
**about $6,800** out of the full book, and the book's ceiling was that whole roughly $360k. The
published figure was off by 35×, in the reassuring direction.

**First classify every issuer position. Shape is a property of ticks, not of owners:**

| Shape | Test, per `tokenId` | Holds | Absorbs a sale? |
|---|---|---|---|
| **Ladder** | range entirely on the far side of spot from the quote | subject token only | No — it competes with your sale |
| **Bid** | range entirely on the quote side of spot | quote only | Yes, fully, for anyone |
| **Two-sided** | `tickLower <= currentTick < tickUpper` | both; quote on one side | Yes, fully, for anyone |

One owner routinely holds all three in one pool. Classify per position and sum by shape —
never from the owner's total, and never from what the last audit found.

**Then report three numbers under three names:**

1. **Spot exit** — simulate against the **whole book, untouched**. What a holder gets
   today. Ownership does not enter the computation.
2. **Post-withdrawal exit** — remove the issuer's positions from the profile
   (`net[tickLower] -= L`, `net[tickUpper] += L`, `L0 -= L` when it straddles), re-assert
   both structural identities, re-simulate. The pool's ERC-20 balances still hold the
   withdrawn tokens, so the cap here is the **re-integrated model reserve**, not the
   balance. This is a **counterfactual** — the rug case — and must be labelled as one.
   `depth.Pool.excluding()` does exactly this and refuses when the subtraction breaks an
   identity.
3. **Issuer net cash** — simulate the issuer's own sale and split each tick segment's
   output by liquidity share: `seg * L_issuer / L_active` is money returning to its own
   pocket. The remainder is what actually reaches it. Note it did not exit either: the
   tokens it "sold" are now inside its own position.

`total quote − issuer quote` is **none of these**. It is an inventory statistic — who
funded the book — and no participant can execute against it. Print it if you like, never
under a label containing the word "reach".

**And number 2 has one more subtraction in it.** What remains after the issuer withdraws
is still not third-party depth if whoever created the pool put it there. In the case
above, $10,000 of a about $10,000 remainder was a single-sided quote position **minted in the
pool-creation block itself**, untouched for a year. Genuinely unattributed third-party
quote was **under $100** — more than a hundredfold. Check every surviving position's mint block
against the pool's creation block. `owned_token_ids()` will not find these for you: it
enumerates the addresses you already suspected, and this one belonged to an address
nobody had a reason to name (an EIP-7702 delegated EOA holding exactly one NFT and no
token balances — see #15 before calling it a contract).

Then ask the question that makes [1] meaningful: **can they execute [2] at will?**
`ownerOf` the position NFTs. An EOA with no timelock means the counterfactual is one
transaction away, and the honest sentence is "a seller can reach X today, of which Y% is
the issuer's and withdrawable in a single call, leaving Z" — all three numbers, one
sentence.

Symptom you have made this mistake: your "third-party reachable" figure is **smaller than
the proceeds your own sell simulator reports** for a mid-sized sale. Those come from
different universes; if the first is below the second, the first is answering a question
nobody asked.

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

- **A price read off the tick is not the price.** `slot0` returns both `sqrtPriceX96`
  and `tick`, and the tick is the *floored* log of the price. `1/1.0001**tick` looks
  like the price and is not: on one pool it gave a tick-derived price where `sqrtPriceX96` gave
  **the sqrtPriceX96 price**. That is under a hundredth of a percent and nobody would notice — which is the problem,
  because the same substitution in a slippage curve or a range-boundary price gets
  multiplied by `L` and comes out in real dollars. Use `(sqrtPriceX96 / 2**96) ** 2`,
  adjusted for decimals; use the tick only for bucketing.

- **Contract addresses.** The most expensive recalled constant is not a number, it is an
  address — a position manager, a factory, a router. A wrong one does not throw:
  `eth_call` against an address with no code returns `0x`, which decodes to "no
  positions", "no pool", "no owner". A run wrote PancakeSwap V3's NFPM from memory;
  `eth_getCode` on it returned **0 bytes** — no contract there at all — and the tool
  reported the pool as having no NFT positions. Derive it, and prove it:

  | Constant | Derive it from | Prove it |
  |---|---|---|
  | Position manager | the `owner` topic of this pool's own `Mint` (or `Burn`) logs | `eth_getCode != "0x"`, and its `factory()` matches the pool's |
  | Factory | `factory()` (`0xc45a0155`) **on the pool itself** | `getPool(token0,token1,fee)` returns the pool you started from |
  | Any address a human handed you | nothing — verify it | `eth_getCode != "0x"` before the first call that uses it. Refuse, loudly, on `0x` |

  And when you *write down* an address for someone else to check, write all 20 bytes. A
  briefing that said "the impostor on Ethereum is `0x82C637cA`" gave every downstream
  reader a string they could not verify, only believe.

- **Event topics.** Forks change event signatures, so they change topic hashes.
  PancakeSwap V3's `Swap` carries two extra `uint128` protocol-fee fields, so its topic0
  is not Uniswap V3's. Filtering a Pancake pool by the Uniswap topic returns `[]`, with
  no error, and reads as "this pool never traded". Worse, a *mistyped* topic does the
  same: one run used a `Mint` hash whose first 22 hex characters happened to be correct,
  got `[]`, and published "no liquidity was added or removed in a million blocks" — the real
  window held several hundred Mints. Compute topic0 with keccak from the signature string at runtime
  (`scripts/topics.py` does nothing else), and for any *census* query with **no topic
  filter** and bucket by `topic0`, so an unrecognised event is a visible unknown rather
  than an absence. A topic you do filter by must be shown to occur at least once at that
  address before an empty result from it is allowed to mean anything.

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

## 25. SQL string-slicing a wei amount silently truncates it

Token amounts do not fit in SQLite's INTEGER. The habit that grows out of that is to
slice the decimal string instead — `CAST(SUBSTR(val, 1, LENGTH(val)-18) AS INTEGER)` to
turn wei into whole tokens. It is fast, it is used in every aggregate, and it is lossy in
two ways at once:

- It **floors** every row. Across 1.16M transfers the dropped fractions are not noise;
  they are a systematic downward bias that grows with row count, and they never cancel
  because truncation only ever rounds one way.
- Any amount **below 1 token** becomes `0` — an entire class of transfers (dust probes,
  the `10.00` test transfer that reveals a shell chain, per-user airdrop remainders)
  aggregates to nothing and disappears from the analysis that was supposed to find it.

Use string slicing only for ranking and eyeballing. Every number that reaches a
deliverable must be summed with Python `int()` over the raw wei and divided once at the
end. When both appear in one report, say which is which: a headline that is 0.3% below
the exact figure is indistinguishable from a real discrepancy, and you will spend a day
chasing it.

## 26. A refusal is not a data point

Three different things arrive looking alike: the node answered "there is nothing here",
the node refused to answer, and the node was never asked because a worker died. Only the
first is data. Fold the other two into it and the analysis reports absence of evidence as
evidence of absence — no pool, no transfers, no privileged function.

- `eth_getLogs` returning `[]` is a claim about the chain. `result: null`, a timeout, or
  an exception is a claim about the node. Never write the second into a coverage table.
- An `eth_call` that reverts tells you something. An `eth_call` that was rate-limited
  tells you nothing — and if you treat the empty return as "function absent", a live
  escape hatch reads as safe.
- Count refusals separately and **print the count**. A run that answered 13 of 20 windows
  and a run that answered 20 of 20 must not produce the same-looking report.

The rule that follows: when a required probe cannot be answered, exit non-zero rather
than emit a number. A missing conclusion is recoverable; a confident wrong one is not.

## 27. Concurrency has a ceiling set by the node, not by your CPU

Raising worker count past what the endpoint tolerates does not speed a scan up — it
converts successful windows into 429s, which the retry path then re-queues, which
produces more 429s. Throughput peaks well before the failure rate does, so the run gets
slower *and* its coverage table starts filling with refusals that look like empty ranges
(see #26).

Two limits worth respecting: keep JSON-RPC batches at or below ~120 items, and keep
in-flight requests per endpoint in the single digits. Prefer more endpoints over more
threads per endpoint. Measure once with a small scan: if doubling workers does not
roughly halve wall-clock, you are already past the ceiling and everything above it is
being paid for in retries.

## 28. Netting the pool's Transfer legs is not the buy/sell flow

You have a certified Transfer table, so you compute "net tokens to the market" as
`sum(value) where dst == pool` minus `sum(value) where frm == pool`. Every row is real,
the arithmetic is exact, and the answer measures something else. **Four unrelated
mechanisms move tokens across a pool's boundary and one of them is a trade:**

| Event | token0 | token1 | A trade? |
|---|---|---|---|
| `Swap` | signed | signed | **Yes — only this one** |
| `Mint` | in | in | No. Liquidity added |
| `Burn` | **nothing** | **nothing** | No. It only credits `tokensOwed` |
| `Collect` | out | out | No. Principal + fees withdrawn |
| `Flash`, `CollectProtocol` | out/in | out/in | No |

A fortnight in which JIT makers zap in and out reads, under netting, as enormous selling
followed by enormous buying. In the case this entry comes from, "13 days, net roughly 29,000
tokens to market" was computed this way. The real figure from `Swap` alone was
**roughly 130,000 tokens** — over 4x larger — and the gap was roughly 140,000 tokens of **liquidity being
added**, counted as the market dumping. The roughly 29,000 was not even wrong as a quantity: it
is exactly the pool's ERC-20 balance change. It was wrong as a *label*.

**Use `Swap` and only `Swap`.** `amount0`/`amount1` are signed from the pool's side, so
positives are tokens sold into it and negatives are tokens bought out. Report both
directions and their counts, never the net alone (#18).

Then run the identity, which is cheap and names the leg you mis-signed:

```
Δ(pool balance of token0) == Σ swap.amount0 + Σ mint.amount0
                             − Σ collect.amount0 − Σ collectProtocol.amount0
```

`Burn` is absent on purpose — including it is the most common way to make this fail.
It closed to a hundredth of a token on over 100,000 swaps in the case above, and the residual resolved
to a few dozen transactions where the payer dusted the pool inside the swap callback.

Two attribution traps once you have the swaps:

- **Fold the conduits before ranking anyone.** A batch-settlement router received tokens
  inside swap transactions and forwarded them in separate ones, so a naive per-tx
  attribution made it the single largest buyer at **+over 800,000 tokens** while its actual
  net was roughly zero. Identify pass-throughs (high throughput, `|net| / throughput` near zero,
  balance near zero) and collapse them iteratively.
- **`Mint`'s `sender` is whoever called `mint()`, not who paid.** Matching by address
  lost over 13,000 tokens; match by direction and amount instead.

And the finding that only appears once you do this: **68% of that window's net buying
came from three "buy then immediately LP" bots whose wallet balances are zero** — the
tokens sit in the pool as liquidity. Any holder analysis built on balances is blind to
them.

## 29. A transfer to the pool address is not a sale

The same defect as #28 at address level, and worse there, because what gets published is
a finding about a person.

A one-hop wallet showed **roughly 1.4 million tokens sent to the pool** and was written up as a
seller. The receipts: **6 transactions were `Mint`** (roughly 1.37 million tokens added as
liquidity) and **18 were `Swap`** (under 40,000 actually sold). The real figure was 2.8% of the
reported one, and the story inverts — that wallet was *providing* the exit liquidity.

**The tell is in the transaction, never in the transfer.** For every `addr → pool`
transfer, look at what the pool emitted in that same transaction:

- `Swap` → a sale. Its size is `amount0`/`amount1`, **not** the transfer value: routers
  and multi-hop routes move different amounts through.
- `Mint` → liquidity added. The `owner` topic says whose position it became — usually
  the position manager, not the wallet.
- neither → a donation, a mis-send, or an event you have not decoded. Count it and name
  it; do not classify it.

Cheap version when receipts are too many: pull the pool's `Swap` and `Mint` logs for the
window, index by `transactionHash`, and join. Two `eth_getLogs` replace thousands of
receipt fetches.

The reciprocal error is as common: tokens leaving the pool to an address are a `Collect`
— its own principal coming back — as often as a purchase. #19's `collectFees` case is
this mechanism seen from the other side.

## 30. A public router is not a dedicated shell

#20 warns that N-hop-zero-contact does not prove independence. The inverse error is
just as easy and reads far worse when it is wrong: concluding that because issuer-lineage
tokens moved through intermediaries before reaching the pool, those intermediaries are a
purpose-built laundering chain.

A wallet funded by the issuer split a five-figure holding into several hundred slices of
a few hundred dollars each and pushed them through two addresses into the pool. It was
written up as a four-hop shell chain "accumulating a six-figure total of sales". Both
halves were wrong. The cumulative figures quoted were those two addresses' **lifetime**
totals, spanning more than a year and starting long before the funded wallet existed —
most of them predated it. And the receipts showed the pair was a **general MEV/arbitrage
bot**: in earlier transactions they were moving an unrelated token, and moving the
subject token in the *buy* direction. They were a router someone rented, not a shell
someone built, and the quote proceeds of every slice went straight back to the funded
wallet.

The finding survived — an issuer wallet still sliced that holding into retail-sized
sells — but the mechanism described was fiction.

Before calling an intermediary a shell, check three things:

- **Does it handle other tokens in the same period?** A shell built for this token does
  not. Pull a receipt from outside your window.
- **Which direction does it usually move the subject token?** A dedicated distribution
  conduit does not spend most of its life buying.
- **Does its lifetime predate the wallet it supposedly serves?** Compare first-seen
  blocks before quoting any cumulative figure.

Which is the general rule #20's inverse demands: **never describe one episode's flow with
an intermediary's lifetime totals.** Slice every "routed via X, N tokens" claim to the
time window and the amounts of the episode you are actually describing. The lifetime
number is about X, not about your finding.

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
| Exit liquidity | All three numbers computed and separately labelled: spot exit (whole book, untouched), post-withdrawal exit (issuer positions removed, both identities re-asserted), issuer net cash (per-segment attribution). Neither is `total quote − issuer quote` |
| Position shape | Every issuer position classified ladder / bid / two-sided from its own ticks against the current tick — never carried over from a previous case |
| Withdrawability | `ownerOf` checked on every issuer position NFT; whether the counterfactual is one transaction away is stated beside the spot-exit number |
| Venue coverage | Enumeration method stated (factory sweep across every fee tier × quote, V2 `getPair`, plus counterparty mining), and the measured pools' share of discovered quote printed beside every market figure |
| Window liquidity change | Mint / Burn / Collect / Swap counted over the reporting window with NO topic filter; `Mint == 0 && Burn > 0` treated as a broken query, not a quiet pool; every depth figure carries that window |
| Pool-leg decomposition | Flow computed from `Swap` amounts only; `Δbalance == Σswap + Σmint − Σcollect − ΣcollectProtocol` closes, with `Burn` excluded |
| Conduits folded | Pass-through routers collapsed before any buyer/seller ranking; no episode described with an intermediary's lifetime totals |
| Addresses and topics derived | Every contract address proved with `eth_getCode != "0x"` and written out in full; every topic0 computed by keccak and shown to occur at that address before an empty result from it means anything; price from `sqrtPriceX96`, never from the tick |
| Certification travels | Any artefact built over a `--force`d database is stamped on the artefact itself, not only in the database's metadata |
| Constants | Block time and price measured at a stated block, not recalled or read from cache |
| Privileges | Every contract that holds or moves the token audited — adapter, vesting factory, distributor — not just the token; each live path named with its holder and threshold |
| Cross-chain labels | No address tagged as issuer on one chain and untagged on another |
| Wei arithmetic | Every published figure summed with `int()` over raw wei; string-sliced values used only for ranking, and labelled as such |
| Refusals counted | Windows answered vs. windows asked printed; no refusal folded into "empty" |
| Market-maker bucket | Test-transfer, pre-pool-arrival and return-to-treasury all checked before any desk is called independent |
