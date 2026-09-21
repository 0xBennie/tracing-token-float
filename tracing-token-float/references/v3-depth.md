# Concentrated Liquidity Depth

How to turn a Uniswap-V3-style pool into an answer to "if they dumped, what would they actually get?"

Applies to Uniswap V3, PancakeSwap V3, Aerodrome Slipstream, and other forks. Selectors below are the standard ones; forks occasionally extend the `ticks` struct but keep `liquidityGross`/`liquidityNet` as the first two words.

## Selectors

| Call | Selector | Returns |
|---|---|---|
| `slot0()` | `0x3850c7bd` | word0 `sqrtPriceX96`, word1 `tick` (int24, sign-extended) |
| `liquidity()` | `0x1a686502` | active `L` at the current tick |
| `tickSpacing()` | `0xd0c93a7c` | int24 |
| `fee()` | `0xddca3f43` | uint24, millionths |
| `token0()` / `token1()` | `0x0dfe1681` / `0xd21220a7` | addresses |
| `tickBitmap(int16)` | `0x5339c296` | uint256 word |
| `ticks(int24)` | `0xf30dba93` | word0 `liquidityGross`, **word1 `liquidityNet` (int128, sign-extended to 256 bits)** |

Decode every signed return with a 256-bit two's-complement helper. See pitfalls #3.

## Price

```
price(token1 per token0) = (sqrtPriceX96 / 2**96)**2 * 10**(dec0 - dec1)
sqrtP(tick) = 1.0001 ** (tick / 2)
```

## Scan the full range, and budget for it

Word count is `2 × 887272 / tickSpacing / 256`, so the cost is bounded but very uneven:

| tickSpacing | bitmap words | measured |
|---|---|---|
| 200 (Aerodrome 0.3%) | ~35 | 59 s |
| 60 | ~115 | — |
| 1 (Pancake 0.01%) | ~6,932 | **428 s** |

Seven minutes on a `tickSpacing=1` pool is normal, not a hang. Take it: a windowed scan
cannot satisfy `sum(liquidityNet) == 0`, and without that identity a truncated book is
indistinguishable from a real one — it reconstructs plausible reserves and then reports
the bottom of the scanned range as a price floor.

## Building the profile

1. `comp = tick // tickSpacing`; `wordPos = comp >> 8`. Python's floor division and arithmetic shift already behave correctly for negative ticks — don't "fix" them.
2. Batch-fetch `tickBitmap` words across the range you care about. Downward span matters most: enough ticks to reach a price where nothing is left. Batch ≤120 calls per request.
3. Expand set bits to tick indices: `((wordPos << 8) + bitIndex) * tickSpacing`.
4. Batch-fetch `ticks()` for each initialized tick, decode `liquidityNet` with `s256`.

## Mandatory self-check

Before any number leaves this stage, integrate the profile back into reserves and compare with the pool's actual ERC-20 balances.

- Downward from the current price, accumulating `L * (sqrtP_hi - sqrtP_lo)` → token1
- Upward, accumulating `L * (1/sqrtP_lo - 1/sqrtP_hi)` → token0
- Crossing a tick downward: `L -= liquidityNet`. Upward: `L += liquidityNet`.

Reconstructed reserves should sit at or just below the on-chain balances — never above. The shortfall is uncollected and protocol fees, which sit in the balance but never participate in swaps. Orders-of-magnitude divergence means a decode bug; a large finite gap means the scan window was too narrow.

**Also assert the two structural identities**, which catch truncation the reserve comparison does not: over the full tick range `sum(liquidityNet) == 0`, and `sum(liquidityNet for t <= currentTick) == liquidity()`. A truncated scan still reconstructs plausible-looking reserves and then reports the bottom of the scanned range as a price floor — that is exactly how a depth file full of fake floors got produced.

**Do not report depth numbers from a profile that hasn't passed this check.**

## Before the profile means anything: is the book still the book you measured?

A tick profile is a photograph. Whether it describes the next fortnight or the next
block is a separate measurement, and it decides whether a depth figure may be written
in the past tense.

Census the window you intend to describe, **with no topic filter**, bucketed by
`topic0` (`scripts/topics.py` does this and names what it recognises):

```python
logs = cli.call("eth_getLogs", [{"address": pool,
                                 "fromBlock": hex(lo), "toBlock": hex(hi)}])
counts = collections.Counter(l["topics"][0] for l in logs)
```

Filtering by a topic you typed is how a renamed or mistyped event becomes "no events".
Then read it:

- **`Mint == 0` while `Burn > 0` is a broken query, not a quiet pool.** Liquidity that
  was never minted cannot be burned. One run published "no Mint/Burn in a million blocks";
  a re-query of 13 days found **several hundred Mints and the same number of Burns**. The Mint topic had been
  typed from memory and `eth_getLogs` returned `[]` without error. Nothing in the
  profile could have told you.
- **`Burn` moves no tokens.** It credits `tokensOwed`; `Collect` performs the transfer.
  A window with Burns and no Collects has liquidity out of the book but still in the
  ERC-20 balance — exactly the residual the reserve self-check is tolerating.
- **Same-block Mint/Burn pairs are JIT even when they are two transactions.** 351 of
  those pairs shared a block, median survival 0 blocks. Pitfall #5 applies: that
  liquidity will not absorb a dump, and it must not be counted as depth.
- To know whether a snapshot is representative, sample `liquidity()` across the window
  rather than arguing about it. In the case above 400 equidistant samples showed a
  **binary step** (2.00% of issuer L above one tick, 0.04% below) and never once landed
  on JIT — so the snapshot was sound. That is a measurement, not an assumption.

## The flow inside that window is `Swap` only

```
d(balance token0) == sum swap.amount0 + sum mint.amount0
                     - sum collect.amount0 - sum collectProtocol.amount0
```

`amount0`/`amount1` on `Swap` are signed from the pool's side: positive is into the pool
(someone sold it), negative is out. Compute both directions and their counts; never
publish the net alone. `Burn` is absent from the identity on purpose. Run it as a gate —
it is the only thing that tells you a log query came back short. On over 100,000 swaps it
closed to a hundredth of a token, and that residual resolved to a few dozen transactions where the payer
dusted the pool inside the swap callback.

## The three numbers, and how to compute each

`sell()` answers one question. Which one depends on what book you hand it.

**1. Spot exit — what a third party gets now.** `sell()` on the profile exactly as
scanned. No subtraction, no attribution. The AMM pays from whatever is at the tick.

**2. Post-withdrawal exit — the counterfactual.** `Pool.excluding(positions)`:

```
net[tickLower] -= L ;  net[tickUpper] += L
if tickLower <= currentTick < tickUpper:  L0 -= L
```

Both identities must still hold (the edits are equal and opposite, so a break means a
position's ticks lay outside the scanned profile — the scan was truncated). The ERC-20
balances still contain the withdrawn tokens, so the cap is the **re-integrated model
reserve**, not `reserve1`. A negative `L0` means the positions exceed the book: stop.

**Then subtract one more thing.** The remainder still is not "third-party" depth if part
of it was placed by whoever created the pool. In the case above, $10,000 of a about $10,000
remainder was a single-sided USDT position **minted in the pool-creation block itself**,
untouched for a year — a seed bid, not third-party market-making. Genuinely unattributed
third-party quote was **under $100**. Check every remaining position's mint block against the
pool's creation block before calling it third-party; `owned_token_ids()` cannot find
these, because it only enumerates addresses you already suspected.

**3. Issuer net cash.** Walk the book as for a normal sale, carrying `L_issuer` (the
issuer liquidity active at the current tick, updated at each crossing). Per segment:

```
own      += seg * L_issuer / L_active        # the issuer paying itself
external += seg * (1 - L_issuer / L_active)  # cash that actually arrives
```

`external` is the answer. Measured on the case above: selling 1,000,000 tokens grossed
roughly $300,000 of which **under $6,000** was new external cash. And the issuer did not exit
either — the tokens it "sold" now sit inside its own position.

**What is not one of the three:** `total quote − issuer quote`. That is an inventory
statistic about who funded the book. No participant can execute against it. Labelling it
"third-party reachable" reported about $10,000 where a 25,000-token sale paid about $17,000 out of
the full book — the published ceiling was exceeded by a sale a fifth of that size.

## Simulating a sell

Selling token0 moves price down. Per tick segment, with fee `f` taken from the input:

```
dx_max  = L * (1/sqrtP_next - 1/sqrtP)        # token0 the segment absorbs
if remaining * (1-f) < dx_max:                # fills inside the segment
    sqrtP_end = 1 / (1/sqrtP + remaining*(1-f)/L)
    out += L * (sqrtP - sqrtP_end)
    done
else:
    out += L * (sqrtP - sqrtP_next)
    remaining -= dx_max / (1-f)
    cross: sqrtP = sqrtP_next; L -= liquidityNet[tick_next]
```

Two stopping conditions matter as much as the loop:

- **Quote exhausted.** Cumulative output can never exceed the pool's token1 balance. Stop there and report the sell as *partially filled*.
- **Liquidity exhausted.** Below the lowest initialized tick there are no bids at all. Report the fillable quantity, not the requested one.

Floating point is adequate here — `L` around 10^20–10^23 stays well inside float64 precision, and the answer is a risk estimate, not a settlement figure.

### Selling token1 — the other half, and you will need it

Whether the token you are auditing is `token0` or `token1` is decided by address ordering, not by importance. Roughly half of all pools put it second, and a simulator that only walks downward silently reports **zero depth** for those — which reads as "no exit liquidity" when the truth may be the opposite. `depth.py` exposes both (`sell` / `sell1`, and `curve(sizes, token1=True)`); check `token0()` against your token before quoting a number.

Selling token1 moves price **up**, so the loop mirrors:

```
dy_max  = L * (sqrtP_next - sqrtP)             # token1 the segment absorbs
if remaining * (1-f) < dy_max:                 # fills inside the segment
    sqrtP_end = sqrtP + remaining*(1-f)/L
    out += L * (1/sqrtP - 1/sqrtP_end)         # output is token0
    done
else:
    out += L * (1/sqrtP - 1/sqrtP_next)
    remaining -= dy_max / (1-f)
    cross: sqrtP = sqrtP_next; L += liquidityNet[tick_next]
```

Note the two sign flips that are easy to miss: the tick crossing **adds** `liquidityNet` going up (it subtracts going down), and the output accumulator uses the reciprocal form. Getting one right and the other wrong produces a curve that looks plausible and is wrong by the width of the range.

The stopping conditions swap accordingly: cumulative output cannot exceed the pool's **token0** balance, and above the highest initialized tick there are no asks left.

## Reporting

For each size, report: requested, **actually fillable**, proceeds, average price,
post-trade price, drawdown, and stop reason. Then, for each of the three numbers above,
aggregate across **every venue the enumeration step found** — saying how many that was
and what share of discovered quote they hold — and set the **spot-exit** total beside
the position's mark-price valuation.

That ratio is usually the headline. A position can be worth tens of millions on paper
against a few hundred thousand dollars of reachable liquidity. State which of the three
the denominator is: on one token the same numerator gave roughly 50 : 1 against spot exit and
nearly 1,900 : 1 against the post-withdrawal counterfactual, and only one of those is what a
holder faces today.

Every figure carries four stamps or it is not quotable: the **block**, the
**timestamp**, the **window** the liquidity census covered, and **which of the three
numbers it is**. Pools with JIT move between blocks; pools with hundreds of Mint/Burn
pairs per fortnight move between weeks.
