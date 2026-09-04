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

## Reporting

For each size, report: requested, **actually fillable**, proceeds, average price, post-trade price, drawdown. Then aggregate across every pool on every chain into one figure — **total reachable quote currency** — and set it beside the position's mark-price valuation.

That ratio is usually the headline. A position can be worth tens of millions on paper against a few hundred thousand dollars of reachable liquidity.

Note the snapshot block and time. Pools with JIT activity move between blocks.
