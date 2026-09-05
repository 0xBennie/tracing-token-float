# tracing-token-float

An [Agent Skill](https://agentskills.io/specification) for establishing **who actually controls a token's circulating float** — and whether the resulting market cap is backed by any real exit liquidity.

Works with Claude Code, Codex, Copilot CLI, Gemini CLI, and anything else that reads the Agent Skills format.

## What it's for

You have a token. The team published a tokenomics table. You want to know what the chain actually says:

- How much of the "circulating" float is still controlled by the issuer, through multisigs, intermediaries, market-making wallets, or bridged inventory
- Whether the locks are worth what the docs claim — or whether an admin path can unwind them in days
- How much of an airdrop went to a sybil farm rather than to users
- **What the position is actually worth if it hits the book** — usually the number that reframes everything else

## Start here

```bash
python scripts/scan.py --chain base --token 0xABC... \
       --also-audit 0xBRIDGE_ADAPTER... --holdings 100000000
```

No database, three numbers that change a decision. Budget **ten to twenty minutes**:
pool discovery mines tens of thousands of blocks, and each pool's tick profile is scanned
over the full valid range — 35 bitmap words at tickSpacing 200, but ~6,900 at spacing 1,
which is around seven minutes for that pool alone. It prints progress as it goes.

```
[1] PRIVILEGES — can they print, freeze, or drain?
    !! [escape] sweep(address)   OWNER-ONLY (stranger refused: OwnableUnauthorizedAccount)
    -> LIVE escape hatch — held balances can be withdrawn unilaterally, no delay
    -> owner is a Safe 4/6: 4 signatures move it

  NOTE: only the token contract was audited. Escrow lives elsewhere — re-run with
        --also-audit <addr>... before reading the result above as 'clean'.

[2] EXIT LIQUIDITY
  0xa1b2c3…   quote MEME  [NOT priced — excluded from $ totals]
  0xd4e5f6…   quote USDC
             sell      fillable       proceeds          avg         after    drop
           10,000        10,000       4,120.00     0.412000    0.41142000   -0.9%
          100,000       100,000      19,400.00     0.194000 3.1000000e-07 -100.0%

[3] VERDICT
  pools discovered 2   measured 2   skipped 0
     ! discovery only mined the last 20,000 blocks of Transfers
     ! 1 pool(s) quoted in MEME: 2,400,000 MEME reachable, not converted
     -> the totals below are a FLOOR, not the market

  displayed liquidity (TVL style)   $1,480,000
  actually reachable by selling     $25,293   (76.3x overstated)
  position at mark price            $41,200,000
  paper : reachable                 2,124 : 1
```

Run this before the full method below — either answer can make the rest academic.

**It deliberately does not compute "the team controls X% of float."** That number is
expensive, mostly restates the published allocation table, and is the same decision at
across the plausible range. The layers below are there when you need it anyway.

## The layers

Bottom-up. Each layer is void if the one below it didn't pass its gate.

```
L0  Replay      every Transfer into a local DB    → gate: EVERY block range answered, AND
                                                          rebuilt balances == totalSupply, wei-exact
L1  Distribution  genesis tree, allocation buckets  → gate: reconciles against the published table
L2  Attribution   tier every material address       → gate: tiers close exactly onto the float
L3  Clustering    addresses under one controller    → gate: infrastructure excluded, no collapse
L4  Sybil         batch-controlled claimers         → gate: collision rate vs a stated null model
L5  Control       key holders, effective lock life  → gate: lock period computed, not assumed
L6  Cross-chain   per-chain supply                  → gate: adapter escrow == remote totalSupply
L7  Market        depth curve, real exit liquidity  → gate: profile reproduces pool reserves
L8  Close         two independent totals            → gate: they agree, residual named
```

## Layout

```
tracing-token-float/
  SKILL.md                  the method, the tiers, the discipline
  references/
    pitfalls.md             24 traps that corrupt results while every number still looks fine
    v3-depth.md             concentrated-liquidity math and the depth simulator
  scripts/
    scan.py                 the three-number pass — start here
    privileges.py           selector extraction from bytecode + live-control proof
    rpc.py                  rotating JSON-RPC; separate endpoint pools for historical logs
    replay.py               parallel event replay into SQLite + the coverage and supply gates
    balances.py             exact rebuild, and the float denominator that closes in wei
    control.py              Safe signer intersection, effective lock, cross-chain supply
    positions.py            V3 liquidity attributed to owners; third-party reachable quote
    attribute.py            the tier table, the closure gate, and the re-audit diff
    lineage.py              weighted provenance, net-flow, first-funder
    depth.py                V3 profile, structural identities, sell simulator (both directions)
```

## Install

Drop the `tracing-token-float/` directory into your skills directory:

```bash
git clone https://github.com/0xBennie/tracing-token-float.git
cp -r tracing-token-float/tracing-token-float ~/.claude/skills/
```

> The repository is currently **private**, so that clone only works for accounts with
> access. It also carries `case-study/`, which names a real project — split or redact
> that directory before making the repo public.

Codex, Copilot CLI and Gemini CLI also read `~/.agents/skills/`.

## Using the tools standalone

```python
from rpc import Client, BASE
from depth import Pool

p = Pool(Client(BASE), "0xPOOL...", dec0=18, dec1=6)

print(p.selfcheck())          # run this first — depth numbers are void without it
print(p.sell(1_000_000))      # what a 1M-token sell would ACTUALLY fill and fetch
```

`selfcheck()` runs during construction and raises `InconsistentState` if it fails, so
reaching the next line already means it passed; call it to read the numbers. It tests
four things: the model never exceeds the ERC-20 balance and never goes negative (the two
decode bugs), and two structural identities — `sum(liquidityNet) == 0` over the whole
book, and the below-price sum equalling `liquidity()`. Those identities are what catch a
truncated tick scan, which is the dangerous case: a short scan reconstructs plausible
reserves and then reports the bottom of the scanned range as a price floor.

It deliberately does NOT test that the model is *close* to the balance. Accrued protocol
fees sit in the balance and back no swap — on a dead pool 99.8% of the balance can be
fees, leaving a model that is exactly right and 500x below the balance. The residual is
reported and attributed instead of gated on.

Use `sell()` when your token is the pool's token0 and `sell1()` when it is token1. Which
one you are is decided by address sort order and is otherwise meaningless — `scan.py`
picks for you.

## Why the traps file matters

Every entry in `references/pitfalls.md` is a mistake that produces a plausible-looking wrong answer rather than an error:

- A replayed range that no node ever answered, which the supply identity cannot see:
  ordinary peer-to-peer transfers net to zero across all balances, so the identity holds
  to the wei with the range missing. On a fixed-supply token its entire detection power
  is spent in the deploy block
- `CAST(val AS REAL)` losing wei above 2^53, so the supply identity misses by thousands
- `liquidityNet` decoded as int128 when the ABI sign-extends it to 256 bits, turning negatives into 10^38
- Treating a pool's token balance as the issuer's LP position, attributing every third-party LP to them
- Reading pool state across blocks while a JIT vault churns, so liquidity and ticks describe different states
- Weighted lineage on a high-frequency address, where its own churn dilutes provenance to noise
- Auditing the token contract and stopping there, while the bridge adapter holding the
  remote chain's entire collateral carries a non-standard `sweep()`
- A mixed numerator and denominator — the one that produces impressive, meaningless percentages

## Provenance

Distilled from a full two-chain float audit: ~4.7M Transfer events replayed across Base
and BNB Chain, attribution closed exactly onto the float, then cross-examined by 25
independent agents — one per layer, with adversaries assigned to *refute* the disputed
findings rather than confirm them. Every trap listed was hit during that work.

The review overturned three of the original report's headline claims, including a
realized-proceeds figure that was wrong by 40x in the direction of accusing the issuer.
It also found what none of the flow analysis had: a live `sweep()` on the bridge adapter
putting the entire remote-chain supply at the discretion of a 4/6 multisig.

That is why `scan.py` leads with privileges rather than percentages. The forensics were
worth far less than the two contract reads.

## License

MIT
