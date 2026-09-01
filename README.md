# tracing-token-float

An [Agent Skill](https://agentskills.io/specification) for establishing **who actually controls a token's circulating float** — and whether the resulting market cap is backed by any real exit liquidity.

Works with Claude Code, Codex, Copilot CLI, Gemini CLI, and anything else that reads the Agent Skills format.

## What it's for

You have a token. The team published a tokenomics table. You want to know what the chain actually says:

- How much of the "circulating" float is still controlled by the issuer, through multisigs, intermediaries, market-making wallets, or bridged inventory
- Whether the locks are worth what the docs claim — or whether an admin path can unwind them in days
- How much of an airdrop went to a sybil farm rather than to users
- **What the position is actually worth if it hits the book** — usually the number that reframes everything else

## The layers

Bottom-up. Each layer is void if the one below it didn't pass its gate.

```
L0  Replay      every Transfer into a local DB    → gate: rebuilt balances == totalSupply, wei-exact
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
    pitfalls.md             13 traps that corrupt results while every number still looks fine
    v3-depth.md             concentrated-liquidity math and the depth simulator
  scripts/
    rpc.py                  rotating multi-endpoint JSON-RPC, batching, signed-word decode
    replay.py               event replay into SQLite + the supply-identity gate
    lineage.py              weighted provenance, net-flow, first-funder
    depth.py                V3 profile, reserve self-check, sell simulator
```

## Install

Drop the `tracing-token-float/` directory into your skills directory:

```bash
git clone https://github.com/0xBennie/tracing-token-float.git
cp -r tracing-token-float/tracing-token-float ~/.claude/skills/
```

Codex, Copilot CLI and Gemini CLI also read `~/.agents/skills/`.

## Using the tools standalone

```python
from rpc import Client, BASE
from depth import Pool

p = Pool(Client(BASE), "0xPOOL...", dec0=18, dec1=6)

print(p.selfcheck())          # run this first — depth numbers are void without it
print(p.sell(1_000_000))      # what a 1M-token sell would ACTUALLY fill and fetch
```

`selfcheck()` integrates the tick profile back into pool reserves and compares against the real ERC-20 balances. Model exceeding the balance, or coming out negative, means a decode or scan bug — the two failure modes that otherwise produce confident, wrong depth numbers.

## Why the traps file matters

Every entry in `references/pitfalls.md` is a mistake that produces a plausible-looking wrong answer rather than an error:

- `CAST(val AS REAL)` losing wei above 2^53, so the supply identity misses by thousands
- `liquidityNet` decoded as int128 when the ABI sign-extends it to 256 bits, turning negatives into 10^38
- Treating a pool's token balance as the issuer's LP position, attributing every third-party LP to them
- Reading pool state across blocks while a JIT vault churns, so liquidity and ticks describe different states
- Weighted lineage on a high-frequency address, where its own churn dilutes provenance to noise
- A mixed numerator and denominator — the one that produces impressive, meaningless percentages

## Provenance

Distilled from a full two-chain float audit: ~4.7M Transfer events replayed across Base and BNB Chain, attribution closed exactly onto the float, then cross-examined by independent agents per layer with adversarial reviewers assigned to refute the disputed findings rather than confirm them. Every trap listed was hit and fixed during that work.

## License

MIT
