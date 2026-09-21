#!/usr/bin/env python3
"""Event topics, derived from signature strings — never stored as hashes.

    import topics
    topics.T["v3.Mint"]                      # computed, not typed
    topics.census(cli, pool, lo, hi)         # NO topic filter, bucketed by topic0
    topics.must_occur(cli, pool, t, lo, hi)  # refuse to read [] as a finding

A wrong topic0 does not raise. `eth_getLogs` filtered on a hash that matches nothing
returns `{"result": []}`, byte-identical to a genuinely quiet range, and the analysis
reads it as "this never happened". One run typed a Mint topic from memory whose first
22 hex characters happened to be right; the query came back empty and the deliverable
said "no liquidity was added or removed in a million blocks". The real window held
several hundred Mints and as many Burns, and the depth conclusion that rested on "the
book is static" was wrong.

Two habits, both enforced here:
  - compute topic0 with keccak from the signature at import time, so a typo becomes a
    different signature string that a reader can check, not an opaque hash nobody can
  - before an EMPTY result from a filtered query is allowed to mean anything, show that
    the topic occurs at least once in that contract's history (`must_occur`)

Forks rename events. PancakeSwap V3's `Swap` carries two extra uint128 protocol-fee
fields, so its topic0 differs from Uniswap V3's entirely. Filtering a Pancake pool by
the Uniswap topic returns [] and reads as "this pool has never traded". Both are below;
`swap_topics()` returns the pair so a census can accept either.
"""
from Crypto.Hash import keccak as _k


def topic0(signature: str) -> str:
    """keccak256 of a canonical event signature. The only way a topic enters this skill."""
    h = _k.new(digest_bits=256)
    h.update(signature.encode())
    return "0x" + h.hexdigest()


def selector(signature: str) -> str:
    """First 4 bytes of keccak256 — a function selector, derived the same way."""
    return topic0(signature)[:10]


# Canonical signatures. Read these, not hashes: a wrong one is visible here.
SIG = {
    "erc20.Transfer":   "Transfer(address,address,uint256)",
    "erc20.Approval":   "Approval(address,address,uint256)",
    # Uniswap-V3-style pool
    "v3.Mint":          "Mint(address,address,int24,int24,uint128,uint256,uint256)",
    "v3.Burn":          "Burn(address,int24,int24,uint128,uint256,uint256)",
    "v3.Collect":       "Collect(address,address,int24,int24,uint128,uint128)",
    "v3.CollectProtocol": "CollectProtocol(address,address,uint128,uint128)",
    "v3.Flash":         "Flash(address,address,uint256,uint256,uint256,uint256)",
    "v3.Swap":          "Swap(address,address,int256,int256,uint160,uint128,int24)",
    # PancakeSwap V3 appends protocolFeesToken0/1 — a DIFFERENT topic0, same name
    "pancake.Swap":     "Swap(address,address,int256,int256,uint160,uint128,int24,"
                        "uint128,uint128)",
    # Position manager
    "nfpm.IncreaseLiquidity": "IncreaseLiquidity(uint256,uint128,uint256,uint256)",
    "nfpm.DecreaseLiquidity": "DecreaseLiquidity(uint256,uint128,uint256,uint256)",
    "nfpm.Collect":     "Collect(uint256,address,uint256,uint256)",
    # Factories
    "v3.PoolCreated":   "PoolCreated(address,address,uint24,int24,address)",
    "v2.PairCreated":   "PairCreated(address,address,address,uint256)",
    # V2 pool
    "v2.Swap":          "Swap(address,uint256,uint256,uint256,uint256,address)",
    "v2.Sync":          "Sync(uint112,uint112)",
    # Access control / ownership, for the privilege audit
    "ac.RoleGranted":   "RoleGranted(bytes32,address,address)",
    "ac.RoleRevoked":   "RoleRevoked(bytes32,address,address)",
    "own.OwnershipTransferred": "OwnershipTransferred(address,address)",
}

T = {k: topic0(v) for k, v in SIG.items()}
NAME = {}
for _k_, _v_ in T.items():          # topic0 -> readable name, for census output
    NAME.setdefault(_v_, []).append(_k_)


def swap_topics():
    """Both Swap variants. A pool census must accept either; a fork may use neither."""
    return [T["v3.Swap"], T["pancake.Swap"]]


def census(cli, address, lo, hi, span=10_000):
    """Every log a contract emitted in [lo, hi], bucketed by topic0, NO topic filter.

    Filtering by a topic you typed is how a fork's renamed event becomes "no events".
    Bucketing turns an unrecognised signature into a visible unknown instead of a
    silent zero, and it costs the same number of calls.

    Returns (counts, asked, answered, refused). Refusals are counted separately and
    NEVER folded into the counts — a window nobody answered is not a window with no
    events. Treat every count as a floor whenever refused > 0.
    """
    import collections
    counts = collections.Counter()
    asked = answered = refused = 0
    cur = lo
    while cur <= hi:
        top = min(cur + span - 1, hi)
        asked += 1
        try:
            logs = cli.call("eth_getLogs", [{"address": address,
                                             "fromBlock": hex(cur), "toBlock": hex(top)}])
            answered += 1
            for l in logs:
                counts[l["topics"][0] if l["topics"] else "0x(anonymous)"] += 1
        except Exception:
            refused += 1
        cur = top + 1
    return counts, asked, answered, refused


def describe(counts):
    """Render a census, naming what we recognise and flagging what we do not."""
    out = []
    for t, n in counts.most_common():
        out.append(f"  {('/'.join(NAME.get(t, []))) or 'UNKNOWN ' + t:26} {n:>9,}")
    return "\n".join(out)


def liquidity_sanity(counts):
    """Consistency checks that catch a broken query for free.

    Liquidity that was never minted cannot be burned. Mint == 0 while Burn > 0 is not
    a quiet pool, it is a query that failed — a mistyped topic, a pruned node, or a
    refusal folded into the count. This check costs nothing and catches three distinct
    failure modes at once; it is the check that would have caught the one in the
    module docstring.
    """
    problems = []
    mint, burn = counts.get(T["v3.Mint"], 0), counts.get(T["v3.Burn"], 0)
    coll = counts.get(T["v3.Collect"], 0)
    swaps = sum(counts.get(t, 0) for t in swap_topics())
    if burn and not mint:
        problems.append(f"Mint == 0 but Burn == {burn:,}. Liquidity that was never "
                        f"minted cannot be burned — the Mint query failed (wrong topic, "
                        f"pruned node, or a refusal counted as zero).")
    if coll and not burn:
        problems.append(f"Collect == {coll:,} but Burn == 0. Possible, but unusual "
                        f"enough to verify: Collect normally follows Burn.")
    if not swaps and (mint or burn):
        problems.append(f"Swap == 0 while the book was being changed {mint + burn:,} "
                        f"times. A fork's Swap topic is not Uniswap's — census without "
                        f"a filter and check the UNKNOWN buckets.")
    return problems


def must_occur(cli, address, topic, lo, hi, span=10_000, name=""):
    """Prove a topic occurs at this address before an empty result from it means anything.

    Walks backward from `hi` and stops at the first hit. Raises when the whole range
    came back empty AND nothing was refused — because at that point the honest reading
    is "this topic is wrong", not "this never happened".
    """
    cur, asked, refused = hi, 0, 0
    while cur >= lo:
        bot = max(lo, cur - span + 1)
        asked += 1
        try:
            logs = cli.call("eth_getLogs", [{"address": address, "topics": [topic],
                                             "fromBlock": hex(bot), "toBlock": hex(cur)}])
            if logs:
                return True
        except Exception:
            refused += 1
        cur = bot - 1
    raise RuntimeError(
        f"topic {topic}{' (' + name + ')' if name else ''} never occurs at {address} "
        f"across {asked} window(s) ({refused} refused). Before reading any empty result "
        f"from this filter as a finding: verify the signature, and check whether this "
        f"contract is a fork that renamed the event.")


if __name__ == "__main__":
    print("event topics, computed from signatures at import:\n")
    for k in sorted(SIG):
        print(f"  {k:26} {T[k]}\n  {'':26} {SIG[k]}")
    print("\nNote the two Swap variants — same event name, different topic0:")
    print(f"  uniswap  {T['v3.Swap']}")
    print(f"  pancake  {T['pancake.Swap']}")
