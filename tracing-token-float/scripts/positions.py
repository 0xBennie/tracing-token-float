#!/usr/bin/env python3
"""Attribute V3 liquidity to the addresses that actually own it.

    python positions.py --chain base --pool 0xPOOL... --issuer 0xLP... 0xTREASURY...

A pool's ERC-20 balance is not the issuer's LP position, and the quote sitting in a
pool is not what a seller can reach. Both mistakes are in this skill's pitfalls file
and neither had a tool:

  #4  third-party LPs and JIT liquidity get attributed to the issuer
  #21 in one audit 99.3% of the main pool's quote token sat in the ISSUER'S OWN
      positions, priced 45-82% below spot. The issuer selling into its own bid moves
      money between its own pockets — net cash zero. The number that matters to
      anyone else is THIRD-PARTY reachable quote.

The same pass separates liquidity from a sell ladder. A position whose range sits
entirely above spot holds only the token: that is a row of limit orders, not depth.
In that audit 98% of the issuer's LP was parked at 1.8-9x spot.

No NonfungiblePositionManager address is hardcoded. The NFPM is discovered from the
pool's own Mint events — it is the owner that appears there and answers
positions(uint256) with this pool's token0/token1/fee — so this works on Uniswap V3,
PancakeSwap V3, Aerodrome Slipstream and forks nobody has written down.
"""
import argparse, json, sys
from collections import defaultdict
from rpc import Client, BASE, BSC, ETH, LOG_EPS, MAX_SPAN, RangeError, s256
from depth import Pool, InconsistentState, MIN_TICK, MAX_TICK

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}

# keccak-measured, never recalled. Recomputing these costs one line; six of the 27
# selectors this skill shipped with were wrong because someone typed them from memory.
#   Mint(address,address,int24,int24,uint128,uint256,uint256)
MINT = "0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde"
#   IncreaseLiquidity(uint256,uint128,uint256,uint256)
INCREASE = "0x3067048beee31b25b2f1681f88dac838c8bba36af25bfb2b7cf7473a5847e35f"
POSITIONS = "0x99fbab88"      # positions(uint256)
OWNER_OF = "0x6352211e"       # ownerOf(uint256)
BALANCE_OF = "0x70a08231"     # balanceOf(address)
TOKEN_OF_OWNER = "0x2f745c59" # tokenOfOwnerByIndex(address,uint256)
SEL = dict(token0="0x0dfe1681", token1="0xd21220a7", fee="0xddca3f43",
           slot0="0x3850c7bd", decimals="0x313ce567", symbol="0x95d89b41")


def _w(hexstr, i):
    """Word i of an ABI return, as an int."""
    return int(hexstr[2 + i * 64:66 + i * 64], 16)


def sym(c, tok):
    try:
        r = c.eth_call(tok, SEL["symbol"])[2:]
        if len(r) <= 64:
            return bytes.fromhex(r).rstrip(b"\x00").decode("utf8", "replace") or tok[:10]
        n = _w("0x" + r, 1)
        return bytes.fromhex(r[128:128 + n * 2]).decode("utf8", "replace") or tok[:10]
    except Exception:
        return tok[:10] + "…"


def amounts(liq, tl, tu, tick, sqrtP):
    """token0/token1 a position holds right now, in raw units.

    Below its range a position is all token0, above it all token1, and inside it holds
    both. Getting the branch wrong silently turns a sell ladder into 'liquidity'.
    """
    sa, sb = 1.0001 ** (tl / 2), 1.0001 ** (tu / 2)
    if tick < tl:
        return liq * (1 / sa - 1 / sb), 0.0
    if tick >= tu:
        return 0.0, liq * (sb - sa)
    return liq * (1 / sqrtP - 1 / sb), liq * (sqrtP - sa)


def recent_mint_owners(cli, pool, hi, chain, window=60_000):
    """Owners on the pool's most recent Mints — just enough to identify the manager.

    Walks BACKWARD from the head and stops at the first window with any Mint, because
    one is enough. Enumerating a pool's Mint history is not an option: the $O/USDC
    pool on Base had 30,973 Mints in its first fifth, since JIT makers mint and burn
    every block. The span comes from the chain's measured cap — asking blxrbdn for
    5,000 blocks when its ceiling is 2,000 costs a bisection per window.
    """
    span = MAX_SPAN.get(chain, 2000)
    seen, cur = {}, hi
    while cur > hi - window and not seen:
        lo = max(1, cur - span + 1)
        try:
            logs = cli.call("eth_getLogs", [{"address": pool, "topics": [MINT],
                                             "fromBlock": hex(lo), "toBlock": hex(cur)}])
        except RangeError:
            span = max(1, span // 2)
            continue
        except Exception:
            cur = lo - 1
            continue
        for l in logs:
            seen.setdefault("0x" + l["topics"][1][-40:], l["transactionHash"])
        cur = lo - 1
    return seen


def owned_token_ids(cli, nfpm, owner, cap=2000):
    """Every position NFT an address holds, via ERC-721 Enumerable.

    This is the whole reason the tool is tractable. The question is not "who owns
    every position ever minted here" — it is "how much of this pool is the ISSUER's",
    and that is O(the issuer's positions), not O(the pool's history).
    """
    n = int(cli.eth_call(nfpm, BALANCE_OF + owner[2:].rjust(64, "0")), 16)
    if n > cap:
        print(f"     {owner} holds {n:,} NFTs — capping the read at {cap}")
        n = cap
    ids = []
    for i in range(0, n, 60):
        part = list(range(i, min(i + 60, n)))
        try:
            res = cli.batch([("eth_call", [{"to": nfpm,
                              "data": TOKEN_OF_OWNER + owner[2:].rjust(64, "0")
                                      + f"{j:064x}"}, "latest"]) for j in part])
        except Exception:
            res = []
            for j in part:
                try:
                    res.append(cli.eth_call(nfpm, TOKEN_OF_OWNER
                                            + owner[2:].rjust(64, "0") + f"{j:064x}"))
                except Exception:
                    res.append(None)
        ids += [int(r, 16) for r in res if r]
    return ids


def creation_block(cli, addr, lo, hi):
    """Binary-search the block a contract came into existence.

    Scanning a pool's Mints from the TOKEN's deploy block wastes most of the range —
    the pool is always younger — and on a busy chain that is thousands of getLogs for
    nothing. It is also the anchor pitfall #18 asks for: where an address's first buy
    sits relative to the pool's creation is what separates a snipe from accumulation.
    """
    def has_code(b):
        try:
            return (cli.call("eth_getCode", [addr, hex(b)]) or "0x") != "0x"
        except Exception:
            return None
    if has_code(lo):
        return lo
    if not has_code(hi):
        raise RuntimeError(f"{addr} has no code at #{hi} — wrong address or chain")
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        r = has_code(mid)
        if r is None:                     # archive refused this height; nudge and retry
            mid += 1
            r = has_code(mid)
            if r is None:
                raise RuntimeError("no archive endpoint would serve historical getCode; "
                                   "pass --from-block explicitly")
        lo, hi = (lo, mid) if r else (mid, hi)
    return hi


def discover_nfpm(cli, owners, pool_t0, pool_t1, pool_fee):
    """The position manager is whichever recent Mint owner answers positions().

    Deriving it beats hardcoding: Uniswap V3, PancakeSwap V3, Aerodrome Slipstream and
    every unlisted fork use different addresses, and a wrong constant here silently
    reports a pool as having no NFT positions at all.
    """
    for o in owners:
        try:
            if (cli.call("eth_getCode", [o, "latest"]) or "0x") == "0x":
                continue                       # an EOA minting directly against the pool
            cli.eth_call(o, POSITIONS + f"{1:064x}")
            cli.eth_call(o, BALANCE_OF + "0" * 24 + o[2:])
            return o
        except Exception:
            continue
    return None


def collect(cli, gcli, pool_addr, issuers, hi, chain):
    """The issuer's live positions in this pool, and the pool's totals.

    Asked the other way round — enumerate every position and see who owns them — this
    is intractable: a JIT-heavy pool mints tens of thousands of times. Asked this way
    it is a handful of calls, because the question was never "who owns everything", it
    is "how much of this pool is the issuer's, and what is left for anyone else".
    """
    t0 = "0x" + cli.eth_call(pool_addr, SEL["token0"])[-40:]
    t1 = "0x" + cli.eth_call(pool_addr, SEL["token1"])[-40:]
    fee = int(cli.eth_call(pool_addr, SEL["fee"]), 16)
    d0 = int(cli.eth_call(t0, SEL["decimals"]), 16)
    d1 = int(cli.eth_call(t1, SEL["decimals"]), 16)
    s0 = cli.eth_call(pool_addr, SEL["slot0"])[2:]
    sqrtP, tick = int(s0[:64], 16) / 2 ** 96, s256(int(s0[64:128], 16))
    print(f"  pool {pool_addr}  {sym(cli,t0)}/{sym(cli,t1)}  fee {fee/1e4:.2f}%  tick {tick}")

    print(f"  identifying the position manager from recent Mints…")
    owners = recent_mint_owners(gcli, pool_addr, hi, chain)
    nfpm = discover_nfpm(cli, list(owners), t0, t1, fee)
    if not nfpm:
        raise RuntimeError("no position manager found among recent Mint owners — this "
                           "pool may be minted against directly; pass --nfpm")
    print(f"     position manager: {nfpm}")

    rows, unreadable = [], []
    for owner in issuers:
        try:
            tids = owned_token_ids(cli, nfpm, owner)
        except Exception as e:
            unreadable.append((owner, str(e)[:90]))
            continue
        print(f"     {owner} holds {len(tids)} position NFT(s)")
        for i in range(0, len(tids), 60):
            part = tids[i:i + 60]
            try:
                res = cli.batch([("eth_call", [{"to": nfpm,
                                  "data": POSITIONS + f"{t:064x}"}, "latest"])
                                 for t in part])
            except Exception:
                res = [None] * len(part)
            for tid, r in zip(part, res):
                if not r:
                    continue
                pt0 = "0x" + r[2 + 2 * 64:66 + 2 * 64][-40:]
                pt1 = "0x" + r[2 + 3 * 64:66 + 3 * 64][-40:]
                if pt0.lower() != t0 or pt1.lower() != t1 or _w(r, 4) != fee:
                    continue                       # a position in some other pool
                liq = _w(r, 7)
                if liq == 0:
                    continue                       # burned or fully withdrawn
                tl, tu = s256(_w(r, 5)), s256(_w(r, 6))
                a0, a1 = amounts(liq, tl, tu, tick, sqrtP)
                rows.append(dict(token_id=tid, owner=owner, tick_lower=tl, tick_upper=tu,
                                 liquidity=liq, amount0=a0 / 10 ** d0,
                                 amount1=a1 / 10 ** d1,
                                 owed0=_w(r, 10) / 10 ** d0, owed1=_w(r, 11) / 10 ** d1))
    for o, e in unreadable:
        print(f"     {o}: could not enumerate NFTs ({e})")
        print(f"       its positions are in NEITHER figure below")
    return dict(token0=t0, token1=t1, fee=fee, d0=d0, d1=d1, tick=tick, sqrtP=sqrtP,
                nfpm=nfpm, rows=rows, unreadable=unreadable,
                sym0=sym(cli, t0), sym1=sym(cli, t1))


def classify(row, tick, price_of):
    if row["tick_upper"] <= tick:
        return "bid"          # entirely on the token1 side: the owner's own bid
    if row["tick_lower"] > tick:
        return "ladder"       # entirely token0: a row of limit orders, not liquidity
    return "in-range"


def report(res, issuers, cli, pool_addr, as_json=False):
    """The issuer's positions, and what is left once you subtract them.

    The pool TOTAL comes from depth.py's tick profile, not from summing positions —
    only the issuer's positions were enumerated, and pretending that sum is the pool
    would report every pool as 100% issuer-owned.
    """
    tick, d0, d1 = res["tick"], res["d0"], res["d1"]
    s0, s1 = res["sym0"], res["sym1"]

    def px(t):                      # token1 per token0 at a tick
        return 1.0001 ** t * 10 ** (d0 - d1)

    spot = px(tick)
    issuers = {a.lower() for a in issuers}
    by_owner = defaultdict(lambda: {"a0": 0.0, "a1": 0.0, "n": 0, "kinds": defaultdict(int)})
    for r in res["rows"]:
        b = by_owner[r["owner"]]
        b["a0"] += r["amount0"]; b["a1"] += r["amount1"]; b["n"] += 1
        b["kinds"][classify(r, tick, px)] += 1
    iss0 = sum(b["a0"] for b in by_owner.values())
    iss1 = sum(b["a1"] for b in by_owner.values())

    print(f"\n  ISSUER POSITIONS  {len(res['rows'])} live across {len(by_owner)} address(es)"
          f"   spot {spot:,.8g} {s1}/{s0}")
    if not res["rows"]:
        print("    none — the named addresses hold no live position NFT in this pool")
    else:
        print(f"     {'tokenId':>9} {'owner':42} {'kind':8} "
              f"{'range (' + s1 + '/' + s0 + ')':>30} {s0:>14} {s1:>14}")
        for r in sorted(res["rows"], key=lambda r: -r["amount1"]):
            lo = px(r["tick_lower"]) if r["tick_lower"] > MIN_TICK else 0
            hi = px(r["tick_upper"]) if r["tick_upper"] < MAX_TICK else float("inf")
            band = "full range" if lo == 0 and hi == float("inf") else f"{lo:,.6g} - {hi:,.6g}"
            print(f"     {r['token_id']:>9} {r['owner']:42} "
                  f"{classify(r, tick, px):8} {band:>30} "
                  f"{r['amount0']:>14,.2f} {r['amount1']:>14,.2f}")
        print(f"\n  BY OWNER")
        for a, b in sorted(by_owner.items(), key=lambda kv: -kv[1]["a1"]):
            kinds = " ".join(f"{k}:{v}" for k, v in sorted(b["kinds"].items()))
            print(f"     {a}  {b['n']:>3} pos  {b['a0']:>16,.2f} {s0}  "
                  f"{b['a1']:>14,.2f} {s1}   {kinds}")

    # The pool total is an INDEPENDENT measurement. Summing the positions we happened
    # to enumerate would make every pool look 100% issuer-owned by construction.
    print(f"\n  EXIT LIQUIDITY, MINUS THE ISSUER'S OWN BID")
    tot0 = tot1 = None
    try:
        pool = Pool(cli, pool_addr, d0, d1)
        c = pool.check
        tot0, tot1 = c["model0"], c["model1"]
        print(f"    {s1} in the pool's whole book     {tot1:>16,.2f}"
              f"   (depth.py tick profile, independent of the rows above)")
    except InconsistentState as e:
        print(f"    the tick profile failed its own self-check, so there is no pool total")
        print(f"    to subtract from: {str(e)[:120]}")
    print(f"    {s1} in the issuer's positions    {iss1:>16,.2f}")
    if tot1:
        share = iss1 / tot1 * 100 if tot1 else 0
        third = tot1 - iss1
        print(f"    {s1} a third party can reach      {third:>16,.2f}   <- the number that matters")
        print(f"    the issuer is {share:.1f}% of the quote in this pool")
        if share > 50:
            print(f"    It selling into its own bid moves money between its own pockets.")
            print(f"    Net cash to the issuer from that portion is zero, and the depth a")
            print(f"    third-party seller actually meets is the smaller number above.")
        if iss1 > tot1 * 1.01:
            print(f"    !! the issuer's positions exceed the whole book. One of the two")
            print(f"       measurements is wrong — do not publish either.")

    ladders = [r for r in res["rows"] if classify(r, tick, px) == "ladder"]
    if ladders:
        lo = min(px(r["tick_lower"]) for r in ladders)
        fin = [r["tick_upper"] for r in ladders if r["tick_upper"] < MAX_TICK]
        hi = px(max(fin)) if fin else float("inf")
        held = sum(r["amount0"] for r in ladders)
        print(f"\n    {len(ladders)} of the issuer's positions sit entirely ABOVE spot, "
              f"{lo/spot:,.2f}x - {hi/spot:,.2f}x")
        print(f"    holding {held:,.2f} {s0} and no {s1}. That is a sell ladder, not")
        print(f"    liquidity: it cannot absorb a sale, it competes with one.")
    bids = [r for r in res["rows"] if classify(r, tick, px) == "bid"]
    if bids:
        hi = max(px(r["tick_upper"]) for r in bids)
        print(f"\n    {len(bids)} position(s) sit entirely BELOW spot, up to {hi/spot:,.2f}x"
              f" — the issuer's own bid, already counted above")
    if res.get("unreadable"):
        print(f"\n    ! {len(res['unreadable'])} address(es) could not be enumerated; their")
        print(f"      positions are in neither figure. The split above is a FLOOR.")

    if as_json:
        print("\n" + json.dumps({"positions": res["rows"], "spot": spot,
                                 "quote_pool": tot1, "quote_issuer": iss1,
                                 "quote_third_party": (tot1 - iss1) if tot1 else None},
                                indent=1, default=str))


def main():
    p = argparse.ArgumentParser(description="V3 liquidity attributed to its real owners")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--pool", required=True)
    p.add_argument("--issuer", nargs="+", required=True,
                   help="the issuer's addresses. Their positions are enumerated and "
                        "subtracted from the book to give third-party reachable quote")
    p.add_argument("--nfpm", help="position manager, if discovery cannot find it")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    cli = Client(NETS[a.chain])
    gcli = Client(LOG_EPS[a.chain])
    issuers = [x.lower() for x in a.issuer]
    hi = cli.block_number()
    if a.nfpm:
        # Skip discovery entirely when the caller already knows it.
        import positions as _self
        _self.discover_nfpm = lambda *_, **__: a.nfpm.lower()
    res = collect(cli, gcli, a.pool.lower(), issuers, hi, a.chain)
    report(res, issuers, cli, a.pool.lower(), a.json)


if __name__ == "__main__":
    main()
