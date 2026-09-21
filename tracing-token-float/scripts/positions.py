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
from scan import STABLES
from topics import T as _T
from depth import Pool, InconsistentState, MIN_TICK, MAX_TICK

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}

# keccak-measured, never recalled. Recomputing these costs one line; six of the 27
# selectors this skill shipped with were wrong because someone typed them from memory.
#   Mint(address,address,int24,int24,uint128,uint256,uint256)
MINT = _T["v3.Mint"]
#   IncreaseLiquidity(uint256,uint128,uint256,uint256)
INCREASE = _T["nfpm.IncreaseLiquidity"]
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
    asked = answered = refused = 0
    while cur > hi - window and not seen:
        lo = max(1, cur - span + 1)
        asked += 1
        try:
            logs = cli.call("eth_getLogs", [{"address": pool, "topics": [MINT],
                                             "fromBlock": hex(lo), "toBlock": hex(cur)}])
        except RangeError:
            asked -= 1                      # not a question the chain declined to answer
            span = max(1, span // 2)
            continue
        except Exception as e:
            # "this range holds no Mint" and "the node would not answer" arrived here
            # through the same branch, and only the first is data. When every window is
            # refused this returned {} and the caller printed "no position manager
            # found", which is the node's silence published as a fact about the pool.
            refused += 1
            print(f"     Mint window #{lo:,}-#{cur:,} NOT ANSWERED ({str(e)[:60]})")
            cur = lo - 1
            continue
        answered += 1
        for l in logs:
            seen.setdefault("0x" + l["topics"][1][-40:], l["transactionHash"])
        cur = lo - 1
    print(f"     Mint scan: asked {asked} answered {answered} refused {refused}")
    if not seen and refused:
        raise RuntimeError(
            f"{refused} of {asked} Mint windows were never answered and the answered "
            f"ones held no Mint. Reporting 'no position manager' from that would be "
            f"absence of evidence published as evidence of absence. Retry, or pass "
            f"--nfpm (it is verified before use).")
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


def collect(cli, gcli, pool_addr, issuers, hi, chain, nfpm=None, token=None):
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

    # WHICH SIDE IS THE QUOTE. Uniswap-style pools sort token0/token1 by address, so
    # whether the quote is token0 or token1 is a coin flip per pool. This tool used to
    # assume token1 and printed the SUBJECT TOKEN's amount under the label "quote a
    # third party can reach" — a number in the wrong unit that still looked plausible.
    # Decide it explicitly, and refuse rather than guess.
    stables = STABLES.get(chain, {})
    if token:
        token = token.lower()
        if token not in (t0, t1):
            raise RuntimeError(f"--token {token} is neither side of this pool "
                               f"({t0} / {t1}).")
        flip = (t0 != token)                      # flip => subject is token1
    elif (t0 in stables) != (t1 in stables):
        flip = t1 not in stables                  # the stable side is the quote
        print(f"     quote side inferred from the stable registry: "
              f"{'token0 ' + sym(cli,t0) if not flip else 'token1 ' + sym(cli,t1)}")
    else:
        raise RuntimeError(
            f"cannot tell which side of this pool is the quote ({sym(cli,t0)}/"
            f"{sym(cli,t1)}); neither or both are known stables. Pass --token <subject "
            f"token address>. Guessing here reports one token's amount in the other's "
            f"unit, and the figure looks entirely reasonable.")
    qsym, tsym = (sym(cli, t0), sym(cli, t1)) if flip else (sym(cli, t1), sym(cli, t0))
    print(f"     subject {tsym}, quote {qsym}"
          f"   (quote is token{'0' if flip else '1'})")

    if nfpm:
        # A caller-supplied address is the likeliest way a RECALLED constant enters this
        # tool, and a wrong one does not raise: eth_call against an address with no code
        # returns 0x, which decodes to "holds no positions". A run once passed a position
        # manager address written from memory; eth_getCode on it returned 0 bytes — no
        # contract there at all — and the pool read as having no NFT positions.
        nfpm = nfpm.lower()
        if (cli.call("eth_getCode", [nfpm, "latest"]) or "0x") == "0x":
            raise RuntimeError(
                f"--nfpm {nfpm} has NO CODE on {chain}. That is not a position manager, "
                f"it is a recalled address. Read the owner field of this pool's own Mint "
                f"logs instead of supplying one.")
        print(f"     position manager: {nfpm}  (--nfpm, code verified)")
    else:
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
                nfpm=nfpm, rows=rows, unreadable=unreadable, flip=flip,
                qsym=qsym, tsym=tsym,
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
    #
    # THREE NUMBERS, THREE QUESTIONS. This block used to print one — "quote a third
    # party can reach" = total quote minus issuer quote — and call it the number that
    # matters. That is an inventory statistic about who FUNDED the book, and nobody can
    # execute against it. An AMM pays out of whatever liquidity sits at the tick it is
    # crossing; it does not know who minted it. On a pool whose issuer position
    # straddles spot, that subtraction understated a real $357k bid as $10k.
    flip = res.get("flip", True)
    qsym, tsym = res.get("qsym", s0), res.get("tsym", s1)
    iss_q = iss0 if flip else iss1          # quote held inside the issuer's positions
    print(f"\n  EXIT LIQUIDITY — three numbers, three different questions")
    pool = None
    try:
        pool = Pool(cli, pool_addr, d0, d1)
        c = pool.check
        tot_q = c["model0"] if flip else c["model1"]
    except InconsistentState as e:
        print(f"    the tick profile failed its own self-check, so there are no exit")
        print(f"    numbers at all: {str(e)[:140]}")
        tot_q = None

    if tot_q:
        share = iss_q / tot_q * 100 if tot_q else 0
        # flip is True when the SUBJECT token is token1, and selling token1 is
        # sell1(). Getting this backwards charts the other half of the book and
        # prints the reciprocal price, which still looks like a price.
        sell = (lambda n: pool.sell1(n)) if flip else (lambda n: pool.sell(n))
        # 1. SPOT EXIT — what a third party gets right now, whole book, no subtraction.
        print(f"\n    [1] SPOT EXIT — a third party sells NOW, against the whole book")
        print(f"        Ownership is irrelevant here: the pool pays from whatever is at")
        print(f"        the tick. This is the number for 'can a holder get out today'.")
        for n in (1_000, 10_000, 100_000):
            try:
                r = sell(n)
                print(f"          sell {n:>9,.0f} {tsym:<8} -> {r['proceeds']:>14,.2f} {qsym}"
                      f"   avg {r['avg']:.6g}   {r['stop']}")
            except Exception as e:
                print(f"          sell {n:>9,.0f} {tsym:<8} -> unavailable ({str(e)[:50]})")
        print(f"          absolute ceiling (drain the book) {tot_q:>14,.2f} {qsym}")

        # 2. POST-WITHDRAWAL EXIT — the counterfactual, and labelled as one.
        iss_pos = [(r["tick_lower"], r["tick_upper"], r["liquidity"]) for r in res["rows"]]
        print(f"\n    [2] POST-WITHDRAWAL EXIT — COUNTERFACTUAL: the issuer pulls its")
        print(f"        {len(iss_pos)} position(s) first, then a third party sells")
        try:
            cf = pool.excluding(iss_pos)
            cf_sell = (lambda n: cf.sell1(n)) if flip else (lambda n: cf.sell(n))
            cf_q = cf.check["model0"] if flip else cf.check["model1"]
            for n in (1_000, 10_000, 100_000):
                try:
                    r = cf_sell(n)
                    print(f"          sell {n:>9,.0f} {tsym:<8} -> {r['proceeds']:>14,.2f} {qsym}"
                          f"   avg {r['avg']:.6g}   {r['stop']}")
                except Exception as e:
                    print(f"          sell {n:>9,.0f} {tsym:<8} -> unavailable ({str(e)[:50]})")
            print(f"          absolute ceiling                  {cf_q:>14,.2f} {qsym}")
            print(f"          -> this is a COUNTERFACTUAL. It is what remains if they")
            print(f"             withdraw, not what anyone can get today.")
        except InconsistentState as e:
            print(f"          cannot be computed: {str(e)[:140]}")

        # 3. Whether the issuer can execute [2] at will.
        print(f"\n    [3] CAN THEY? the issuer holds {share:.2f}% of the {qsym} in this book")
        print(f"        Check every position NFT for a lock before treating [1] as stable:")
        print(f"        ownerOf() an EOA with no timelock means [2] is one transaction away.")
        if share > 50:
            print(f"        The issuer selling into its OWN bid is money moving between its")
            print(f"        own pockets — that is a third number again (issuer net cash),")
            print(f"        and it is NOT [1] and NOT [2].")
        if iss_q > tot_q * 1.01:
            print(f"    !! the issuer's positions exceed the whole book. One of the two")
            print(f"       measurements is wrong — do not publish either.")
        print(f"\n    inventory note (NOT an exit number): {qsym} funded by third parties")
        print(f"      = {tot_q - iss_q:,.2f}. Nobody can execute against this. It is here")
        print(f"      only so it is never again printed under the word 'reach'.")

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
        # No key here may be named for a question it does not answer. The old shape
        # was {quote_pool, quote_issuer, quote_third_party} in token1's unit regardless
        # of which side was the quote, and "quote_third_party" was read as exit
        # liquidity. Both defects shipped.
        print("\n" + json.dumps({
            "positions": res["rows"], "spot": spot,
            "quote_symbol": qsym, "subject_symbol": tsym,
            "quote_is_token0": bool(flip),
            "quote_in_book": tot_q,
            "quote_inside_issuer_positions": iss_q,
            "quote_funded_by_third_parties": (tot_q - iss_q) if tot_q else None,
            "_note": ("quote_funded_by_third_parties is an INVENTORY statistic, not an "
                      "exit number: no participant can execute against it. For what a "
                      "seller actually gets, simulate against the whole book (spot "
                      "exit); for what remains if the issuer withdraws, use "
                      "Pool.excluding() (post-withdrawal exit). See pitfalls #21.")},
            indent=1, default=str))


def main():
    p = argparse.ArgumentParser(description="V3 liquidity attributed to its real owners")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--pool", required=True)
    p.add_argument("--issuer", nargs="+", required=True,
                   help="the issuer's addresses. Their positions are enumerated and "
                        "subtracted from the book to give third-party reachable quote")
    p.add_argument("--nfpm", help="position manager, if discovery cannot find it")
    p.add_argument("--token", help="the SUBJECT token (the one being audited). Without "
                        "it the quote side is inferred from the stable registry, and if "
                        "that is ambiguous the run refuses rather than guessing — a "
                        "guess here reports one token's amount in the other's unit")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    cli = Client(NETS[a.chain])
    gcli = Client(LOG_EPS[a.chain])
    issuers = [x.lower() for x in a.issuer]
    hi = cli.block_number()
    # NOT a monkeypatch. `import positions as _self` from inside `python positions.py`
    # loads a SECOND copy of this module under the name "positions" and patches that
    # copy; collect() lives in __main__ and kept resolving the original, so --nfpm was
    # accepted, silently ignored, and answered with "pass --nfpm" — a closed loop.
    res = collect(cli, gcli, a.pool.lower(), issuers, hi, a.chain,
                  nfpm=a.nfpm, token=a.token)
    report(res, issuers, cli, a.pool.lower(), a.json)


if __name__ == "__main__":
    main()
