#!/usr/bin/env python3
"""Enumerate every venue a token trades on, before anyone measures one of them.

    python venues.py --chain bsc --token 0xTOKEN
    python venues.py --chain bsc --token 0xTOKEN --factory 0xFACTORY:v3 --quote 0xQUOTE

One audit measured a single pool and wrote "全市场 / total market exit liquidity" over
the result. It happened to be right — that pool held 99.8% of the quote — but nothing in
the method established it, and the next token will not be so kind. This tool makes venue
coverage a number you print rather than an assumption you inherit.

Two discovery paths, because neither alone is coverage:

  - **Factory sweep.** `getPool(token, quote, fee)` across every fee tier and quote, and
    V2 `getPair`. This is the ONLY way to see a pool with no recent trades — a dormant
    pool holding real quote is invisible to log mining.
  - **Counterparty mining.** The addresses the token actually moves against, probed for
    `slot0()`/`getReserves()`. This is the only way to see a DEX whose factory you did
    not think to list.

No factory address is trusted because it was written down. Every candidate is verified
by round-trip — `getPool(...)` must return a pool whose own `factory()` points back —
and any that fails is dropped with a printed note, never silently. Factories are also
LEARNED: every pool found by mining is asked for its `factory()`, and a new one is swept
too. That is how a fork nobody listed gets covered.
"""
import argparse, collections, json, sys
from rpc import Client, BASE, BSC, ETH, LOG_EPS, MAX_SPAN, RangeError
from scan import STABLES
import topics as TP

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
GET_POOL = TP.selector("getPool(address,address,uint24)")
GET_PAIR = TP.selector("getPair(address,address)")
SEL = dict(token0="0x0dfe1681", token1="0xd21220a7", fee="0xddca3f43",
           slot0="0x3850c7bd", liquidity="0x1a686502", reserves="0x0902f1ac",
           factory="0xc45a0155", decimals="0x313ce567", symbol="0x95d89b41")
BALANCE_OF = "0x70a08231"
FEE_TIERS = [100, 500, 2500, 3000, 10000]

# Seeds only. Each is round-trip verified at runtime before it is sweept, and more are
# learned from discovered pools. A wrong entry here costs a printed line, not a result.
SEED_FACTORIES = {
    "bsc":  [("0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865", "v3"),
             ("0xca143ce32fe78f1f7019d7d551a6402fc5350c73", "v2")],
    "base": [],
    "eth":  [],
}
# Non-stable quotes worth sweeping. Read the wrapped-native address off a pool rather
# than recalling it wherever possible; these are seeds and are code-checked before use.
SEED_QUOTES = {
    "bsc":  ["0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"],   # WBNB
    "base": ["0x4200000000000000000000000000000000000006"],   # WETH
    "eth":  ["0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"],   # WETH
}

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def _addr(word):
    return "0x" + word[-40:]


def has_code(cli, a):
    try:
        return (cli.call("eth_getCode", [a, "latest"]) or "0x") != "0x"
    except Exception:
        return None                     # a refusal, NOT a "no"


def sym(cli, tok):
    try:
        r = cli.eth_call(tok, SEL["symbol"])[2:]
        if len(r) <= 64:
            return bytes.fromhex(r).rstrip(b"\x00").decode("utf8", "replace") or tok[:10]
        n = int(r[64:128], 16)
        return bytes.fromhex(r[128:128 + n * 2]).decode("utf8", "replace") or tok[:10]
    except Exception:
        return tok[:10] + "…"


def verify_factory(cli, fac, kind, token, quotes):
    """A factory is usable only if getPool round-trips to a pool that points back."""
    if has_code(cli, fac) is not True:
        return False, "no code at that address"
    probes = [(q, f) for q in quotes for f in (FEE_TIERS if kind == "v3" else [None])]
    for q, fee in probes:
        try:
            data = (GET_POOL + token[2:].rjust(64, "0") + q[2:].rjust(64, "0")
                    + f"{fee:064x}") if kind == "v3" else \
                   (GET_PAIR + token[2:].rjust(64, "0") + q[2:].rjust(64, "0"))
            r = cli.eth_call(fac, data)
            if not r or int(r, 16) == 0:
                continue
            pool = _addr(r)
            if kind == "v3":
                back = _addr(cli.eth_call(pool, SEL["factory"]))
                if back.lower() != fac.lower():
                    return False, f"pool {pool} points at factory {back}"
            return True, f"round-tripped via {pool}"
        except Exception:
            continue
    return False, "no pool found to round-trip against (unverified, swept anyway)"


def mine_counterparties(gcli, cli, token, head, chain, window=200_000, cap=120):
    """Addresses the token moves against, probed for pool interfaces."""
    span = MAX_SPAN.get(chain, 2000)
    seen, cur, asked, answered, refused = collections.Counter(), head, 0, 0, 0
    while cur > head - window:
        lo = max(1, cur - span + 1)
        asked += 1
        try:
            logs = gcli.call("eth_getLogs", [{"address": token,
                                              "topics": [TP.T["erc20.Transfer"]],
                                              "fromBlock": hex(lo), "toBlock": hex(cur)}])
            answered += 1
            for l in logs:
                if len(l["topics"]) >= 3:
                    seen[_addr(l["topics"][1])] += 1
                    seen[_addr(l["topics"][2])] += 1
        except RangeError:
            asked -= 1
            span = max(1, span // 2)
            continue
        except Exception:
            refused += 1
        cur = lo - 1
    found = []
    for a, _ in seen.most_common(cap):
        try:
            t0 = _addr(cli.eth_call(a, SEL["token0"]))
            t1 = _addr(cli.eth_call(a, SEL["token1"]))
        except Exception:
            continue
        if token not in (t0.lower(), t1.lower()):
            continue
        kind = "v2"
        try:
            cli.eth_call(a, SEL["slot0"]); kind = "v3"
        except Exception:
            pass
        found.append((a.lower(), kind, t0.lower(), t1.lower()))
    return found, asked, answered, refused


def main():
    p = argparse.ArgumentParser(description="enumerate every venue a token trades on")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--token", required=True)
    p.add_argument("--quote", action="append", default=[],
                   help="extra quote asset; repeatable. Stables + wrapped native are swept anyway")
    p.add_argument("--factory", action="append", default=[],
                   help="extra factory as 0xADDR:v2|v3; repeatable")
    p.add_argument("--min-share", type=float, default=99.0,
                   help="exit 2 if the largest pool holds less than this %% of discovered quote")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    cli, gcli = Client(NETS[a.chain]), Client(LOG_EPS[a.chain])
    token = a.token.lower()
    head = cli.block_number()
    stables = STABLES.get(a.chain, {})
    quotes = [q.lower() for q in list(stables) + SEED_QUOTES.get(a.chain, []) + a.quote]
    quotes = [q for q in dict.fromkeys(quotes) if q != token]

    facs = list(SEED_FACTORIES.get(a.chain, []))
    for f in a.factory:
        addr, _, kind = f.partition(":")
        facs.append((addr.lower(), kind or "v3"))

    print(f"  token {token}   chain {a.chain}   head #{head:,}")
    print(f"  sweeping {len(quotes)} quote asset(s) x {len(FEE_TIERS)} fee tier(s)\n")

    pools = {}

    # ---- path 2 first: mining teaches us factories the seed list lacks -------
    print("  [mining] addresses the token actually moves against…")
    mined, ask, ans, ref = mine_counterparties(gcli, cli, token, head, a.chain)
    print(f"     asked {ask} answered {ans} refused {ref}   -> {len(mined)} pool-like")
    for addr, kind, t0, t1 in mined:
        pools[addr] = {"how": "mined", "kind": kind, "t0": t0, "t1": t1}
        if kind == "v3":
            try:
                f = _addr(cli.eth_call(addr, SEL["factory"])).lower()
                if f not in [x[0] for x in facs]:
                    facs.append((f, "v3"))
                    print(f"     learned factory {f} from {addr}")
            except Exception:
                pass

    # ---- path 1: factory sweep, every tier, every quote ---------------------
    for fac, kind in facs:
        ok, why = verify_factory(cli, fac, kind, token, quotes)
        print(f"\n  [factory] {fac} ({kind})  {'VERIFIED' if ok else 'UNVERIFIED'} — {why}")
        hits = 0
        for q in quotes:
            tiers = FEE_TIERS if kind == "v3" else [None]
            for fee in tiers:
                try:
                    data = (GET_POOL + token[2:].rjust(64, "0") + q[2:].rjust(64, "0")
                            + f"{fee:064x}") if kind == "v3" else \
                           (GET_PAIR + token[2:].rjust(64, "0") + q[2:].rjust(64, "0"))
                    r = cli.eth_call(fac, data)
                except Exception:
                    continue
                if not r or int(r, 16) == 0:
                    continue
                pa = _addr(r).lower()
                hits += 1
                pools.setdefault(pa, {"how": "factory", "kind": kind,
                                      "t0": None, "t1": None})
                pools[pa]["fee"] = fee
        print(f"     {hits} pool(s)")

    # ---- inventory ----------------------------------------------------------
    print(f"\n  {len(pools)} pool(s) total. Reading inventory…\n")
    rows = []
    for pa, meta in pools.items():
        try:
            t0 = meta["t0"] or _addr(cli.eth_call(pa, SEL["token0"])).lower()
            t1 = meta["t1"] or _addr(cli.eth_call(pa, SEL["token1"])).lower()
        except Exception:
            continue
        quote = t0 if t1 == token else t1
        try:
            qd = int(cli.eth_call(quote, SEL["decimals"]), 16)
            td = int(cli.eth_call(token, SEL["decimals"]), 16)
            qb = int(cli.eth_call(quote, BALANCE_OF + pa[2:].rjust(64, "0")), 16) / 10 ** qd
            tb = int(cli.eth_call(token, BALANCE_OF + pa[2:].rjust(64, "0")), 16) / 10 ** td
        except Exception:
            continue
        rows.append({"pool": pa, "quote": quote, "qsym": stables.get(quote) or sym(cli, quote),
                     "quote_balance": qb, "token_balance": tb,
                     "fee": meta.get("fee"), "kind": meta["kind"], "how": meta["how"]})

    tot_q = sum(r["quote_balance"] for r in rows) or 1.0
    rows.sort(key=lambda r: -r["quote_balance"])
    print(f"  {'pool':44} {'kind':5} {'fee':>6} {'quote':>7} {'quote bal':>16} {'share':>8} {'token bal':>16} how")
    for r in rows:
        r["share_pct"] = r["quote_balance"] / tot_q * 100
        print(f"  {r['pool']:44} {r['kind']:5} {str(r['fee'] or '-'):>6} {r['qsym']:>7} "
              f"{r['quote_balance']:>16,.2f} {r['share_pct']:>7.3f}% {r['token_balance']:>16,.2f} {r['how']}")

    top = rows[0]["share_pct"] if rows else 0.0
    print(f"\n  VENUE COVERAGE: {len(rows)} pool(s) hold quote; the largest is "
          f"{top:.3f}% of all discovered quote.")
    print(f"  Quote this beside every market figure. 'The market' means these "
          f"{len(rows)} venues and nothing else — CEX inventory is invisible here, and "
          f"so is any chain you did not scan.")
    if ref:
        print(f"  !! {ref} mining window(s) refused — a venue reachable only through a "
              f"counterparty in those windows was never probed. This is a FLOOR.")

    if a.json:
        print("\n" + json.dumps({"token": token, "head": head, "pools": rows,
                                 "total_quote": tot_q, "top_share_pct": top,
                                 "mining_refused": ref}, indent=1, default=str))
    sys.exit(0 if top >= a.min_share and not ref else 2)


if __name__ == "__main__":
    main()
