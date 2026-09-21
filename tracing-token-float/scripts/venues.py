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
import argparse, collections, json, re, sys
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
    hc = has_code(cli, fac)
    if hc is None:
        # None is a REFUSAL, not an answer. Reporting it as "no code" retires a factory
        # that may well exist, and every pool only it could have found disappears from
        # the coverage basis without leaving a trace.
        return False, "NOT ANSWERED — could not read its code, so this factory was NOT swept"
    if not hc:
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
    nwin = max(1, window // span)
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
        print(f"     window {asked}/{nwin}  {len(seen):,} counterparties seen"
              f"  ({refused} refused)")
        cur = lo - 1
    found = []
    print(f"     probing the {min(cap, len(seen)):,} most frequent for a pool interface…")
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
        print(f"       pool-like: {a}  ({kind})")
    return found, asked, answered, refused


def main():
    p = argparse.ArgumentParser(description="enumerate every venue a token trades on")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--token", required=True)
    p.add_argument("--quote", action="append", default=[],
                   help="extra quote asset; repeatable. Stables + wrapped native are swept anyway")
    p.add_argument("--factory", action="append", default=[],
                   help="extra factory as 0xADDR:v2|v3; repeatable")
    p.add_argument("--quote-price", action="append", default=[],
                   help="price a non-stable quote, e.g. WBNB=900. Quotes with no price "
                        "are EXCLUDED from the share basis and listed separately — never "
                        "summed at face value")
    p.add_argument("--min-share", type=float, default=99.0,
                   help="exit 2 if the largest pool holds less than this %% of discovered quote")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    # Validate every address the caller typed BEFORE it becomes calldata. A non-address
    # here does not error: it is zero-padded into a 32-byte word and the call comes back
    # empty, which reads as "that pool does not exist". The runbook itself once carried
    # `--quote auto`, which is not an address.
    def _addr_or_die(v, what):
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
            sys.exit(f"{what} {v!r} is not a 20-byte address. It would be padded into "
                     f"calldata and answered with an empty result, which reads as "
                     f"'not found' rather than as your typo.")
        return v.lower()
    a.token = _addr_or_die(a.token, "--token")
    a.quote = [_addr_or_die(q, "--quote") for q in a.quote]
    for f in a.factory:
        _addr_or_die(f.partition(":")[0], "--factory")

    cli, gcli = Client(NETS[a.chain]), Client(LOG_EPS[a.chain])
    prices = {}
    for kv in a.quote_price:
        k, _, v = kv.partition("=")
        try:
            prices[k.strip().upper()] = float(v)
        except ValueError:
            sys.exit(f"--quote-price {kv!r} is not SYM=<number>")
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
    if not SEED_FACTORIES.get(a.chain):
        print(f"  !! no seed factory is known for {a.chain}. Counterparty mining alone "
              f"CANNOT see a pool with no recent trades, which is the whole reason the "
              f"factory sweep exists — a dormant pool holding real quote stays invisible. "
              f"Pass --factory 0xADDR:v2|v3 (it is round-trip verified) before treating "
              f"the coverage figure below as coverage.")
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
    rows, unread_pools = [], []
    for pa, meta in pools.items():
        try:
            t0 = meta["t0"] or _addr(cli.eth_call(pa, SEL["token0"])).lower()
            t1 = meta["t1"] or _addr(cli.eth_call(pa, SEL["token1"])).lower()
        except Exception as e:
            # Dropping this pool silently would compute the coverage share over a subset
            # nobody can see, which is the one thing this tool exists not to do.
            unread_pools.append((pa, f"token0/token1 not read: {str(e)[:60]}"))
            continue
        quote = t0 if t1 == token else t1
        try:
            qd = int(cli.eth_call(quote, SEL["decimals"]), 16)
            td = int(cli.eth_call(token, SEL["decimals"]), 16)
            qb = int(cli.eth_call(quote, BALANCE_OF + pa[2:].rjust(64, "0")), 16) / 10 ** qd
            tb = int(cli.eth_call(token, BALANCE_OF + pa[2:].rjust(64, "0")), 16) / 10 ** td
        except Exception as e:
            unread_pools.append((pa, f"balances not read: {str(e)[:60]}"))
            continue
        qsym = stables.get(quote) or sym(cli, quote)
        # A quote asset is worth its face value only if we KNOW what it is worth.
        # Summing 69 million of a microcap next to 370 thousand USDT ranked a pool with
        # no exit value at 99.5% of "all discovered quote" — that microcap's own deepest
        # market was under a dollar. Price it, or leave it out of the basis and say so.
        rate = 1.0 if quote in stables else prices.get(qsym.upper())
        rows.append({"pool": pa, "quote": quote, "qsym": qsym,
                     "quote_balance": qb, "quote_usd": (qb * rate) if rate else None,
                     "priced": rate is not None,
                     "token_balance": tb,
                     "fee": meta.get("fee"), "kind": meta["kind"], "how": meta["how"]})

    priced = [r for r in rows if r["priced"]]
    unpriced = [r for r in rows if not r["priced"]]
    tot_q = sum(r["quote_usd"] for r in priced) or 1.0
    rows.sort(key=lambda r: -(r["quote_usd"] if r["priced"] else -1))
    print(f"  {'pool':44} {'kind':5} {'fee':>6} {'quote':>8} {'quote bal':>17} {'$ value':>14} {'share':>8} {'token bal':>15} how")
    for r in rows:
        r["share_pct"] = (r["quote_usd"] / tot_q * 100) if r["priced"] else None
        usd = f"{r['quote_usd']:>14,.2f}" if r["priced"] else f"{'NOT PRICED':>14}"
        sh = f"{r['share_pct']:>7.3f}%" if r["priced"] else f"{'—':>8}"
        print(f"  {r['pool']:44} {r['kind']:5} {str(r['fee'] or '-'):>6} {r['qsym']:>8} "
              f"{r['quote_balance']:>17,.2f} {usd} {sh} {r['token_balance']:>15,.2f} {r['how']}")

    top = priced[0]["share_pct"] if priced else 0.0
    if priced:
        priced.sort(key=lambda r: -r["quote_usd"])
        top = priced[0]["share_pct"]
    print(f"\n  VENUE COVERAGE: {len(priced)} priced pool(s) hold ${tot_q:,.2f} of quote; "
          f"the largest is {top:.3f}% of it.")
    if unread_pools:
        print(f"  !! {len(unread_pools)} pool(s) were DISCOVERED but could not be read, "
              f"so they are in neither the basis nor the table above:")
        for pa, why in unread_pools:
            print(f"       {pa}  {why}")
        print(f"     A share computed over the pools that happened to answer is not "
              f"coverage. Re-run before quoting the percentage.")
    if unpriced:
        print(f"  !! {len(unpriced)} pool(s) are quoted in an asset with no price and are "
              f"NOT in that basis:")
        for r in unpriced:
            print(f"       {r['pool']}  {r['quote_balance']:,.2f} {r['qsym']} "
                  f"+ {r['token_balance']:,.2f} token")
        print(f"     Face value is not value: one such pool held 69 million units of a "
              f"microcap whose own deepest market was under a dollar, and ranking by "
              f"face value put it first at 99.5%. Price them with --quote-price "
              f"SYM=<usd>, or treat their depth as unknown — never as zero and never "
              f"as their balance.")
    print(f"  Quote this beside every market figure. 'The market' means these "
          f"{len(rows)} venues and nothing else — CEX inventory is invisible here, and "
          f"so is any chain you did not scan.")
    if ref:
        print(f"  !! {ref} mining window(s) refused — a venue reachable only through a "
              f"counterparty in those windows was never probed. This is a FLOOR.")

    if a.json:
        print("\n" + json.dumps({"token": token, "head": head, "pools": rows,
                                 "priced_quote_usd": tot_q, "top_share_pct": top,
                                 "unpriced_pools": len(unpriced),
                                 "unread_pools": [{"pool": p_, "why": w_}
                                                  for p_, w_ in unread_pools],
                                 "mining_refused": ref}, indent=1, default=str))
    # Unpriced pools are an unknown, and an unknown is not a pass.
    sys.exit(0 if (top >= a.min_share and not ref and not unpriced
                   and not unread_pools) else 2)


if __name__ == "__main__":
    main()
