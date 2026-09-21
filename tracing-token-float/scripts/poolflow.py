#!/usr/bin/env python3
"""What actually happened in a pool over a window — census, flow, and the identity.

    python poolflow.py --chain bsc --pool 0xPOOL --from-block <lo> --to-block <hi>

Three things this exists to stop, all of which shipped in one audit:

  1. "No Mint/Burn events in a million blocks, so the book is static." The Mint topic had
     been typed from memory; eth_getLogs returned [] without error. The window really
     held several hundred Mints and as many Burns. This tool censuses with NO topic
     filter and buckets
     by topic0, so a wrong or unknown signature shows up as an unknown bucket instead
     of as absence — and it runs the free consistency check (liquidity that was never
     minted cannot be burned).

  2. "Net flow to market = tokens out of the pool minus tokens in." That counts Mint as
     the market dumping and Collect as the market buying. The real net was over 4x larger
     than the figure published, and the gap was liquidity provisioning. Flow here comes
     from Swap amounts and nothing else.

  3. A silent short read. The identity below closes to dust or it does not close, and a
     log query that came back short cannot survive it:

        d(pool balance token0) == sum swap.amount0 + sum mint.amount0
                                  - sum collect.amount0 - sum collectProtocol.amount0

     Burn is absent on purpose: it moves no tokens, it only credits tokensOwed.
"""
import argparse, collections, json, sys
from rpc import Client, BASE, BSC, ETH, LOG_EPS, RangeError
import topics as TP

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
BALANCE_OF = "0x70a08231"
SEL = dict(token0="0x0dfe1681", token1="0xd21220a7", decimals="0x313ce567",
           symbol="0x95d89b41")

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def s256(v):
    return v - (1 << 256) if v >= (1 << 255) else v


def _words(data):
    d = data[2:]
    return [int(d[i:i + 64], 16) for i in range(0, len(d), 64)]


def fetch(gcli, pool, lo, hi, span):
    """Every log, no topic filter. Returns (logs, asked, answered, refused)."""
    out, asked, answered, refused = [], 0, 0, 0
    cur = lo
    while cur <= hi:
        top = min(cur + span - 1, hi)
        asked += 1
        try:
            out += gcli.call("eth_getLogs", [{"address": pool, "fromBlock": hex(cur),
                                              "toBlock": hex(top)}])
            answered += 1
        except RangeError:
            asked -= 1
            span = max(1, span // 2)
            continue
        except Exception as e:
            refused += 1
            print(f"    window #{cur:,}-#{top:,} NOT ANSWERED ({str(e)[:60]})")
        cur = top + 1
    return out, asked, answered, refused


def main():
    p = argparse.ArgumentParser(description="pool event census + true swap flow")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--pool", required=True)
    p.add_argument("--from-block", type=int, required=True)
    p.add_argument("--to-block", type=int, required=True)
    p.add_argument("--span", type=int, default=10_000)
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    cli, gcli = Client(NETS[a.chain]), Client(LOG_EPS[a.chain])
    pool, lo, hi = a.pool.lower(), a.from_block, a.to_block
    t0 = "0x" + cli.eth_call(pool, SEL["token0"])[-40:]
    t1 = "0x" + cli.eth_call(pool, SEL["token1"])[-40:]
    d0 = int(cli.eth_call(t0, SEL["decimals"]), 16)
    d1 = int(cli.eth_call(t1, SEL["decimals"]), 16)

    print(f"  pool {pool}  window #{lo:,}-#{hi:,}  ({hi - lo + 1:,} blocks)")
    logs, asked, answered, refused = fetch(gcli, pool, lo, hi, a.span)
    print(f"\n  RPC CENSUS  asked {asked}  answered {answered}  refused {refused}")
    if refused:
        print(f"  !! every count below is a FLOOR. {refused} window(s) were never "
              f"answered, and a window nobody answered is not a window with no events.")

    counts = collections.Counter(l["topics"][0] if l["topics"] else "0x(anonymous)"
                                 for l in logs)
    print(f"\n  EVENT CENSUS  (no topic filter — unknown signatures stay visible)")
    print(TP.describe(counts))

    for problem in TP.liquidity_sanity(counts):
        print(f"\n  !! {problem}")

    # ---- flow, from Swap and only Swap -------------------------------------
    swap_t = set(TP.swap_topics())
    bought0 = sold0 = bought1 = sold1 = 0
    nbuy = nsell = 0
    for l in logs:
        if not l["topics"] or l["topics"][0] not in swap_t:
            continue
        w = _words(l["data"])
        a0, a1 = s256(w[0]), s256(w[1])       # signed, from the POOL's perspective
        if a1 > 0:                             # token1 into the pool == token1 sold
            sold1 += a1; nsell += 1
        else:
            bought1 += -a1; nbuy += 1
        if a0 > 0:
            sold0 += a0
        else:
            bought0 += -a0
    net0, net1 = sold0 - bought0, sold1 - bought1

    print(f"\n  TRUE FLOW  (Swap only — Mint/Burn/Collect are not trades)")
    print(f"    token1 sold into the pool   {sold1 / 10**d1:>18,.6f}   {nsell:>7,} swaps")
    print(f"    token1 bought out of it     {bought1 / 10**d1:>18,.6f}   {nbuy:>7,} swaps")
    print(f"    token1 NET into the pool    {net1 / 10**d1:>18,.6f}")
    print(f"    token0 NET into the pool    {net0 / 10**d0:>18,.6f}")

    # ---- the identity ------------------------------------------------------
    mint0 = mint1 = coll0 = coll1 = cp0 = cp1 = 0
    for l in logs:
        t = l["topics"][0] if l["topics"] else ""
        w = _words(l["data"])
        if t == TP.T["v3.Mint"] and len(w) >= 3:
            mint0 += w[-2]; mint1 += w[-1]
        elif t == TP.T["v3.Collect"] and len(w) >= 2:
            coll0 += w[-2]; coll1 += w[-1]
        elif t == TP.T["v3.CollectProtocol"] and len(w) >= 2:
            cp0 += w[-2]; cp1 += w[-1]

    def bal(tok, blk):
        return int(cli.call("eth_call", [{"to": tok, "data": BALANCE_OF
                                          + pool[2:].rjust(64, "0")}, hex(blk)]), 16)
    print(f"\n  IDENTITY  d(balance) == swap + mint - collect - collectProtocol")
    print(f"            (Burn is absent on purpose: it moves no tokens)")
    try:
        for name, tok, dec, net, mint, coll, cp in (
                ("token0", t0, d0, net0, mint0, coll0, cp0),
                ("token1", t1, d1, net1, mint1, coll1, cp1)):
            delta = bal(tok, hi) - bal(tok, lo)
            model = net + mint - coll - cp
            resid = delta - model
            flag = "OK" if abs(resid) <= max(10 ** (dec - 12), 1) else "!! DOES NOT CLOSE"
            print(f"    {name}  chain {delta / 10**dec:>18,.6f}   model "
                  f"{model / 10**dec:>18,.6f}   residual {resid / 10**dec:>14,.9f}  {flag}")
    except Exception as e:
        print(f"    could not read balances at both heights (archive node needed): "
              f"{str(e)[:90]}")

    if a.json:
        print("\n" + json.dumps({
            "window": [lo, hi], "asked": asked, "answered": answered, "refused": refused,
            "census": {("/".join(TP.NAME.get(k, [])) or k): v for k, v in counts.items()},
            "swap_only": {"token1_sold": sold1 / 10 ** d1,
                          "token1_bought": bought1 / 10 ** d1,
                          "token1_net_into_pool": net1 / 10 ** d1,
                          "token0_net_into_pool": net0 / 10 ** d0,
                          "n_sell": nsell, "n_buy": nbuy},
            "_note": "counts are FLOORS whenever refused > 0"}, indent=1, default=str))

    sys.exit(2 if refused else 0)


if __name__ == "__main__":
    main()
