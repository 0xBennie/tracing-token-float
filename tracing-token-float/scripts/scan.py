#!/usr/bin/env python3
"""One command, three numbers that actually change a decision.

    python scan.py --chain base --token 0xABC... --holdings 100000000

    1. Can they print more, freeze you, or drain the escrow?   (privileges)
    2. How much is reachable if the float hits the book?       (exit liquidity)
    3. What is the paper position worth against that?          (the ratio)

Deliberately does NOT compute "the team controls X% of float". That number is
expensive to produce, mostly restates the published allocation table, and is the
same decision at across the plausible range. If you need it, that is what the full method in
SKILL.md is for — but run this first, because a live mint or sweep path makes the
percentage moot, and thin exit liquidity makes it academic.
"""
import argparse, sys, json
from rpc import Client, BASE, BSC, ETH
from privileges import audit, safe_control
from depth import Pool, InconsistentState

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SLOT0 = "0x3850c7bd"


def discover_pools(c, token, lookback=40_000, chunk=2_000, cap=400):
    """Find V3-style pools by asking recent counterparties whether they have slot0()."""
    head = c.block_number()
    seen, pools = set(), []
    for lo in range(head - lookback, head, chunk):
        try:
            logs = c.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                           "fromBlock": hex(lo),
                                           "toBlock": hex(min(lo + chunk - 1, head))}], tries=2)
        except Exception:
            continue
        for l in logs:
            for t in l["topics"][1:3]:
                a = "0x" + t[-40:]
                if int(a, 16) > 1:
                    seen.add(a)
        if len(seen) > cap:
            break
    cands = sorted(seen)[:cap]
    for i in range(0, len(cands), 60):
        ch = cands[i:i + 60]
        try:
            res = c.batch([("eth_call", [{"to": a, "data": SLOT0}, "latest"]) for a in ch])
        except Exception:
            res = []
            for a in ch:
                try:
                    res.append(c.eth_call(a, SLOT0))
                except Exception:
                    res.append("0x")
        for a, r in zip(ch, res):
            if r and len(r) > 66:
                pools.append(a)
    return pools


def decimals(c, tok):
    # No silent default. Falling back to 18 on a USDC-quoted pool misprices every figure
    # by 1e12 — a wrong number that still looks like a number.
    for _ in range(3):
        try:
            return int(c.eth_call(tok, "0x313ce567"), 16)
        except Exception:
            pass
    raise RuntimeError(f"decimals() unreadable for {tok} — refusing to guess; "
                       f"pass the pool explicitly or retry when the node recovers")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--token", required=True)
    p.add_argument("--pools", nargs="*", default=None, help="skip discovery")
    p.add_argument("--also-audit", nargs="*", default=[],
                   help="bridge adapters, vesting factories, distributors — audit these too")
    p.add_argument("--holdings", type=float, default=None,
                   help="token count whose paper value to compare against exit liquidity")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    c = Client(NETS[a.chain])
    tok = a.token.lower()
    out = {"chain": a.chain, "token": tok, "block": c.block_number()}

    print(f"\n{'='*78}\n  {a.chain.upper()}  {tok}   block {out['block']}\n{'='*78}")

    # ---- 1. privileges -------------------------------------------------------
    print("\n[1] PRIVILEGES — can they print, freeze, or drain?\n")
    out["privileges"] = []
    for label, addr in [("token", tok)] + [(f"also:{x[:10]}…", x.lower()) for x in a.also_audit]:
        r = audit(c, addr)
        out["privileges"].append({"label": label, **r})
        if not r.get("is_contract"):
            print(f"  {label:16s} {addr}  EOA — not a contract")
            continue
        print(f"  {label:16s} {addr}")
        print(f"  {'':16s} codesize {r['codesize']}  proxy={r['is_proxy']}  owner={r['owner']}")
        for f in r["privileged"]:
            live = f.get("owner_can_call", "")
            mark = "!!" if f.get("live") else "  "
            print(f"  {'':16s} {mark} [{f['kind']:9s}] {f['name']:36s} {live}")
        for v in r["verdict"]:
            print(f"  {'':16s} -> {v}")
        if r.get("owner"):
            s = safe_control(c, r["owner"])
            if s["is_safe"]:
                print(f"  {'':16s} -> owner is a Safe {s['threshold']}/{len(s['owners'])}: "
                      f"{s['threshold']} signatures move it")
                out["privileges"][-1]["owner_safe"] = s
        print()

    # ---- 2. exit liquidity ---------------------------------------------------
    print("[2] EXIT LIQUIDITY — what the book can actually absorb\n")
    pools = [x.lower() for x in a.pools] if a.pools else discover_pools(c, tok)
    if not pools:
        print("  no V3-style pools found. The token may trade only on V2-style pools")
        print("  (constant-product, no slot0) or on CEXs — pass --pools explicitly.")
        print("  WARNING: absence of V3 pools is NOT absence of liquidity; this scan cannot see V2.")
    d_tok = decimals(c, tok)
    reachable, tvl, rows = 0.0, 0.0, []
    for pa in pools:
        try:
            t0 = "0x" + c.eth_call(pa, "0x0dfe1681")[-40:]
            t1 = "0x" + c.eth_call(pa, "0xd21220a7")[-40:]
            flip = t0.lower() != tok
            quote = t0 if flip else t1
            # Whether a token is token0 or token1 is decided by address sort order, which
            # is arbitrary — half of all tokens can only be sold in the token1 direction.
            # Skipping those pools silently reports zero exit liquidity for the token.
            pool = Pool(c, pa, decimals(c, t0), decimals(c, t1))
            pool.flip = flip
        except InconsistentState as e:
            print(f"  {pa}  profile failed self-check, skipped: {str(e)[:90]}")
            continue
        except Exception as e:
            print(f"  {pa}  unreadable, skipped: {str(e)[:90]}")
            continue
        sell = pool.sell1 if pool.flip else pool.sell
        px = pool.price1 if pool.flip else pool.price
        res0 = pool.reserve1 if pool.flip else pool.reserve0
        res1 = pool.reserve0 if pool.flip else pool.reserve1
        drain = sell(10 ** 12)
        reachable += drain["proceeds"]
        tvl += res0 * px + res1
        rows.append((pa, pool, drain))
        print(f"  {pa}")
        print(f"     price ${px:.6f}   reserves {res0:,.0f} tok / "
              f"${res1:,.0f} quote   self-check ok={pool.check['ok']}"
              f"{'   [token is token1]' if pool.flip else ''}")
        print(f"     {'sell':>13} {'fillable':>13} {'proceeds':>12} {'avg':>10} "
              f"{'after':>11} {'drop':>7}  stop")
        for s in (10_000, 100_000, 1_000_000):
            r = sell(s)
            print(f"     {s:>13,} {r['filled']:>13,.0f} {r['proceeds']:>12,.0f} "
                  f"{r['avg']:>10.4f} {r['end_price']:>11.6f} {r['drawdown_pct']:>6.1f}%  {r['stop']}")
        print(f"     book absorbs {drain['filled']:,.0f} tokens in total, paying ${drain['proceeds']:,.0f}")
        print(f"     (a full fill is not a good fill — watch the average, not the stop reason)\n")

    out["reachable_usd"], out["displayed_tvl_usd"] = reachable, tvl

    # ---- 3. the ratio --------------------------------------------------------
    print("[3] VERDICT\n")
    if not rows:
        live = [f["name"] for e in out["privileges"] for f in e.get("privileged", []) if f.get("live")]
        if live:
            print(f"  !! live unilateral control path: {live}")
            print("     (no depth measured — the privilege finding stands on its own)")
        return
    px = (rows[0][1].price1 if rows[0][1].flip else rows[0][1].price) if rows else 0
    print(f"  displayed liquidity (TVL style)   ${tvl:,.0f}")
    print(f"  actually reachable by selling     ${reachable:,.0f}"
          + (f"   ({tvl/reachable:.1f}x overstated)" if reachable > 0 else ""))
    if a.holdings and px:
        paper = a.holdings * px
        out["paper_value_usd"] = paper
        print(f"  position at mark price            ${paper:,.0f}  ({a.holdings:,.0f} tokens @ ${px:.4f})")
        if reachable > 0:
            print(f"  paper : reachable                 {paper/reachable:,.0f} : 1")
    live = [f["name"] for e in out["privileges"] for f in e.get("privileged", []) if f.get("live")]
    if live:
        print(f"\n  !! live unilateral control path: {live}")
        print("     supply or escrow can move without warning — the liquidity number above")
        print("     is the optimistic case, and it assumes they queue behind you.")
    if a.json:
        print("\n" + json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
