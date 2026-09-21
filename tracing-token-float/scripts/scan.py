#!/usr/bin/env python3
"""One command, three numbers that actually change a decision.

    python scan.py --chain base --token 0xABC... --holdings 100000000

    1. Can they print more, freeze you, or drain the escrow?   (privileges)
    2. What does a seller get against the book AS IT STANDS?   (SPOT EXIT)
    3. What is the paper position worth against that?          (the ratio)

The depth figure here is exit number ONE of the three in pitfall #21: the whole
book, untouched, which is what a holder selling right now actually receives. This
tool does NOT attribute LP ownership, so it cannot tell you how much of that book
is the issuer's own bid — and on one token that was over 99% of it, withdrawable
in a single transaction, leaving under $100 behind. Never quote this number as
"third-party" or "real" liquidity. Run positions.py for the other two.

Deliberately does NOT compute "the team controls X% of float". That number is
expensive to produce, mostly restates the published allocation table, and rarely
changes the decision across the plausible range. If you need it, that is what the
full method in SKILL.md is for — but run this first, because a live mint or sweep path makes the
percentage moot, and thin exit liquidity makes it academic.

Every number this prints is a floor, and it says so: pools it could not read are
counted and named, non-dollar quote assets are never silently converted, and a
token audited without --also-audit gets a caveat rather than a clean bill.
"""
import argparse, sys, json, collections
from rpc import Client, BASE, BSC, ETH, LOG_EPS
from privileges import audit, safe_control
from depth import Pool, InconsistentState

# Line-buffer stdout. Without this a redirected or agent-captured run shows nothing
# at all until the process exits — a 13-minute scan is indistinguishable from a hang.
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SLOT0 = "0x3850c7bd"
SYMBOL = "0x95d89b41"

# Quote assets worth $1. Every address below was read on-chain (symbol + decimals)
# rather than recalled — see pitfalls "derived constants must be measured".
# Anything NOT in here is reported in its own units and never folded into a $ total.
STABLES = {
    "base": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC",
             "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": "USDbC",
             "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": "DAI",
             "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": "USDT"},
    "bsc":  {"0x55d398326f99059ff775485246999027b3197955": "USDT",
             "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
             "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
             "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": "FDUSD"},
    "eth":  {"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
             "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
             "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI"},
}


def block_time(c, span=5_000):
    """Measured seconds per block. Never assume it, and never carry a value over from a
    previous run: chains change it at upgrades, and published constants go stale. A fixed
    block `lookback` therefore covers a different span of history on every chain, so the
    same default silently means different things. Measure, then convert."""
    head = c.block_number()
    lo = max(0, head - span)
    t1 = int(c.call("eth_getBlockByNumber", [hex(head), False])["timestamp"], 16)
    t0 = int(c.call("eth_getBlockByNumber", [hex(lo), False])["timestamp"], 16)
    return max((t1 - t0) / max(head - lo, 1), 0.05)


def discover_pools(c, token, lookback=None, chunk=2_000, cap=400, logc=None,
                   window_sec=24 * 3600):
    """Find V3-style pools by asking recent counterparties whether they have slot0().

    Log queries go through their own endpoint pool: the general pool contains nodes
    that serve eth_call fine and do not implement eth_getLogs at all (base.meowrpc.com
    answers "the method eth_getLogs is not supported"). Mixing them made 7 of 20
    discovery windows return nothing, silently, so a third of the counterparty set —
    and any pool reachable only through it — was never probed.

    Two things the obvious version gets wrong:

    - `lookback` in blocks means a different amount of history on every chain. It is
      derived here from a measured block time so `window_sec` means what it says.
    - Ranking candidates by `sorted(addresses)` is ranking by hex prefix, i.e. at
      random, and then truncating at `cap` throws away real pools while keeping dust
      that happens to start with 0x0. A pool is by construction one of the *most
      frequent* counterparties, so rank by appearance count and probe the top `cap`.
      For the same reason the window scan no longer stops early on `cap`: breaking out
      biases the counterparty set toward whichever windows ran first.
    """
    logc = logc or c
    head = c.block_number()
    if lookback is None:
        bt = block_time(c)
        lookback = max(chunk, int(window_sec / bt))
        print(f"     block time {bt:.2f}s → lookback {lookback:,} blocks "
              f"for {window_sec/3600:.0f}h")
    seen, pools = collections.Counter(), []
    print(f"     discovering pools: blocks {head - lookback:,}–{head:,} "
          f"({lookback // chunk} windows)")
    missed = 0
    for i, lo in enumerate(range(head - lookback, head, chunk), 1):
        try:
            logs = logc.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                              "fromBlock": hex(lo),
                                              "toBlock": hex(min(lo + chunk - 1, head))}], tries=3)
        except Exception as e:
            # A window that never answered is a counterparty set never seen, which is a
            # pool possibly never found. Silence here becomes "no liquidity" downstream.
            missed += 1
            print(f"     window {i}  NO ANSWER ({str(e)[:60]}) — counterparties in "
                  f"#{lo:,}–#{min(lo+chunk-1, head):,} were never seen")
            continue
        for l in logs:
            for t in (l.get("topics") or [])[1:3]:
                a = "0x" + t[-40:]
                if int(a, 16) > 1:
                    seen[a] += 1
        print(f"     window {i}  {len(seen):,} counterparties seen")
    cands = [a for a, _ in seen.most_common(cap)]
    if len(seen) > cap:
        print(f"     {len(seen):,} counterparties → probing the {cap} most frequent; "
              f"tail cut at {seen.most_common(cap)[-1][1]} appearances")
    print(f"     probing {len(cands):,} addresses for slot0()")
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
    print(f"     {len(pools)} V3-style pool(s) found"
          + (f"  ({missed} discovery window(s) never answered)" if missed else "") + "\n")
    return pools, missed, lookback


def decimals(c, tok):
    # No silent default. Falling back to 18 on a USDC-quoted pool misprices every figure
    # by 1e12 — a wrong number that still looks like a number. (Base USDT is 6 decimals,
    # BSC USDT is 18: there is no safe guess.)
    for _ in range(3):
        try:
            return int(c.eth_call(tok, "0x313ce567"), 16)
        except Exception:
            pass
    raise RuntimeError(f"decimals() unreadable for {tok} — refusing to guess; "
                       f"pass the pool explicitly or retry when the node recovers")


def symbol(c, tok):
    try:
        r = c.eth_call(tok, SYMBOL)[2:]
        if len(r) <= 64:                                   # bytes32-style symbol
            return bytes.fromhex(r).rstrip(b"\x00").decode("utf8", "replace") or tok[:10]
        n = int(r[64:128], 16)
        return bytes.fromhex(r[128:128 + n * 2]).decode("utf8", "replace") or tok[:10]
    except Exception:
        return tok[:10] + "…"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--token", required=True)
    p.add_argument("--pools", nargs="*", default=None, help="skip discovery")
    p.add_argument("--also-audit", nargs="*", default=[],
                   help="bridge adapters, vesting factories, distributors — audit these too")
    p.add_argument("--holdings", type=float, default=None,
                   help="token count whose paper value to compare against exit liquidity")
    p.add_argument("--lookback", type=int, default=None,
                   help="blocks of Transfer history to mine for pool candidates. "
                        "Default: derived from measured block time so the window is "
                        "--window-hours of real time on any chain")
    p.add_argument("--window-hours", type=float, default=24.0,
                   help="hours of Transfer history to mine when --lookback is not given "
                        "(default 24)")
    p.add_argument("--quote-price", nargs="*", default=[], metavar="SYM=USD",
                   help="price a non-stable quote asset, e.g. WETH=3400 — without this, "
                        "pools quoted in it are reported but never folded into a $ total")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    prices = {"": 1.0}
    for kv in a.quote_price:
        k, _, v = kv.partition("=")
        prices[k.upper()] = float(v)

    c = Client(NETS[a.chain])
    tok = a.token.lower()
    stables = STABLES[a.chain]
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

    # A clean token contract is the expected result and means very little on its own.
    # The highest-value finding in the case this skill came from was a sweep() on a
    # bridge adapter — a contract that never appears in a token-only audit.
    if not a.also_audit:
        print("  NOTE: only the token contract was audited. Escrow lives elsewhere — bridge")
        print("        adapters, vesting factories, distributors, staking pools. Re-run with")
        print("        --also-audit <addr>... before reading the result above as 'clean'.\n")
        out["also_audit_omitted"] = True

    # ---- 2. exit liquidity ---------------------------------------------------
    print("[2] EXIT LIQUIDITY — what the book can actually absorb\n")
    if a.pools:
        pools, disc_missed, explicit = [x.lower() for x in a.pools], 0, True
        eff_lookback = None
    else:
        pools, disc_missed, eff_lookback = discover_pools(
            c, tok, a.lookback, logc=Client(LOG_EPS[a.chain]),
            window_sec=a.window_hours * 3600)
        explicit = False
    if not pools:
        print("  no V3-style pools found. The token may trade only on V2-style pools")
        print("  (constant-product, no slot0) or on CEXs — pass --pools explicitly.")
        print("  WARNING: absence of V3 pools is NOT absence of liquidity; this scan cannot see V2.")

    rows, skipped = [], []
    by_quote = {}                    # quote symbol -> {"reachable":, "tvl":, "usd": bool}
    for pa in pools:
        try:
            t0 = "0x" + c.eth_call(pa, "0x0dfe1681")[-40:]
            t1 = "0x" + c.eth_call(pa, "0xd21220a7")[-40:]
            flip = t0.lower() != tok
            quote = (t0 if flip else t1).lower()
            # Whether a token is token0 or token1 is decided by address sort order, which
            # is arbitrary — half of all tokens can only be sold in the token1 direction.
            # Skipping those pools silently reports zero exit liquidity for the token.
            pool = Pool(c, pa, decimals(c, t0), decimals(c, t1))
            pool.flip = flip
        except InconsistentState as e:
            # Never truncate this. The message names which invariant broke, and that is
            # the difference between "widen the scan" and "the decode is wrong".
            print(f"  {pa}  profile failed self-check, SKIPPED")
            print(f"     {e}")
            skipped.append((pa, "self-check", str(e)))
            continue
        except Exception as e:
            print(f"  {pa}  unreadable, SKIPPED: {e}")
            skipped.append((pa, "unreadable", str(e)))
            continue

        sell = pool.sell1 if pool.flip else pool.sell
        px = pool.price1 if pool.flip else pool.price
        res_tok = pool.reserve1 if pool.flip else pool.reserve0
        res_q = pool.reserve0 if pool.flip else pool.reserve1
        qsym = stables.get(quote) or symbol(c, quote)
        # Proceeds are denominated in the QUOTE asset, which is not necessarily a dollar.
        # Summing USDC, WETH and a microcap into one "$" figure is how a $405 number
        # becomes a $4,050,000 headline. Convert only what we have a price for.
        rate = 1.0 if quote in stables else prices.get(qsym.upper())
        drain = sell(10 ** 12)
        b = by_quote.setdefault(qsym, {"reachable": 0.0, "tvl": 0.0, "rate": rate, "pools": 0})
        b["reachable"] += drain["proceeds"]
        b["tvl"] += res_tok * px + res_q
        b["pools"] += 1
        rows.append((pa, pool, drain, px, qsym, rate))

        ck = pool.check
        print(f"  {pa}   quote {qsym}{'' if rate else '  [NOT priced — excluded from $ totals]'}")
        print(f"     price {px:,.8g} {qsym}/token   reserves {res_tok:,.0f} tok / "
              f"{res_q:,.0f} {qsym}   self-check ok={ck['ok']}"
              f"{'   [token is token1]' if pool.flip else ''}")
        # residual0/1 follow the POOL's token order, not the analysed token's
        r_tok = ck["residual1"] if pool.flip else ck["residual0"]
        e_tok = ck["explained1"] if pool.flip else ck["explained0"]
        if e_tok is not None and r_tok > 0:
            print(f"     residual {r_tok:,.6g} tok sits outside positions — "
                  f"{e_tok*100:.1f}% of it is accrued protocol fees, which back no swap")
        print(f"     {'sell':>13} {'fillable':>13} {'proceeds':>14} {'avg':>12} "
              f"{'after':>13} {'drop':>7}  stop")
        for s in (10_000, 100_000, 1_000_000):
            r = sell(s)
            print(f"     {s:>13,} {r['filled']:>13,.0f} {r['proceeds']:>14,.2f} "
                  f"{r['avg']:>12.6g} {r['end_price']:>13.8g} {r['drawdown_pct']:>6.1f}%  {r['stop']}")
        print(f"     the entire book can pay out at most {drain['proceeds']:,.2f} {qsym}"
              f" — that is the ceiling, at any size")
        print(f"     (a full-range position means every size 'fills'; it fills by taking the")
        print(f"      price to zero. Watch the average, never the stop reason.)\n")

    reachable = sum(b["reachable"] * b["rate"] for b in by_quote.values() if b["rate"])
    tvl = sum(b["tvl"] * b["rate"] for b in by_quote.values() if b["rate"])
    # Named for the question it answers. "reachable_usd" kept as an alias so older
    # callers do not silently read zero, but the honest key is the one with the number
    # in it: this is exit number 1 of the three in pitfall #21, not third-party depth.
    out["spot_exit_usd"] = reachable
    out["reachable_usd"] = reachable          # deprecated alias
    out["post_withdrawal_exit_usd"] = None    # positions.py computes this
    out["_exit_note"] = ("spot_exit_usd is the WHOLE book including any issuer LP. It is "
                         "not third-party depth and not what survives the issuer "
                         "withdrawing. See pitfalls #21 and run positions.py.")
    out["displayed_tvl_usd"] = tvl
    out["by_quote"] = by_quote
    out["skipped_pools"] = [{"pool": s[0], "why": s[1], "detail": s[2]} for s in skipped]

    # ---- 3. the ratio --------------------------------------------------------
    print("[3] VERDICT\n")

    # Coverage first. Every figure below is computed on the pools that survived, and a
    # ratio quoted over a subset reads exactly like one quoted over the whole market.
    print(f"  pools discovered {len(pools)}   measured {len(rows)}   skipped {len(skipped)}")
    if not explicit:
        print(f"     ! discovery only mined the last {eff_lookback:,} blocks of Transfers. A pool")
        print(f"       with no recent activity is invisible to it — pass --pools to be sure.")
    if disc_missed:
        print(f"     ! {disc_missed} discovery window(s) never answered — pools whose only")
        print(f"       recent counterparties fell in them were never even probed")
    for pa, why, _ in skipped:
        print(f"     ! {pa}  {why} — its liquidity is in NEITHER figure below")
    unpriced = {q: b for q, b in by_quote.items() if not b["rate"]}
    for q, b in unpriced.items():
        print(f"     ! {b['pools']} pool(s) quoted in {q}: {b['reachable']:,.2f} {q} reachable, "
              f"not converted (pass --quote-price {q.upper()}=<usd> to include)")
    print("     -> the totals below are a FLOOR, not the market\n")

    live = [f["name"] for e in out["privileges"] for f in e.get("privileged", []) if f.get("live")]
    if not rows:
        print("  no pool could be measured — no depth figure is available")
        if live:
            print(f"\n  !! live unilateral control path: {live}")
            print("     (no depth measured — the privilege finding stands on its own)")
        if a.json:
            print("\n" + json.dumps(out, indent=1, default=str))
        return

    priced = [r for r in rows if r[5]]
    px = (priced[0][3] * priced[0][5]) if priced else 0
    if len(priced) > 1:
        spread = [r[3] * r[5] for r in priced]
        if max(spread) > min(spread) * 1.05:
            print(f"  ! pools disagree on price: ${min(spread):,.6g} … ${max(spread):,.6g} "
                  f"— using ${px:,.6g}\n")
    print(f"  displayed liquidity (TVL style)   ${tvl:,.0f}")
    print(f"  [1] SPOT EXIT — sellable right now ${reachable:,.0f}"
          + (f"   ({tvl/reachable:.1f}x overstated)" if reachable > 0 else ""))
    print(f"      whole book, untouched. This is what a holder selling TODAY receives,")
    print(f"      whoever provided the liquidity — an AMM pays from whatever is at the tick.")
    print(f"  [2] POST-WITHDRAWAL EXIT             not computed here")
    print(f"      what is left if the issuer pulls its own positions first. Requires LP")
    print(f"      attribution, which this tool does not do:")
    print(f"        python positions.py --chain {a.chain} --pool <pool> --token {tok} --issuer <addr>...")
    print(f"      On one token [1] was over 99% the issuer's own bid, withdrawable in a")
    print(f"      single transaction, and [2] was under $100. Until you have run that,")
    print(f"      [1] above is a number the issuer can revoke, not depth you can rely on.")
    if a.holdings and px:
        paper = a.holdings * px
        out["paper_value_usd"] = paper
        print(f"  position at mark price            ${paper:,.0f}  ({a.holdings:,.0f} tokens @ ${px:.6g})")
        if reachable > 0:
            print(f"  paper : [1] spot exit             {paper/reachable:,.0f} : 1")
            print(f"      against [2] this ratio is larger, often by orders of magnitude.")
    if live:
        print(f"\n  !! live unilateral control path: {live}")
        print("     supply or escrow can move without warning — the liquidity number above")
        print("     is the optimistic case, and it assumes they queue behind you.")
    if a.json:
        print("\n" + json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
