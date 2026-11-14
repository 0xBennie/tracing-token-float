"""Follow the money that is not the token: time, gas, the quote asset, wallet rotations.

A token-only ledger sees half of every trade. The decisive links in the audit this was
written for were all on the other side — the dump's USDT proceeds landing in one wallet
together with exchange withdrawals made the same hour, a "dip buyer" funded with round
millions minutes before it bought, and a 57-million-token "deposit" that was really an
exchange moving fifty-odd tokens to a new wallet in one sweep.

    python funding.py --chain bsc when 125733000 122148476
    python funding.py --chain bsc when --utc "2026-09-16 03:00"
    python funding.py --chain bsc gas 0xADDR 0xADDR2 ...
    python funding.py --chain bsc quote --quote 0xUSDT --from-block <lo> --to-block <hi> 0xADDR ...
    python funding.py --chain bsc migration --from-block <lo> --to-block <hi> 0xADDR

`when` exists because a wall-clock time derived by hand from block deltas went wrong by
about eleven hours in one report and moved three dated claims onto the wrong day
(pitfall #35). Every time a deliverable prints comes from a block header.
"""
import argparse, collections, datetime, sys
from rpc import Client, BASE, BSC, ETH, LOG_EPS, ARCHIVE_EPS, MAX_SPAN, RangeError, refuse
from topics import T as _T

TRANSFER = _T["erc20.Transfer"]
NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
# A funder that has sent this many transactions is a custodian's gas or withdrawal
# wallet. It funds everyone; sharing it is a weak signal, never a link (pitfall #36).
CUSTODIAL_NONCE = 1_000_000


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def block_ts(c, b):
    return int(c.call("eth_getBlockByNumber", [hex(b), False])["timestamp"], 16)


def cmd_when(a, arch):
    if a.utc:
        target = int(datetime.datetime.strptime(a.utc, "%Y-%m-%d %H:%M").replace(
            tzinfo=datetime.UTC).timestamp())
        hi = arch.block_number()
        lo = 1
        while hi - lo > 1:
            m = (lo + hi) // 2
            if block_ts(arch, m) >= target:
                hi = m
            else:
                lo = m
        print(f"  first block at/after {a.utc} UTC: #{hi:,}  ({utc(block_ts(arch, hi))})")
    for b in a.blocks:
        print(f"  #{int(b):,}  {utc(block_ts(arch, int(b)))}")


def cmd_gas(a, arch):
    head = arch.block_number()
    for addr in (x.lower() for x in a.addrs):
        def touched(b):
            return (int(arch.call("eth_getBalance", [addr, hex(b)]), 16) > 0 or
                    int(arch.call("eth_getTransactionCount", [addr, hex(b)]), 16) > 0)
        if not touched(head):
            print(f"  {addr}  never funded")
            continue
        lo, hi = a.floor, head
        if touched(lo):
            print(f"  {addr}  already funded at the search floor #{lo:,} — lower --floor")
            continue
        while hi - lo > 1:
            m = (lo + hi) // 2
            if touched(m):
                hi = m
            else:
                lo = m
        blk = arch.call("eth_getBlockByNumber", [hex(hi), True])
        src = [(t["from"].lower(), int(t["value"], 16) / 1e18) for t in blk["transactions"]
               if (t.get("to") or "").lower() == addr and int(t["value"], 16) > 0]
        when = utc(int(blk["timestamp"], 16))
        if not src:
            print(f"  {addr}  first funded #{hi:,} ({when}) by an INTERNAL transfer — "
                  f"read the block's traces to name the contract")
            continue
        for f, v in src:
            n = int(arch.call("eth_getTransactionCount", [f, "latest"]), 16)
            kind = (f"custodial-scale (nonce {n:,}) — WEAK as a shared-funder link"
                    if n >= CUSTODIAL_NONCE else f"nonce {n:,}")
            print(f"  {addr}  first funded #{hi:,} ({when}) by {f}  {v:.6g} native  [{kind}]")


def _logs(c, filt, lo, hi):
    """eth_getLogs over [lo, hi], halving the window whenever every endpoint calls it
    too large. Never returns a partial answer: a refusal propagates."""
    try:
        return c.call("eth_getLogs", [dict(filt, fromBlock=hex(lo), toBlock=hex(hi))])
    except RangeError:
        if lo == hi:
            refuse("eth_getLogs")
            raise
        m = (lo + hi) // 2
        return _logs(c, filt, lo, m) + _logs(c, filt, m + 1, hi)


def _windows(lo, hi, span):
    a = lo
    while a <= hi:
        yield a, min(a + span - 1, hi)
        a += span


def cmd_quote(a, logc, span):
    pad = lambda x: "0x" + x[2:].rjust(64, "0")
    q = a.quote.lower()
    for addr in (x.lower() for x in a.addrs):
        ins, outs, first, n_win = (collections.Counter(), collections.Counter(), {}, 0)
        for lo, hi in _windows(a.from_block, a.to_block, span):
            for side, topics in (("in", [TRANSFER, None, pad(addr)]), ("out", [TRANSFER, pad(addr)])):
                for l in _logs(logc, {"address": q, "topics": topics}, lo, hi):
                    v = int(l["data"] or "0x0", 16) / 10 ** a.decimals
                    if v == 0:
                        continue          # zero-value poison rows say nothing (pitfall #33)
                    o = "0x" + l["topics"][1 if side == "in" else 2][-40:]
                    (ins if side == "in" else outs)[o] += v
                    first.setdefault(side + o, int(l["blockNumber"], 16))
            n_win += 1
        print(f"== {addr}  quote in {sum(ins.values()):,.2f} from {len(ins)}  "
              f"out {sum(outs.values()):,.2f} to {len(outs)}  ({n_win} windows answered)")
        for o, v in ins.most_common(a.top):
            print(f"   IN  {o} {v:>16,.2f}  first #{first['in' + o]:,}")
        for o, v in outs.most_common(a.top):
            print(f"   OUT {o} {v:>16,.2f}  first #{first['out' + o]:,}")


def cmd_migration(a, logc, span):
    """Distinct tokens an address moved out in a window. Dozens of tokens to one
    destination inside hours is a custodian rotating wallets, not a holder depositing."""
    pad = lambda x: "0x" + x[2:].rjust(64, "0")
    for addr in (x.lower() for x in a.addrs):
        toks, dst = collections.Counter(), collections.Counter()
        for lo, hi in _windows(a.from_block, a.to_block, span):
            for l in _logs(logc, {"topics": [TRANSFER, pad(addr)]}, lo, hi):
                if int(l["data"] or "0x0", 16) == 0:
                    continue
                toks[l["address"].lower()] += 1
                dst["0x" + l["topics"][2][-40:]] += 1
        verdict = ("WALLET ROTATION — not a deposit (pitfall #36)"
                   if len(toks) >= a.rotation_min else "no rotation signature")
        print(f"  {addr}  {len(toks)} distinct token(s) out, {sum(toks.values())} transfers; "
              f"top destinations {dst.most_common(3)}  -> {verdict}")


def main():
    p = argparse.ArgumentParser(description="time, gas funders, quote-asset flow, wallet rotations")
    p.add_argument("--chain", required=True, choices=list(NETS))
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("when", help="block -> UTC, or --utc -> first block at/after it")
    w.add_argument("blocks", nargs="*")
    w.add_argument("--utc", help='"YYYY-MM-DD HH:MM", read as UTC')
    g = sub.add_parser("gas", help="first native-coin funder of each address, with its class")
    g.add_argument("addrs", nargs="+")
    g.add_argument("--floor", type=int, default=1, help="lowest block the bisect searches")
    q = sub.add_parser("quote", help="quote-asset (USDT, WBNB, ...) in/out of addresses")
    q.add_argument("addrs", nargs="+")
    q.add_argument("--quote", required=True, help="the quote token contract")
    q.add_argument("--decimals", type=int, default=18)
    q.add_argument("--from-block", type=int, required=True)
    q.add_argument("--to-block", type=int, required=True)
    q.add_argument("--top", type=int, default=6)
    m = sub.add_parser("migration", help="distinct tokens an address moved out in a window")
    m.add_argument("addrs", nargs="+")
    m.add_argument("--from-block", type=int, required=True)
    m.add_argument("--to-block", type=int, required=True)
    m.add_argument("--rotation-min", type=int, default=10,
                   help="distinct tokens that make it a rotation (default 10)")
    a = p.parse_args()
    arch = Client(ARCHIVE_EPS[a.chain])
    logc = Client(LOG_EPS[a.chain])
    span = MAX_SPAN.get(a.chain, 2000)
    if a.cmd == "when":
        cmd_when(a, arch)
    elif a.cmd == "gas":
        cmd_gas(a, arch)
    elif a.cmd == "quote":
        cmd_quote(a, logc, span)
    else:
        cmd_migration(a, logc, span)


if __name__ == "__main__":
    main()
