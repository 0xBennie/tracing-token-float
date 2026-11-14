"""Find the Uniswap-V4 pools a token trades in, and recover each one's PoolKey.

A V4 pool is not a contract. Every pool lives inside one PoolManager, keyed by a 32-byte
poolId, so a factory sweep never sees it and a counterparty probe for `slot0()` finds
nothing to probe — the token's counterparty is the manager itself. In the audit this was
written for, the manager was the single largest "net buyer" in the pump window and four
live pools were invisible to venue enumeration until they were found by hand
(pitfall #37). And the manager stores no PoolKey: without (currency0, currency1, fee,
tickSpacing, hooks) depth.py cannot even read the pool.

Method, all from chain data:
  1. sample transactions in which the token moved into or out of the manager
  2. in each receipt, match the manager's Swap amounts to the token's net delta on the
     manager: the poolId whose amount equals that delta (within --tol) trades the token.
     Multi-hop routes also touch pools that never hold the token; this filters them out
  3. bisect the first block at which each poolId's slot0 is non-zero (archive extsload),
     and read the Initialize event in exactly that block: the PoolKey
  4. prove it: keccak(abi.encode(key)) must equal the poolId

    python v4pools.py --chain bsc --token 0xTOKEN --manager 0xPOOLMANAGER \\
           --from-block <lo> --to-block <hi>

Prints a ready `depth.py --pool-id ... --v4-key ...` line per pool. Pancake Infinity
CL pools use a different manager and event layout and are not covered here.
"""
import argparse, collections, random, sys
from rpc import Client, BASE, BSC, ETH, LOG_EPS, ARCHIVE_EPS, MAX_SPAN, RangeError, refuse
from topics import T as _T, selector
from depth import _keccak, _w

TRANSFER = _T["erc20.Transfer"]
V4_SWAP = _T["v4.Swap"]
V4_INIT = _T["v4.Initialize"]
POOLS_SLOT = 6            # v4-core StateLibrary; proved below by the key -> poolId hash
NETS = {"base": BASE, "bsc": BSC, "eth": ETH}


def s256(h):
    v = int(h, 16)
    return v - (1 << 256) if v >= 1 << 255 else v


def _logs(c, filt, lo, hi):
    try:
        return c.call("eth_getLogs", [dict(filt, fromBlock=hex(lo), toBlock=hex(hi))])
    except RangeError:
        if lo == hi:
            refuse("eth_getLogs")
            raise
        m = (lo + hi) // 2
        return _logs(c, filt, lo, m) + _logs(c, filt, m + 1, hi)


def sample_txs(logc, token, manager, lo, hi, span, want):
    pad = "0x" + manager[2:].rjust(64, "0")
    txs = set()
    for a in range(hi - span + 1, lo - 1, -span):          # newest first
        a = max(a, lo)
        for topics in ([TRANSFER, pad], [TRANSFER, None, pad]):
            for l in _logs(logc, {"address": token, "topics": topics}, a, min(a + span - 1, hi)):
                txs.add(l["transactionHash"])
        if len(txs) >= want * 3 or a == lo:
            break
    txs = sorted(txs)
    random.Random(7).shuffle(txs)
    return txs[:want]


def match_pools(cli, token, manager, txs, tol):
    hits = collections.Counter()
    for h in txs:
        r = cli.call("eth_getTransactionReceipt", [h])
        delta = 0
        for l in r["logs"]:
            if l["address"].lower() == token and l["topics"][0] == TRANSFER:
                v = int(l["data"], 16)
                if "0x" + l["topics"][2][-40:] == manager:
                    delta += v
                if "0x" + l["topics"][1][-40:] == manager:
                    delta -= v
        if not delta:
            continue
        for l in r["logs"]:
            if l["address"].lower() == manager and l["topics"][0] == V4_SWAP:
                d = l["data"][2:]
                for side, amt in (("c0", s256(d[0:64])), ("c1", s256(d[64:128]))):
                    if abs(abs(amt) - abs(delta)) <= tol * abs(delta):
                        hits[(l["topics"][1], side)] += 1
    return hits


def init_block(arch, manager, pid, lo, hi):
    slot = int.from_bytes(_keccak(bytes.fromhex(pid[2:]) + _w(POOLS_SLOT)), "big")
    sel = selector("extsload(bytes32)")
    def live(b):
        # Before the manager existed the call returns bare "0x": no code, so no pool.
        r = arch.call("eth_call", [{"to": manager, "data": sel + f"{slot:064x}"}, hex(b)])
        return r not in ("0x", "") and int(r, 16) != 0
    if not live(hi):
        return None
    if live(lo):
        return lo
    while hi - lo > 1:
        m = (lo + hi) // 2
        if live(m):
            hi = m
        else:
            lo = m
    return hi


def main():
    p = argparse.ArgumentParser(description="Uniswap V4 pools trading a token, with PoolKeys")
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("--token", required=True)
    p.add_argument("--manager", required=True,
                   help="the V4 PoolManager. Prove it: it must hold the token and emit the "
                        "v4.Swap topic — a recalled address returns nothing, silently")
    p.add_argument("--from-block", type=int, required=True)
    p.add_argument("--to-block", type=int, required=True)
    p.add_argument("--sample", type=int, default=60, help="transactions to inspect (default 60)")
    p.add_argument("--tol", type=float, default=0.02, help="amount match tolerance (default 2%%)")
    p.add_argument("--min-hits", type=int, default=1)
    a = p.parse_args()
    token, manager = a.token.lower(), a.manager.lower()
    cli, logc, arch = Client(NETS[a.chain]), Client(LOG_EPS[a.chain]), Client(ARCHIVE_EPS[a.chain])

    txs = sample_txs(logc, token, manager, a.from_block, a.to_block,
                     MAX_SPAN.get(a.chain, 2000), a.sample)
    if not txs:
        sys.exit("REFUSED: no transfer of this token touched the manager in the window. "
                 "Either it has no V4 pools, or the window/manager is wrong — that is two "
                 "different findings, so widen the window before writing either.")
    hits = match_pools(cli, token, manager, txs, a.tol)
    print(f"  {len(txs)} transactions sampled; {len(hits)} (poolId, side) matched the token's "
          f"delta on the manager")
    seen = set()
    for (pid, side), n in hits.most_common():
        if n < a.min_hits or pid in seen:
            continue
        seen.add(pid)
        b = init_block(arch, manager, pid, 1, a.to_block)
        if b is None:
            print(f"  {pid}  slot0 empty at #{a.to_block:,} — not initialised, skipped")
            continue
        filt = {"address": manager, "fromBlock": hex(b), "toBlock": hex(b),
                "topics": [V4_INIT, pid]}
        logs = None
        # The log pool may be a recent-only provider (a tail segment on blxrbdn); a pool
        # initialised months ago is below its floor. One block is cheap, so fall back to
        # the archive pool, which carries a full-history node.
        for c in (logc, arch):
            try:
                logs = c.call("eth_getLogs", [filt])
                if logs:
                    break
            except Exception:
                continue
        if not logs:
            print(f"  {pid}  initialised at #{b:,} but no Initialize log answered — refused, "
                  f"not absent; retry on another log pool")
            continue
        l = logs[0]
        d = l["data"][2:]
        c0, c1 = "0x" + l["topics"][2][-40:], "0x" + l["topics"][3][-40:]
        fee, ts = int(d[0:64], 16), s256(d[64:128])
        hooks = "0x" + d[128:192][-40:]
        derived = "0x" + _keccak(b"".join((_w(int(c0, 16)), _w(int(c1, 16)), _w(fee),
                                           _w(ts & ((1 << 256) - 1)), _w(int(hooks, 16))))).hex()
        ok = derived == pid
        tok_side = "token1" if c1 == token else ("token0" if c0 == token else "NEITHER")
        print(f"  {pid}  matches={n}  init #{b:,}  fee {fee} ({fee / 1e4:.4g}%)  "
              f"tickSpacing {ts}  hooks {hooks}  subject={tok_side}  "
              f"key->poolId {'PROVED' if ok else 'MISMATCH'}")
        if ok and tok_side != "NEITHER":
            print(f"      python depth.py --chain {a.chain} --pool-id {pid} --manager {manager} "
                  f"--v4-key {c0},{c1},{fee},{ts},{hooks} --dec0 <d0> --dec1 <d1>"
                  + (" --token1" if tok_side == "token1" else "") + " --block <snapshot>")
        if int(hooks, 16):
            print(f"      ! hooks set: a hook can take a fee or reroute a swap — read it "
                  f"before trusting the book")


if __name__ == "__main__":
    main()
