"""Replay every ERC-20 Transfer event into SQLite, then prove the dataset is trustworthy.

    python replay.py --rpc base --token 0xABC... --from-block 46488435 --db o.db
    python replay.py --db o.db --verify --token 0xABC... --rpc base

Never skip --verify. If rebuilt balances don't sum to totalSupply in wei, every
downstream number is built on sand.
"""
import argparse, sqlite3, sys, time
from rpc import Client, BASE, BSC, ETH, RangeError

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
NETS = {"base": BASE, "bsc": BSC, "eth": ETH}


def setup(db):
    c = sqlite3.connect(db)
    c.executescript("""
      CREATE TABLE IF NOT EXISTS transfers(
        block INTEGER, tx TEXT, li INTEGER, frm TEXT, dst TEXT, val TEXT,
        PRIMARY KEY(tx, li));
      CREATE INDEX IF NOT EXISTS idx_frm ON transfers(frm);
      CREATE INDEX IF NOT EXISTS idx_dst ON transfers(dst);
      CREATE TABLE IF NOT EXISTS ranges_done(lo INTEGER, hi INTEGER);
    """)
    return c


def scan(cli, db, token, lo, hi, span=2000):
    """Adaptive range scan: halve the window whenever a node complains it's too big."""
    c = setup(db)
    done = {(a, b) for a, b in c.execute("SELECT lo, hi FROM ranges_done")}
    cur, t0, n = lo, time.time(), 0
    while cur <= hi:
        end = min(cur + span - 1, hi)
        if (cur, end) in done:
            cur = end + 1
            continue
        try:
            logs = cli.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                             "fromBlock": hex(cur), "toBlock": hex(end)}])
        except RangeError:
            if span <= 1:
                raise
            span = max(1, span // 2)
            continue
        rows = [(int(l["blockNumber"], 16), l["transactionHash"], int(l["logIndex"], 16),
                 "0x" + l["topics"][1][-40:], "0x" + l["topics"][2][-40:],
                 str(int(l["data"], 16))) for l in logs]
        c.executemany("INSERT OR IGNORE INTO transfers VALUES(?,?,?,?,?,?)", rows)
        c.execute("INSERT INTO ranges_done VALUES(?,?)", (cur, end))
        c.commit()
        n += len(rows)
        print(f"\r  #{cur}-{end}  +{len(rows):>5}  total {n:>9,}  "
              f"{(cur-lo)/max(hi-lo,1)*100:5.1f}%  {time.time()-t0:.0f}s", end="", file=sys.stderr)
        cur = end + 1
        if len(logs) < 200 and span < 20000:
            span = min(span * 2, 20000)
    print(file=sys.stderr)
    return n


def verify(db, cli=None, token=None):
    """The gate. Integer arithmetic only — floats lose wei above 2^53."""
    c = sqlite3.connect(db)
    bal = {}
    for frm, dst, val in c.execute("SELECT frm, dst, val FROM transfers"):
        v = int(val)
        bal[frm] = bal.get(frm, 0) - v
        bal[dst] = bal.get(dst, 0) + v
    zero = "0x" + "0" * 40
    bal.pop(zero, None)
    pos = {a: v for a, v in bal.items() if v > 0}
    neg = {a: v for a, v in bal.items() if v < 0}
    total = sum(pos.values())
    print(f"  transfers        {c.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]:,}")
    print(f"  holders (>0)     {len(pos):,}")
    print(f"  negative         {len(neg)}  {'OK' if not neg else 'FAIL — mis-scanned range or missed mints'}")
    print(f"  rebuilt supply   {total} wei")
    if cli and token:
        ts = int(cli.eth_call(token, "0x18160ddd"), 16)
        d = total - ts
        print(f"  totalSupply()    {ts} wei")
        print(f"  difference       {d} wei  {'OK — exact' if d == 0 else 'FAIL'}")
        if d:
            print("  → a range is missing, or the token mints/burns outside Transfer events")
        # The supply identity is the gate. Returning True on a mismatch lets every
        # downstream percentage be computed on a dataset that is known to be incomplete.
        return not neg and d == 0
    return not neg


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", choices=list(NETS)); p.add_argument("--token")
    p.add_argument("--from-block", type=int); p.add_argument("--to-block", type=int)
    p.add_argument("--db", required=True); p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    cli = Client(NETS[a.rpc]) if a.rpc else None
    if a.from_block is not None:
        hi = a.to_block or int(cli.call("eth_blockNumber", []), 16)
        scan(cli, a.db, a.token.lower(), a.from_block, hi)
    if a.verify:
        ok = verify(a.db, cli, a.token.lower() if a.token else None)
        sys.exit(0 if ok else 1)
