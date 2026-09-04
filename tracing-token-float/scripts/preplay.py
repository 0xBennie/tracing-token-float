"""Parallel event replay — fans block ranges across every endpoint at once.

Public nodes cap eth_getLogs at a few thousand blocks, so a year of history is
tens of thousands of requests. Serially that is hours; spread across endpoints
with a thread pool it is minutes. Each worker rotates endpoints on failure, and
every range is retried until it lands or is recorded as a hole — a silently
dropped range is a hole in the supply identity later, so holes are reported.

    python preplay.py --token 0x... --from 59397467 --span 2000 --db t.db
"""
import argparse, itertools, sqlite3, threading, time, requests
from concurrent.futures import ThreadPoolExecutor

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# blxrbdn is the only free BSC endpoint that reliably answers HISTORICAL getLogs.
# Concurrency is a hard ceiling, not a tuning knob: 24 workers rate-limited every public
# endpoint into returning zero for minutes. Keep --workers at or below 4 on BSC.
BSC = ["https://bsc.rpc.blxrbdn.com",
       "https://bsc-dataseed.bnbchain.org", "https://bsc-dataseed1.defibit.io",
       "https://bsc-dataseed1.ninicoin.io", "https://bsc-dataseed2.bnbchain.org",
       "https://bsc-dataseed3.bnbchain.org", "https://bsc-dataseed4.bnbchain.org",
       "https://bsc-rpc.publicnode.com", "https://bsc.meowrpc.com",
       "https://bsc.blockrazor.xyz", "https://bsc-pokt.nodies.app",
       "https://binance.llamarpc.com", "https://bsc.drpc.org"]

_lock = threading.Lock()
_stats = {"ok": 0, "logs": 0, "holes": 0}


def fetch(sess, urls, token, lo, hi, tries=8):
    for i in range(tries):
        u = urls[(i + hash((lo, hi))) % len(urls)]
        try:
            j = sess.post(u, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
                                   "params": [{"address": token, "topics": [TRANSFER],
                                               "fromBlock": hex(lo), "toBlock": hex(hi)}]},
                          timeout=25).json()
            if "result" in j:
                return j["result"]
        except Exception:
            pass
        time.sleep(0.15 * (i + 1))
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--token", required=True)
    p.add_argument("--from", dest="lo", type=int, required=True)
    p.add_argument("--to", dest="hi", type=int, default=None)
    p.add_argument("--span", type=int, default=2000)
    p.add_argument("--workers", type=int, default=4,
                   help="4 is the safe ceiling on free public BSC endpoints; higher "
                        "rate-limits the whole pool into returning nothing")
    p.add_argument("--db", required=True)
    a = p.parse_args()
    token = a.token.lower()

    sess = requests.Session()
    hi = a.hi or int(sess.post(BSC[0], json={"jsonrpc": "2.0", "id": 1,
                     "method": "eth_blockNumber", "params": []}, timeout=15).json()["result"], 16)
    ranges = [(b, min(b + a.span - 1, hi)) for b in range(a.lo, hi + 1, a.span)]
    print(f"块 {a.lo:,}–{hi:,}  {len(ranges):,} 个窗口  {a.workers} 并发", flush=True)

    db = sqlite3.connect(a.db, check_same_thread=False)
    db.executescript("""PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS transfers(block INTEGER,tx TEXT,li INTEGER,
        frm TEXT,dst TEXT,val TEXT,PRIMARY KEY(tx,li));
      CREATE TABLE IF NOT EXISTS holes(lo INTEGER,hi INTEGER);""")
    t0 = time.time()

    def work(rg):
        lo, hi_ = rg
        s = requests.Session()
        logs = fetch(s, BSC, token, lo, hi_)
        if logs is None:
            with _lock:
                _stats["holes"] += 1
                db.execute("INSERT INTO holes VALUES(?,?)", (lo, hi_)); db.commit()
            return
        rows = [(int(l["blockNumber"], 16), l["transactionHash"], int(l["logIndex"], 16),
                 "0x" + l["topics"][1][-40:], "0x" + l["topics"][2][-40:],
                 str(int(l["data"], 16))) for l in logs]
        with _lock:
            if rows:
                db.executemany("INSERT OR IGNORE INTO transfers VALUES(?,?,?,?,?,?)", rows)
            _stats["ok"] += 1; _stats["logs"] += len(rows)
            n = _stats["ok"]
            if n % 500 == 0:
                db.commit()
                el = time.time() - t0
                print(f"  {n:,}/{len(ranges):,}  {_stats['logs']:,} 笔  "
                      f"{el:.0f}s  {n/el:.0f} win/s  剩 {(len(ranges)-n)/(n/el)/60:.1f} 分  "
                      f"洞 {_stats['holes']}", flush=True)

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        list(ex.map(work, ranges))
    db.commit()
    n = db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
    h = db.execute("SELECT COUNT(*) FROM holes").fetchone()[0]
    print(f"\n完成 {time.time()-t0:.0f}s  transfers {n:,}  未取到的窗口 {h}", flush=True)
    # A hole is a silently missing slice of history. Downstream it becomes a wrong
    # balance, a wrong percentage, and no error — so it must fail the run.
    if h:
        for lo, hi_ in db.execute("SELECT lo, hi FROM holes ORDER BY lo LIMIT 20"):
            print(f"  hole: #{lo:,}–#{hi_:,}", flush=True)
        print(f"\nFAILED: {h} block ranges never returned. Re-run to fill them before "
              f"computing anything — the dataset is incomplete.", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
