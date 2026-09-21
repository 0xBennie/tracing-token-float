#!/usr/bin/env python3
"""Replay every ERC-20 Transfer event into SQLite, then prove the dataset is trustworthy.

    python replay.py --rpc bsc --token 0xABC... --from-block 112756423 --db t.db --workers 4
    python replay.py --db t.db --verify

Two gates, and they are not the same gate:

  COVERAGE — did a node actually answer for every block in the range? This is
  provenance metadata that exists only at fetch time. It is the ONLY check that
  sees the dominant failure mode.

  SUPPLY IDENTITY — do rebuilt balances sum to totalSupply, to the wei?

The supply identity alone is not enough, and believing otherwise is what produced
this skill's worst error. A missing range full of ordinary peer-to-peer transfers
contributes exactly zero to the sum of all balances, so the identity holds to the
wei with the range gone. It moves only if the hole swallowed a mint or a burn —
and on a fixed-supply token every mint happens in the deploy block, so the
identity's entire detection power is spent before the first transfer. A hole
positioned after distribution completes produces no negative balances either.
The failure mode gets quieter as the token matures, i.e. quietest exactly when
the analysis matters most.

126 of 1383 ranges once failed this way on a BSC replay: no error, no crash, 620
negative balances, rebuilt supply 2.82M tokens too high, and every downstream
percentage wrong. The endpoints were pruned and answered historical queries with
`{"result": []}` — byte-identical to a genuinely empty range.
"""
import argparse, sqlite3, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from rpc import Client, LOG_EPS, MAX_SPAN, RangeError

from topics import T as _T
TRANSFER = _T["erc20.Transfer"]   # derived, never typed
TOTAL_SUPPLY = "0x18160ddd"
# Fixed, and taken from rpc.MAX_SPAN — the measured ceiling of the endpoint pool, not a
# hopeful default. Growing the span against a silently-truncating node is how a window
# returns exactly the node's result cap and gets recorded as complete; exceeding a hard
# cap (blxrbdn at 2,000 on BSC) fails 100% of the time at exactly 30s.

_lock = threading.Lock()


def setup(db):
    c = sqlite3.connect(db, check_same_thread=False)
    c.executescript("""
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS transfers(
        block INTEGER, tx TEXT, li INTEGER, frm TEXT, dst TEXT, val TEXT,
        PRIMARY KEY(tx, li));
      CREATE INDEX IF NOT EXISTS idx_frm ON transfers(frm);
      CREATE INDEX IF NOT EXISTS idx_dst ON transfers(dst);
      -- Record SUCCESSES, never failures. A missing row IS the hole record: it cannot
      -- be forgotten, cannot go stale, and a re-run heals it. A `holes` table is
      -- write-only state that nothing consumes and everything can drift from.
      CREATE TABLE IF NOT EXISTS ranges_done(
        lo INTEGER PRIMARY KEY, hi INTEGER NOT NULL, n INTEGER NOT NULL, ts INTEGER);
      -- The scan's own bounds, so verify() can pin totalSupply() to the same height
      -- instead of comparing against a later 'latest'.
      CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    """)
    return c


def meta_get(c, k, default=None):
    r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def merge(intervals):
    """Union of closed integer intervals, sorted and coalesced (touching counts)."""
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def coverage(c, lo, hi):
    """Gaps in [lo, hi] not covered by any ranges_done row, plus truncation suspects."""
    rows = list(c.execute("SELECT lo, hi, n FROM ranges_done ORDER BY lo"))
    cov = merge([(a, b) for a, b, _ in rows])
    gaps, cur = [], lo
    for a, b in cov:
        if b < lo or a > hi:
            continue
        if a > cur:
            gaps.append((cur, min(a - 1, hi)))
        cur = max(cur, b + 1)
        if cur > hi:
            break
    if cur <= hi:
        gaps.append((cur, hi))
    # A window whose log count lands exactly on a round number is the signature of a
    # node result cap: the response was truncated and returned without an error.
    caps = {1000, 2000, 5000, 10000, 10_000, 20000}
    suspect = [(a, b, n) for a, b, n in rows if n in caps]
    return gaps, cov, suspect


def qualify(cli, token, probe_lo, probe_hi):
    """Refuse to start unless the endpoint pool can actually serve historical logs.

    A pruned node answers a range it cannot serve with an empty result and no error.
    From the response alone that is indistinguishable from a quiet range, so the
    question has to be settled out of band: query a window known to contain logs.
    """
    got = cli.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                    "fromBlock": hex(probe_lo), "toBlock": hex(probe_hi)}])
    return len(got or [])


def rows_from(logs, lo, hi):
    out, skipped = [], 0
    for l in logs:
        tp = l.get("topics") or []
        if len(tp) < 3:                      # not a standard ERC-20 Transfer
            skipped += 1
            continue
        d = l.get("data") or "0x"
        if d in ("0x", ""):
            skipped += 1
            continue
        # Exactly ONE ABI word. A Transfer carrying an extra non-indexed field decodes
        # as value*2**256 + extra with no error, corrupting two balances astronomically.
        out.append((int(l["blockNumber"], 16), l["transactionHash"], int(l["logIndex"], 16),
                    "0x" + tp[1][-40:], "0x" + tp[2][-40:], str(int(d[:66], 16))))
    if skipped:
        print(f"  #{lo}-{hi}: skipped {skipped} non-standard Transfer log(s)", file=sys.stderr)
    return out


def fetch_window(cli, token, lo, hi, empty_quorum=2):
    """One window. Returns rows, or raises — never returns a half-answer.

    An empty result is not accepted on one node's word. The window is re-queried
    (rpc.Client rotates endpoints per call) and every attempt must agree before
    `[]` is believed. That is the difference between a quiet range and a pruned node.
    """
    logs = cli.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                     "fromBlock": hex(lo), "toBlock": hex(hi)}])
    if logs is None:
        raise RuntimeError(f"#{lo}-{hi}: node returned result=null")
    if not logs:
        for _ in range(empty_quorum):
            again = cli.call("eth_getLogs", [{"address": token, "topics": [TRANSFER],
                                              "fromBlock": hex(lo), "toBlock": hex(hi)}])
            if again:
                logs = again
                break
        else:
            return []            # every independent attempt agreed the window is empty
    return rows_from(logs, lo, hi)


def scan(cli, db, token, lo, hi, span=2000, workers=4):
    """Fetch every window in [lo, hi] that ranges_done does not already cover.

    Concurrency is a ceiling, not a knob: 24 workers rate-limited every public BSC
    endpoint into returning nothing, which — combined with an empty result being
    accepted as an answer — is precisely how history goes missing.
    """
    c = setup(db)
    c.execute("INSERT OR REPLACE INTO meta VALUES('token',?)", (token,))
    c.execute("INSERT OR REPLACE INTO meta VALUES('from_block',?)", (str(lo),))
    prev_hi = meta_get(c, "to_block")
    c.execute("INSERT OR REPLACE INTO meta VALUES('to_block',?)",
              (str(max(hi, int(prev_hi))) if prev_hi else str(hi),))
    c.commit()

    todo = [(a, min(b, hi)) for a, b in
            [(x, x + span - 1) for x in range(lo, hi + 1, span)]]
    gaps, _, _ = coverage(c, lo, hi)
    need = [w for w in todo if any(not (w[1] < g[0] or w[0] > g[1]) for g in gaps)]
    print(f"range #{lo:,}–#{hi:,}  {len(todo):,} windows, {len(need):,} not yet covered, "
          f"{workers} workers", flush=True)
    if not need:
        return 0

    stats = {"ok": 0, "rows": 0, "fail": 0}
    t0 = time.time()

    def work(w):
        wlo, whi = w
        try:
            rows = fetch_window(cli, token, wlo, whi)
        except RangeError:
            # Window too large for the node. Split rather than record a hole.
            if whi > wlo:
                mid = (wlo + whi) // 2
                work((wlo, mid)); work((mid + 1, whi))
                return
            rows = None
        except Exception as e:
            with _lock:
                stats["fail"] += 1
            print(f"  #{wlo}-{whi} FAILED: {str(e)[:120]}", file=sys.stderr, flush=True)
            return
        if rows is None:
            with _lock:
                stats["fail"] += 1
            return
        # Coverage and data commit in ONE transaction. A crash must never leave a
        # window claimed as covered whose rows were rolled back — nor the reverse.
        with _lock:
            if rows:
                c.executemany("INSERT OR IGNORE INTO transfers VALUES(?,?,?,?,?,?)", rows)
            c.execute("INSERT OR REPLACE INTO ranges_done VALUES(?,?,?,?)",
                      (wlo, whi, len(rows), int(time.time())))
            c.commit()
            stats["ok"] += 1
            stats["rows"] += len(rows)
            n = stats["ok"]
            if n % 25 == 0 or n >= len(need):
                el = time.time() - t0
                left = max(len(need) - n, 0)
                print(f"  {n:,}/{len(need):,} windows  {stats['rows']:,} rows  {el:.0f}s  "
                      f"eta {el / n * left:.0f}s  failed {stats['fail']}"
                      + ("  (count exceeds plan: windows were split)" if n > len(need) else ""),
                      flush=True)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, need))
    print(f"done in {time.time()-t0:.0f}s — {stats['rows']:,} rows, "
          f"{stats['fail']} window(s) never answered", flush=True)
    return stats["rows"]


def verify(db, cli=None):
    """The gate. Coverage first, then the supply identity. Integer arithmetic only."""
    c = setup(db)
    token = meta_get(c, "token")
    lo, hi = meta_get(c, "from_block"), meta_get(c, "to_block")
    ok = True

    print("\n  COVERAGE")
    if lo is None or hi is None:
        print("    REFUSED — no scan bounds recorded in this database.")
        print("    A database with no provenance cannot be certified. Re-scan with replay.py.")
        return 3
    lo, hi = int(lo), int(hi)
    gaps, cov, suspect = coverage(c, lo, hi)
    missing = sum(b - a + 1 for a, b in gaps)
    print(f"    requested        #{lo:,}–#{hi:,}  ({hi - lo + 1:,} blocks)")
    print(f"    answered         {len(list(c.execute('SELECT 1 FROM ranges_done')))} windows "
          f"in {len(cov)} contiguous run(s)")
    print(f"    gaps             {len(gaps)}  ({missing:,} blocks)  "
          f"{'OK' if not gaps else 'FAIL'}")
    for a, b in gaps[:20]:
        print(f"      missing #{a:,}–#{b:,}")
    if len(gaps) > 20:
        print(f"      … and {len(gaps)-20} more")
    if suspect:
        print(f"    truncation suspects {len(suspect)} window(s) returned exactly a round "
              f"result count — likely a silent node cap:")
        for a, b, n in suspect[:5]:
            print(f"      #{a:,}–#{b:,} returned exactly {n:,} logs")
        ok = False
    if gaps:
        print("    -> re-run replay.py with the same --db to fill them. Do NOT compute")
        print("       anything from this database: a hole made of ordinary transfers is")
        print("       invisible to every check below.")
        ok = False

    print("\n  SUPPLY IDENTITY")
    bal = {}
    for frm, dst, val in c.execute("SELECT frm, dst, val FROM transfers"):
        v = int(val)
        bal[frm] = bal.get(frm, 0) - v
        bal[dst] = bal.get(dst, 0) + v
    zero = "0x" + "0" * 40
    bal.pop(zero, None)
    neg = {a: v for a, v in bal.items() if v < 0}
    pos = {a: v for a, v in bal.items() if v > 0}
    # The TRUE conservation sum, over every balance. Summing only positives makes the
    # printed difference algebraically equal to the negative mass — one check reported
    # twice, dressed up as two agreeing gates.
    total = sum(bal.values())
    print(f"    transfers        {c.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]:,}")
    print(f"    holders (>0)     {len(pos):,}")
    print(f"    negative         {len(neg)}  {'OK' if not neg else 'FAIL — a funding transfer is missing'}")
    print(f"    rebuilt supply   {total} wei  (sum of ALL balances, negatives included)")
    if neg:
        ok = False
    if cli and token:
        # Pin to the scan's own upper bound. Comparing against 'latest' lets any mint or
        # burn after the scan produce a difference that has nothing to do with integrity
        # — and lets a later burn cancel a missing mint inside a hole.
        try:
            ts = int(cli.eth_call(token, TOTAL_SUPPLY, hex(hi)), 16)
            at = f"@#{hi:,}"
        except Exception:
            ts = int(cli.eth_call(token, TOTAL_SUPPLY), 16)
            at = "@latest (archive node refused the pinned read — this weakens the check)"
        d = total - ts
        print(f"    totalSupply()    {ts} wei  {at}")
        print(f"    difference       {d} wei  {'OK — exact' if d == 0 else 'FAIL'}")
        if d:
            print("    -> a mint or burn is missing, or the token moves supply outside Transfer")
            ok = False
    else:
        print("    REFUSED — no RPC client, so totalSupply() was never compared.")
        print("    This database is NOT certified. Re-run with --rpc.")
        return 3
    print(f"\n  VERDICT  {'CERTIFIED' if ok else 'NOT CERTIFIED — do not compute from this database'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", choices=["bsc", "base", "eth"])
    p.add_argument("--token")
    p.add_argument("--from-block", type=int)
    p.add_argument("--to-block", type=int)
    p.add_argument("--db", required=True)
    p.add_argument("--workers", type=int, default=4,
                   help="parallel windows. Keep low: 24 workers rate-limited every "
                        "public BSC endpoint into returning nothing (default 4)")
    p.add_argument("--span", type=int, default=None,
                   help="block window size; defaults to the measured cap for the chain")
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()

    cli = Client(LOG_EPS[a.rpc]) if a.rpc else None
    span = a.span or (MAX_SPAN.get(a.rpc, 2000) if a.rpc else 2000)
    if a.from_block is not None:
        tok = a.token.lower()
        hi = a.to_block if a.to_block is not None else cli.block_number()
        n = qualify(cli, tok, a.from_block, min(a.from_block + span - 1, hi))
        if n == 0:
            sys.exit(f"REFUSED: the endpoint pool returned no logs for the token's own "
                     f"first window (#{a.from_block}–). Either the from-block is wrong or "
                     f"every endpoint is pruned. Starting now would record empty answers "
                     f"as covered history.")
        print(f"endpoint pool qualified: {n} logs in the first window", flush=True)
        scan(cli, a.db, tok, a.from_block, hi, span, a.workers)
    if a.verify:
        sys.exit(verify(a.db, cli))
