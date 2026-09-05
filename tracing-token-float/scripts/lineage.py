"""Weighted provenance: propagate an address's balance backward by amount share.

    from lineage import trace
    trace(cur, "0xdead...", terminals={"0xgenesis...": "genesis"}, max_hop=4)
    -> {"genesis": 0.83, "Bitget hot wallet": 0.11, "<diluted>": 0.06}

READ THIS BEFORE BELIEVING THE OUTPUT
-------------------------------------
Share-weighted lineage is only meaningful for addresses that received and held.
On an actively trading address its own churn recycles through the pool and dilutes
true provenance toward zero — an address funded 100% by the issuer can show <10%
issuer lineage after enough round trips. A large "cycle@..." or pool share in the
result is the signal that this method does not apply; switch to net-flow between
the address and known issuer addresses, first-funding, or timing evidence.
"""
import collections

WEI = 1e18


def trace(cur, target, terminals, max_hop=4, min_share=0.01, table="transfers"):
    """cur: sqlite cursor over transfers(frm, dst, val).
    terminals: {address: label} — stop and attribute when reached.
    Returns {label: share} summing to ~1.0."""
    agg = collections.Counter()
    frontier = {target.lower(): 1.0}
    terminals = {k.lower(): v for k, v in terminals.items()}
    seen = set()
    for hop in range(max_hop):
        nxt = collections.Counter()
        for node, w in frontier.items():
            if w < min_share:
                agg["<diluted, not traced>"] += w
                continue
            if hop and node in terminals:
                agg[terminals[node]] += w
                continue
            if node in seen:
                agg[f"cycle@{node[:10]}…"] += w
                continue
            seen.add(node)
            rows = cur.execute(
                f"SELECT frm, SUM(CAST(val AS REAL)) FROM {table} WHERE dst=? GROUP BY frm",
                (node,)).fetchall()
            tot = sum(r[1] for r in rows)
            if not tot:
                agg[f"no inflow@{node[:10]}…"] += w
                continue
            for frm, v in rows:
                nxt[frm] += w * (v / tot)
        frontier = dict(nxt)
        if not frontier:
            break
    for node, w in frontier.items():
        agg[terminals.get(node, f"unresolved@{node[:10]}…")] += w
    return dict(agg)


def net_flow(cur, a, b, table="transfers"):
    """Net tokens from a -> b.

    NOT a behaviour signal on its own — see pitfalls #18. Useful only for the narrow
    question "did value move between these two specific addresses", e.g. testing whether
    a supposedly independent desk returns inventory to the issuer's treasury."""
    a, b = a.lower(), b.lower()
    q = f"SELECT COALESCE(SUM(CAST(val AS REAL)),0)/{WEI} FROM {table} WHERE frm=? AND dst=?"
    return cur.execute(q, (a, b)).fetchone()[0] - cur.execute(q, (b, a)).fetchone()[0]


def first_funder(cur, a, table="transfers"):
    """(block, from, amount) of the first inbound transfer — who opened this address."""
    r = cur.execute(f"SELECT block, frm, CAST(val AS REAL)/{WEI} FROM {table} "
                    f"WHERE dst=? ORDER BY block, li LIMIT 1", (a.lower(),)).fetchone()
    return r


def balance(cur, a, table="transfers"):
    """Display balance. Float — do NOT use in an identity check (pitfalls #2).

    For "rebuilt balances sum to totalSupply", accumulate the raw wei strings with
    Python int instead; REAL loses precision above 2^53, i.e. above ~9 tokens."""
    a = a.lower()
    q_in = f"SELECT COALESCE(SUM(CAST(val AS REAL)),0) FROM {table} WHERE dst=?"
    q_out = f"SELECT COALESCE(SUM(CAST(val AS REAL)),0) FROM {table} WHERE frm=?"
    return (cur.execute(q_in, (a,)).fetchone()[0] - cur.execute(q_out, (a,)).fetchone()[0]) / WEI


def balance_exact(cur, a, table="transfers"):
    """Exact wei balance via Python int — the one to use in identity checks."""
    a = a.lower()
    i = sum(int(v) for (v,) in cur.execute(f"SELECT val FROM {table} WHERE dst=?", (a,)))
    o = sum(int(v) for (v,) in cur.execute(f"SELECT val FROM {table} WHERE frm=?", (a,)))
    return i - o


if __name__ == "__main__":
    import argparse, json, sqlite3, sys
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser(description="weighted provenance / net-flow / first-funder")
    p.add_argument("--db", required=True)
    p.add_argument("--table", default="transfers")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("trace", help="propagate a balance backward by amount share")
    t.add_argument("address")
    t.add_argument("--terminals", required=True,
                   help="JSON file or inline JSON: {\"0xaddr\": \"label\", ...}")
    t.add_argument("--max-hop", type=int, default=4)
    t.add_argument("--min-share", type=float, default=0.01)

    n = sub.add_parser("netflow", help="net token flow between two addresses")
    n.add_argument("a"); n.add_argument("b")

    f = sub.add_parser("funder", help="who sent this address its first tokens")
    f.add_argument("address")

    b = sub.add_parser("balance", help="exact wei balance from the replayed ledger")
    b.add_argument("address")

    a = p.parse_args()
    cur = sqlite3.connect(a.db).cursor()

    if a.cmd == "trace":
        try:
            terms = json.loads(a.terminals)
        except json.JSONDecodeError:
            terms = json.load(open(a.terminals))
        terms = {k.lower(): v for k, v in terms.items()}
        r = trace(cur, a.address.lower(), terms, a.max_hop, a.min_share, a.table)
        for k, v in sorted(r.items(), key=lambda kv: -kv[1]):
            print(f"  {v*100:6.2f}%  {k}")
        # A large cycle/pool share is the signal that this method does not apply here.
        churn = sum(v for k, v in r.items() if k.startswith("cycle@") or "pool" in k.lower())
        if churn > 0.25:
            print(f"\n  !! {churn*100:.1f}% of provenance dissolved into this address's own")
            print("     churn. Weighted lineage does not apply to an actively trading")
            print("     address — use net-flow against known issuer addresses, the")
            print("     first-funding transfer, or timing evidence instead.")
    elif a.cmd == "netflow":
        print(json.dumps(net_flow(cur, a.a.lower(), a.b.lower(), a.table), indent=1))
    elif a.cmd == "funder":
        print(json.dumps(first_funder(cur, a.address.lower(), a.table), indent=1, default=str))
    elif a.cmd == "balance":
        wei = balance_exact(cur, a.address.lower(), a.table)
        print(f"{wei} wei  ({wei / 10**18:,.6f} @ 18 dec)")
