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
    Returns {label: share} summing to ~1.0.

    A cycle is a node appearing in its *own* ancestry, not a node reached twice.
    Two funding paths converging on one exchange is the normal shape of a token's
    history; a global `seen` set calls that a cycle and books real issuer lineage
    under `cycle@…`, which understates attribution by however much converged.
    So the frontier is keyed by (node, ancestors) and only a genuine self-loop is
    charged to `cycle@`. Branch count stays bounded by `min_share` pruning.
    """
    agg = collections.Counter()
    terminals = {k.lower(): v for k, v in terminals.items()}
    t0 = target.lower()
    frontier = {(t0, frozenset()): 1.0}
    for hop in range(max_hop):
        nxt = collections.Counter()
        for (node, anc), w in frontier.items():
            if w < min_share:
                agg["<diluted, not traced>"] += w
                continue
            if hop and node in terminals:
                agg[terminals[node]] += w
                continue
            if node in anc:                       # node is its own ancestor: real churn
                agg[f"cycle@{node[:10]}…"] += w
                continue
            rows = cur.execute(
                f"SELECT frm, SUM(CAST(val AS REAL)) FROM {table} WHERE dst=? GROUP BY frm",
                (node,)).fetchall()
            tot = sum(r[1] for r in rows)
            if not tot:
                agg[f"no inflow@{node[:10]}…"] += w
                continue
            anc2 = anc | {node}
            for frm, v in rows:
                nxt[(frm, anc2)] += w * (v / tot)
        frontier = dict(nxt)
        if not frontier:
            break
    for (node, _anc), w in frontier.items():
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


def closure(cur, roots, terminals, thresh=0.95, max_hop=12, table="transfers"):
    """Forward issuer-lineage set: an address joins when >= `thresh` of its non-zero
    inflow came from the set, and it is not a terminal (venue, custodian, router).
    Iterated to a fixpoint. Returns (members, hop_of, inflow, outflow).

    The complement of trace(): trace asks "where did THIS balance come from", closure
    asks "where did the ISSUER's tokens go, and how much of them still sits still".
    It is a SIEVE (pitfall #19). It sweeps airdrop recipients in at hop two — thousands
    of addresses that are lineage-traced and not issuer-controlled — so read members by
    balance, and never publish the member count as "issuer wallets".
    """
    roots = {r.lower() for r in roots}
    term = {t.lower() for t in terminals}
    inflow = collections.defaultdict(collections.Counter)
    for f, d, v in cur.execute(f"SELECT frm, dst, SUM(CAST(val AS REAL)) FROM {table} "
                               f"WHERE CAST(val AS REAL) > 0 GROUP BY frm, dst"):
        inflow[d][f] += v / WEI
    outflow = collections.defaultdict(collections.Counter)
    for d, c in inflow.items():
        for f, v in c.items():
            outflow[f][d] += v
    zero = "0x" + "0" * 40
    S, hop, frontier = set(roots), {r: 0 for r in roots}, set(roots)
    for h in range(1, max_hop + 1):
        cand = set().union(*(outflow[a].keys() for a in frontier)) - S - term - {zero}
        new = set()
        for d in cand:
            tot = sum(inflow[d].values())
            if tot and sum(v for f, v in inflow[d].items() if f in S) / tot >= thresh:
                new.add(d)
        if not new:
            break
        for d in new:
            hop[d] = h
        S |= new
        frontier = new
    return S, hop, inflow, outflow


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

    c = sub.add_parser("closure", help="forward issuer-lineage set and where it sent tokens")
    c.add_argument("--roots", required=True, help="comma-separated issuer addresses")
    c.add_argument("--terminals", required=True,
                   help="JSON {addr: class}: venues, custodians, routers — never absorbed")
    c.add_argument("--thresh", type=float, default=0.95)
    c.add_argument("--min-balance", type=float, default=100_000)

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
    elif a.cmd == "closure":
        try:
            terms = json.loads(a.terminals)
        except json.JSONDecodeError:
            terms = json.load(open(a.terminals))
        terms = {k.lower(): v for k, v in terms.items()}
        S, hop, inflow, outflow = closure(cur, a.roots.split(","), terms, a.thresh,
                                          table=a.table)
        bal = {}
        for d, cc in inflow.items():
            bal[d] = bal.get(d, 0) + sum(cc.values())
        for f, cc in outflow.items():
            bal[f] = bal.get(f, 0) - sum(cc.values())
        held = sum(bal.get(x, 0) for x in S)
        print(f"  closure (>= {a.thresh:.0%} of inflow from the set): {len(S):,} addresses, "
              f"holding {held:,.0f} now")
        ext = collections.Counter()
        for x in S:
            for d, v in outflow[x].items():
                if d not in S:
                    ext[terms.get(d, "other")] += v
        print("  sent outside the set, by destination class:")
        for k, v in ext.most_common():
            print(f"     {k:<14} {v:>18,.0f}")
        print(f"  members holding >= {a.min_balance:,.0f}:")
        for x in sorted(S, key=lambda y: -bal.get(y, 0)):
            if bal.get(x, 0) >= a.min_balance:
                print(f"     hop{hop[x]}  {x}  {bal[x]:>16,.0f}")
    elif a.cmd == "netflow":
        print(json.dumps(net_flow(cur, a.a.lower(), a.b.lower(), a.table), indent=1))
    elif a.cmd == "funder":
        print(json.dumps(first_funder(cur, a.address.lower(), a.table), indent=1, default=str))
    elif a.cmd == "balance":
        wei = balance_exact(cur, a.address.lower(), a.table)
        print(f"{wei} wei  ({wei / 10**18:,.6f} @ 18 dec)")
