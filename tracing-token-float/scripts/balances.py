#!/usr/bin/env python3
"""Rebuild balances exactly, and get the DENOMINATOR right.

    python balances.py --db o.db --at-block 50707679 --supply 1e9 \
        --exclude 0xc1b5...:seed:vesting --exclude 0xc866...:team:vesting --top 20
    python balances.py --db a.db --supply 1e9 --reconcile b.db

Pitfall #1 — locked supply in the numerator, total supply in the denominator — is the
most common way this analysis fails, and it fails silently: the percentage still looks
like a percentage. Four things here are built to make it hard to reproduce.

  * `float_denominator()` prints the subtraction line by line and asserts it closes to
    the wei, so the float is never a figure somebody typed.
  * `pct_of_float()` and `pct_of_supply()` are separate functions returning a `Pct` that
    carries its denominator, prints it inline, and REFUSES to be added to a percentage
    of anything else.
  * `top(denominator='float')` drops the excluded addresses from the ranking. A vesting
    contract at 480% of float is pitfall #1 with a rank next to it.
  * `reconcile()` set-differences two balance maps, because L8's "two independent
    totals agree" needs to name the addresses that disagree, not just the delta.

Before any of that, the coverage gate. A balance table rebuilt over a holed database is
the exact artefact this skill exists to prevent, so `rebuild()` runs replay.coverage()
first and refuses. --force overrides it and stamps `coverage_incomplete=1` into meta so
nothing downstream can forget.

Division of labour: this file never touches the chain. `total_supply` is the rebuilt sum
by default, and `replay.py --verify` is what pins that sum to a real `totalSupply()` at
the scan's own upper block. Certify there, denominate here.
"""
import argparse, json, os, sqlite3, sys, time
from decimal import Decimal
from typing import NamedTuple

from replay import coverage

# Line-buffer stdout: a redirected replay of 1.2M rows prints nothing at all until the
# process exits, which is indistinguishable from a hang.
sys.stdout.reconfigure(line_buffering=True)

ZERO = "0x" + "0" * 40

# Every kind means "held, but not in the float". They stay separate because they carry
# opposite risk: a burn is gone forever, a treasury multisig can sell this afternoon.
KINDS = ("vesting", "timelock", "treasury", "unclaimed_distributor", "burn", "bridge_escrow")


class Holder(NamedTuple):
    wei: int          # authoritative, exact
    n_in: int
    n_out: int
    vol_in: int       # wei. The `balances` column is REAL and lossy; this one is not
    vol_out: int
    first_block: int
    last_block: int


class CoverageError(RuntimeError):
    """This database cannot be shown to cover the range it claims. Compute nothing."""


class DenominatorError(RuntimeError):
    """The float subtraction did not close, or an exclusion cannot be trusted."""


# ---------------------------------------------------------------- percentages

class Pct(float):
    """A percentage that carries its denominator, prints it, and refuses to be mixed.

    A bare float cannot tell "% of float" from "% of supply", which is why the two get
    added together in the first place. Formatting a Pct always appends the denominator
    — `f"{p:.2f}"` gives "12.40% of float" — and adding two with different denominators
    raises instead of producing the impressive meaningless number.
    """

    def __new__(cls, v, denom):
        p = super().__new__(cls, v)
        p.denom = denom
        return p

    def __format__(self, spec):
        return f"{float(self):{spec or '.4f'}}% of {self.denom}"

    def __str__(self):
        return format(self, "")

    __repr__ = __str__

    def _same(self, o):
        if isinstance(o, Pct) and o.denom != self.denom:
            raise DenominatorError(f"refusing to combine '% of {self.denom}' with "
                                   f"'% of {o.denom}' — that is pitfall #1")
        return float(o)

    def __add__(self, o):
        return Pct(float(self) + self._same(o), self.denom)

    __radd__ = __add__      # sum() starts at 0, which carries no denominator

    def __sub__(self, o):
        return Pct(float(self) - self._same(o), self.denom)


def pct_of_float(wei, float_wei):
    """Share of the FLOAT. The only denominator a control claim may use."""
    return Pct(100.0 * wei / float_wei, "float")


def pct_of_supply(wei, supply_wei):
    """Share of TOTAL SUPPLY. Includes locked allocations, so never a control claim."""
    return Pct(100.0 * wei / supply_wei, "supply")


def to_wei(x, decimals=18):
    """Decimal, never float: 1e9 tokens is 10**27 wei and float(1e27) is not 10**27."""
    w = Decimal(str(x)) * 10 ** decimals
    if w != w.to_integral_value():
        raise ValueError(f"{x} is not a whole number of wei at {decimals} decimals")
    return int(w)


def tok(wei, decimals=18):
    """Display only. Exact to the wei up to ~2**53 wei; never feed it back into a sum."""
    return wei / 10 ** decimals


# ---------------------------------------------------------------- coverage gate

def _provenance(c):
    """(coverage table, lo, hi, where the bounds came from), with a shim view installed.

    Three databases in this skill's own corpus spell the coverage table three ways:
    ranges_done(lo,hi,n,ts) from replay.py, ranges_done(a,b,n) in o.db, done(lo,hi,n) in
    aiw3.db. A TEMP VIEW shadows the name for unqualified lookups so replay.coverage()
    runs UNMODIFIED — the gate that ships with the skill is the gate that runs, with no
    second copy of it here to drift out of step.
    """
    tbls = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    src = next((t for t in ("ranges_done", "done") if t in tbls), None)
    if not src:
        raise CoverageError(
            "no ranges_done/done table: this database holds no record of which block "
            "ranges a node actually answered. Coverage cannot be established at all, and "
            "a hole made of ordinary peer-to-peer transfers is invisible to every other "
            "check. Re-scan with replay.py.")
    cols = [r[1] for r in c.execute(f"PRAGMA table_info({src})")][:3]
    c.execute(f"CREATE TEMP VIEW IF NOT EXISTS ranges_done AS SELECT {cols[0]} AS lo, "
              f"{cols[1]} AS hi, {cols[2]} AS n FROM main.{src}")

    # Bounds are provenance. Taking them from the covered rows makes the endpoints
    # tautologically covered, so when that is what happened the caller is told.
    for tbl, klo, khi in (("meta", "from_block", "to_block"),
                          ("scan_state", "deploy", "head")):
        if tbl in tbls:
            kv = dict(c.execute(f"SELECT k, v FROM {tbl}"))
            if klo in kv and khi in kv:
                return src, int(kv[klo]), int(kv[khi]), tbl
    lo, hi = c.execute("SELECT MIN(lo), MAX(hi) FROM ranges_done").fetchone()
    return src, lo, hi, f"{src} (bounds DERIVED — the endpoints are unverified)"


def check_coverage(c, at_block=None):
    """replay.coverage() over this database's own bounds. Raises on any gap.

    With at_block the gate only has to hold up to the snapshot: blocks above it are
    never read, so a hole up there cannot reach the numbers.
    """
    src, lo, hi, bsrc = _provenance(c)
    if at_block is not None:
        hi = min(hi, at_block)
    gaps, cov, suspect = coverage(c, lo, hi)
    missing = sum(b - a + 1 for a, b in gaps)
    print(f"  COVERAGE   #{lo:,}-#{hi:,} ({hi - lo + 1:,} blocks) from {bsrc}")
    print(f"    answered {len(list(c.execute('SELECT 1 FROM ranges_done'))):,} windows in "
          f"{len(cov)} contiguous run(s)")
    print(f"    gaps     {len(gaps)} ({missing:,} blocks)  {'OK' if not gaps else 'FAIL'}")
    for a, b in gaps[:10]:
        print(f"      missing #{a:,}-#{b:,}")
    if len(gaps) > 10:
        print(f"      ... and {len(gaps) - 10} more")
    for a, b, n in suspect[:5]:
        print(f"    truncation suspect #{a:,}-#{b:,} returned exactly {n:,} logs")
    if gaps or suspect:
        raise CoverageError(
            f"{len(gaps)} gap(s) covering {missing:,} blocks, {len(suspect)} truncation "
            f"suspect(s). Balances rebuilt over a hole are wrong in a way no later check "
            f"can see: a missing range of ordinary transfers moves the sum of all "
            f"balances by exactly zero. Re-run replay.py against the same --db.")
    return lo, hi


# ---------------------------------------------------------------- the rebuild

def rebuild(db, at_block=None, force=False, progress=200_000):
    """Replay `transfers` into exact integer balances. Returns {addr: Holder}.

    Every wei stays in Python int. CAST(val AS REAL) loses precision above 2**53, which
    a token crosses at ~9 tokens, and the loss is invisible to four significant figures.
    """
    c = sqlite3.connect(db)
    try:
        check_coverage(c, at_block)
    except CoverageError as e:
        if not force:
            raise
        print(f"  !! FORCED over an uncertified database: {e}")
        _stamp(c, {"coverage_incomplete": 1, "coverage_forced_at": int(time.time())})

    q = "SELECT block, frm, dst, val FROM transfers"
    if at_block is not None:
        q += f" WHERE block <= {int(at_block)}"     # a snapshot has to be reproducible
    bal, st, n = {}, {}, 0
    t0 = time.time()
    for blk, frm, dst, val in c.execute(q):
        v = int(val)
        bal[frm] = bal.get(frm, 0) - v
        bal[dst] = bal.get(dst, 0) + v
        for a, out in ((frm, True), (dst, False)):
            r = st.get(a)
            if r is None:
                st[a] = [0, 0, 0, 0, blk, blk]
                r = st[a]
            r[1 if out else 0] += 1
            r[3 if out else 2] += v
            if blk < r[4]:
                r[4] = blk
            if blk > r[5]:
                r[5] = blk
        n += 1
        if n % progress == 0:
            print(f"    {n:,} transfers  {len(bal):,} addresses  {time.time() - t0:.0f}s")
    # The zero address is the mint/burn counterparty, not a holder. Its balance is
    # -totalSupply on a fixed-supply token; leaving it in makes every total nonsense.
    bal.pop(ZERO, None)
    st.pop(ZERO, None)
    out = {a: Holder(bal[a], st[a][0], st[a][1], st[a][2], st[a][3], st[a][4], st[a][5])
           for a in bal}
    pos = [h for h in out.values() if h.wei > 0]
    neg = [a for a, h in out.items() if h.wei < 0]
    total = sum(h.wei for h in out.values())
    print(f"  REBUILT    {n:,} transfers -> {len(out):,} addresses "
          f"({'@#%s' % f'{at_block:,}' if at_block is not None else 'full range'}), "
          f"{time.time() - t0:.0f}s")
    print(f"    holders (>0)   {len(pos):,}")
    print(f"    zero balance   {len(out) - len(pos) - len(neg):,}  (churned through)")
    print(f"    negative       {len(neg)}  "
          f"{'OK' if not neg else 'FAIL - a funding transfer is missing'}")
    print(f"    rebuilt supply {total} wei = {tok(total):,.6f} tokens "
          f"(sum of ALL balances, negatives included)")
    for a in neg[:5]:
        print(f"      {a} {tok(out[a].wei):,.6f}")
    return out


def weis(m):
    """{addr: Holder} or {addr: wei} -> {addr: wei}. Lets reconcile() take either."""
    return {a: (v.wei if isinstance(v, Holder) else int(v)) for a, v in m.items()}


def _stamp(c, kv):
    c.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    c.executemany("INSERT OR REPLACE INTO meta VALUES(?,?)",
                  [(k, str(v)) for k, v in kv.items()])
    c.commit()


def save(db, bal, supply_wei, float_wei=None, decimals=18, pct_denominator="supply",
         at_block=None, force=False):
    """Persist to the `balances` schema already in o.db and aiw3.db.

    `raw` (wei, TEXT) is authoritative. `tokens` and `pct` are display floats and must
    never be summed — pitfall #2. `pct` needs a denominator that the column itself
    cannot carry, so the choice is stamped into meta as `pct_denominator`; a reader who
    does not check it is reading an unlabelled number.
    """
    if pct_denominator not in ("supply", "float"):
        raise DenominatorError(f"pct_denominator must be supply or float, not "
                               f"{pct_denominator!r}")
    den = supply_wei if pct_denominator == "supply" else float_wei
    if den is None:
        raise DenominatorError("pct_denominator='float' but no float was computed — "
                               "pass exclusions, or persist pct of supply")
    neg = [a for a, h in bal.items() if h.wei < 0]
    if neg and not force:
        raise CoverageError(
            f"{len(neg)} negative balance(s): a funding transfer is missing, so these "
            f"rows are wrong and the ones they fund may be too. Refusing to persist. "
            f"Re-scan, or --force and read `negative_balances` in meta.")
    pf = pct_of_supply if pct_denominator == "supply" else pct_of_float
    rows = [(a, str(h.wei), tok(h.wei, decimals), float(pf(h.wei, den)),
             h.n_in, h.n_out, tok(h.vol_in, decimals), tok(h.vol_out, decimals),
             h.first_block, h.last_block)
            for a, h in bal.items() if h.wei > 0]
    c = sqlite3.connect(db)
    c.execute("""CREATE TABLE IF NOT EXISTS balances(
        addr TEXT PRIMARY KEY, raw TEXT, tokens REAL, pct REAL,
        n_in INTEGER, n_out INTEGER, vol_in REAL, vol_out REAL,
        first_block INTEGER, last_block INTEGER)""")
    # A rebuild REPLACES. Rows left over from a higher snapshot would otherwise survive
    # as holders who do not exist at this block.
    c.execute("DELETE FROM balances")
    c.executemany("INSERT INTO balances VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    c.commit()
    _stamp(c, {"snapshot_block": at_block if at_block is not None else "",
               "rebuilt_supply_wei": sum(h.wei for h in bal.values()),
               "total_supply_wei": supply_wei,
               "float_wei": float_wei if float_wei is not None else "",
               "pct_denominator": pct_denominator,
               "negative_balances": len(neg),
               "balances_built_at": int(time.time())})
    print(f"  SAVED      {len(rows):,} rows to balances; pct is % of {pct_denominator} "
          f"(stamped in meta as pct_denominator)"
          + (f"; FORCED over {len(neg)} negative balance(s), stamped as negative_balances"
             if neg else ""))
    return len(rows)


# ---------------------------------------------------------------- the denominator

def float_denominator(total_supply, bal, exclusions, decimals=18, quiet=False):
    """total_supply minus each excluded balance, itemised, = float. Exact in wei.

    exclusions: (address, label, kind) or (address, label, kind, wei). The fourth field
    exists for a DISCLOSED figure that has no address to look up — a lock announced in a
    blog post. Those print marked, and never silently stand in for an on-chain balance:
    if the address is also given, both numbers print and the difference is the finding.

    Refuses rather than returns a plausible number when an exclusion is a typo (an
    address that never appears in the transfer graph), is listed twice (double counting),
    carries an unknown kind, or drives the float negative.
    """
    items, seen, excl = [], set(), 0
    for e in exclusions:
        addr, label, kind = e[0], e[1], e[2]
        disclosed = e[3] if len(e) > 3 else None
        if kind not in KINDS:
            raise DenominatorError(f"unknown exclusion kind {kind!r} for {label}; "
                                   f"expected one of {KINDS}")
        key = (addr or label).lower()
        if key in seen:
            raise DenominatorError(f"{key} excluded twice — that is double counting, and "
                                   f"the float would come out too small")
        seen.add(key)
        chain = bal[addr.lower()].wei if addr and addr.lower() in bal else None
        if addr and chain is None:
            raise DenominatorError(
                f"{addr} ({label}) never appears in this database's transfer graph. It is "
                f"a typo, the wrong chain, or a hole — not a zero balance. Subtracting 0 "
                f"here would quietly inflate the float.")
        if disclosed is None and chain is None:
            raise DenominatorError(f"exclusion {label!r} has neither an address nor a "
                                   f"disclosed amount")
        wei = disclosed if disclosed is not None else chain
        items.append(dict(addr=addr, label=label, kind=kind, wei=wei, chain_wei=chain,
                          disclosed=disclosed is not None))
        excl += wei
    float_wei = total_supply - excl
    if float_wei < 0:
        raise DenominatorError(f"exclusions ({excl} wei) exceed total supply "
                               f"({total_supply} wei) — an address is counted twice or "
                               f"the supply is wrong")
    if total_supply - excl != float_wei:                       # the arithmetic, asserted
        raise DenominatorError("float subtraction did not close")

    # Independent second path: add up every balance that was NOT excluded. A disclosed
    # figure removes no address, so it must reappear here — anything left over after
    # subtracting the disclosed total is an unexplained residual, i.e. an address that is
    # tagged wrongly. This is L8's two-method agreement in miniature.
    ex_addrs = {i["addr"].lower() for i in items if i["addr"]}
    kept = sum(h.wei for a, h in bal.items() if a not in ex_addrs)
    disclosed_only = sum(i["wei"] for i in items if not i["addr"])
    residual = kept - disclosed_only - float_wei

    # A single un-excluded address holding more than the WHOLE float means the exclusion
    # set does not cover what the float claims is locked. The classic shape is a disclosed
    # lock with no address: it removes nothing from any ranking, so the very next thing
    # printed is a holder at "133% of float".
    over = sorted(((h.wei, a) for a, h in bal.items()
                   if a not in ex_addrs and h.wei > float_wei), reverse=True)

    if not quiet:
        print("\n  FLOAT DENOMINATOR")
        print(f"    total supply                          {tok(total_supply, decimals):>22,.6f}"
              f"   {total_supply} wei")
        for i in items:
            mark = "DISCLOSED" if i["disclosed"] else "         "
            # Pad the LABELLED string, not the number inside it: a column of bare
            # percentages aligned under a distant header is how the denominator is lost.
            share = f"{pct_of_supply(i['wei'], total_supply):.4f}"
            print(f"  -   {i['kind']:<21} {i['label']:<20} {tok(i['wei'], decimals):>18,.6f}"
                  f"   {share:>20}  {mark} {i['addr'] or '(no address)'}")
            if i["disclosed"] and i["chain_wei"] is not None and i["chain_wei"] != i["wei"]:
                d = i["chain_wei"] - i["wei"]
                print(f"      ^ on-chain balance is {tok(i['chain_wei'], decimals):,.6f} — "
                      f"disclosure and chain disagree by {tok(d, decimals):+,.6f} tokens")
        print(f"  = float                                 {tok(float_wei, decimals):>22,.6f}"
              f"   {float_wei} wei")
        print(f"    float is {pct_of_supply(float_wei, total_supply)}; "
              f"{tok(excl, decimals):,.6f} ({pct_of_supply(excl, total_supply)}) excluded")
        print(f"    closure     total - excluded - float = "
              f"{total_supply - excl - float_wei} wei  (exact)")
        print(f"    cross-check sum of every non-excluded balance "
              f"{tok(kept, decimals):>22,.6f}")
        print(f"                less disclosed-only exclusions   "
              f"{tok(disclosed_only, decimals):>22,.6f}   (no address to verify)")
        print(f"                residual against the float       {residual} wei  "
              f"{'exact — the two paths agree' if not residual else 'FAIL — an address is tagged wrongly'}")
        if over:
            print(f"    !! {len(over)} un-excluded address(es) hold MORE than the entire "
                  f"float. The exclusion set does not cover what this float says is locked,")
            print(f"       so every share below is denominated against a float those "
                  f"tokens are not in. Name them by address instead of by disclosure:")
            for w, addr in over[:3]:
                print(f"       {addr}  {tok(w, decimals):,.6f}  "
                      f"{pct_of_float(w, float_wei):.4f}")
    return dict(total_supply_wei=total_supply, float_wei=float_wei, excluded_wei=excl,
                items=items, crosscheck_wei=kept, disclosed_only_wei=disclosed_only,
                residual_wei=residual, over_float=[a for _, a in over])


# ---------------------------------------------------------------- reporting

def top(bal, n=20, denominator="float", float_wei=None, supply_wei=None, exclude=(),
        labels=None, decimals=18, quiet=False):
    """Ranked holders, denominator named in the header, running cumulative alongside.

    Excluded addresses are REMOVED when ranking by float. A vesting contract holding 4.8x
    the float is not the top of the float; it is pitfall #1 with a rank next to it.
    """
    if denominator not in ("float", "supply"):
        raise DenominatorError(f"denominator must be float or supply, not {denominator!r}")
    den = float_wei if denominator == "float" else supply_wei
    if den is None:
        raise DenominatorError(f"ranking by {denominator} needs the {denominator} in wei")
    pf = pct_of_float if denominator == "float" else pct_of_supply
    drop = {a.lower() for a in exclude} if denominator == "float" else set()
    labels = labels or {}
    rows, cum = [], 0
    for a, h in sorted(bal.items(), key=lambda kv: -kv[1].wei):
        if a in drop or h.wei <= 0:
            continue
        cum += h.wei
        rows.append(dict(rank=len(rows) + 1, addr=a, wei=h.wei, tokens=tok(h.wei, decimals),
                         pct=pf(h.wei, den), cum_pct=pf(cum, den),
                         n_in=h.n_in, n_out=h.n_out, label=labels.get(a, "")))
        if len(rows) >= n:
            break
    if not quiet:
        print(f"\n  TOP {len(rows)} HOLDERS — every percentage below is OF {denominator.upper()} "
              f"({tok(den, decimals):,.6f} tokens)")
        if drop:
            print(f"    {len(drop)} excluded address(es) removed from this ranking; they are "
                  f"not in the float and cannot hold a share of it")
        print(f"    {'#':>3}  {'address':<42} {'tokens':>18}  {'share':>19}  "
              f"{'cumulative':>19}  in/out")
        for r in rows:
            # Pad the labelled string, never the bare number — see float_denominator.
            share, cum = f"{r['pct']:.4f}", f"{r['cum_pct']:.4f}"
            print(f"    {r['rank']:>3}  {r['addr']:<42} {r['tokens']:>18,.4f}  "
                  f"{share:>19}  {cum:>19}  {r['n_in']}/{r['n_out']} {r['label']}"
                  + ("   !! more than the whole float — not in it" if r["pct"] > 100 else ""))
    return rows


def reconcile(map_a, map_b, name_a="A", name_b="B", decimals=18, show=10, quiet=False):
    """Set-difference two balance maps and say WHICH addresses disagree.

    L8 wants two independent totals to agree. "They differ by 3.2 tokens" is not an
    answer to that — the address the difference lives on is, because it is either an
    in-flight cross-chain transfer you can name or an address one method mis-tagged.
    """
    a, b = weis(map_a), weis(map_b)
    only_a = {k: v for k, v in a.items() if k not in b and v}
    only_b = {k: v for k, v in b.items() if k not in a and v}
    differ = [(k, a[k], b[k]) for k in a.keys() & b.keys() if a[k] != b[k]]
    differ.sort(key=lambda r: -abs(r[1] - r[2]))
    ta, tb = sum(a.values()), sum(b.values())
    if not quiet:
        print(f"\n  RECONCILE  {name_a} vs {name_b}")
        print(f"    addresses       {len(a):,} / {len(b):,}   "
              f"({len(only_a):,} only in {name_a}, {len(only_b):,} only in {name_b}, "
              f"{len(differ):,} present in both but differing)")
        print(f"    total           {tok(ta, decimals):,.6f} / {tok(tb, decimals):,.6f}")
        print(f"    difference      {ta - tb} wei = {tok(ta - tb, decimals):+,.6f} tokens"
              f"  {'(totals match)' if ta == tb else '(name every wei of this or an address is mis-tagged)'}")
        if ta == tb and differ:
            # Two maps whose totals agree to the wei can still disagree on hundreds of
            # addresses: every transfer moves the same amount out of one and into another,
            # so a whole missing window nets to zero. A matching total is not agreement.
            print(f"    !! the totals match to the wei and {len(differ):,} addresses still "
                  f"disagree — a transfer conserves the sum, so a matching total proves "
                  f"nothing about the rows")
        for k, va, vb in differ[:show]:
            print(f"      {k}  {tok(va, decimals):>18,.6f} vs {tok(vb, decimals):>18,.6f}"
                  f"   {tok(va - vb, decimals):+,.6f}")
        for k, v in sorted(only_a.items(), key=lambda kv: -abs(kv[1]))[:show]:
            print(f"      only in {name_a}: {k}  {tok(v, decimals):,.6f}")
        for k, v in sorted(only_b.items(), key=lambda kv: -abs(kv[1]))[:show]:
            print(f"      only in {name_b}: {k}  {tok(v, decimals):,.6f}")
    return dict(only_a=only_a, only_b=only_b, differ=differ, total_a=ta, total_b=tb,
                delta_wei=ta - tb)


# ---------------------------------------------------------------- CLI

def _exclusion(s, decimals):
    """addr:label:kind  or  label:kind:amount for a disclosed lock with no address."""
    parts = s.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"{s!r}: expected addr:label:kind (or label:kind:amount for a disclosed "
            f"figure). Colons are the separator, so labels may not contain one.")
    if parts[0].startswith("0x"):
        return (parts[0].lower(), parts[1], parts[2])
    return (None, parts[0], parts[1], to_wei(parts[2], decimals))


def main():
    p = argparse.ArgumentParser(description="exact balance rebuild + the float denominator")
    p.add_argument("--db", required=True)
    p.add_argument("--at-block", type=int, help="snapshot block; rows above it are ignored")
    p.add_argument("--supply", help="total supply in TOKEN units; defaults to the rebuilt "
                                    "sum, and disagreeing with it is a hard error")
    p.add_argument("--decimals", type=int, default=18)
    p.add_argument("--exclude", action="append", default=[], metavar="ADDR:LABEL:KIND",
                   help=f"not in the float. KIND is one of {','.join(KINDS)}. Use "
                        f"LABEL:KIND:AMOUNT for a disclosed lock with no address.")
    p.add_argument("--top", type=int, default=0)
    p.add_argument("--denominator", choices=("float", "supply"), default="float")
    p.add_argument("--pct-of", choices=("supply", "float"), default="supply",
                   help="denominator for the persisted `pct` column (stamped in meta)")
    p.add_argument("--show", action="append", default=[], metavar="ADDR",
                   help="print this address's share of float and of supply side by side")
    p.add_argument("--position", action="append", default=[], metavar="TOKENS",
                   help="same, for an attributed total that spans several addresses")
    p.add_argument("--reconcile", metavar="OTHER.db",
                   help="rebuild a second database and set-difference the two maps")
    p.add_argument("--no-persist", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="rebuild over an uncertified database; stamps coverage_incomplete=1")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    print(f"\n{a.db}" + (f"  @#{a.at_block:,}" if a.at_block else ""))
    bal = rebuild(a.db, a.at_block, a.force)
    rebuilt = sum(h.wei for h in bal.values())
    supply = to_wei(a.supply, a.decimals) if a.supply else rebuilt
    if supply != rebuilt and not a.force:
        raise SystemExit(
            f"\nREFUSED: --supply is {supply} wei but the rebuilt balances sum to "
            f"{rebuilt} wei (difference {supply - rebuilt}). Denominating a float on a "
            f"supply the data does not support is how the headline percentage goes wrong "
            f"while looking fine. Certify with `replay.py --verify --rpc <chain>` first.")
    print(f"    supply         {supply} wei  "
          f"{'(matches the rebuilt sum exactly)' if supply == rebuilt else '(FORCED, differs)'}")

    out = dict(db=a.db, at_block=a.at_block, addresses=len(bal),
               holders=sum(1 for h in bal.values() if h.wei > 0),
               rebuilt_supply_wei=rebuilt, total_supply_wei=supply)
    fl = None
    if a.exclude:
        ex = [_exclusion(s, a.decimals) for s in a.exclude]
        fl = float_denominator(supply, bal, ex, a.decimals)
        out["float"] = fl
    if not a.no_persist:
        save(a.db, bal, supply, fl["float_wei"] if fl else None, a.decimals, a.pct_of,
             a.at_block, a.force)
    if a.top:
        out["top"] = top(bal, a.top, a.denominator, fl["float_wei"] if fl else None, supply,
                         exclude=[i["addr"] for i in fl["items"] if i["addr"]] if fl else [],
                         decimals=a.decimals)
    if a.show or a.position:
        print(f"\n  THE MIXED-DENOMINATOR TRAP, SIDE BY SIDE")
        out["show"] = []
        for s in a.show:
            if s.lower() not in bal:
                raise SystemExit(f"{s} never appears in this database")
        for name, wei in ([(s.lower(), bal[s.lower()].wei) for s in a.show] +
                          [(f"position of {p}", to_wei(p, a.decimals)) for p in a.position]):
            pf = pct_of_float(wei, fl["float_wei"]) if fl else None
            ps = pct_of_supply(wei, supply)
            print(f"    {name}  {tok(wei, a.decimals):,.6f} tokens")
            print(f"      {pf if pf else 'no float computed — pass --exclude'}")
            print(f"      {ps}")
            if pf:
                print(f"      the same tokens, {float(pf) / float(ps):.4f}x larger against "
                      f"the float — the two lines above differ by nothing but a divisor")
            out["show"].append(dict(who=name, wei=wei, of_float=str(pf), of_supply=str(ps)))
    if a.reconcile:
        print(f"\n{a.reconcile}")
        other = rebuild(a.reconcile, a.at_block, a.force)
        out["reconcile"] = reconcile(bal, other, os.path.basename(a.db),
                                     os.path.basename(a.reconcile), a.decimals)
    if a.json:
        print("\n" + json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    # A refusal is the intended outcome, not a crash: print the reason and exit non-zero
    # so a wrapper script stops, without a traceback that reads like a bug in the tool.
    try:
        main()
    except (CoverageError, DenominatorError) as e:
        raise SystemExit(f"\nREFUSED: {e}")
