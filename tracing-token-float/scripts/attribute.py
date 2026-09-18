#!/usr/bin/env python3
"""L2 attribution: the tier table, and the gate that makes it close onto the float.

    python attribute.py --tiers audit.json                   # the report
    python attribute.py --tiers audit.json --out run.json    # + a re-runnable record
    python attribute.py --tiers audit.json --diff run.json   # what moved since run.json

This is the skill's deliverable, so it is the file that has to refuse hardest.

Three refusals. No assignment without an evidence string — a claim a reviewer cannot
reject on its own is not a claim, it is an assertion with a number attached. No
denominator this file did not watch `balances.float_denominator()` derive from
totalSupply minus a named exclusion list — pitfall #1 is invisible in the output once
made, so it has to be impossible to make here. And no point estimate: the headline is
a range, because a single decimal invites the issuer to rebut one address and dismiss
the whole analysis.

The gate is close(): every tier plus the unattributed remainder equals the float
EXACTLY, in wei, and no address is counted twice — not in two tiers, not once directly
and once inside a cluster, and not both as a whole balance and as a carve-out of that
same balance. A tier table that does not close is not a weaker answer to the question.
It is an answer to a different question about a different set of tokens.

Division of labour: replay.py certifies the database, balances.py rebuilds the balances
and derives the float, this file attributes it. Nothing here touches the chain.
"""
import argparse, json, os, sys
from balances import (CoverageError, DenominatorError, float_denominator, pct_of_float,
                      rebuild, to_wei, tok, weis)

# Line-buffer stdout: a rebuild of 1.2M transfers prints nothing at all until the process
# exits otherwise, and a silent script is indistinguishable from a hung one.
sys.stdout.reconfigure(line_buffering=True)

TIERS = {"A": "provable ownership",
         "B": "lineage-traced",
         "C": "issuer-funded liquidity",
         "D": "assumed",
         "M": "market makers"}

# The headline range. D is an assumption and M is unresolvable on chain, so neither may
# enter it: publishing D as fact is how analyses get discredited, and forcing M to either
# side destroys the number. Both get their own line BELOW the range instead.
FLOOR, CEILING = ("A",), ("A", "B", "C")

# Two different questions with opposite implications. Float that was never really
# distributed is a disclosure problem; tokens bought back after listing are ordinary
# buying. Merging them is indefensible, so every claim declares which it is and the
# report prints them on separate lines that no formatting can run together.
SOURCES = {"never-distributed": "never left issuer control",
           "re-accumulated": "bought back from the market after listing",
           "unresolved": "origin not established on chain"}


class DoesNotClose(RuntimeError):
    """Tiers plus remainder != float, or an address was counted twice. Publish nothing."""


class Claim:
    """One reviewable assertion: these tokens, this tier, this evidence, this id.

    `full` addresses contribute their entire balance. `part` carves a stated amount out
    of an address whose balance is shared — an issuer LP position inside a pool that
    also holds third-party liquidity (pitfall #4: the pool's ERC-20 balance is never the
    issuer's position). The two are tracked separately because the double-count test is
    different for each; see Attribution.close().
    """

    def __init__(self, cid, tier, label, evidence, source, full=(), part=()):
        if tier not in TIERS:
            raise ValueError(f"{cid}: tier {tier!r} is not one of {sorted(TIERS)}")
        if not str(evidence).strip():
            raise ValueError(f"{cid} ({label}): evidence is required. An unevidenced claim "
                             f"cannot be accepted or rejected on its own, which is the "
                             f"entire discipline this tier table exists to support.")
        if source not in SOURCES:
            raise ValueError(f"{cid} ({label}): source must be one of {sorted(SOURCES)}, "
                             f"not {source!r} — 'never distributed' and 're-accumulated "
                             f"after listing' have opposite implications and never merge")
        self.cid, self.tier, self.label = cid, tier, label
        self.evidence, self.source = evidence, source
        self.full = tuple(dict.fromkeys(a.lower() for a in full))
        self.part = tuple((a.lower(), int(w)) for a, w in part)
        self.wei = 0                      # set by close() from the balance table
        self.retracted = None

    def addrs(self):
        return set(self.full) | {a for a, _ in self.part}

    def n(self):
        return len(self.full) + len(self.part)


class Attribution:
    """A certified balance table, a derived float denominator, and the tiers on them.

    Constructed from `balances.rebuild()` output and `balances.float_denominator()`
    output — never from a float somebody typed. rebuild() runs the coverage gate and
    raises CoverageError, so a database whose ranges nobody answered cannot reach this
    class at all.
    """

    def __init__(self, bal, den, snapshot=None, decimals=18):
        self.bal = weis(bal)
        self.den, self.dec, self.snapshot = den, decimals, snapshot
        self.float_wei = den["float_wei"]
        self.total_supply = den["total_supply_wei"]
        self.exclude = {i["addr"].lower(): f"{i['kind']}: {i['label']}"
                        for i in den["items"] if i["addr"]}
        self.claims, self.retractions, self.methods = [], [], None
        if den["disclosed_only_wei"]:
            # A lock announced in a blog post removes no address from the table, so those
            # tokens are still sitting in the float universe under some address nobody
            # has identified. Closing address-level attribution onto that float would be
            # closing onto a denominator that is short by exactly that much.
            raise DenominatorError(
                f"{tok(den['disclosed_only_wei'], decimals):,.6f} tokens are excluded by "
                f"DISCLOSURE with no address: "
                f"{[i['label'] for i in den['items'] if not i['addr']]}. Attribution needs "
                f"every excluded token to have an address, because the tiers must partition "
                f"the remaining addresses exactly. Find the addresses, or attribute against "
                f"a float that does not subtract them.")

    @classmethod
    def from_db(cls, db, exclusions, supply=None, at_block=None, decimals=18,
                snapshot=None, force=False):
        bal = rebuild(db, at_block, force)
        rebuilt = sum(h.wei for h in bal.values())
        ts = to_wei(supply, decimals) if supply is not None else rebuilt
        if ts != rebuilt and not force:
            raise DenominatorError(
                f"stated supply {ts} wei != rebuilt {rebuilt} wei (difference "
                f"{ts - rebuilt}). Attributing a float derived from a supply the data "
                f"does not support is how the headline goes wrong while looking fine.")
        return cls(bal, float_denominator(ts, bal, exclusions, decimals), snapshot, decimals)

    @property
    def universe(self):
        """The addresses that are actually in the float. The exclusion list is the ONLY
        thing standing between totalSupply and this, which is what makes the denominator
        auditable instead of asserted."""
        return {a: v for a, v in self.bal.items() if a not in self.exclude}

    # -- assignment --------------------------------------------------------------
    def assign(self, addr, tier, evidence, source, label=None, cid=None):
        """The whole balance of one address."""
        return self._add(Claim(cid or self._cid(tier), tier, label or addr, evidence,
                               source, full=[addr]))

    def assign_cluster(self, addrs, tier, evidence, source, label, cid=None):
        """The whole balance of every address in a cluster, as one reviewable claim."""
        return self._add(Claim(cid or self._cid(tier), tier, label, evidence, source,
                               full=addrs))

    def assign_part(self, addr, amount, tier, evidence, source, label, cid=None):
        """A stated amount carved out of one shared address — an issuer LP position
        inside a pool. The amount comes from position math, never from the balance."""
        return self._add(Claim(cid or self._cid(tier), tier, label, evidence, source,
                               part=[(addr, to_wei(amount, self.dec))]))

    def retract(self, cid, why):
        """Withdraw a claim and keep it in the output. An analysis that shows what it got
        wrong is more credible, not less — and a retraction that vanishes from the
        deliverable is indistinguishable from never having made the claim."""
        for c in self.claims:
            if c.cid == cid:
                c.retracted = why
                self.retractions.append({"id": cid, "was": c.label, "why": why,
                                         "tier": c.tier})
                return c
        raise KeyError(f"no claim {cid} to retract")

    def _add(self, c):
        if any(x.cid == c.cid for x in self.claims):
            raise ValueError(f"duplicate claim id {c.cid} — ids are how a reviewer names "
                             f"the one claim they reject")
        self.claims.append(c)
        return c

    def _cid(self, tier):
        return f"{tier}{sum(1 for c in self.claims if c.tier == tier) + 1}"

    def live(self):
        return [c for c in self.claims if not c.retracted]

    def remainders(self):
        """{addr: wei} left unattributed, carve-outs already removed from their host."""
        live = self.live()
        full = {a for c in live for a in c.full}
        carve = {}
        for c in live:
            for a, w in c.part:
                carve[a] = carve.get(a, 0) + w
        return {a: v - carve.get(a, 0) for a, v in self.universe.items() if a not in full}

    # -- the gate ----------------------------------------------------------------
    def close(self, out=sys.stdout):
        """Tiers + remainder == float, exactly, in wei. Raises DoesNotClose otherwise.

        Failures, in the order they are worth knowing about:
          DOUBLE COUNT   one address in two claims, or claimed whole and also carved
          OVER-CLAIM     carve-outs on an address exceed its balance
          CONTRADICTION  a claim on an address the denominator excluded from the float
          NOT IN TABLE   a claim on an address the certified table does not contain
          DENOMINATOR    totalSupply - excluded != float, or the cross-check disagreed
          CLOSURE        the universe and the stated float are different token sets
        """
        p = lambda s: print(s, file=out)
        uni, live, bad = self.universe, self.live(), []

        # One address in two claims covers both "assigned to two tiers" and "counted
        # directly and again inside a cluster": a cluster is a claim over many addresses,
        # so the two defects are the same defect and one test finds both.
        seen = {}
        for c in live:
            for a in c.full:
                seen.setdefault(a, []).append(c)
        for a, cs in sorted(((a, cs) for a, cs in seen.items() if len(cs) > 1),
                            key=lambda kv: -uni.get(kv[0], 0)):
            how = ("in " + " and ".join(sorted({c.tier for c in cs}))
                   if len({c.tier for c in cs}) > 1 else f"twice in tier {cs[0].tier}")
            bad.append(f"DOUBLE COUNT  {a}  {tok(uni.get(a, 0), self.dec):,.6f} counted {how}"
                       f" -> " + " + ".join(f"{c.cid} {c.label}" for c in cs))

        carve = {}
        for c in live:
            for a, w in c.part:
                carve.setdefault(a, []).append((c, w))
        for a, items in carve.items():
            if a in seen:
                bad.append(f"DOUBLE COUNT  {a}  carved by "
                           f"{' + '.join(c.cid for c, _ in items)} AND claimed whole by "
                           f"{' + '.join(c.cid for c in seen[a])}")
            s = sum(w for _, w in items)
            if s > uni.get(a, 0):
                bad.append(f"OVER-CLAIM    {a}  carve-outs {tok(s, self.dec):,.6f} exceed the "
                           f"balance {tok(uni.get(a, 0), self.dec):,.6f} by "
                           f"{tok(s - uni.get(a, 0), self.dec):,.6f}")

        for c in live:
            for a in c.addrs():
                if a in self.exclude:
                    bad.append(f"CONTRADICTION {a}  {c.cid} claims it as float, but the "
                               f"denominator excluded it as {self.exclude[a]}")
                elif a not in uni:
                    bad.append(f"NOT IN TABLE  {a}  {c.cid} claims an address the certified "
                               f"balance table does not contain")
            c.wei = sum(uni.get(a, 0) for a in c.full) + sum(w for _, w in c.part)

        # The denominator, re-asserted here rather than taken on trust. float_denominator
        # already printed the subtraction; this is the same arithmetic checked by the
        # consumer, because every percentage below rests on it.
        d = self.total_supply - self.den["excluded_wei"] - self.float_wei
        if d:
            bad.append(f"DENOMINATOR   totalSupply - excluded - float = {d} wei")
        if self.den["residual_wei"]:
            bad.append(f"DENOMINATOR   the sum of every non-excluded balance differs from the "
                       f"float by {self.den['residual_wei']} wei — an address is tagged wrongly")

        attributed = sum(c.wei for c in live)
        unattributed = sum(self.remainders().values())
        gap = attributed + unattributed - self.float_wei

        p("\n  CLOSURE")
        p(f"    float (denominator)   {self.float_wei:>32} wei  {tok(self.float_wei, self.dec):>20,.6f}")
        p(f"    attributed            {attributed:>32} wei  {tok(attributed, self.dec):>20,.6f}")
        p(f"    unattributed          {unattributed:>32} wei  {tok(unattributed, self.dec):>20,.6f}")
        p(f"    tiers + remainder - float   {gap} wei   "
          f"{'OK - exact' if gap == 0 else 'FAIL'}")
        if gap:
            bad.append(f"CLOSURE       tiers + remainder - float = {gap} wei "
                       f"({tok(gap, self.dec):+,.6f} tokens): the balance table and the "
                       f"stated float describe different sets of tokens")
        if unattributed < 0:
            bad.append(f"OVER-CLAIM    the claims exceed the whole float universe by "
                       f"{tok(-unattributed, self.dec):,.6f} tokens")
        if bad:
            for b in bad:
                p(f"    {b}")
            p("    five largest unattributed addresses:")
            for a, v in sorted(self.remainders().items(), key=lambda kv: -kv[1])[:5]:
                p(f"      {a}  {tok(v, self.dec):>20,.6f}  "
                  f"{pct_of_float(v, self.float_wei):.4f}")
            raise DoesNotClose("; ".join(sorted({b.split("  ")[0] for b in bad})))
        p(f"    {len(live)} claim(s) over {len({a for c in live for a in c.addrs()}):,} "
          f"address(es); no address counted twice; tiers partition the float exactly")
        return {"attributed": attributed, "unattributed": unattributed}

    # -- L8 ----------------------------------------------------------------------
    def two_methods(self, lineage_total, balance_total, residual=(), out=sys.stdout):
        """The two independent totals must agree, and any residual must be NAMED.

        'Close enough' is not a result here. A residual is acceptable when it resolves to
        a specific thing — tokens in flight across a bridge, a transfer sent to the token
        contract itself — and the named amounts must sum to the difference to the wei. An
        unnamed residual means an address is mis-tagged: a finding, not a rounding note.
        """
        p = lambda s: print(s, file=out)
        lt, bt = to_wei(lineage_total, self.dec), to_wei(balance_total, self.dec)
        named = [(n, to_wei(w, self.dec)) for n, w in residual]
        d = lt - bt
        p("\n  TWO METHODS (L8)")
        p(f"    lineage   issuer pushed out, minus what came back   {tok(lt, self.dec):>20,.6f}")
        p(f"    balance   supply minus every issuer-held address    {tok(bt, self.dec):>20,.6f}")
        p(f"    difference                                          {tok(d, self.dec):>20,.6f}")
        for n, w in named:
            p(f"      named   {tok(w, self.dec):>18,.6f}   {n}")
        left = d - sum(w for _, w in named)
        if left:
            p(f"    UNNAMED RESIDUAL {left} wei ({tok(left, self.dec):+,.6f} tokens).")
            p(f"    A gap you cannot name to a transaction means an address is mis-tagged.")
            p(f"    Find it before publishing; do not widen a tolerance around it.")
            raise DoesNotClose(f"unnamed residual {left} wei between the two methods")
        p("    exact agreement" if not d else
          "    every wei of the difference is named to a specific cause")
        self.methods = {"lineage_wei": lt, "balance_wei": bt,
                        "residual": [[n, str(w)] for n, w in named]}
        return self.methods

    # -- output ------------------------------------------------------------------
    def report(self, out=sys.stdout):
        """Output built so that no single line can be lifted out of it and be wrong."""
        p = lambda s: print(s, file=out)
        dec, F, live = self.dec, self.float_wei, self.live()
        fl = f"{tok(F, dec):,.0f}"
        pc = lambda w: f"{pct_of_float(w, F):.4f}"      # always prints "% of float"

        p("\n" + "=" * 100)
        p(f"ATTRIBUTION   {self.snapshot or '(snapshot not stated)'}")
        p(f"  table       {len(self.bal):,} addresses, {len(self.universe):,} of them in the float")

        p(f"\n  DENOMINATOR   fix it first: a mixed denominator makes every % below meaningless")
        p(f"    totalSupply {tok(self.total_supply, dec):>22,.6f}")
        for a, why in sorted(self.exclude.items(), key=lambda kv: -self.bal[kv[0]]):
            p(f"    - excluded  {tok(self.bal[a], dec):>22,.6f}   {a}  {why}")
        p(f"    = FLOAT     {tok(F, dec):>22,.6f}   every percentage below divides by THIS")

        p(f"\n  TIERS   claim ids are how a reviewer rejects one row without touching the rest")
        p(f"    {'id':<5}{'tier':<27}{'addrs':>7}{'tokens':>21}   {'share':<20} claim")
        for t in "ABCDM":
            cs = sorted((c for c in live if c.tier == t), key=lambda c: -c.wei)
            if not cs:
                continue
            for c in cs:
                p(f"    {c.cid:<5}{t + '  ' + TIERS[t]:<27}{c.n():>7}{tok(c.wei, dec):>21,.6f}"
                  f"   {pc(c.wei):<20} {c.label}")
            s = sum(c.wei for c in cs)
            p(f"    {'':<5}{'-> tier ' + t + ' subtotal':<27}{sum(c.n() for c in cs):>7}"
              f"{tok(s, dec):>21,.6f}   {pc(s):<20}")
        rest = self.remainders()
        un = sum(rest.values())
        p(f"    {'--':<5}{'unattributed / dispersed':<27}{sum(1 for v in rest.values() if v > 0):>7}"
          f"{tok(un, dec):>21,.6f}   {pc(un):<20} everyone this audit could not tie to the issuer")
        tot = sum(c.wei for c in live) + un
        p(f"    {'':<5}{'TOTAL':<27}{'':>7}{tok(tot, dec):>21,.6f}   {pc(tot):<20}")

        floor = sum(c.wei for c in live if c.tier in FLOOR)
        ceil = sum(c.wei for c in live if c.tier in CEILING)
        p(f"\n  HEADLINE")
        # A range, printed as one token so no reader can lift half of it: floor-ceiling,
        # with the denominator named on the same line it is divided by.
        p(f"    issuer control of the float:   {float(pct_of_float(floor, F)):.2f}%"
          f"-{float(pct_of_float(ceil, F)):.2f}%   of the {fl} token float")
        p(f"      floor    {'+'.join(FLOOR):<5} {tok(floor, dec):>20,.6f}   on-chain fact alone")
        p(f"      ceiling  {'+'.join(CEILING):<5} {tok(ceil, dec):>20,.6f}   every tier a reviewer "
          f"could reasonably accept")
        p(f"      Quote the range. One decimal lets the issuer rebut a single address and")
        p(f"      dismiss the analysis; a range survives losing any individual call.")

        m = sum(c.wei for c in live if c.tier == "M")
        p(f"\n    M  market makers   {tok(m, dec):>20,.6f}   {pc(m):<20} NOT inside the range above")
        p(f"       Unresolvable on chain: a market maker's inventory may be the issuer's,")
        p(f"       borrowed from the issuer, or its own. Resolving it needs the off-chain")
        p(f"       agreements. Forcing it to either side destroys the number.")
        d = sum(c.wei for c in live if c.tier == "D")
        p(f"\n    D  assumed         {tok(d, dec):>20,.6f}   {pc(d):<20} ASSUMPTION, not in the headline")
        p(f"       Publishing D as fact is how analyses get discredited. It sits here so a")
        p(f"       reviewer can add it deliberately, never so a reader adds it by accident.")

        p(f"\n  TWO QUESTIONS   opposite implications; these lines never merge")
        p(f"    (over the A+B+C tiers only — D and M are not attributed control, so they"
          f" have no origin to split)")
        for s, why in SOURCES.items():
            v = sum(c.wei for c in live if c.source == s and c.tier in CEILING)
            p(f"    {s:<18}{tok(v, dec):>20,.6f}   {pc(v):<20} {why}")
        p(f"    Float that was never really distributed is a DISCLOSURE PROBLEM.")
        p(f"    Tokens re-accumulated from the market after listing are ORDINARY BUYING.")
        p(f"    A single number covering both is indefensible whichever way it is read.")

        p(f"\n  RETRACTIONS")
        if not self.retractions:
            p(f"    none in this run")
        for r in self.retractions:
            p(f"    {r['id']}  WITHDRAWN ({r['tier']}): {r['was']}")
            p(f"          why: {r['why']}")
        p("=" * 100)

    def to_json(self):
        live = self.live()
        floor = sum(c.wei for c in live if c.tier in FLOOR)
        ceil = sum(c.wei for c in live if c.tier in CEILING)
        return {"snapshot": self.snapshot, "decimals": self.dec,
                "total_supply_wei": str(self.total_supply),
                "float_wei": str(self.float_wei),
                "excluded": {a: w for a, w in self.exclude.items()},
                "claims": [{"id": c.cid, "tier": c.tier, "label": c.label, "wei": str(c.wei),
                            "addrs": sorted(c.addrs()), "n": c.n(), "evidence": c.evidence,
                            "source": c.source, "retracted": c.retracted}
                           for c in self.claims],
                "unattributed_wei": str(sum(self.remainders().values())),
                "headline": {"floor_tiers": list(FLOOR), "ceiling_tiers": list(CEILING),
                             "floor_wei": str(floor), "ceiling_wei": str(ceil),
                             "floor_pct_of_float": float(pct_of_float(floor, self.float_wei)),
                             "ceiling_pct_of_float": float(pct_of_float(ceil, self.float_wei))},
                "two_methods": self.methods,
                "retractions": self.retractions}


# ---------------------------------------------------------------- re-auditability

def diff(old, new, out=sys.stdout):
    """What moved between two runs of the same audit, claim by claim.

    This skill's own headline moved from 71.00% to 69.29% under review and there was no
    tool that could show what moved. A percentage that changes without a named claim
    behind the change is not a correction, it is a new opinion.
    """
    p = lambda s: print(s, file=out)
    F = int(new["float_wei"])
    p("\n  DIFF   old -> new")
    for k in ("snapshot", "float_wei", "total_supply_wei"):
        a, b = old.get(k), new.get(k)
        mark = "unchanged" if a == b else "CHANGED"
        p(f"    {k:<18}{str(a):<34} -> {str(b):<34} {mark}")
    if old.get("float_wei") != new.get("float_wei"):
        p(f"    ! the denominator moved, so every percentage below is measured against a")
        p(f"      different float. Compare the token amounts, not the percentages.")

    ho, hn = old["headline"], new["headline"]
    p(f"    headline          {ho['floor_pct_of_float']:.2f}%-{ho['ceiling_pct_of_float']:.2f}%"
      f"  ->  {hn['floor_pct_of_float']:.2f}%-{hn['ceiling_pct_of_float']:.2f}%"
      f"   floor {hn['floor_pct_of_float'] - ho['floor_pct_of_float']:+.2f}pp"
      f"   ceiling {hn['ceiling_pct_of_float'] - ho['ceiling_pct_of_float']:+.2f}pp")

    o = {c["id"]: c for c in old["claims"]}
    n = {c["id"]: c for c in new["claims"]}
    dec = new.get("decimals", 18)
    p(f"    claims            {len(o)} -> {len(n)}")
    for cid in sorted(o.keys() | n.keys()):
        a, b = o.get(cid), n.get(cid)
        if a and not b:
            p(f"      - {cid:<5} DROPPED   {tok(int(a['wei']), dec):>18,.6f}  {a['tier']}  {a['label']}")
        elif b and not a:
            p(f"      + {cid:<5} ADDED     {tok(int(b['wei']), dec):>18,.6f}  {b['tier']}  {b['label']}")
            continue
        if not (a and b):
            continue
        if not a.get("retracted") and b.get("retracted"):
            p(f"      ! {cid:<5} RETRACTED {tok(int(a['wei']), dec):>18,.6f}  {b['retracted']}")
        if a["tier"] != b["tier"]:
            p(f"      ~ {cid:<5} TIER      {a['tier']} -> {b['tier']}  {b['label']}")
        if a["wei"] != b["wei"]:
            d = int(b["wei"]) - int(a["wei"])
            p(f"      ~ {cid:<5} AMOUNT    {tok(int(a['wei']), dec):>18,.6f} -> "
              f"{tok(int(b['wei']), dec):>18,.6f}   {tok(d, dec):+,.6f}   {pct_of_float(d, F):+.4f}")
        if a["source"] != b["source"]:
            p(f"      ~ {cid:<5} SOURCE    {a['source']} -> {b['source']}  (a disclosure "
              f"problem and ordinary buying are not the same finding)")
        if a["evidence"] != b["evidence"]:
            p(f"      ~ {cid:<5} EVIDENCE  {a['evidence'][:60]}")
            p(f"      {'':<7}       -> {b['evidence'][:60]}")
    du = int(new["unattributed_wei"]) - int(old["unattributed_wei"])
    p(f"    unattributed      {tok(int(old['unattributed_wei']), dec):>18,.6f} -> "
      f"{tok(int(new['unattributed_wei']), dec):>18,.6f}   {tok(du, dec):+,.6f}")


# ---------------------------------------------------------------- the tiers file

def build(spec, db=None, force=False):
    """Build an Attribution from a --tiers JSON document. See the module docstring of
    the shipped example for the shape; every field below is required to be explicit
    because an audit you cannot re-run from a file is an audit nobody can check."""
    dec = spec.get("decimals", 18)
    db = db or spec["db"]
    ex = [tuple(e) for e in spec.get("exclude", [])]
    a = Attribution.from_db(db, ex, spec.get("supply"), spec.get("at_block"), dec,
                            spec.get("snapshot"), force)
    for c in spec.get("claims", []):
        kw = dict(cid=c.get("id"), label=c.get("label"), evidence=c.get("evidence", ""),
                  source=c.get("source", ""), tier=c.get("tier", ""))
        if "of" in c:
            a.assign_part(c["of"], c.get("tokens", c.get("wei", 0)), **kw)
        elif "addrs" in c:
            a.assign_cluster(c["addrs"], **kw)
        else:
            a.assign(c["addr"], **kw)
    for cid, why in spec.get("retract", []):
        a.retract(cid, why)
    return a


def main():
    p = argparse.ArgumentParser(
        description="tier attribution that closes exactly onto the float")
    p.add_argument("--tiers", help="audit JSON: db, supply, exclude, claims, retract")
    p.add_argument("--run", help="a previous --out record, reported without recomputing")
    p.add_argument("--db", help="override the database named in --tiers")
    p.add_argument("--diff", metavar="RUN.json", help="show what moved since that run")
    p.add_argument("--out", metavar="RUN.json", help="write this run's record")
    p.add_argument("--json", action="store_true", help="print the record to stdout")
    p.add_argument("--force", action="store_true",
                   help="proceed over an uncertified database; balances.py stamps it")
    a = p.parse_args()
    if not (a.tiers or a.run):
        p.error("--tiers or --run is required")

    if a.run:
        rec = json.load(open(a.run))
    else:
        spec = json.load(open(a.tiers))
        db = a.db or spec["db"]
        if not os.path.isabs(db):       # relative to the tiers file, so an audit moves whole
            db = os.path.join(os.path.dirname(os.path.abspath(a.tiers)), db)
        try:
            at = build(spec, db, a.force)
        except (ValueError, KeyError) as e:
            sys.exit(f"REFUSED: the audit file is not valid — {e}")
        at.close()
        if "two_methods" in spec:
            t = spec["two_methods"]
            at.two_methods(t["lineage"], t["balance"], [tuple(r) for r in t.get("residual", [])])
        at.report()
        rec = at.to_json()
        if a.out:
            json.dump(rec, open(a.out, "w"), indent=1)
            print(f"  record written to {a.out}")
    if a.diff:
        diff(json.load(open(a.diff)), rec)
    if a.json:
        print(json.dumps(rec, indent=1))


if __name__ == "__main__":
    try:
        main()
    except (DoesNotClose, CoverageError, DenominatorError) as e:
        # Exit non-zero and print nothing that could be quoted. A tier table that did not
        # close is not a weaker number; there is no number.
        sys.exit(f"\nREFUSED: {e}\n  Nothing above this line may be published.")
