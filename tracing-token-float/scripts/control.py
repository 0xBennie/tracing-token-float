#!/usr/bin/env python3
"""Who holds the keys, what the locks are worth, and how many chains the supply is on.

    python control.py safes    --chain eth 0xSAFE1 0xSAFE2 ...
    python control.py lock     --chain bsc 0xVESTING
    python control.py bridge   --home eth:0xTOKEN:0xADAPTER --remote bsc:0xTOKEN

Three findings this skill has made that a per-address tool cannot make:

  SEVEN multisigs holding 72.21875% of a supply, every one of them threshold 4-of-6
  with an IDENTICAL signer set. Reported as seven holders that is a dispersed
  treasury; it is one controller wearing seven hats, and the concentration is
  understated sevenfold. Only the INTERSECTION of the owner sets shows it.

  A 48-hour timelock whose proposer, executor and canceller are the same 3-of-5
  Safe. The nominal lock was 36 months. The effective lock was 48 hours — and
  because the same Safe can cancel, an observer cannot even rely on seeing the
  proposal land.

  A lock-and-mint bridge where adding up three chains' totalSupply gives 1.49e9
  against a true global supply of 1e9. The escrow on the home chain IS the remote
  supply; counting both double-counts every percentage downstream.

Every selector below was computed with keccak and is shown next to its signature.
Six of the 27 selectors this skill shipped with were wrong from being recalled.
"""
import argparse, json, sys
from itertools import combinations
from topics import topic0
from rpc import Client, BASE, BSC, ETH
from privileges import audit, safe_control

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}

SEL = dict(
    threshold="0xe75235b8",       # getThreshold()
    owners="0xa0e67e2b",          # getOwners()
    nonce="0xaffed0e0",           # nonce()
    min_delay="0xf27a0c92",       # getMinDelay()
    has_role="0x91d14854",        # hasRole(bytes32,address)
    role_count="0xca15c873",      # getRoleMemberCount(bytes32)
    role_member="0x9010d07c",     # getRoleMember(bytes32,uint256)
    total_supply="0x18160ddd",    # totalSupply()
    balance_of="0x70a08231",      # balanceOf(address)
    decimals="0x313ce567",        # decimals()
    owner="0x8da5cb5b",           # owner()
    beneficiary="0x38af3eed",     # beneficiary()
    released="0x96132521",        # released()
    releasable="0xfbccedae",      # releasable()
    start="0xbe9a6555",           # start()
    duration="0x0fb5a6b4",        # duration()
    cliff="0x13d033c0",           # cliff()
)
# keccak256 of the role name, which is how OpenZeppelin's TimelockController defines them.
ROLES = {
    # Derived, not typed. These decide whether a timelock can be bypassed, so a wrong
    # one reads as "nobody holds PROPOSER_ROLE" — i.e. as a real lock. The four below
    # were verified correct when this changed, but nothing would have caught a drift.
    "PROPOSER":  topic0("PROPOSER_ROLE"),
    "EXECUTOR":  topic0("EXECUTOR_ROLE"),
    "CANCELLER": topic0("CANCELLER_ROLE"),
    "ADMIN":     topic0("TIMELOCK_ADMIN_ROLE"),
}


def _w(h, i):
    return int(h[2 + i * 64:66 + i * 64], 16)


def safe(c, addr):
    """A Safe's threshold, owners and nonce. Anything else is not a Safe."""
    s = safe_control(c, addr)
    if not s.get("is_safe"):
        return None
    s["owners"] = [o.lower() for o in s["owners"]]
    try:
        s["nonce"] = int(c.eth_call(addr, SEL["nonce"]), 16)
    except Exception:
        s["nonce"] = None
    return s


def balances(c, token, addrs, dec):
    return {a: int(c.eth_call(token, SEL["balance_of"] + a[2:].rjust(64, "0")), 16) / 10 ** dec
            for a in addrs}


def intersect(safes, bal=None, float_tokens=None):
    """Group Safes that share enough signers to be one control domain.

    Two Safes are the same hand when their shared signers number at least the higher
    of the two thresholds: that many people can move both. Reporting such Safes
    separately is the error this function exists to prevent.
    """
    ids = list(safes)
    print(f"\n  SIGNER INTERSECTION  ({len(ids)} Safe(s))")
    hdr = "".join(f"{a[:8]:>10}" for a in ids)
    print(f"    {'':44}{hdr}")
    for a in ids:
        row = ""
        for b in ids:
            n = len(set(safes[a]["owners"]) & set(safes[b]["owners"]))
            row += f"{'—' if a == b else n:>10}"
        print(f"    {a} {safes[a]['threshold']}/{len(safes[a]['owners'])}  {row}")
    print("    cells are the number of signers two Safes have in common")

    parent = {a: a for a in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in combinations(ids, 2):
        shared = len(set(safes[a]["owners"]) & set(safes[b]["owners"]))
        if shared >= max(safes[a]["threshold"], safes[b]["threshold"]):
            parent[find(a)] = find(b)

    groups = {}
    for a in ids:
        groups.setdefault(find(a), []).append(a)

    print(f"\n  CONTROL DOMAINS  {len(groups)} distinct hand(s) behind {len(ids)} Safe(s)")
    for i, (_, members) in enumerate(sorted(groups.items(), key=lambda kv: -len(kv[1])), 1):
        common = set.intersection(*(set(safes[m]["owners"]) for m in members))
        tot = sum(bal.get(m, 0) for m in members) if bal else None
        print(f"    domain {i}: {len(members)} Safe(s), {len(common)} signer(s) in common"
              + (f", holding {tot:,.6f} tokens" if tot is not None else ""))
        if float_tokens and tot:
            share = tot / float_tokens * 100
            print(f"               {share:.4f}% of float")
            if share > 100:
                # Pitfall #1, showing itself. A holding cannot exceed the float unless
                # it is not IN the float — a locked or escrowed bucket measured against
                # the circulating denominator.
                print(f"               !! over 100% of float. These tokens are not IN the")
                print(f"                  float — they are locked, escrowed or otherwise")
                print(f"                  excluded. Measure them against supply, or exclude")
                print(f"                  them and re-derive the float (balances.py).")
        for m in members:
            s = safes[m]
            print(f"      {m}  {s['threshold']}/{len(s['owners'])}"
                  + (f"  {bal[m]:>18,.6f}" if bal and m in bal else ""))
        if len(members) > 1:
            print(f"      -> ONE controller. Any {max(safes[m]['threshold'] for m in members)}"
                  f" of these signers moves all {len(members)}.")
            for o in sorted(common):
                print(f"         shared signer {o}")

    # A signer who sits on enough Safes to move a majority of what is held here.
    if bal:
        total = sum(bal.values())
        seats = {}
        for a in ids:
            for o in safes[a]["owners"]:
                seats.setdefault(o, []).append(a)
        for o, on in sorted(seats.items(), key=lambda kv: -len(kv[1])):
            reach = sum(bal.get(x, 0) for x in on)
            if len(on) > 1 and total and reach / total > 0.5:
                print(f"\n    ! signer {o} sits on {len(on)} of these Safes, which together"
                      f" hold {reach/total*100:.1f}% of the audited balance")
    return groups


def effective_lock(c, addr, token=None):
    """What the lock is actually worth, which is its shortest unlock path.

    A nominal 36-month vest administered by a timelock whose proposer, executor and
    canceller are one Safe is worth the timelock delay, not 36 months. Report the
    path, never echo the schedule as if it were the answer.
    """
    print(f"\n  LOCK  {addr}")
    out = {"address": addr}
    for name, sel in (("beneficiary", "beneficiary"), ("owner", "owner"),
                      ("start", "start"), ("duration", "duration"), ("cliff", "cliff"),
                      ("released", "released"), ("releasable", "releasable")):
        try:
            r = c.eth_call(addr, SEL[sel])
            v = int(r, 16)
            out[name] = ("0x" + r[-40:]) if name in ("beneficiary", "owner") else v
        except Exception:
            out[name] = None
    for k in ("beneficiary", "owner", "start", "duration", "cliff"):
        if out.get(k) is not None:
            print(f"    {k:14} {out[k]}")
    if out.get("duration"):
        print(f"    nominal term   {out['duration']/86400:,.1f} days"
              + (f", cliff {(out['cliff']-out['start'])/86400:,.1f} days"
                 if out.get("cliff") and out.get("start") else ""))

    a = audit(c, addr)
    out["privileged"] = a.get("privileged", [])
    priv = a.get("privileged", [])
    rewritable = [f["name"] for f in priv if f["kind"] in ("vesting", "escape", "supply")]
    # privileges.py speaks token language. On an escrow, `pause` does not freeze
    # transfers — it stops the BENEFICIARY claiming, which is a different power with a
    # different victim, and reading the token verdict here misclassifies it.
    pausable = [f["name"] for f in priv if f["kind"] == "freeze"]
    for v in a.get("verdict", []):
        if "frozen or addresses blacklisted" in v and pausable:
            print(f"    -> releases can be HALTED by the admin ({', '.join(pausable)}).")
            print(f"       That blocks the beneficiary; it does not move the tokens.")
        else:
            print(f"    -> {v}")

    # The admin decides everything. If it is a Safe, its threshold is the real gate.
    admin = out.get("owner")
    hours = None
    if admin and int(admin, 16) > 1:
        try:
            code = c.call("eth_getCode", [admin, "latest"]) or "0x"
        except Exception:
            code = "0x"
        if code == "0x":
            print(f"    !! the admin {admin} is an EOA — one private key, no threshold,")
            print(f"       no delay. Whatever it can do, one person can do alone.")
            out["admin_is_eoa"] = True
        s = safe(c, admin)
        if s:
            print(f"    admin is a Safe {s['threshold']}/{len(s['owners'])} — "
                  f"{s['threshold']} signature(s) are the real gate")
            out["admin_safe"] = s
        try:
            d = int(c.eth_call(admin, SEL["min_delay"]), 16)
            hours = d / 3600
            print(f"    admin is a Timelock, minDelay {d:,}s = {hours:,.1f}h")
            holders = {}
            for rn, rh in ROLES.items():
                try:
                    n = int(c.eth_call(admin, SEL["role_count"] + rh[2:]), 16)
                    holders[rn] = ["0x" + c.eth_call(
                        admin, SEL["role_member"] + rh[2:] + f"{i:064x}")[-40:] for i in range(n)]
                except Exception:
                    holders[rn] = None
            out["timelock_roles"] = holders
            for rn, hs in holders.items():
                if hs is not None:
                    print(f"      {rn:10} {hs}")
            p, e, x = (set(holders.get(k) or []) for k in ("PROPOSER", "EXECUTOR", "CANCELLER"))
            if p and p == e:
                print(f"    !! proposer and executor are the same party — the delay is a"
                      f" waiting period, not a check")
            if p and p == x:
                print(f"    !! the proposer can also CANCEL, so an observer cannot rely on"
                      f" seeing a proposal land before it is withdrawn")
        except Exception:
            pass

    if rewritable:
        print(f"    !! the schedule itself is reachable: {rewritable}")
        print(f"    EFFECTIVE LOCK  {hours:,.1f}h (the admin path)" if hours else
              f"    EFFECTIVE LOCK  0h — an admin can rewrite or drain it with no delay")
        out["effective_lock_hours"] = hours or 0
    else:
        print(f"    no admin path to the schedule was found in the dispatch table")
        print(f"    EFFECTIVE LOCK  the nominal term stands, subject to the caveat that")
        print(f"                    absence from the dispatch table is not proof of absence")
        out["effective_lock_hours"] = None
    return out


def bridge_reconcile(home, remotes):
    """Which supply is real when the same token exists on several chains.

    Lock-and-mint: the home escrow holds collateral equal to the sum of remote
    totalSupply. Adding all chains together double-counts. Native burn/mint: the
    per-chain supplies genuinely sum to the global total. Getting the mode wrong
    inflates or deflates every percentage downstream, so it is named, not assumed.
    """
    hc, htok, hadapter = home
    c = Client(NETS[hc])
    dec = int(c.eth_call(htok, SEL["decimals"]), 16)
    hsupply = int(c.eth_call(htok, SEL["total_supply"]), 16) / 10 ** dec
    escrow = None
    if hadapter:
        escrow = int(c.eth_call(htok, SEL["balance_of"] + hadapter[2:].rjust(64, "0")),
                     16) / 10 ** dec

    print(f"\n  CROSS-CHAIN SUPPLY")
    print(f"    {hc:6} totalSupply        {hsupply:>20,.6f}   (home)")
    rem = 0.0
    for rc, rtok in remotes:
        rcc = Client(NETS[rc])
        rd = int(rcc.eth_call(rtok, SEL["decimals"]), 16)
        rs = int(rcc.eth_call(rtok, SEL["total_supply"]), 16) / 10 ** rd
        rem += rs
        print(f"    {rc:6} totalSupply        {rs:>20,.6f}")
    naive = hsupply + rem
    print(f"    naive sum of chains    {naive:>20,.6f}   <- almost always wrong")

    if escrow is not None:
        resid = escrow - rem
        print(f"    home escrow balance    {escrow:>20,.6f}   {hadapter}")
        print(f"    sum of remote supply   {rem:>20,.6f}")
        print(f"    residual               {resid:>20,.6f}"
              + ("   exact" if abs(resid) < 1e-9 else "   MUST BE NAMED (in flight?)"))
        if abs(resid) < max(1.0, rem * 1e-6):
            print(f"\n    MODE: lock-and-mint. The escrow IS the remote supply.")
            print(f"    GLOBAL SUPPLY = {hsupply:,.6f} (the home total), NOT {naive:,.6f}.")
            print(f"    The {naive - hsupply:,.6f} difference is the same tokens counted twice.")
            return dict(mode="lock-and-mint", global_supply=hsupply, naive=naive)
    print(f"\n    MODE: not lock-and-mint (escrow does not match remote supply).")
    print(f"    If this is native burn/mint the chains DO sum: {naive:,.6f}.")
    print(f"    Do not adopt either reading until the adapter has been audited —")
    print(f"    privileges.py on the adapter is the next call.")
    return dict(mode="undetermined", naive=naive)


def main():
    p = argparse.ArgumentParser(description="key holders, effective locks, cross-chain supply")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("safes", help="resolve Safes and intersect their signer sets")
    s.add_argument("--chain", required=True, choices=list(NETS))
    s.add_argument("addresses", nargs="+")
    s.add_argument("--token", help="value each Safe's holding of this token")
    s.add_argument("--float", type=float, dest="flt", help="float, to express shares against")
    s.add_argument("--json", action="store_true")

    l = sub.add_parser("lock", help="what a vesting or timelock contract is actually worth")
    l.add_argument("--chain", required=True, choices=list(NETS))
    l.add_argument("addresses", nargs="+")
    l.add_argument("--json", action="store_true")

    b = sub.add_parser("bridge", help="reconcile supply across chains")
    b.add_argument("--home", required=True, metavar="CHAIN:TOKEN[:ADAPTER]")
    b.add_argument("--remote", nargs="+", required=True, metavar="CHAIN:TOKEN")
    b.add_argument("--json", action="store_true")

    a = p.parse_args()

    if a.cmd == "safes":
        c = Client(NETS[a.chain])
        found, plain = {}, []
        for addr in (x.lower() for x in a.addresses):
            s = safe(c, addr)
            if s:
                found[addr] = s
            else:
                plain.append(addr)
        for addr in plain:
            print(f"  {addr}  not a Safe (no getThreshold/getOwners)")
        if not found:
            sys.exit("no Safes among the addresses given")
        bal = None
        if a.token:
            dec = int(c.eth_call(a.token.lower(), SEL["decimals"]), 16)
            bal = balances(c, a.token.lower(), list(found), dec)
        g = intersect(found, bal, a.flt)
        if a.json:
            print(json.dumps({"safes": found, "balances": bal,
                              "domains": {k: v for k, v in g.items()}}, indent=1, default=str))
    elif a.cmd == "lock":
        c = Client(NETS[a.chain])
        out = [effective_lock(c, x.lower()) for x in a.addresses]
        if a.json:
            print(json.dumps(out, indent=1, default=str))
    else:
        hp = a.home.split(":")
        home = (hp[0], hp[1].lower(), hp[2].lower() if len(hp) > 2 else None)
        remotes = [(x.split(":")[0], x.split(":")[1].lower()) for x in a.remote]
        r = bridge_reconcile(home, remotes)
        if a.json:
            print(json.dumps(r, indent=1, default=str))


if __name__ == "__main__":
    main()
