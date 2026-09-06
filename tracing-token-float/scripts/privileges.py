"""Contract privilege audit — run this BEFORE replaying a single event.

If a mint path exists outside the bridge logic, "who controls the float" is the
wrong question: they don't need to control supply, they can print. If a bridge
adapter can be swept, the remote chain's entire supply is unbacked on demand.

    from rpc import Client, BASE
    from privileges import audit
    print(audit(Client(BASE), "0xtoken..."))

Works by extracting every 4-byte selector the runtime bytecode PUSH4s, then
matching against a list of selectors that grant unilateral control. That finds
non-standard functions a source-code skim misses — the ones that matter most are
exactly the ones nobody expects to be there.
"""
from rpc import Client

# EIP-1967
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

DANGEROUS = {
    # Every selector below computed with keccak-256 at patch time — no recalled
    # constants. Regenerate rather than hand-edit; a wrong selector reads as "absent".
    "0x40c10f19": ("mint(address,uint256)", "supply"),
    "0xa0712d68": ("mint(uint256)", "supply"),
    "0x449a52f8": ("mintTo(address,uint256)", "supply"),
    "0x9dc29fac": ("burn(address,uint256)", "supply"),
    "0x94d008ef": ("mint(address,uint256,bytes)", "supply"),
    "0x8456cb59": ("pause()", "freeze"),
    "0x3f4ba83a": ("unpause()", "freeze"),
    "0xf9f92be4": ("blacklist(address)", "freeze"),
    "0x0ecb93c0": ("addBlackList(address)", "freeze"),
    "0xe4997dc5": ("removeBlackList(address)", "freeze"),
    "0xd01dd6d2": ("setBlacklisted(address,bool)", "freeze"),
    "0x01681a62": ("sweep(address)", "escape"),
    "0x6ea056a9": ("sweep(address,uint256)", "escape"),
    "0xdf2ab5bb": ("sweepToken(address,uint256,address)", "escape"),
    "0xcea9d26f": ("rescueTokens(address,address,uint256)", "escape"),
    "0x8cd4426d": ("rescueERC20(address,uint256)", "escape"),
    "0x8980f11f": ("recoverERC20(address,uint256)", "escape"),
    "0xbc25cf77": ("skim(address)", "escape"),
    "0x95ccea67": ("emergencyWithdraw(address,uint256)", "escape"),
    "0xdb2e21bc": ("emergencyWithdraw()", "escape"),
    "0x5312ea8e": ("emergencyWithdraw(uint256)", "escape"),
    "0x51cff8d9": ("withdraw(address)", "escape"),
    "0xf3fef3a3": ("withdraw(address,uint256)", "escape"),
    "0x00f714ce": ("withdraw(uint256,address)", "escape"),
    "0x9e281a98": ("withdrawToken(address,uint256)", "escape"),
    "0x66b44840": ("withdrawPool(address,address)", "escape"),
    "0x8da5cb5b": ("owner()", "ownership"),
    "0xf2fde38b": ("transferOwnership(address)", "ownership"),
    "0x2f2ff15d": ("grantRole(bytes32,address)", "ownership"),
    "0x3659cfe6": ("upgradeTo(address)", "upgrade"),
    "0x4f1ef286": ("upgradeToAndCall(address,bytes)", "upgrade"),
    "0xe6671f90": ("updateSchedule(uint256,uint256)", "vesting"),
    "0x0aaffd2a": ("updateBeneficiary(address)", "vesting"),
    "0x1c31f710": ("setBeneficiary(address)", "vesting"),
    "0x20c5429b": ("revoke(uint256)", "vesting"),
}


def selectors(code_hex):
    """Every 4-byte value the bytecode PUSH4s — the dispatch table, plus noise."""
    b = bytes.fromhex(code_hex[2:]) if code_hex.startswith("0x") else bytes.fromhex(code_hex)
    out, i, n = set(), 0, len(b)
    while i < n:
        op = b[i]
        if op == 0x63 and i + 5 <= n:                 # PUSH4
            out.add("0x" + b[i + 1:i + 5].hex())
            i += 5
        elif 0x60 <= op <= 0x7F:                      # PUSH1..PUSH32, skip immediate
            i += 1 + (op - 0x5F)
        else:
            i += 1
    return out


def _slot(c, addr, slot):
    v = c.call("eth_getStorageAt", [addr, slot, "latest"])
    a = "0x" + v[-40:]
    return None if int(a, 16) == 0 else a


AUTH_ERRORS = {
    "0x118cdaa7": "OwnableUnauthorizedAccount",
    "0xe2517d3f": "AccessControlUnauthorizedAccount",
    "0x82b42900": "Unauthorized",
    "0x1b1a1f1a": "NotOwner",
}
AUTH_STRINGS = ("caller is not the owner", "not owner", "accesscontrol",
                "unauthorized", "forbidden", "only owner", "admin")


def _raw_call(c, addr, data, caller):
    """eth_call that surfaces the revert payload instead of swallowing it.

    The payload is the whole point: an access-controlled function refuses a
    stranger with a *specific* error and lets the owner through to fail (or
    succeed) somewhere else entirely. Success/failure alone cannot tell those
    apart — a privileged function often still reverts for the owner in a
    simulated call, on a later precondition."""
    import requests
    for url in c.endpoints:
        try:
            j = c.s.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                                    "params": [{"to": addr, "data": data, "from": caller},
                                               "latest"]}, timeout=c.timeout).json()
        except Exception:
            continue
        if "result" in j:
            return dict(ok=True, data=None, msg="")
        e = j.get("error", {})
        if e.get("code") in (-32001, -32005, 429):        # rate limited, try next node
            continue
        return dict(ok=False, data=(e.get("data") or "")[:10], msg=str(e.get("message", "")))
    return dict(ok=False, data=None, msg="all endpoints failed")


def _is_auth_refusal(r):
    if r["ok"]:
        return False
    if r["data"] in AUTH_ERRORS:
        return True
    return any(k in r["msg"].lower() for k in AUTH_STRINGS)


def encode_args(sig, addr_val):
    """ABI-encode a plausible argument list from a selector's own signature.

    One padded word is NOT enough. `withdrawPool(address,address)` needs two,
    `sweepToken(address,uint256,address)` three, and a call whose calldata is
    short falls through the dispatcher into the fallback — which reverts for
    owner and stranger *identically*, so the probe reports INCONCLUSIVE and a
    live escape hatch reads as absent. Arity comes from the signature we already
    store next to every selector; there is no need to guess it.

    Values are chosen to reach the auth guard rather than trip an earlier check:
    a nonzero amount, the owner in every address slot, empty tails for dynamic
    types. The verdict never depends on these succeeding — only on owner and
    stranger failing *differently*.
    """
    inner = sig[sig.index("(") + 1:sig.rindex(")")]
    types = [t.strip() for t in inner.split(",") if t.strip()]
    head, tail = [], []
    off = len(types) * 32
    for t in types:
        if t in ("bytes", "string") or t.endswith("[]"):
            head.append(f"{off:064x}")
            tail.append(f"{0:064x}")          # zero-length tail
            off += 32
        elif t == "address":
            head.append(addr_val[2:].lower().rjust(64, "0"))
        elif t == "bool":
            head.append(f"{0:064x}")
        elif t.startswith(("uint", "int")):
            head.append(f"{1:064x}")          # nonzero: a 0 amount can early-return
        else:                                  # bytes32 and friends
            head.append(f"{0:064x}")
    return "".join(head) + "".join(tail)


def probe_callable(c, addr, sel, owner, arg=None, sig=None):
    """Is this a live unilateral control path, and is everyone else locked out?

    Three probes, because any one alone lies:
      - a garbage selector, to catch a contract whose fallback accepts anything
      - `sel` from a stranger, which a guarded function refuses with an auth error
      - `sel` from the owner, which must NOT hit that same auth error

    The verdict rests on the two calls failing *differently*. A privileged
    function commonly still reverts for the owner under simulation — on a later
    precondition, a zero-value transfer, a paused check — so requiring success
    would report every real escape hatch as absent.

    All three probes carry the same calldata shape, so a difference in outcome
    can only come from the selector or the caller, never from the encoding.
    """
    STRANGER = "0x1111111111111111111111111111111111111111"
    sig = sig or (DANGEROUS.get(sel, ("f(address)",))[0])
    args = encode_args(sig, arg or owner)
    ctl = _raw_call(c, addr, "0xdeadbeef" + args, owner)
    own = _raw_call(c, addr, sel + args, owner)
    stranger = _raw_call(c, addr, sel + args, STRANGER)
    if ctl["ok"]:
        return "INCONCLUSIVE (fallback accepts anything)"
    if _is_auth_refusal(stranger) and not _is_auth_refusal(own):
        return f"OWNER-ONLY (stranger refused: {AUTH_ERRORS.get(stranger['data'], stranger['data'] or stranger['msg'][:30])})"
    if own["ok"] and stranger["ok"]:
        return "ANYONE"
    if _is_auth_refusal(own):
        return "OWNER REFUSED (owner() is not the gate — check roles)"
    return "INCONCLUSIVE (both revert alike)"


def is_delegated_eoa(code):
    """EIP-7702 delegation: 23 bytes of 0xef0100 + a 20-byte implementation address.

    Such an account HAS code but is still an EOA. `getCode != "0x"` counts it as a
    contract — in one holder cohort that turned 71 real contracts into 219. The same
    tell also identifies batch tooling: many claimers delegating to one implementation."""
    c = code[2:] if code.startswith("0x") else code
    return len(c) == 46 and c.lower().startswith("ef0100")


def delegate_target(code):
    c = code[2:] if code.startswith("0x") else code
    return "0x" + c[6:46] if is_delegated_eoa(code) else None


def audit(c, addr, check_callable=True):
    code = c.call("eth_getCode", [addr, "latest"])
    if code in ("0x", "0x0"):
        return dict(address=addr, is_contract=False, is_eoa=True)
    if is_delegated_eoa(code):
        return dict(address=addr, is_contract=False, is_eoa=True,
                    eip7702_delegated=True, delegate=delegate_target(code),
                    verdict=["EIP-7702 delegated EOA — has code but is not a contract"])
    sels = selectors(code)
    found = [dict(selector=s, name=DANGEROUS[s][0], kind=DANGEROUS[s][1])
             for s in sorted(sels & DANGEROUS.keys())]
    impl, admin = _slot(c, addr, SLOT_IMPL), _slot(c, addr, SLOT_ADMIN)
    # A proxy's own bytecode is a 45-byte delegate stub with no dispatch table — scanning
    # it finds nothing. The functions that matter live in the implementation.
    if impl:
        try:
            icode = c.call("eth_getCode", [impl, "latest"])
            if icode not in ("0x", "0x0"):
                sels |= selectors(icode)
        except Exception:
            pass
    owner = None
    try:
        owner = "0x" + c.eth_call(addr, "0x8da5cb5b")[-40:]
        if int(owner, 16) == 0:
            owner = None
    except Exception:
        pass
    if check_callable and owner:
        for f in found:
            if f["kind"] in ("escape", "supply", "vesting"):
                f["owner_can_call"] = probe_callable(c, addr, f["selector"], owner)
                # ANYONE is strictly worse than OWNER-ONLY: an unguarded escape hatch
                # can be called by anyone, not merely by the owner. Both are live.
                f["live"] = (f["owner_can_call"].startswith("OWNER-ONLY")
                             or f["owner_can_call"] == "ANYONE")
                f["unguarded"] = f["owner_can_call"] == "ANYONE"
    return dict(address=addr, is_contract=True, codesize=(len(code) - 2) // 2,
                is_proxy=bool(impl or admin), implementation=impl, proxy_admin=admin,
                owner=owner, privileged=found,
                verdict=_verdict(found, impl, admin))


def _verdict(found, impl, admin):
    kinds = {f["kind"] for f in found}
    bad = []
    if impl or admin:
        bad.append("upgradeable — today's bytecode is not a commitment")
    if "supply" in kinds:
        bad.append("supply is mutable — float control is moot, they can print")
    if "escape" in kinds:
        live = [f["name"] for f in found if f["kind"] == "escape" and f.get("live")]
        openf = [f["name"] for f in found if f["kind"] == "escape" and f.get("unguarded")]
        if openf:
            bad.append(f"UNGUARDED escape hatch {openf} — callable by ANYONE, not just the owner")
        if live:
            bad.append(f"LIVE escape hatch {live} — held balances can be withdrawn unilaterally, no delay")
        if not live and not openf:
            bad.append("escape hatch present — held balances may be withdrawable")
    if "freeze" in kinds:
        bad.append("transfers can be frozen or addresses blacklisted")
    if "vesting" in kinds:
        bad.append("vesting schedule is rewritable")
    return bad or ["no unilateral control path found in the dispatch table"]


def safe_control(c, addr):
    """If `addr` is a Gnosis Safe: its threshold and owners. Separate multisigs
    that share signers are not separation of control — intersect the owner sets."""
    try:
        thr = int(c.eth_call(addr, "0xe75235b8"), 16)                # getThreshold()
        raw = c.eth_call(addr, "0xa0e67e2b")[2:]                     # getOwners()
        n = int(raw[64:128], 16)
        return dict(is_safe=True, threshold=thr,
                    owners=["0x" + raw[128 + i * 64:192 + i * 64][-40:] for i in range(n)])
    except Exception:
        return dict(is_safe=False)


if __name__ == "__main__":
    import argparse, json, sys
    from rpc import Client, BASE, BSC, ETH
    NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
    p = argparse.ArgumentParser(description=__doc__ and __doc__.split("\n")[0])
    p.add_argument("--chain", required=True, choices=list(NETS))
    p.add_argument("addresses", nargs="+",
                   help="every contract that HOLDS or MOVES the token, not just the token: "
                        "bridge adapters, vesting factories, distributors, staking pools")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-probe", action="store_true",
                   help="skip the live stranger-vs-owner call that proves a path is real")
    a = p.parse_args()
    c = Client(NETS[a.chain])
    out = []
    for addr in a.addresses:
        r = audit(c, addr.lower(), check_callable=not a.no_probe)
        out.append({"address": addr.lower(), **r})
        if a.json:
            continue
        print(f"\n{addr.lower()}")
        if not r.get("is_contract"):
            print("  EOA — not a contract"); continue
        print(f"  codesize {r['codesize']}  proxy={r['is_proxy']}  owner={r['owner']}")
        for f in r["privileged"]:
            print(f"  {'!!' if f.get('live') else '  '} [{f['kind']:9s}] {f['name']:36s} "
                  f"{f.get('owner_can_call','')}")
        for v in r["verdict"]:
            print(f"  -> {v}")
        if r.get("owner"):
            s = safe_control(c, r["owner"])
            if s["is_safe"]:
                print(f"  -> owner is a Safe {s['threshold']}/{len(s['owners'])}")
    if a.json:
        print(json.dumps(out, indent=1, default=str))
    sys.exit(1 if any(f.get("live") for o in out for f in o.get("privileged", [])) else 0)
