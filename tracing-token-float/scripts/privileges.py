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
    # supply
    "0x40c10f19": ("mint(address,uint256)", "supply"),
    "0xa0712d68": ("mint(uint256)", "supply"),
    "0x449a52f8": ("mintTo(address,uint256)", "supply"),
    "0x9dc29fac": ("burn(address,uint256)", "supply"),
    "0x156e29f6": ("mint(address,uint256,bytes)", "supply"),
    # transfer control
    "0x8456cb59": ("pause()", "freeze"),
    "0x3f4ba83a": ("unpause()", "freeze"),
    "0xf9f92be4": ("blacklist(address)", "freeze"),
    "0x0ecb93c0": ("addBlackList(address)", "freeze"),
    "0xe4997dc5": ("removeBlackList(address)", "freeze"),
    "0x1a8e55b0": ("setBlacklisted(address,bool)", "freeze"),
    # escape hatches — the ones that quietly drain escrow
    "0x01681a62": ("sweep(address)", "escape"),
    "0x6ea056a9": ("sweep(address,uint256)", "escape"),
    "0x71f4e1b0": ("rescueTokens(address,address,uint256)", "escape"),
    "0x8980f11f": ("emergencyWithdraw(address,uint256)", "escape"),
    "0x51cff8d9": ("withdraw(address)", "escape"),
    "0xf3fef3a3": ("withdraw(address,uint256)", "escape"),
    "0x00f714ce": ("withdraw(uint256,address)", "escape"),
    "0xdb2e21bc": ("emergencyWithdraw()", "escape"),
    "0x5312ea8e": ("emergencyWithdraw(uint256)", "escape"),
    # ownership / upgrade
    "0x8da5cb5b": ("owner()", "ownership"),
    "0xf2fde38b": ("transferOwnership(address)", "ownership"),
    "0x3659cfe6": ("upgradeTo(address)", "upgrade"),
    "0x4f1ef286": ("upgradeToAndCall(address,bytes)", "upgrade"),
    "0x2f2ff15d": ("grantRole(bytes32,address)", "ownership"),
    # vesting rewrite
    "0x0e8ddd4d": ("updateSchedule(uint256,uint256)", "vesting"),
    "0x1c31f710": ("updateBeneficiary(address)", "vesting"),
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


def probe_callable(c, addr, sel, owner, arg=None):
    """Is this a live unilateral control path, and is everyone else locked out?

    Three probes, because any one alone lies:
      - a garbage selector, to catch a contract whose fallback accepts anything
      - `sel` from a stranger, which a guarded function refuses with an auth error
      - `sel` from the owner, which must NOT hit that same auth error

    The verdict rests on the two calls failing *differently*. A privileged
    function commonly still reverts for the owner under simulation — on a later
    precondition, a zero-value transfer, a paused check — so requiring success
    would report every real escape hatch as absent.
    """
    STRANGER = "0x1111111111111111111111111111111111111111"
    argw = (arg or owner)[2:].rjust(64, "0")
    ctl = _raw_call(c, addr, "0xdeadbeef" + argw, owner)
    own = _raw_call(c, addr, sel + argw, owner)
    stranger = _raw_call(c, addr, sel + argw, STRANGER)
    if ctl["ok"]:
        return "INCONCLUSIVE (fallback accepts anything)"
    if _is_auth_refusal(stranger) and not _is_auth_refusal(own):
        return f"OWNER-ONLY (stranger refused: {AUTH_ERRORS.get(stranger['data'], stranger['data'] or stranger['msg'][:30])})"
    if own["ok"] and stranger["ok"]:
        return "ANYONE"
    if _is_auth_refusal(own):
        return "OWNER REFUSED (owner() is not the gate — check roles)"
    return "INCONCLUSIVE (both revert alike)"


def audit(c, addr, check_callable=True):
    code = c.call("eth_getCode", [addr, "latest"])
    if code in ("0x", "0x0"):
        return dict(address=addr, is_contract=False)
    sels = selectors(code)
    found = [dict(selector=s, name=DANGEROUS[s][0], kind=DANGEROUS[s][1])
             for s in sorted(sels & DANGEROUS.keys())]
    impl, admin = _slot(c, addr, SLOT_IMPL), _slot(c, addr, SLOT_ADMIN)
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
                f["live"] = f["owner_can_call"].startswith("OWNER-ONLY")
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
        bad.append(f"LIVE escape hatch {live} — held balances can be withdrawn unilaterally, no delay"
                   if live else "escape hatch present — held balances may be withdrawable")
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
