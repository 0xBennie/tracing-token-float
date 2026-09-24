"""Contract privilege audit — run this BEFORE replaying a single event.

If a mint path exists outside the bridge logic, "who controls the float" is the
wrong question: they don't need to control supply, they can print. If a bridge
adapter can be swept, the remote chain's entire supply is unbacked on demand.

    from rpc import Client, BASE
    from privileges import audit
    print(audit(Client(BASE), "0xtoken..."))

Works by extracting the dispatch table from the runtime bytecode (every PUSH4, plus
the PUSH1..PUSH3 entries solc emits for selectors with leading zero bytes), then
matching against a list of selectors that grant unilateral control. That finds
non-standard functions a source-code skim misses — the ones that matter most are
exactly the ones nobody expects to be there. Each hit is then probed from a stranger
and from every authority-shaped getter the contract answers (owner(), primaryOwner(),
admin(), guardian(), ...), so the report names who holds the gate, not only whether
owner() does.
"""
from rpc import Client, RevertError
from topics import selector

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
    # The 3-arg form is what an upgradeable deposit vault actually ships (token, amount,
    # recipient). Found live on a BSC protocol vault holding 13.7% of a token's supply
    # while the 2-arg selector above matched nothing — one missing overload read as clean.
    "0x551512de": ("emergencyWithdraw(address,uint256,address)", "escape"),
    # Not a withdrawal, but on a deposit vault it is the same class of hole: the router
    # is where deposits are forwarded, so an owner-only setter redirects the flow.
    "0xc0d78655": ("setRouter(address)", "escape"),
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
    # TGE is the anchor every cliff and every slice is measured from, so an owner-only
    # setter for it accelerates the WHOLE remaining schedule in one call — a bigger hole
    # than revoking any single schedule, and it is not in any standard vesting interface.
    "0xad70bc7c": ("updateTge(uint256)", "vesting"),
    "0x3c7a4af7": ("createVestingSchedule(uint256,address,uint256,uint256,uint256,uint256,uint256,uint256)", "vesting"),
}

# Getters whose answer is a candidate for "who may call the dangerous function".
# owner() is the convention, not the rule. The case that put this list here was an
# upgradeable token vault whose full-balance emergencyWithdraw was gated on a custom
# primaryOwner(); it had no owner() at all, so the audit printed owner=None — which
# reads as "nobody controls this" — over the largest single escape hatch in the case.
# Selectors are derived from the signatures at import, like every other constant here.
AUTHORITY_GETTERS = ("owner()", "getOwner()", "primaryOwner()", "secondaryOwner()",
                     "pendingOwner()", "admin()", "getAdmin()", "guardian()",
                     "governance()", "governor()", "operator()", "manager()",
                     "controller()", "timelock()", "multisig()", "keeper()")
AUTH_GETTER = {selector(s): s for s in AUTHORITY_GETTERS}

# Probed for WHO can call them. Only these three also count toward `live` (and the CLI
# exit code): an owner-only upgrade or pause is reported with its holder, but the
# verdict already flags upgradeability and freezing on their own lines.
PROBE_KINDS = ("escape", "supply", "vesting", "upgrade", "freeze")
LIVE_KINDS = ("escape", "supply", "vesting")
STRANGER = "0x1111111111111111111111111111111111111111"


_DUP1, _DUP2, _EQ, _GT, _LT, _JUMPI, _SHR, _AND = 0x80, 0x81, 0x14, 0x11, 0x10, 0x57, 0x1C, 0x16


def _disasm(b):
    """[(opcode, immediate)] — linear, so an immediate is never read as an opcode."""
    ops, i, n = [], 0, len(b)
    while i < n:
        op = b[i]
        k = op - 0x5F if 0x60 <= op <= 0x7F else 0      # PUSH1..PUSH32
        ops.append((op, b[i + 1:i + 1 + k]))
        i += 1 + k
    return ops


def _push(o, lo=1, hi=4):
    return 0x5F + lo <= o[0] <= 0x5F + hi


def _dispatch_entry(ops, k):
    """(length, pushed immediate, is_selector) if a dispatch comparison starts at ops[k].

    The shapes solc emits for `if (selector == x) goto f`:
        DUP1 PUSHn x EQ  PUSHm dst JUMPI      (every entry but the last)
        PUSHn x DUP2 EQ  PUSHm dst JUMPI      (older solc)
        PUSHn x EQ       PUSHm dst JUMPI      (the last entry consumes the selector)
    and, for binary-search pivots that route between buckets, GT/LT in place of EQ.
    A pivot is itself a selector that reappears as an EQ entry in its bucket, so it
    is returned only to keep the run connected, never as a selector."""
    def tail(j):
        return (j + 2 < len(ops) and ops[j][0] in (_EQ, _GT, _LT)
                and _push(ops[j + 1], 1, 3) and ops[j + 2][0] == _JUMPI)
    n = len(ops)
    if k + 1 < n and ops[k][0] == _DUP1 and _push(ops[k + 1]) and tail(k + 2):
        return 5, ops[k + 1][1], ops[k + 2][0] == _EQ
    if k + 1 < n and _push(ops[k]) and ops[k + 1][0] == _DUP2 and tail(k + 2):
        return 5, ops[k][1], ops[k + 2][0] == _EQ
    if _push(ops[k]) and tail(k + 1):
        return 4, ops[k][1], ops[k + 1][0] == _EQ
    return None


def selectors(code_hex):
    """Every selector in the dispatch table, plus every PUSH4 anywhere (noise).

    PUSH4 alone is NOT the dispatch table. solc pushes a constant with the fewest
    bytes that hold it, so a selector whose first byte is 0x00 is a PUSH3, and one
    starting 0x0000 a PUSH2 — and those functions were invisible. The one that
    shipped was `withdraw(uint256,address)` = 0x00f714ce on a private LP vault: the
    audit said "no withdraw" while the owner could pull the entire bid in one call.

    Short pushes are NOT collected wholesale. PUSH1..PUSH3 are overwhelmingly jump
    targets, offsets and small constants; PUSH2 alone would add every jump
    destination in the contract. A short value counts only as an EQ comparison in
    dispatcher shape, inside a RUN of such comparisons that is anchored — by a PUSH4
    entry in the same run, or by the `PUSH1 0xe0 SHR` / `PUSH4 0xffffffff AND` that
    extracted the selector. The anchor is what rejects an ordinary `if (x == 0)`,
    which has the same five-opcode shape. Left-padded to 4 bytes."""
    b = bytes.fromhex(code_hex[2:]) if code_hex.startswith("0x") else bytes.fromhex(code_hex)
    ops = _disasm(b)
    out = {"0x" + imm.hex() for op, imm in ops if op == 0x63 and len(imm) == 4}
    k, n = 0, len(ops)
    while k < n:
        e = _dispatch_entry(ops, k)
        if not e:
            k += 1
            continue
        start, run = k, []
        while k < n and e:
            run.append(e)
            k += e[0]
            e = _dispatch_entry(ops, k) if k < n else None
        prev = ops[start - 2:start] if start >= 2 else []
        anchored = (any(len(imm) == 4 for _, imm, _ in run)
                    or prev == [(0x60, b"\xe0"), (_SHR, b"")]
                    or prev == [(0x63, b"\xff\xff\xff\xff"), (_AND, b"")])
        if anchored:
            out |= {"0x" + imm.rjust(4, b"\0").hex() for _, imm, sel in run if sel}
    return out


def _slot(c, addr, slot):
    v = c.call("eth_getStorageAt", [addr, slot, "latest"])
    a = "0x" + v[-40:]
    return None if int(a, 16) == 0 else a


# Derived from the signatures, like everything else. This table used to be typed, and
# its NotOwner entry was 0x1b1a1f1a — keccak("NotOwner()") is 0x30cd7471 — so every
# contract refusing a stranger with NotOwner() read as "both revert alike".
# ProxyDeniedAdminAccess is what an OZ5 transparent proxy returns to its OWN admin on
# any implementation call; not listing it made the proxy admin look like it had got
# past the gate the stranger could not.
# OnlyOwner() is how a private LP vault refused the stranger on its full-balance
# withdraw; without it the gate read only as CALLER-DEPENDENT. A custom error not
# listed here still lands there, never in "both revert alike".
AUTH_ERROR_SIGS = ("OwnableUnauthorizedAccount(address)",
                   "AccessControlUnauthorizedAccount(address,bytes32)",
                   "Unauthorized()", "NotOwner()", "OnlyOwner()", "CallerNotOwner()",
                   "NotAuthorized()", "Forbidden()", "OnlyAdmin()", "NotAdmin()",
                   "OnlyGuardian()", "OnlyManager()", "ProxyDeniedAdminAccess()")
AUTH_ERRORS = {selector(s): s[:s.index("(")] for s in AUTH_ERROR_SIGS}
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
    # NOT the same shape as a refusal by the contract. ok=False with data=None means
    # nobody answered, and a caller comparing revert payloads must not read that as
    # "the gate rejected this caller".
    return dict(ok=False, data=None, msg="all endpoints failed", unanswered=True)


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


def _as_address(v, floor=1 << 100):
    """A 32-byte return that is shaped like an address, else None. The floor rejects
    timestamps and token amounts, which also have twelve zero leading bytes."""
    if not isinstance(v, str) or len(v) != 66:
        return None
    w = int(v, 16)
    return None if (w >> 160 or w < floor) else "0x" + v[-40:]


def authorities(c, addr, sels, admin=None, sweep=False):
    """({label: address}, [unread labels]) — every authority-shaped getter in `sels`.

    Named getters first (AUTHORITY_GETTERS, intersected with the dispatch table so
    nothing absent is called). `sweep=True` also calls every OTHER selector in the
    table with empty calldata and keeps the ones that return an address, labelled by
    selector — the way to find a gate named something nobody thought to list. It
    costs one eth_call per selector, so audit() uses it only when a gate refused the
    stranger and no named candidate got past it.

    A getter that reverts is absent. One that was never answered is UNREAD and is
    returned as such, never folded into absent (pitfall #26)."""
    found, unread = {}, []
    # Named getters in AUTHORITY_GETTERS order, so owner() is tried — and labels an
    # address — before any alias of it.
    todo = ([(selector(g), g) for g in AUTHORITY_GETTERS if selector(g) in sels]
            if not sweep else
            [(s, s + "()") for s in sorted(sels)
             if s not in AUTH_GETTER and s not in DANGEROUS][:64])
    for s, label in todo:
        try:
            v = c.eth_call(addr, s)
        except RevertError:
            continue
        except Exception:
            unread.append(label)
            continue
        a = _as_address(v)
        if a and a not in found.values():       # getOwner() == owner() is one holder
            found[label] = a
    if admin and not sweep:
        found["eip1967.admin"] = admin
    return found, unread


def probe_authorities(c, addr, sel, cands, sig=None):
    """Who, among `cands` ({label: address}), gets past the gate on `sel`?

    Same method as probe_callable — compare revert payloads, never success — widened
    from one owner to every candidate. The calldata is IDENTICAL for the control, the
    stranger and every candidate (address slots all carry one fixed address), so any
    difference in outcome can only come from msg.sender.

    Returns dict(verdict=str, callable_by={label: address}, gated_unknown=bool).
    """
    sig = sig or (DANGEROUS.get(sel, ("f(address)",))[0])
    fill = next(iter(cands.values()), STRANGER)
    args = encode_args(sig, fill)
    ctl = _raw_call(c, addr, "0xdeadbeef" + args, fill)
    stranger = _raw_call(c, addr, sel + args, STRANGER)
    res = {k: _raw_call(c, addr, sel + args, a) for k, a in cands.items()}
    out = dict(callable_by={}, gated_unknown=False)
    if ctl.get("unanswered") or stranger.get("unanswered"):
        return {**out, "verdict": "UNREAD (the probe was never answered — re-run)"}
    if ctl["ok"]:
        return {**out, "verdict": "INCONCLUSIVE (fallback accepts anything)"}
    if stranger["ok"]:
        return {**out, "verdict": "ANYONE"}
    answered = {k: r for k, r in res.items() if not r.get("unanswered")}
    silent = [k for k in res if k not in answered]
    tried = ", ".join(cands) or "none found"
    if _is_auth_refusal(stranger):
        why = AUTH_ERRORS.get(stranger["data"]) or (
            stranger["msg"].replace("execution reverted: ", "")[:40]
            if stranger["data"] in (None, "", "0x08c379a0")                 # Error(string)
            else stranger["data"])
        passed = {k: cands[k] for k, r in answered.items() if not _is_auth_refusal(r)}
        if passed:
            who = "" if list(passed) == ["owner()"] else f" [{', '.join(passed)}]"
            return {**out, "callable_by": passed,
                    "verdict": f"OWNER-ONLY{who} (stranger refused: {why})"}
        if silent:
            # The holder may be exactly the candidate whose probe went unanswered.
            return {**out, "verdict": f"UNREAD (stranger refused: {why}; the probe from "
                                      f"{', '.join(silent)} was never answered — re-run)"}
        return {**out, "gated_unknown": True,
                "verdict": f"GATED, HOLDER UNKNOWN (stranger refused: {why}; no candidate "
                           f"passes — tried {tried}). A role or a custom slot holds it; "
                           f"find it before calling this path absent"}
    # The stranger was refused with a payload we do not recognise as an auth error. A
    # candidate that fails DIFFERENTLY on identical calldata still shows the function
    # depends on the caller — but a per-caller balance check does the same, so this is
    # reported as a lead, not as a proven gate, and never counts as live.
    differs = {k: cands[k] for k, r in answered.items()
               if r["ok"] or (not _is_auth_refusal(r)
                              and (r["data"], r["msg"]) != (stranger["data"], stranger["msg"]))}
    if differs:
        return {**out, "callable_by": differs,
                "verdict": f"CALLER-DEPENDENT [{', '.join(differs)}] (stranger reverts "
                           f"{stranger['data'] or stranger['msg'][:30]!r}, they do not) — "
                           f"auth error not recognised; confirm by hand"}
    return {**out, "verdict": "INCONCLUSIVE (both revert alike)"}


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
    impl, admin = _slot(c, addr, SLOT_IMPL), _slot(c, addr, SLOT_ADMIN)
    # A proxy's own bytecode is a 45-byte delegate stub with no dispatch table — scanning
    # it finds nothing. The functions that matter live in the implementation.
    impl_unread = None
    if impl:
        try:
            icode = c.call("eth_getCode", [impl, "latest"])
            if icode not in ("0x", "0x0"):
                sels |= selectors(icode)
        except Exception as e:
            # A proxy keeps its ENTIRE privilege surface in the implementation. Swallowing
            # this refusal reports "no dangerous selectors" for a contract whose selectors
            # were never read — the escape hatch reads as absent because the node was busy.
            # One audit's deposit vault was a 130-byte proxy whose full-balance
            # emergencyWithdraw lived only in its implementation.
            impl_unread = str(e)[:90]
    # AFTER the implementation's selectors are merged. Computing this from the proxy's
    # own stub reported every UUPS proxy as bare "upgradeable" while the full-balance
    # emergencyWithdraw in its implementation never reached the list at all.
    found = [dict(selector=s, name=DANGEROUS[s][0], kind=DANGEROUS[s][1])
             for s in sorted(sels & DANGEROUS.keys())]
    # Getters are called on `addr`, never on the implementation: behind a proxy the
    # implementation's own storage is empty, and the authority lives in the proxy's.
    # "This contract has no owner()" and "the node would not answer" are different
    # facts, and only the first is data — a revert is absence, anything else is UNREAD.
    auth, auth_unread = authorities(c, addr, sels | {"0x8da5cb5b"}, admin)
    owner = auth.get("owner()")
    owner_unread = "owner() was never answered" if "owner()" in auth_unread else None
    swept = False
    if check_callable:
        for f in found:
            if f["kind"] not in PROBE_KINDS:
                continue
            r = probe_authorities(c, addr, f["selector"], auth)
            if r["gated_unknown"] and not swept:
                # A gate refused the stranger and no named getter holds it. Before
                # reporting "holder unknown", ask every other getter in the table once.
                swept = True
                more, silent = authorities(c, addr, sels, sweep=True)
                auth_unread += silent
                more = {k: v for k, v in more.items() if v not in auth.values()}
                if more:
                    auth.update(more)
                    r = probe_authorities(c, addr, f["selector"], auth)
            f["owner_can_call"] = r["verdict"]
            f["callable_by"] = r["callable_by"]
            f["gated_unknown"] = r["gated_unknown"]
            # ANYONE is strictly worse than OWNER-ONLY: an unguarded escape hatch can
            # be called by anyone, not merely by the owner. Both are live.
            f["live"] = (f["kind"] in LIVE_KINDS
                         and (r["verdict"].startswith("OWNER-ONLY") or r["verdict"] == "ANYONE"))
            f["unguarded"] = r["verdict"] == "ANYONE"
    return dict(address=addr, is_contract=True, codesize=(len(code) - 2) // 2,
                is_proxy=bool(impl or admin), implementation=impl, proxy_admin=admin,
                owner=owner, authorities=auth, authorities_unread=auth_unread,
                privileged=found,
                impl_unread=impl_unread, owner_unread=owner_unread,
                verdict=_verdict(found, impl, admin, impl_unread, owner_unread,
                                 auth=auth, owner=owner,
                                 unread_getters=[g for g in auth_unread if g != "owner()"]))


def _verdict(found, impl, admin, impl_unread=None, owner_unread=None, auth=None, owner=None,
             unread_getters=()):
    kinds = {f["kind"] for f in found}
    bad = []
    # These come FIRST. A clean-looking privilege list over an unread implementation is
    # the most dangerous output this tool can produce, so it may never be printed
    # without the reason it is incomplete.
    if impl_unread:
        bad.append(f"IMPLEMENTATION NOT READ ({impl_unread}) — this is a proxy and its "
                   f"selectors are where the escape hatch lives. Everything below "
                   f"describes the PROXY ONLY and is not an audit. Re-run.")
    if owner_unread:
        bad.append(f"owner() NOT READ ({owner_unread}) — the probes below ran without it, so "
                   f"a path it holds reads as HOLDER UNKNOWN, not as OWNER-ONLY. Re-run.")
    others = {k: v for k, v in (auth or {}).items() if k != "owner()"}
    if not owner and others:
        # owner=None printed alone reads as "nobody controls this". It meant only that
        # the one conventional getter is absent.
        bad.append("no owner() — but authority getters answer: "
                   + ", ".join(f"{k}={v}" for k, v in others.items())
                   + ". owner=None does NOT mean ownerless")
    if unread_getters:
        bad.append(f"{len(unread_getters)} authority getter(s) never answered "
                   f"({', '.join(unread_getters[:4])}) — a holder among them would read as "
                   f"HOLDER UNKNOWN, not as absent. Re-run")
    unknown = [f["name"] for f in found if f.get("gated_unknown")]
    if unknown:
        bad.append(f"GATED BY AN UNIDENTIFIED AUTHORITY {unknown} — the stranger is refused "
                   f"and no getter's address gets past it. Someone holds this; find the "
                   f"role or storage slot before reporting the path as unowned")
    leads = [f"{f['name']} ({', '.join(f['callable_by'])})" for f in found
             if f.get("owner_can_call", "").startswith("CALLER-DEPENDENT")]
    if leads:
        bad.append(f"caller-dependent, auth error not recognised: {leads} — likely gated, "
                   f"confirm by hand")
    if impl or admin:
        bad.append("upgradeable — today's bytecode is not a commitment")
    if "supply" in kinds:
        bad.append("supply is mutable — float control is moot, they can print")
    if "escape" in kinds:
        live = [f["name"] + (f" by {', '.join(f['callable_by'])}" if f.get("callable_by") else "")
                for f in found if f["kind"] == "escape" and f.get("live")]
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
                   help="skip the live stranger-vs-authority calls that prove a path is real")
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
        for k, v in r.get("authorities", {}).items():
            if k != "owner()":
                print(f"  {'':9s}{k:>24s} {v}")
        for f in r["privileged"]:
            print(f"  {'!!' if f.get('live') else '  '} [{f['kind']:9s}] {f['name']:36s} "
                  f"{f.get('owner_can_call','')}")
        for v in r["verdict"]:
            print(f"  -> {v}")
        # Every address that actually got past a gate, not only owner(): the threshold
        # of whoever holds the key is the real control, whatever the getter is called.
        held = {v: k for f in r["privileged"] for k, v in f.get("callable_by", {}).items()}
        if r.get("owner"):
            held.setdefault(r["owner"], "owner()")
        for holder, label in held.items():
            s = safe_control(c, holder)
            if s["is_safe"]:
                who = "owner" if label == "owner()" else f"{label} {holder}"
                print(f"  -> {who} is a Safe {s['threshold']}/{len(s['owners'])}")
    if a.json:
        print(json.dumps(out, indent=1, default=str))
    sys.exit(1 if any(f.get("live") for o in out for f in o.get("privileged", [])) else 0)
