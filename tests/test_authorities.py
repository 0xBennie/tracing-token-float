#!/usr/bin/env python3
"""Who holds the gate — privileges.audit() against a stubbed node. No network.

    python tests/test_authorities.py          # or: python -m pytest tests

The live cases (a vault gated on a custom primaryOwner(), a token whose mint answers to
getOwner()) exercise only the named-getter path. The sweep for a getter nobody listed,
and the verdicts that must NOT count as live, need a contract built to hit them.
"""
import pathlib, sys, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent
                       / "tracing-token-float" / "scripts"))
import privileges as PV                                   # noqa: E402
from rpc import Client                                    # noqa: E402
from topics import selector                               # noqa: E402

HOLDER = "0x" + "ab" * 20
EW = selector("emergencyWithdraw()")                      # in DANGEROUS, kind escape


def _word(addr):
    return "0x" + addr[2:].rjust(64, "0")


class FakeContract:
    """A dispatch table, a set of getters, and one gated function."""

    def __init__(self, getters, gate):
        self.getters = getters                # {selector: address}
        self.gate = gate                      # f(caller) -> JSON-RPC reply for EW
        sels = list(getters) + [EW]
        body = "".join(f"8063{s[2:]}14610100 57".replace(" ", "") for s in sels)
        self.code = "0x3560e01c" + body + "5f80fd"

    def reply(self, req):
        m, p = req["method"], req["params"]
        if m == "eth_getCode":
            return {"result": self.code}
        if m == "eth_getStorageAt":
            return {"result": "0x" + "0" * 64}
        data, caller = p[0]["data"], p[0].get("from")
        if data[:10] in self.getters and len(data) == 10:
            return {"result": _word(self.getters[data[:10]])}
        if data[:10] == EW:
            return self.gate(caller)
        return {"error": {"code": 3, "message": "execution reverted", "data": "0x"}}


class _Resp:
    status_code = 200

    def __init__(self, j):
        self._j = j

    def raise_for_status(self):
        pass

    def json(self):
        return self._j


class _Session:
    def __init__(self, k):
        self.k = k

    def post(self, url, json, timeout):
        return _Resp({"jsonrpc": "2.0", "id": json["id"], **self.k.reply(json)})


def _audit(contract):
    c = Client(["stub://node"])
    c.s = _Session(contract)
    return PV.audit(c, "0x" + "cd" * 20)


def _revert(data):
    return {"error": {"code": 3, "message": "execution reverted", "data": data}}


def _gate(allowed, refusal="0x82b42900"):
    return lambda caller: {"result": "0x"} if caller == allowed else _revert(refusal)


def _finding(r):
    return next(f for f in r["privileged"] if f["selector"] == EW)


class Authorities(unittest.TestCase):
    def test_named_getter_other_than_owner(self):
        r = _audit(FakeContract({selector("primaryOwner()"): HOLDER}, _gate(HOLDER)))
        f = _finding(r)
        self.assertIsNone(r["owner"])
        self.assertTrue(f["live"])
        self.assertEqual(f["callable_by"], {"primaryOwner()": HOLDER})
        self.assertTrue(any("does NOT mean ownerless" in v for v in r["verdict"]))

    def test_unlisted_getter_is_found_by_the_sweep(self):
        odd = selector("custodian()")
        self.assertNotIn(odd, PV.AUTH_GETTER)
        r = _audit(FakeContract({odd: HOLDER}, _gate(HOLDER)))
        f = _finding(r)
        self.assertTrue(f["live"], f["owner_can_call"])
        self.assertEqual(f["callable_by"], {odd + "()": HOLDER})

    def test_gate_nobody_passes_is_holder_unknown_not_clean(self):
        r = _audit(FakeContract({}, _gate("0x" + "ee" * 20)))
        f = _finding(r)
        self.assertFalse(f["live"])
        self.assertTrue(f["gated_unknown"])
        self.assertTrue(any("UNIDENTIFIED AUTHORITY" in v for v in r["verdict"]))

    def test_unrecognised_refusal_is_a_lead_not_live(self):
        r = _audit(FakeContract({selector("owner()"): HOLDER},
                                _gate(HOLDER, refusal="0xabcdef01")))
        f = _finding(r)
        self.assertTrue(f["owner_can_call"].startswith("CALLER-DEPENDENT"))
        self.assertFalse(f["live"])

    def test_anyone(self):
        r = _audit(FakeContract({}, lambda caller: {"result": "0x"}))
        f = _finding(r)
        self.assertEqual(f["owner_can_call"], "ANYONE")
        self.assertTrue(f["live"] and f["unguarded"])

    def test_proxy_admin_denied_is_not_a_pass(self):
        # An OZ5 transparent proxy refuses its OWN admin with ProxyDeniedAdminAccess().
        # Unlisted, that reads as "the admin got past the gate the stranger could not".
        admin_err = selector("ProxyDeniedAdminAccess()")
        r = _audit(FakeContract({selector("admin()"): HOLDER},
                                lambda caller: _revert(admin_err if caller == HOLDER
                                                       else "0x82b42900")))
        f = _finding(r)
        self.assertFalse(f["live"])
        self.assertNotIn("admin()", f["callable_by"])

    def test_unanswered_candidate_is_unread_not_unknown(self):
        # The probe from the real holder times out. "Holder unknown" would be a claim
        # about the contract made from a silence of the node (pitfall #26).
        def gate(caller):
            if caller == HOLDER:
                raise ConnectionError("node went away")
            return _revert("0x82b42900")
        r = _audit(FakeContract({selector("primaryOwner()"): HOLDER}, gate))
        f = _finding(r)
        self.assertTrue(f["owner_can_call"].startswith("UNREAD"), f["owner_can_call"])
        self.assertFalse(f["gated_unknown"] or f["live"])

    def test_same_address_under_two_getters_is_one_holder(self):
        r = _audit(FakeContract({selector("owner()"): HOLDER,
                                 selector("getOwner()"): HOLDER}, _gate(HOLDER)))
        self.assertEqual(r["authorities"], {"owner()": HOLDER})
        self.assertEqual(_finding(r)["owner_can_call"],
                         "OWNER-ONLY (stranger refused: Unauthorized)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
