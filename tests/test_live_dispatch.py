#!/usr/bin/env python3
"""Live regression: a selector with a leading zero byte must be found in real bytecode.

    python tests/test_live_dispatch.py          # or: python -m pytest tests

Network test, deliberately kept OUT of scripts/selftest.py (which never touches the
chain) and out of the installed skill. selftest checks the same dispatcher shapes on
synthetic bytecode; this checks them on a contract solc actually compiled.

The contract is a private LP vault on BNB Chain whose `withdraw(uint256,address)` —
selector 0x00f714ce, pushed with PUSH3 — let its owner pull the whole position in one
call. The PUSH4-only scan reported that vault as having no withdraw at all.
"""
import pathlib, sys, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent
                       / "tracing-token-float" / "scripts"))
import privileges as PV                                   # noqa: E402
from rpc import Client                                    # noqa: E402

ENDPOINT = "https://bsc-dataseed.bnbchain.org"
VAULT = "0x35cef3cc00c657228f91a987e98ac1cde8544d37"
WITHDRAW = "0x00f714ce"                                  # withdraw(uint256,address)


def _push2_jump_targets(code_hex):
    """Every PUSH2 immediate that feeds a JUMPI — the values a naive short-push scan
    would report as selectors."""
    ops = PV._disasm(bytes.fromhex(code_hex[2:]))
    return {"0x" + imm.rjust(4, b"\0").hex()
            for (op, imm), (nxt, _) in zip(ops, ops[1:]) if op == 0x61 and nxt == 0x57}


class LiveDispatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.code = Client([ENDPOINT], timeout=20).call("eth_getCode", [VAULT, "latest"])
        except Exception as e:
            # Unanswered is not "absent" (pitfall #26): skip loudly, never pass.
            raise unittest.SkipTest(f"{ENDPOINT} did not answer eth_getCode: {e}")
        if cls.code in ("0x", "0x0"):
            raise unittest.SkipTest(f"{VAULT} has no code at latest — the fixture is gone")

    def test_selector_self_derived(self):
        from topics import selector
        self.assertEqual(selector("withdraw(uint256,address)"), WITHDRAW)

    def test_push3_selector_is_found(self):
        self.assertIn(WITHDRAW, PV.selectors(self.code))

    def test_it_is_pushed_with_push3(self):
        # If this ever fails the fixture no longer exercises the bug: solc changed, or
        # the address now holds different code. Find another 0x00-prefixed contract.
        b = bytes.fromhex(self.code[2:])
        self.assertIn(bytes.fromhex("62f714ce14"), b)
        self.assertNotIn(bytes.fromhex("6300f714ce"), b)

    def test_push2_jump_targets_are_not_reported(self):
        jumps = _push2_jump_targets(self.code)
        self.assertTrue(jumps, "no PUSH2 JUMPI in the fixture — the check below is vacuous")
        self.assertFalse(PV.selectors(self.code) & jumps,
                         f"jump targets reported as selectors: "
                         f"{sorted(PV.selectors(self.code) & jumps)}")

    def test_escape_hatch_reaches_the_audit(self):
        found = {s for s in PV.selectors(self.code) if s in PV.DANGEROUS}
        self.assertIn(WITHDRAW, found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
