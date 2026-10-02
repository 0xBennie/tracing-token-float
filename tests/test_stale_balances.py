#!/usr/bin/env python3
"""A persisted `balances` table must never pass for a later snapshot. No network.

    python tests/test_stale_balances.py          # or: python -m pytest tests

The failure this pins: balances.py stamped snapshot_block = "" when no --at-block was
given, replay.py then extended to_block by an increment, and the old table kept the
name `balances` — every ad-hoc SELECT read the past while meta said the present.
Also pins that a zero-value Transfer (address poisoning) is not activity.
"""
import contextlib, io, pathlib, sqlite3, sys, tempfile, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent
                       / "tracing-token-float" / "scripts"))
import balances as BL                                     # noqa: E402
import replay as RP                                       # noqa: E402

ZERO = "0x" + "0" * 40
A, B, P = "0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "ee" * 20
E = 10 ** 18


def _db(path, hi, rows):
    c = RP.setup(path)
    c.executemany("INSERT INTO transfers VALUES(?,?,?,?,?,?)",
                  [(b, f"0x{i:064x}", 0, f, d, str(v)) for i, (b, f, d, v) in enumerate(rows)])
    c.execute("INSERT INTO ranges_done VALUES(1,?,?,0)", (hi, len(rows)))
    for k, v in (("token", "0x" + "11" * 20), ("from_block", "1"), ("to_block", str(hi))):
        c.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))
    c.commit()
    return c


def _quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        r = fn(*a, **kw)
    return r, out.getvalue()


class StaleBalances(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(pathlib.Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_without_at_block_stamps_head(self):
        c = _db(self.db, 100, [(1, ZERO, A, 10 * E)])
        bal, _ = _quiet(BL.rebuild, self.db)
        _quiet(BL.save, self.db, bal, 10 * E)
        self.assertEqual(RP.meta_get(c, "snapshot_block"), "100")

    def test_increment_retires_old_table(self):
        c = _db(self.db, 100, [(1, ZERO, A, 10 * E)])
        bal, _ = _quiet(BL.rebuild, self.db)
        _quiet(BL.save, self.db, bal, 10 * E)
        c.execute("INSERT INTO transfers VALUES(150,'0xff',0,?,?,?)", (A, B, str(4 * E)))
        c.commit()
        _, out = _quiet(RP.retire_stale_balances, c, "100", 200)
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("balances", names)          # a stale SELECT now fails loudly
        self.assertIn("balances_at_100", names)      # and nothing was deleted
        self.assertIn("Renamed", out)

    def test_legacy_empty_stamp_is_bounded_by_previous_head(self):
        c = _db(self.db, 100, [(1, ZERO, A, 10 * E)])
        bal, _ = _quiet(BL.rebuild, self.db)
        _quiet(BL.save, self.db, bal, 10 * E)
        c.execute("UPDATE meta SET v='' WHERE k='snapshot_block'")   # pre-fix database
        c.commit()
        _quiet(RP.retire_stale_balances, c, "100", 200)
        self.assertIsNotNone(c.execute(
            "SELECT 1 FROM sqlite_master WHERE name='balances_at_100'").fetchone())

    def test_current_table_is_left_alone(self):
        c = _db(self.db, 100, [(1, ZERO, A, 10 * E)])
        bal, _ = _quiet(BL.rebuild, self.db)
        _quiet(BL.save, self.db, bal, 10 * E)
        _quiet(RP.retire_stale_balances, c, "100", 100)
        self.assertIsNotNone(c.execute(
            "SELECT 1 FROM sqlite_master WHERE name='balances'").fetchone())

    def test_verify_reports_stale(self):
        c = _db(self.db, 100, [(1, ZERO, A, 10 * E)])
        bal, _ = _quiet(BL.rebuild, self.db)
        _quiet(BL.save, self.db, bal, 10 * E, at_block=50)
        _, out = _quiet(RP.verify, self.db)
        self.assertIn("STALE", out)

    def test_zero_value_transfer_is_not_activity(self):
        _db(self.db, 300, [(1, ZERO, A, 10 * E), (5, A, B, 1 * E), (250, A, P, 0)])
        bal, _ = _quiet(BL.rebuild, self.db)
        self.assertEqual(bal[A].wei, 9 * E)
        self.assertEqual(bal[A].last_block, 5)       # not 250: the poison row
        self.assertEqual(bal[A].n_out, 1)
        self.assertNotIn(P, {a for a, h in bal.items() if h.n_in})


if __name__ == "__main__":
    unittest.main()
